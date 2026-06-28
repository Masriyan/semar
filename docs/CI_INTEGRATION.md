# CI/CD Integration

SEMAR is built for pipelines: a single static binary, deterministic output, a
stable exit-code contract, and SARIF for native code-scanning integration.

- [The exit-code contract](#the-exit-code-contract)
- [GitHub Actions](#github-actions)
- [GitLab CI](#gitlab-ci)
- [Jenkins](#jenkins)
- [pre-commit](#pre-commit)
- [Docker in CI](#docker-in-ci)
- [Tuning the signal](#tuning-the-signal)

---

## The exit-code contract

| Code | Meaning | Typical CI behavior |
|------|---------|---------------------|
| `0` | No findings ≥ `--fail-on` | Pass |
| `1` | Findings ≥ `--fail-on` / `--fail-on-count` | Fail the job |
| `2` | Scan error (bad target, timeout, module failure) | Fail / investigate |
| `3` | Config error (bad flags) | Fail / fix the invocation |

These never change meaning within a major version, so you can rely on them.

---

## GitHub Actions

### Minimal gate

```yaml
name: AI Agent Security
on: [pull_request]

jobs:
  semar:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with: { go-version: '1.22' }
      - run: go install github.com/masriyan/semar@latest
      - run: semar audit --target . --fail-on HIGH
```

### With SARIF code-scanning (inline PR annotations)

```yaml
name: SEMAR
on:
  pull_request:
  push: { branches: [main] }

permissions:
  contents: read
  security-events: write   # required to upload SARIF

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with: { go-version: '1.22' }
      - run: go install github.com/masriyan/semar@latest

      - name: Run SEMAR
        run: semar audit --target . --severity LOW --output sarif --file semar.sarif
        continue-on-error: true   # let SARIF upload even if findings exist

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: semar.sarif

      - name: Enforce gate
        run: semar audit --target . --fail-on CRITICAL
```

> The repo ships a ready-to-use workflow at `.github/workflows/ci.yml` that
> tests, lints, and self-audits SEMAR on every PR.

---

## GitLab CI

```yaml
semar:
  image: golang:1.22
  stage: test
  script:
    - go install github.com/masriyan/semar@latest
    - $(go env GOPATH)/bin/semar audit --target . --fail-on HIGH --output json --file semar.json
  artifacts:
    when: always
    paths: [semar.json]
    reports:
      # GitLab can ingest SARIF as a SAST report:
      sast: semar.sarif
  allow_failure: false
```

To produce the SARIF artifact too, add
`--formats json,sarif --output-dir .` and rename as needed.

---

## Jenkins

```groovy
pipeline {
  agent any
  stages {
    stage('SEMAR Audit') {
      steps {
        sh 'go install github.com/masriyan/semar@latest'
        sh '$(go env GOPATH)/bin/semar audit --target . --formats json,html --output-dir semar-report'
      }
    }
  }
  post {
    always {
      archiveArtifacts artifacts: 'semar-report/**', allowEmptyArchive: true
      publishHTML(target: [reportDir: 'semar-report', reportFiles: 'semar-report.html', reportName: 'SEMAR'])
    }
  }
}
```

Gate the build with a dedicated step:

```groovy
sh '$(go env GOPATH)/bin/semar audit --target . --fail-on CRITICAL'  // non-zero fails the stage
```

---

## pre-commit

Block secrets and injected instructions before they're committed.

`.pre-commit-config.yaml`:

```yaml
repos:
  - repo: local
    hooks:
      - id: semar
        name: SEMAR AI agent audit
        entry: semar audit --modules secrets,prompt-injection --fail-on HIGH --quiet
        language: system
        pass_filenames: false
```

Or a plain Git hook (`.git/hooks/pre-commit`):

```bash
#!/usr/bin/env bash
semar audit --modules secrets,prompt-injection --fail-on HIGH --quiet || {
  echo "SEMAR blocked the commit — resolve the findings above."; exit 1; }
```

---

## Docker in CI

```bash
docker run --rm -v "$PWD:/scan:ro" semar:local \
  audit --target /scan --fail-on HIGH --no-color
```

Mounting `:ro` makes SEMAR's read-only guarantee kernel-enforced.

---

## Tuning the signal

- **Start permissive, then tighten.** Begin with `--fail-on CRITICAL`, fix the
  worst issues, then ratchet down to `HIGH`.
- **Scope modules in fast hooks.** Pre-commit: `--modules secrets,prompt-injection`.
  Full CI: all modules.
- **Keep `--cve-lookup` out of offline runners.** It needs network to `api.osv.dev`.
- **Archive JSON every run.** Deterministic output makes diffing scans trivial and
  feeds trend dashboards.
- **Use `--quiet` in hooks** to suppress the banner/logs and show only findings.

For format details, see [OUTPUT_FORMATS.md](OUTPUT_FORMATS.md). For the full flag
list, see [../USAGE.md](../USAGE.md).
