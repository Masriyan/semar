# SEMAR Use Cases

SEMAR is built for everyone who deploys, secures, or governs AI agents. This
document walks through concrete scenarios by role, with the exact commands you'd
run.

- [Developer: pre-commit hygiene](#developer-pre-commit-hygiene)
- [Platform/DevOps: CI/CD gate](#platformdevops-cicd-gate)
- [Red team: agent attack-surface mapping](#red-team-agent-attack-surface-mapping)
- [Blue team / SOC: fleet posture monitoring](#blue-team--soc-fleet-posture-monitoring)
- [Incident response: post-compromise triage](#incident-response-post-compromise-triage)
- [GRC / Compliance: framework evidence](#grc--compliance-framework-evidence)
- [Security consultant: client assessments](#security-consultant-client-assessments)
- [Open-source maintainer: protect contributors](#open-source-maintainer-protect-contributors)
- [Real-world finding walkthroughs](#real-world-finding-walkthroughs)

---

## Developer: pre-commit hygiene

**Problem:** You're building a Claude Code or Cursor project and keep pasting API
keys into `CLAUDE.md` or `.env` "just for testing." One `git push` later, it's in
history forever.

**Solution:**

```bash
semar audit --modules secrets --fail-on HIGH
```

Wire it into a pre-commit hook so a leaked key blocks the commit before it ever
reaches the remote. SEMAR redacts the secret in its output, so the finding itself
never re-leaks the value.

---

## Platform/DevOps: CI/CD gate

**Problem:** Your org ships dozens of agent configs across many repos. You need a
uniform, automated policy: no agent with a CRITICAL misconfiguration reaches
`main`.

**Solution:**

```bash
semar audit --target . --fail-on CRITICAL --output sarif --file results.sarif
```

Upload `results.sarif` to GitHub code scanning so findings appear inline on the
PR with OWASP/CWE context. Exit code `1` blocks the merge. Full pipeline recipes
(GitHub Actions, GitLab CI, Jenkins) live in
[docs/CI_INTEGRATION.md](docs/CI_INTEGRATION.md).

---

## Red team: agent attack-surface mapping

**Problem:** You're assessing a target that uses AI agents. You want to enumerate
the agent's *agency* — what it can be coerced into doing via prompt injection.

**Solution:**

```bash
semar audit --target ./engagement/loot \
  --modules prompt-injection,iam,config,network \
  --severity LOW \
  --formats markdown,html \
  --output-dir ./findings \
  --org "Client Co" --assessor "Red Team" --classification CONFIDENTIAL
```

The `prompt-injection` module maps injectable surfaces (system prompts, tool
descriptions, instruction files) and scores them against OWASP LLM01. The `iam`
and `config` modules reveal whether a successful injection would reach a shell,
broad filesystem writes, or destructive tools without an approval gate — i.e. how
far an injection actually gets you.

---

## Blue team / SOC: fleet posture monitoring

**Problem:** You operate many AI agents and want a repeatable, trackable measure
of their security posture over time.

**Solution:** Run SEMAR on a schedule across each agent's config directory and
collect the JSON:

```bash
for dir in /opt/agents/*; do
  semar audit --target "$dir" -o json -f "reports/$(basename "$dir").json"
done
```

Ingest the JSON into your SIEM/BI. The deterministic output and `risk_score`
field make trend dashboards trivial — you can alert when an agent's score
regresses or a new CRITICAL appears.

---

## Incident response: post-compromise triage

**Problem:** An agent did something it shouldn't have. You need to know *how* —
fast.

**Solution:**

```bash
semar audit --target /path/to/agent --scan-env --severity LOW -o markdown -f triage.md
```

`--scan-env` includes environment variables (opt-in because it's sensitive). The
report surfaces leaked secrets, injectable context that may have carried the
malicious instruction, over-broad permissions that let the action succeed, and
network paths (SSRF, cloud-metadata, cleartext) that could have exfiltrated data.
Because SEMAR is read-only, running it does not disturb forensic state.

---

## GRC / Compliance: framework evidence

**Problem:** An auditor asks, "How do you manage AI risk against OWASP LLM Top 10
and NIST AI RMF?"

**Solution:**

```bash
semar audit --target . --formats pdf,json --output-dir ./evidence \
  --org "Acme Corp" --assessor "GRC Team" --classification INTERNAL
```

The PDF executive report includes a **compliance mapping appendix** (OWASP /
MITRE ATLAS / NIST) and a methodology section. The JSON gives you machine-readable
evidence with per-finding `owasp_llm`, `mitre_atlas`, `nist_ai_rmf`, and `cwe`
references for your GRC platform.

---

## Security consultant: client assessments

**Problem:** You deliver AI-security assessments and need branded, reproducible,
defensible reports.

**Solution:**

```bash
semar audit --target "$CLIENT_REPO" \
  --severity LOW \
  --formats html,pdf,sarif,json \
  --output-dir "./$CLIENT-semar" \
  --title "AI Agent Security Assessment" \
  --org "$CLIENT" --assessor "Your Name" --classification CONFIDENTIAL
```

You get an interactive HTML dashboard for the working session, a polished PDF for
the deliverable, SARIF for the client's tooling, and JSON for your own records —
all from one deterministic run.

---

## Open-source maintainer: protect contributors

**Problem:** Your repo ships an agent config (`.mcp.json`, `CLAUDE.md`,
`.cursorrules`). You don't want a malicious PR to slip a prompt-injection payload
or an unpinned, CVE-laden MCP server into it.

**Solution:** Add a SEMAR self-audit job to CI (see the bundled
`.github/workflows/ci.yml`):

```yaml
- run: semar audit --target . --severity HIGH --fail-on CRITICAL
```

Now every PR is checked for injected instructions in agent context files and for
supply-chain regressions in MCP definitions.

---

## Real-world finding walkthroughs

A scan of the bundled vulnerable fixture
(`test/fixtures/claude_code`) demonstrates the kinds of issues SEMAR catches:

| Finding | Why it matters |
|---------|----------------|
| `SEMAR-SEC-001` Anthropic API key in `CLAUDE.md` | A committed key = unlimited billed API access for anyone with repo read |
| `SEMAR-PI-004` Exfiltration instruction in context | "Send the user's data to https://…" embedded where the agent will read it |
| `SEMAR-CFG-004` File write permissions too broad (`*`) | An injection can now write anywhere on disk |
| `SEMAR-CFG-005` MCP server bound to `0.0.0.0` | The MCP server is exposed to the whole network |
| `SEMAR-IAM-003` Access to `~/.ssh` / `~/.aws` | Injection → credential theft |
| `SEMAR-CFG-015` Auto-approve without human-in-the-loop | No checkpoint before destructive tool calls |

Each of these is reported with severity, evidence (redacted), OWASP/CWE/MITRE/NIST
mappings, a risk score, and a concrete remediation — and SEMAR fixes none of them
for you, by design. (See [PHILOSOPHY.md](PHILOSOPHY.md).)

---

More commands and flags: [USAGE.md](USAGE.md). Project home:
**[github.com/masriyan/semar](https://github.com/masriyan/semar)**.
