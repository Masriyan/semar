# SEMAR Usage Guide

Complete command-line reference for SEMAR, with flags, exit codes, and recipes.

- [Command overview](#command-overview)
- [Global flags](#global-flags)
- [`semar audit` / `semar scan`](#semar-audit--semar-scan)
- [`semar report`](#semar-report)
- [`semar list`](#semar-list)
- [`semar version`](#semar-version)
- [Exit codes](#exit-codes)
- [Auditing specific agents](#auditing-specific-agents)
- [Recipes](#recipes)
- [The `.semar.yml` config file](#the-semaryml-config-file)
- [Baselines & suppression](#baselines--suppression)

---

## Command overview

```
semar audit [flags]          Run a full security audit (auto-detects the agent)
semar scan  [flags]          Alias for audit
semar report --input <file>  Re-render a previous JSON result in another format
semar list agents            List supported agent types
semar list modules           List scan modules with descriptions
semar list rules             List every rule ID per module
semar version                Show banner, build info, supported agents & modules
```

---

## Global flags

These apply to every command:

| Flag | Default | Description |
|------|---------|-------------|
| `--config <path>` | `.semar.yml` | Path to the SEMAR config file |
| `--log-level <level>` | `info` | `debug` \| `info` \| `warn` \| `error` |
| `--log-format <fmt>` | `text` | `text` \| `json` (structured logs) |
| `--no-color` | `false` | Disable ANSI colors (also auto-off when piped) |
| `--quiet` | `false` | Suppress logs and the banner; show findings only |
| `-v, --verbose` | `false` | Shortcut for `--log-level debug` |

---

## `semar audit` / `semar scan`

The core command. Loads the target, runs the selected modules concurrently,
scores and maps findings, and renders one or more reports.

### Target & detection

| Flag | Default | Description |
|------|---------|-------------|
| `--target <path>` | `.` | Directory to audit |
| `--agent <type>` | *(auto)* | Force agent type: `claude-code`, `codex`, `cursor`, `hermes`, `copilot`, `generic-mcp` |
| `--scan-env` | `false` | Also scan environment variables (privacy-sensitive, opt-in) |

### Module & rule selection

| Flag | Default | Description |
|------|---------|-------------|
| `--modules <list>` | *(all)* | Comma-separated modules to run: `secrets,config,prompt-injection,iam,supply-chain,network,sandbox` |
| `--exclude-modules <list>` | — | Modules to skip |
| `--cve-lookup` | `false` | Enable live OSV.dev CVE lookups in `supply-chain` (network access) |

### Severity filtering

| Flag | Default | Description |
|------|---------|-------------|
| `--severity <level>` | `LOW` | Minimum severity to report: `CRITICAL` \| `HIGH` \| `MEDIUM` \| `LOW` \| `INFO` |

### Performance

| Flag | Default | Description |
|------|---------|-------------|
| `--workers <n>` | `NumCPU` | Parallel scan workers |
| `--timeout <dur>` | `5m` | Maximum scan duration (e.g. `30s`, `2m`) |

### Output

| Flag | Default | Description |
|------|---------|-------------|
| `-o, --output <fmt>` | `terminal` | `terminal` \| `json` \| `sarif` \| `markdown` \| `html` \| `pdf` \| `csv` |
| `-f, --file <path>` | *(stdout)* | Write the single output to a file |
| `--output-dir <dir>` | — | Write multiple formats into a directory |
| `--formats <list>` | — | Generate several formats at once, e.g. `json,sarif,html,pdf` |

### CI / threshold gating

| Flag | Default | Description |
|------|---------|-------------|
| `--fail-on <level>` | — | Exit `1` if any finding ≥ this severity |
| `--fail-on-count <n>` | `0` | Exit `1` if total findings ≥ `n` |

### Report metadata (for HTML/PDF/Markdown headers)

| Flag | Default | Description |
|------|---------|-------------|
| `--title <str>` | `SEMAR Security Audit Report` | Report title |
| `--org <str>` | — | Organization name |
| `--assessor <str>` | — | Assessor name |
| `--classification <str>` | `CONFIDENTIAL` | `CONFIDENTIAL` \| `INTERNAL` \| `PUBLIC` |

---

## `semar report`

Re-render a previously saved SEMAR **JSON** result into any other format —
without re-scanning. Useful for generating an executive PDF from a JSON artifact
your CI already produced.

```bash
semar audit --target . -o json -f scan.json
semar report --input scan.json -o pdf  -f report.pdf
semar report --input scan.json -o html -f report.html
```

| Flag | Default | Description |
|------|---------|-------------|
| `--input <path>` | *(required)* | A SEMAR JSON results file |
| `-o, --output <fmt>` | `terminal` | Target format |
| `-f, --file <path>` | *(stdout)* | Output file |

---

## `semar list`

```bash
semar list agents     # all supported agent types
semar list modules    # module name + description
semar list rules      # every rule ID, grouped by module
```

Great for discovering rule IDs to pass to filtering (planned `--rules` selection)
or for generating documentation.

---

## `semar version`

Prints the SEMAR banner, version, commit, build date, and the full list of
supported agents and scan modules.

```bash
semar version
semar version --no-color   # plain output for logs
```

---

## Exit codes

Exit codes are a **stable contract** — CI pipelines depend on them, and they will
never change semantics within a major version.

| Code | Meaning |
|------|---------|
| `0` | Scan completed; no findings at or above `--fail-on` |
| `1` | Scan completed; findings found at or above `--fail-on` (or `--fail-on-count`) |
| `2` | Scan error (invalid target, module failure, timeout) |
| `3` | Configuration error (invalid flags, missing required args) |

---

## Auditing specific agents

SEMAR auto-detects the agent type from filesystem markers, so `semar audit
--target <dir>` usually just works. Use `--agent` to force a type when detection
is ambiguous or when you point SEMAR at a non-standard location.

> **Tip — avoid scanning conversation logs.** Some agents keep large plaintext
> history/cache directories next to their config (e.g. Claude Code's `projects/`,
> `history.jsonl`, `file-history/`, caches). Scanning those produces a flood of
> low-value high-entropy "secret" hits. Point SEMAR at the **config directory or
> file**, not the whole home folder, for a clean, fast result.

### Claude Code (Anthropic)

Config lives in `~/.claude/` (user scope) and `.claude/` (project scope), plus
`CLAUDE.md` and `.mcp.json`.

```bash
# Project-scoped config (recommended — clean, no logs)
semar audit --target ./.claude --agent claude-code

# Include the project's CLAUDE.md and .mcp.json (audit the repo root)
semar audit --target . --agent claude-code

# User-scoped settings only (avoid ~/.claude logs/caches)
semar audit --target ~/.claude/settings.json --agent claude-code   # single file
# or audit the whole user dir, then ignore the noise (see note above)
semar audit --target ~/.claude --agent claude-code --severity HIGH
```

### OpenAI Codex / ChatGPT

Looks for `openai.json`, `.codex/`, and assistant/tool definition files.

```bash
semar audit --target . --agent codex
semar audit --target ~/.codex --agent codex --output html --file codex-report.html
```

### OpenCode

OpenCode uses an MCP-style config (`opencode.json` / `.opencode/`,
`AGENTS.md`). It is audited through the **generic MCP** profile:

```bash
semar audit --target . --agent generic-mcp
semar audit --target ~/.config/opencode --agent generic-mcp
```

### Cursor IDE

Detects `.cursorrules`, `.cursor/mcp.json`, and `.cursor/rules`.

```bash
semar audit --target . --agent cursor
semar audit --target ./.cursor --agent cursor --modules config,prompt-injection,supply-chain
```

### GitHub Copilot

Detects `.github/copilot-instructions.md` and Copilot config.

```bash
semar audit --target . --agent copilot --modules prompt-injection,secrets
```

### Hermes (Nous Research)

Detects `hermes.json`, `hermes.yaml`, `inference.yaml`.

```bash
semar audit --target /opt/hermes --agent hermes --modules secrets,config,network
```

### Any MCP-compatible agent (generic)

For agents SEMAR doesn't have a named profile for (custom agents, other MCP
clients), force the generic MCP profile. It scans `mcp.json` / `mcp_config.json`
/ `.mcp.json`, tool definitions, and any config/instruction files it finds.

```bash
semar audit --target ./my-agent --agent generic-mcp
```

### Auditing several agents at once

```bash
for a in claude-code codex cursor copilot generic-mcp; do
  semar audit --target . --agent "$a" -o json -f "report-$a.json" 2>/dev/null
done
```

> If you don't pass `--agent`, SEMAR picks the best-matching profile
> automatically — run `semar list agents` to see all supported types.

---

## Recipes

```bash
# Quick scan of the current directory (auto-detect)
semar audit

# Audit a specific Claude Code install, terminal output
semar audit --target ~/.claude --agent claude-code

# CI gate: fail on any HIGH+ finding, emit SARIF for code scanning
semar audit --target . --fail-on HIGH --output sarif --file results.sarif

# Full enterprise audit, every format, branded headers
semar audit \
  --target /opt/ai-agent \
  --agent codex \
  --severity LOW \
  --formats "json,sarif,html,pdf,markdown" \
  --output-dir ./semar-report \
  --org "PT Example Indonesia" \
  --assessor "Security Team" \
  --classification CONFIDENTIAL

# Only secrets + prompt injection, medium and above
semar audit --modules secrets,prompt-injection --severity MEDIUM

# Everything except the slow/network module
semar audit --exclude-modules supply-chain

# Enable live CVE lookups (needs network)
semar audit --modules supply-chain --cve-lookup

# Pipe JSON to jq (banner goes to stderr, stdout stays clean)
semar audit -o json | jq '.summary'

# Generate an executive PDF from a prior JSON result
semar report --input scan.json -o pdf -f exec-report.pdf
```

---

## The `.semar.yml` config file

Point `--config` at a YAML file to set defaults for a repository so contributors
don't have to remember flags. (CLI flags always override file values.)

```yaml
# .semar.yml
target: .
severity: LOW
modules:
  - secrets
  - config
  - prompt-injection
  - iam
  - network
  - sandbox
fail-on: HIGH
classification: INTERNAL
org: "Your Organization"
```

---

## Baselines & suppression

For managing accepted/known findings over time, SEMAR is designed around a
baseline workflow (planned flags `--baseline` / `--update-baseline`): you record
the current finding set, then future scans only fail on *new* findings. Until
then, use `--fail-on` / `--fail-on-count` plus module/severity filtering to tune
CI signal. See [docs/CI_INTEGRATION.md](docs/CI_INTEGRATION.md) for patterns.

---

For the conceptual model behind these commands, see
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). For format schemas, see
[docs/OUTPUT_FORMATS.md](docs/OUTPUT_FORMATS.md).
