# SEMAR Rule Catalog & Authoring Guide

Every SEMAR finding has a stable **rule ID** of the form `SEMAR-<MODULE>-<NNN>`
(plus prompt-injection's `SEMAR-PI-<NNN>`). This document lists the built-in
rules and explains how detection, scoring, and framework mapping work.

- [Rule ID scheme](#rule-id-scheme)
- [Secrets (`SEMAR-SEC-*`)](#secrets-semar-sec)
- [Config hardening (`SEMAR-CFG-*`)](#config-hardening-semar-cfg)
- [Prompt injection (`SEMAR-PI-*`)](#prompt-injection-semar-pi)
- [IAM (`SEMAR-IAM-*`)](#iam-semar-iam)
- [Supply chain (`SEMAR-SCA-*`)](#supply-chain-semar-sca)
- [Network (`SEMAR-NET-*`)](#network-semar-net)
- [Sandbox (`SEMAR-SBX-*`)](#sandbox-semar-sbx)
- [Severity & scoring](#severity--scoring)
- [Confidence & false-positive handling](#confidence--false-positive-handling)
- [Authoring new rules](#authoring-new-rules)

Run `semar list rules` to print the live list from your installed binary.

---

## Rule ID scheme

```
SEMAR-SEC-001
      │   └── zero-padded sequence within the module
      └────── module code: SEC, CFG, PI, IAM, SCA, NET, SBX
```

IDs are stable across releases. A finding also carries a human `rule_id` slug
(e.g. `secrets/anthropic-api-key`) used in SARIF.

---

## Secrets (`SEMAR-SEC-*`)

Scans config files, system prompts, MCP `env` blocks, and (opt-in) environment
variables. **All matches are redacted** before being placed in any finding.

| ID | Detects | Severity |
|----|---------|----------|
| `SEMAR-SEC-001` | Anthropic API key (`sk-ant-*`) | CRITICAL |
| `SEMAR-SEC-002` | OpenAI API key (`sk-*`, `sk-proj-*`) | CRITICAL |
| `SEMAR-SEC-003` | AWS access key ID (`AKIA…`) | CRITICAL |
| `SEMAR-SEC-004` | GCP service-account JSON (`"type":"service_account"`) | HIGH |
| `SEMAR-SEC-005` | GitHub token (`ghp_…`, `github_pat_…`) | HIGH |
| `SEMAR-SEC-006` | High-entropy string (likely secret) | HIGH |
| `SEMAR-SEC-008` | PEM private-key material | CRITICAL |

**Detection methods:** provider regexes; Shannon entropy (threshold 4.5, lowered
to 3.8 when the variable name implies a secret — `key`, `secret`, `token`,
`password`, `credential`, `auth`). Placeholder/example context downgrades
confidence (or skips entropy hits).

---

## Config hardening (`SEMAR-CFG-*`)

| ID | Detects | Severity | OWASP |
|----|---------|----------|-------|
| `SEMAR-CFG-001` | Bash tool enabled without command allowlist | HIGH | LLM06, LLM08 |
| `SEMAR-CFG-002` | Preview/experimental model in use | LOW | — |
| `SEMAR-CFG-003` | Network access enabled without domain allowlist | HIGH | LLM02 |
| `SEMAR-CFG-004` | File-write permissions too broad (`*`, root, `..`) | CRITICAL | LLM08 |
| `SEMAR-CFG-005` | MCP server bound to `0.0.0.0` | HIGH | — |
| `SEMAR-CFG-013` | Logging disabled (audit-trail gap) | MEDIUM | — |
| `SEMAR-CFG-014` | Temperature > 1.5 (unpredictable behavior) | LOW | — |
| `SEMAR-CFG-015` | Auto-approve without human-in-the-loop | HIGH | LLM06 |
| `SEMAR-CFG-016` | MCP/system prompt loaded over cleartext HTTP | HIGH | LLM03 |

---

## Prompt injection (`SEMAR-PI-*`)

Scans system prompts, instruction files (`CLAUDE.md`, `.cursorrules`,
`copilot-instructions.md`, `*.md`), and tool `description` fields.

| ID | Pattern | Severity |
|----|---------|----------|
| `SEMAR-PI-001` | Role override ("ignore previous instructions") | CRITICAL |
| `SEMAR-PI-002` | DAN / jailbreak preamble | CRITICAL |
| `SEMAR-PI-003` | Indirect injection via tool description | HIGH |
| `SEMAR-PI-004` | Exfiltration instruction in context | CRITICAL |
| `SEMAR-PI-005` | Hidden instruction (zero-width steganography) | HIGH |
| `SEMAR-PI-006` | `SYSTEM:`/`ASSISTANT:` override prefix | CRITICAL |
| `SEMAR-PI-000` | **Compound** — multiple PI patterns in one source | scaled |

**Scoring:** each match contributes to an OWASP **LLM01** score (CRITICAL +5.0,
HIGH +3.0, …), capped at 10. When two or more patterns hit one source and the
score ≥ 4.0, a compound `SEMAR-PI-000` finding is raised at a severity derived
from the score (≥7.0 ⇒ CRITICAL).

---

## IAM (`SEMAR-IAM-*`)

| ID | Detects | Severity |
|----|---------|----------|
| `SEMAR-IAM-002` | No rate limiting configured for tool calls | MEDIUM |
| `SEMAR-IAM-003` | Access to sensitive dirs (`~/.ssh`, `/etc`, `~/.aws`, …) | HIGH |
| `SEMAR-IAM-005` | No human approval for destructive tools (delete/write/exec) | HIGH |

---

## Supply chain (`SEMAR-SCA-*`)

| ID | Detects | Severity |
|----|---------|----------|
| `SEMAR-SCA-001` | MCP package not pinned (`latest`, `^`, `~`) | MEDIUM |
| `SEMAR-SCA-003` | MCP package with known CVEs (OSV.dev, `--cve-lookup`) | HIGH |
| `SEMAR-SCA-007` | Dependencies not locked (no lockfile) | MEDIUM |

CVE lookups are **opt-in** via `--cve-lookup` (requires network access to
`api.osv.dev`).

---

## Network (`SEMAR-NET-*`)

| ID | Detects | Severity |
|----|---------|----------|
| `SEMAR-NET-002` | Cleartext HTTP endpoint | MEDIUM |
| `SEMAR-NET-003` | Private/internal IP in allowlist (SSRF risk) | HIGH |
| `SEMAR-NET-005` | TLS verification disabled | HIGH |
| `SEMAR-NET-007` | Cloud metadata endpoint reachable (`169.254.169.254`) | HIGH |

---

## Sandbox (`SEMAR-SBX-*`)

| ID | Detects | Severity |
|----|---------|----------|
| `SEMAR-SBX-002` | Docker socket mounted (container escape) | CRITICAL |
| `SEMAR-SBX-003` | Privileged container mode | CRITICAL |
| `SEMAR-SBX-005` | Running as root (UID 0) | HIGH / LOW |
| `SEMAR-SBX-006` | Host network mode | HIGH |

---

## Severity & scoring

| Severity | CVSS band | Meaning |
|----------|-----------|---------|
| CRITICAL | 9.0–10.0 | Immediate action required |
| HIGH | 7.0–8.9 | Fix before next deployment |
| MEDIUM | 4.0–6.9 | Fix in current sprint |
| LOW | 0.1–3.9 | Fix in backlog |
| INFO | — | Informational only |

Per-finding risk is derived from severity weight × confidence multiplier. The
aggregate scan score blends the worst-case finding (70%) with average pressure
(30%), so one CRITICAL dominates but volume still matters.

---

## Confidence & false-positive handling

Each finding carries a confidence: `HIGH`, `MEDIUM`, or `LOW`. Context that looks
like an example or placeholder (`example`, `placeholder`, `your-key`, `xxx`,
`fake`, `dummy`, `sample`, `<…>`, `redacted`) lowers confidence for secret
findings and suppresses generic entropy hits. Each rule documents its known
false-positive scenarios in the `false_positive_risk` field of the finding.

---

## Authoring new rules

SEMAR's detection lives in Go modules (the engine) with YAML definitions in
`rules/` serving as the canonical documentation/reference. To add detection
logic:

1. Implement (or extend) a module that satisfies `modules.Module`
   (`Name`, `Description`, `Severity`, `Rules`, `Run`).
2. Construct `*modules.Finding` values with a stable `ID`, `RuleID`, severity,
   confidence, location, `OWASP`/`CWE`/`MITRE`/`NIST` references, and a concrete
   `Remediation`. **Redact any sensitive value** via `modules.Redact` before it
   touches a finding.
3. Register the module in `internal/engine/registry.go`.
4. Add a matching YAML entry under `rules/<category>/` for documentation.

See [ARCHITECTURE.md](ARCHITECTURE.md#writing-a-custom-module) for the full
interface and an example. The YAML DSL format is documented inline in
`rules/secrets/api_keys.yml`.
