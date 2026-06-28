# Changelog

All notable changes to SEMAR are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> **Stability contract:** CLI **exit codes** (`0`/`1`/`2`/`3`) and the JSON
> `schema_version` are stable within a major version and will never change
> meaning in a minor or patch release.

---

## [Unreleased]

### Planned
- `--rules` / `--exclude-rules` for individual rule selection
- `--baseline` / `--update-baseline` for suppression of known findings
- YAML-driven rule loading (rules in `rules/` become the source of truth)
- SBOM emission for the audited agent's dependencies
- Audit log for scan operations (who ran what, when, against what)

---

## [0.1.0] — 2026-06-28

The first MVP release. SEMAR can detect, scan, score, map, and report on AI agent
security posture end-to-end.

### Added

**Core engine**
- Concurrent scan engine with a bounded worker pool, context cancellation,
  per-module panic recovery, and deterministic finding ordering
- CVSS-like risk scoring per finding plus an aggregate scan risk score
- Read-only, multi-format config loader (JSON / YAML / `.env`) that normalizes
  configs and extracts MCP servers, tool definitions, and system prompts
- Automatic agent-type detection via filesystem fingerprints

**Scan modules (7)**
- `secrets` — provider-specific patterns (Anthropic, OpenAI, AWS, GCP, GitHub),
  PEM private keys, and Shannon-entropy detection, with redaction at the source
- `config` — agent hardening checks (bash allowlist, write scope, network
  allowlist, MCP host binding, preview models, logging, auto-approve, temperature)
- `prompt-injection` — role override, jailbreak, indirect injection,
  exfiltration, and zero-width steganography patterns, with compounding LLM01
  scoring
- `iam` — sensitive-path access, missing approval gates, missing rate limits
- `supply-chain` — unpinned MCP packages, missing lockfiles, optional OSV.dev CVE
  lookups
- `network` — cleartext HTTP, private-IP/SSRF allowlist risk, cloud-metadata
  endpoint, disabled TLS verification
- `sandbox` — Docker socket mount, privileged mode, host network, running as root

**Compliance**
- Cross-references findings to OWASP LLM Top 10 (2025), MITRE ATLAS, NIST AI RMF
  1.0, and CWE

**Reporters (7)**
- `terminal` — colored interactive summary with severity bars
- `json` — full machine-readable schema (`schema_version` 1.0)
- `sarif` — SARIF 2.1.0 for code-scanning platforms
- `markdown` — report for PRs and wikis
- `html` — standalone, offline **glassmorphism dashboard** (risk gauge, OWASP
  heatmap, filterable findings, CSV export, dark/light theme, print-to-PDF)
- `pdf` — multi-section **executive report** (cover page, executive summary,
  technical findings, compliance appendix, methodology)
- `csv` — tabular export

**CLI**
- `audit` / `scan`, `report`, `list`, `version` commands
- Severity filtering, module include/exclude, multi-format output, threshold
  gating (`--fail-on`, `--fail-on-count`), and report metadata flags
- Colored ASCII **Semar banner** (auto-disabled when piped or `--no-color`),
  rendered to stderr during audits to keep stdout clean for machine formats

**Project**
- Makefile, GoReleaser config, GitHub Actions CI (test, lint, self-audit) and
  release workflows
- Unit tests (secrets/entropy) and an end-to-end integration test with a
  deliberately vulnerable fixture
- Documentation suite: README, INSTALL, USAGE, USECASE, PHILOSOPHY, plus
  `docs/` (ARCHITECTURE, AGENTS, RULES, OUTPUT_FORMATS, CI_INTEGRATION)

### Security
- SEMAR is **read-only by design** — it never modifies a target
- Secrets are redacted the instant they are detected and never stored in full in
  any finding or report

---

[Unreleased]: https://github.com/masriyan/semar/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/masriyan/semar/releases/tag/v0.1.0
