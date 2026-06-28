# SEMAR Output Formats

SEMAR renders the same scan result into seven formats. Pick one with
`-o/--output`, or generate several at once with `--formats` + `--output-dir`.

| Format | Flag value | Best for | Extension |
|--------|-----------|----------|-----------|
| Terminal | `terminal` | Interactive use (default) | — |
| JSON | `json` | Automation, SIEM/BI ingestion | `.json` |
| SARIF | `sarif` | GitHub/Azure code scanning | `.sarif` |
| Markdown | `markdown` | PRs, wikis, tickets | `.md` |
| HTML | `html` | Shareable offline dashboard | `.html` |
| PDF | `pdf` | Executive/management report | `.pdf` |
| CSV | `csv` | Spreadsheets, pivot tables | `.csv` |

```bash
semar audit --formats json,sarif,html,pdf --output-dir ./semar-report
```

> **stdout stays clean.** When you stream a machine format to stdout
> (`-o json`), the banner and logs go to **stderr**, so `semar audit -o json | jq`
> works without contamination.

---

## Terminal

Colored, human-first summary: a header box, per-finding blocks (severity, ID,
file:line, evidence, risk, OWASP/CWE, fix), severity bar chart, an aggregate risk
score, and a compliance summary. Respects `--no-color` and auto-disables color
when not a TTY.

---

## JSON

The canonical machine schema (`schema_version: "1.0"`). Top-level shape:

```json
{
  "schema_version": "1.0",
  "tool": { "name": "SEMAR", "version": "0.1.0", "informationUri": "https://github.com/masriyan/semar" },
  "scan": {
    "id": "scan-…",
    "timestamp": "2026-06-28T14:32:00+07:00",
    "duration_ms": 4218,
    "target": { "path": "…", "agent_type": "claude-code", "agent_version": "" },
    "config": { "rules_evaluated": 40, "files_scanned": 847 }
  },
  "summary": {
    "total_findings": 31,
    "by_severity": { "CRITICAL": 2, "HIGH": 8, "MEDIUM": 5, "LOW": 14, "INFO": 2 },
    "risk_score": 7.4,
    "risk_level": "HIGH",
    "compliance": {
      "owasp_llm": { "categories_triggered": ["LLM01","LLM02"], "coverage": "6/10" },
      "mitre_atlas": { "ttps": ["AML.T0054"], "count": 4 },
      "nist_ai_rmf": { "controls": ["GOVERN-1.1","MANAGE-2.4"] }
    }
  },
  "findings": [ /* array of Finding objects */ ]
}
```

### The `Finding` object

| Field | Type | Notes |
|-------|------|-------|
| `id` | string | Stable rule ID, e.g. `SEMAR-SEC-001` |
| `rule_id` | string | Slug used in SARIF, e.g. `secrets/anthropic-api-key` |
| `title` | string | Short actionable title |
| `severity` | string | `CRITICAL`…`INFO` |
| `confidence` | string | `HIGH` \| `MEDIUM` \| `LOW` |
| `category` | string | `secrets`, `config`, `prompt-injection`, … |
| `file_path`, `line`, `column` | string/int | Location (0 if N/A) |
| `snippet` | string | Redacted context line |
| `description`, `impact`, `evidence` | string | Evidence is redacted |
| `owasp`, `mitre`, `cwe`, `nist` | []string | Framework mappings |
| `remediation`, `remediation_code` | string | Fix guidance (never auto-applied) |
| `references` | []string | External links |
| `risk_score`, `exploitability_score`, `impact_score` | float | 0–10 |
| `cvss_vector` | string | When available |
| `false_positive_risk` | string | Known FP scenarios |

`findings` is always present (empty array on a clean scan, never `null`), and the
order is deterministic: severity desc → ID → file → line.

---

## SARIF

[SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
for code-scanning platforms. Each rule is emitted once in
`runs[].tool.driver.rules` with `security-severity` and framework properties;
each finding becomes a `result` with `level` (`error`/`warning`/`note`),
message, and physical location.

```bash
semar audit --output sarif --file results.sarif
```

Upload to GitHub via `github/codeql-action/upload-sarif` — findings appear inline
on the PR. See [CI_INTEGRATION.md](CI_INTEGRATION.md).

---

## Markdown

A full report: header (org/assessor/date/classification/risk), a severity
dashboard table, OWASP LLM Top 10 coverage table, MITRE ATLAS table, and
per-finding detail with description, impact, evidence, remediation, and
references. Ideal for pasting into PRs, wikis, or issue trackers.

---

## HTML

A **standalone, offline glassmorphism dashboard** — a single `.html` file with
all CSS and JS inline (air-gap friendly):

- Frosted-glass cards over a gradient backdrop
- SVG **risk gauge** and animated severity bars
- **OWASP LLM Top 10 heatmap**, MITRE ATLAS and NIST tables
- Live search + severity filter, expandable finding cards with tag pills and
  highlighted remediation
- Dark/light theme toggle, in-browser **CSV export**, print-to-PDF
- Print-friendly stylesheet

```bash
semar audit --output html --file report.html
```

---

## PDF

A multi-section **executive report**:

1. **Cover page** — gradient banner, title, classification badge, metadata table,
   confidentiality notice
2. **Executive summary** — narrative, risk distribution bars, top critical/high
   findings, compliance posture
3. **Technical findings** — per-finding severity badge, location, description,
   impact, evidence, framework refs, and a highlighted remediation box
4. **Appendix A** — OWASP/MITRE compliance mapping tables
5. **Appendix B** — scan methodology

```bash
semar audit --output pdf --file report.pdf \
  --org "Acme Corp" --assessor "Security Team" --classification CONFIDENTIAL
```

---

## CSV

One row per finding with columns: `id, rule_id, title, severity, confidence,
category, file, line, risk_score, owasp, cwe, mitre, evidence, remediation`.
Multi-value fields are `;`-separated. Perfect for spreadsheets and BI tools.

---

## Re-rendering without re-scanning

Save JSON once, render anything later with `semar report`:

```bash
semar audit -o json -f scan.json
semar report --input scan.json -o pdf  -f exec.pdf
semar report --input scan.json -o html -f dash.html
```
