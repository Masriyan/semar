package reporter

import (
	"fmt"
	"io"
	"strings"

	"github.com/masriyan/semar/internal/modules"
	"github.com/masriyan/semar/internal/modules/compliance"
)

// MarkdownReporter renders a Markdown audit report.
type MarkdownReporter struct{}

var sevEmoji = map[modules.Severity]string{
	modules.SeverityCritical: "🔴",
	modules.SeverityHigh:     "🟠",
	modules.SeverityMedium:   "🟡",
	modules.SeverityLow:      "🟢",
	modules.SeverityInfo:     "ℹ️",
}

// Render implements Reporter.
func (m *MarkdownReporter) Render(w io.Writer, r *Report) error {
	p := func(format string, a ...interface{}) { fmt.Fprintf(w, format, a...) }

	title := r.Meta.Title
	if title == "" {
		title = "SEMAR Security Audit Report"
	}
	p("# %s\n\n", title)
	if r.Meta.Org != "" {
		p("**Organization:** %s  \n", r.Meta.Org)
	}
	if r.Meta.Assessor != "" {
		p("**Assessor:** %s  \n", r.Meta.Assessor)
	}
	p("**Date:** %s  \n", r.Timestamp.Format("2006-01-02"))
	if r.Meta.Classification != "" {
		p("**Classification:** %s  \n", r.Meta.Classification)
	}
	p("**Target:** %s (%s)  \n", r.Target.RootPath, r.Target.AgentType)
	p("**Overall Risk:** %s %s (%.1f/10)\n\n", sevEmoji[r.RiskLevel], r.RiskLevel, r.RiskScore)
	p("---\n\n")

	total := len(r.Result.Findings)
	p("## Risk Dashboard\n\n")
	p("| Severity | Count | %% of Total |\n|----------|-------|------------|\n")
	for _, s := range severityOrder {
		n := r.BySeverity[s]
		pct := 0.0
		if total > 0 {
			pct = float64(n) / float64(total) * 100
		}
		p("| %s %s | %d | %.1f%% |\n", sevEmoji[s], s, n, pct)
	}
	p("| **TOTAL** | %d | 100%% |\n\n", total)

	p("## Compliance Coverage\n\n### OWASP LLM Top 10 (2025)\n\n")
	p("| Category | Name | Status | Findings |\n|----------|------|--------|----------|\n")
	for _, id := range owaspIDs() {
		n := r.Compliance.OWASPCounts[id]
		status := "✅ PASS"
		if n > 0 {
			status = "⚠️ FAIL"
		}
		p("| %s | %s | %s | %d |\n", id, compliance.OWASPLLM[id], status, n)
	}
	p("\n")

	if len(r.Compliance.MITRETTPs) > 0 {
		p("### MITRE ATLAS TTPs\n\n| TTP | Name |\n|-----|------|\n")
		for _, t := range r.Compliance.MITRETTPs {
			p("| %s | %s |\n", t, compliance.MITREATLAS[t])
		}
		p("\n")
	}

	p("## Findings Detail\n\n")
	for _, f := range r.Result.Findings {
		p("### [%s] %s — %s\n\n", f.Severity, f.ID, f.Title)
		p("**Severity:** %s | **Risk Score:** %.1f/10 | **Confidence:** %s  \n", f.Severity, f.RiskScore, f.Confidence)
		if f.FilePath != "" {
			p("**File:** `%s:%d`  \n", f.FilePath, f.Line)
		}
		p("**OWASP:** %s | **CWE:** %s | **MITRE:** %s\n\n",
			join(f.OWASP), join(f.CWE), join(f.MITRE))
		if f.Description != "" {
			p("**Description**  \n%s\n\n", f.Description)
		}
		if f.Impact != "" {
			p("**Impact**  \n%s\n\n", f.Impact)
		}
		if f.Evidence != "" {
			p("**Evidence**\n```\n%s\n```\n\n", f.Evidence)
		}
		if f.Remediation != "" {
			p("**Remediation**  \n%s\n\n", f.Remediation)
		}
		if len(f.References) > 0 {
			p("**References**\n")
			for _, ref := range f.References {
				p("- %s\n", ref)
			}
			p("\n")
		}
		p("---\n\n")
	}

	return nil
}

func owaspIDs() []string {
	return []string{"LLM01", "LLM02", "LLM03", "LLM04", "LLM05", "LLM06", "LLM07", "LLM08", "LLM09", "LLM10"}
}

func join(s []string) string {
	if len(s) == 0 {
		return "—"
	}
	return strings.Join(s, ", ")
}
