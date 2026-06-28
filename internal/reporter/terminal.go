package reporter

import (
	"fmt"
	"io"
	"strings"

	"github.com/fatih/color"

	"github.com/masriyan/semar/internal/modules"
	"github.com/masriyan/semar/internal/modules/compliance"
)

// TerminalReporter renders a human-friendly, colored terminal summary.
type TerminalReporter struct {
	NoColor bool
}

func sevColor(s modules.Severity) *color.Color {
	switch s {
	case modules.SeverityCritical:
		return color.New(color.FgHiRed, color.Bold)
	case modules.SeverityHigh:
		return color.New(color.FgRed)
	case modules.SeverityMedium:
		return color.New(color.FgYellow)
	case modules.SeverityLow:
		return color.New(color.FgGreen)
	default:
		return color.New(color.FgCyan)
	}
}

// Render implements Reporter.
func (t *TerminalReporter) Render(w io.Writer, r *Report) error {
	if t.NoColor {
		color.NoColor = true
	}

	bold := color.New(color.Bold)

	fmt.Fprintln(w, "┌─────────────────────────────────────────────────────────────────┐")
	bold.Fprintf(w, "│  SEMAR %-8s — AI Agent Security Audit%*s│\n", r.Meta.ToolVersion, 25, "")
	fmt.Fprintf(w, "│  Target: %-30s Agent: %-12s│\n", truncStr(r.Target.RootPath, 30), r.Target.AgentType)
	fmt.Fprintf(w, "│  Started: %-25s Duration: %-9s│\n", r.Timestamp.Format("2006-01-02 15:04:05"), r.Result.Duration().Round(1e6))
	fmt.Fprintln(w, "└─────────────────────────────────────────────────────────────────┘")
	fmt.Fprintln(w)

	if len(r.Result.Findings) == 0 {
		color.New(color.FgGreen, color.Bold).Fprintln(w, "✓ No findings. Clean scan.")
		return nil
	}

	fmt.Fprintln(w, "━━━━━━━━━━━━━━━━━━━━━━ FINDINGS ━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Fprintln(w)

	for _, f := range r.Result.Findings {
		c := sevColor(f.Severity)
		c.Fprintf(w, "● %-9s ", f.Severity)
		bold.Fprintf(w, "%-16s ", f.ID)
		fmt.Fprintln(w, f.Title)
		if f.FilePath != "" {
			loc := f.FilePath
			if f.Line > 0 {
				loc = fmt.Sprintf("%s:%d", f.FilePath, f.Line)
			}
			fmt.Fprintf(w, "  File:     %s\n", loc)
		}
		if f.Evidence != "" {
			fmt.Fprintf(w, "  Evidence: %s\n", truncStr(f.Evidence, 80))
		}
		fmt.Fprintf(w, "  Risk:     %.1f  │  OWASP: %s  │  CWE: %s\n", f.RiskScore, strings.Join(f.OWASP, ","), strings.Join(f.CWE, ","))
		if f.Remediation != "" {
			fmt.Fprintf(w, "  Fix:      %s\n", truncStr(f.Remediation, 80))
		}
		fmt.Fprintln(w)
	}

	t.renderSummary(w, r)
	return nil
}

func (t *TerminalReporter) renderSummary(w io.Writer, r *Report) {
	fmt.Fprintln(w, "━━━━━━━━━━━━━━━━━━━━━━ SUMMARY ━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Fprintln(w)
	for _, s := range severityOrder {
		n := r.BySeverity[s]
		bar := strings.Repeat("█", min(n, 10))
		sevColor(s).Fprintf(w, "  %-9s %-10s %d\n", s, bar, n)
	}
	fmt.Fprintln(w, "             ─────────────")
	fmt.Fprintf(w, "  TOTAL      %d findings across %d modules\n\n", len(r.Result.Findings), len(r.Result.ModuleStats))

	fmt.Fprintf(w, "  Risk Score:   %.1f / 10.0  (%s)\n", r.RiskScore, r.RiskLevel)
	fmt.Fprintf(w, "  Compliance:   OWASP LLM Top 10: %s categories triggered\n", r.Compliance.OWASPCoverage())
	fmt.Fprintf(w, "                MITRE ATLAS:      %d TTPs mapped\n", len(r.Compliance.MITRETTPs))
	fmt.Fprintf(w, "                NIST AI RMF:      %d controls referenced\n\n", len(r.Compliance.NISTControls))
	fmt.Fprintf(w, "  Files Scanned:   %d\n", r.FilesScanned)
	fmt.Fprintf(w, "  Rules Evaluated: %d\n", r.RulesCount)
	fmt.Fprintf(w, "  Duration:        %s\n", r.Result.Duration().Round(1e6))

	// Reference the compliance map so unused import is justified and useful.
	if len(r.Compliance.OWASPTriggered) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "  OWASP categories:")
		for _, id := range r.Compliance.OWASPTriggered {
			fmt.Fprintf(w, "    %s %s (%d)\n", id, compliance.OWASPLLM[id], r.Compliance.OWASPCounts[id])
		}
	}
}

func truncStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}
