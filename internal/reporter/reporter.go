// Package reporter renders scan results into the supported output formats.
package reporter

import (
	"fmt"
	"io"
	"time"

	"github.com/masriyan/semar/internal/engine"
	"github.com/masriyan/semar/internal/modules"
	"github.com/masriyan/semar/internal/modules/compliance"
	"github.com/masriyan/semar/internal/scorer"
)

// Meta carries report header metadata supplied via CLI flags.
type Meta struct {
	Title          string
	Org            string
	Assessor       string
	Classification string
	ToolVersion    string
}

// Report is the fully-assembled, render-ready view of a scan.
type Report struct {
	Meta         Meta
	ScanID       string
	Timestamp    time.Time
	Target       *modules.ScanTarget
	Result       *engine.ScanResult
	Compliance   compliance.Summary
	RiskScore    float64
	RiskLevel    modules.Severity
	BySeverity   map[modules.Severity]int
	RulesCount   int
	FilesScanned int
}

// Build assembles a Report from raw scan output.
func Build(meta Meta, scanID string, target *modules.ScanTarget, result *engine.ScanResult, rulesCount int) *Report {
	bySev := map[modules.Severity]int{}
	for _, f := range result.Findings {
		bySev[f.Severity]++
	}
	risk := scorer.Aggregate(result.Findings)

	return &Report{
		Meta:         meta,
		ScanID:       scanID,
		Timestamp:    result.StartTime,
		Target:       target,
		Result:       result,
		Compliance:   compliance.Summarize(result.Findings),
		RiskScore:    risk,
		RiskLevel:    scorer.RiskLevel(risk),
		BySeverity:   bySev,
		RulesCount:   rulesCount,
		FilesScanned: len(target.RawFiles),
	}
}

// Reporter renders a Report to a writer.
type Reporter interface {
	Render(w io.Writer, r *Report) error
}

// For returns the Reporter for a named format.
func For(format string, noColor bool) (Reporter, error) {
	switch format {
	case "", "terminal":
		return &TerminalReporter{NoColor: noColor}, nil
	case "json":
		return &JSONReporter{}, nil
	case "sarif":
		return &SARIFReporter{}, nil
	case "markdown", "md":
		return &MarkdownReporter{}, nil
	case "html":
		return &HTMLReporter{}, nil
	case "pdf":
		return &PDFReporter{}, nil
	case "csv":
		return &CSVReporter{}, nil
	default:
		return nil, fmt.Errorf("unknown output format %q (valid: terminal, json, sarif, markdown, html, pdf, csv)", format)
	}
}

// severityOrder lists severities from most to least severe for stable display.
var severityOrder = []modules.Severity{
	modules.SeverityCritical, modules.SeverityHigh, modules.SeverityMedium, modules.SeverityLow, modules.SeverityInfo,
}
