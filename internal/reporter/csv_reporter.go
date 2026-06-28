package reporter

import (
	"encoding/csv"
	"io"
	"strconv"
	"strings"
)

// CSVReporter emits findings as CSV for spreadsheet consumption.
type CSVReporter struct{}

// Render implements Reporter.
func (c *CSVReporter) Render(w io.Writer, r *Report) error {
	cw := csv.NewWriter(w)
	defer cw.Flush()

	header := []string{"id", "rule_id", "title", "severity", "confidence", "category", "file", "line", "risk_score", "owasp", "cwe", "mitre", "evidence", "remediation"}
	if err := cw.Write(header); err != nil {
		return err
	}

	for _, f := range r.Result.Findings {
		row := []string{
			f.ID, f.RuleID, f.Title, string(f.Severity), string(f.Confidence), f.Category,
			f.FilePath, strconv.Itoa(f.Line), strconv.FormatFloat(f.RiskScore, 'f', 1, 64),
			strings.Join(f.OWASP, ";"), strings.Join(f.CWE, ";"), strings.Join(f.MITRE, ";"),
			f.Evidence, f.Remediation,
		}
		if err := cw.Write(row); err != nil {
			return err
		}
	}
	return cw.Error()
}
