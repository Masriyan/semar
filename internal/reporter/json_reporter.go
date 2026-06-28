package reporter

import (
	"encoding/json"
	"io"

	"github.com/masriyan/semar/internal/modules"
)

// JSONReporter emits the structured JSON schema documented in OUTPUT_FORMATS.md.
type JSONReporter struct{}

type jsonOutput struct {
	SchemaVersion string         `json:"schema_version"`
	Tool          jsonTool       `json:"tool"`
	Scan          jsonScan       `json:"scan"`
	Summary       jsonSummary    `json:"summary"`
	Findings      []*modules.Finding `json:"findings"`
}

type jsonTool struct {
	Name           string `json:"name"`
	Version        string `json:"version"`
	InformationURI string `json:"informationUri"`
}

type jsonScan struct {
	ID        string    `json:"id"`
	Timestamp string    `json:"timestamp"`
	DurationMS int64    `json:"duration_ms"`
	Target    jsonTarget `json:"target"`
	Config    jsonConfig `json:"config"`
}

type jsonTarget struct {
	Path         string `json:"path"`
	AgentType    string `json:"agent_type"`
	AgentVersion string `json:"agent_version"`
}

type jsonConfig struct {
	SeverityThreshold string `json:"severity_threshold"`
	RulesEvaluated    int    `json:"rules_evaluated"`
	FilesScanned      int    `json:"files_scanned"`
}

type jsonSummary struct {
	TotalFindings int            `json:"total_findings"`
	BySeverity    map[string]int `json:"by_severity"`
	RiskScore     float64        `json:"risk_score"`
	RiskLevel     string         `json:"risk_level"`
	Compliance    jsonCompliance `json:"compliance"`
}

type jsonCompliance struct {
	OWASP map[string]interface{} `json:"owasp_llm"`
	MITRE map[string]interface{} `json:"mitre_atlas"`
	NIST  map[string]interface{} `json:"nist_ai_rmf"`
}

// Render implements Reporter.
func (j *JSONReporter) Render(w io.Writer, r *Report) error {
	bySev := map[string]int{}
	for _, s := range severityOrder {
		bySev[string(s)] = r.BySeverity[s]
	}

	out := jsonOutput{
		SchemaVersion: "1.0",
		Tool: jsonTool{
			Name:           "SEMAR",
			Version:        r.Meta.ToolVersion,
			InformationURI: "https://github.com/masriyan/semar",
		},
		Scan: jsonScan{
			ID:         r.ScanID,
			Timestamp:  r.Timestamp.Format("2006-01-02T15:04:05Z07:00"),
			DurationMS: r.Result.Duration().Milliseconds(),
			Target: jsonTarget{
				Path:         r.Target.RootPath,
				AgentType:    string(r.Target.AgentType),
				AgentVersion: r.Target.AgentVersion,
			},
			Config: jsonConfig{
				RulesEvaluated: r.RulesCount,
				FilesScanned:   r.FilesScanned,
			},
		},
		Summary: jsonSummary{
			TotalFindings: len(r.Result.Findings),
			BySeverity:    bySev,
			RiskScore:     r.RiskScore,
			RiskLevel:     string(r.RiskLevel),
			Compliance: jsonCompliance{
				OWASP: map[string]interface{}{
					"categories_triggered": r.Compliance.OWASPTriggered,
					"coverage":             r.Compliance.OWASPCoverage(),
				},
				MITRE: map[string]interface{}{
					"ttps":  r.Compliance.MITRETTPs,
					"count": len(r.Compliance.MITRETTPs),
				},
				NIST: map[string]interface{}{
					"controls": r.Compliance.NISTControls,
				},
			},
		},
		Findings: r.Result.Findings,
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
