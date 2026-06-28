package reporter

import (
	"encoding/json"
	"io"

	"github.com/masriyan/semar/internal/modules"
)

// SARIFReporter emits SARIF 2.1.0 compliant output.
type SARIFReporter struct{}

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string                 `json:"id"`
	Name             string                 `json:"name"`
	ShortDescription sarifText              `json:"shortDescription"`
	FullDescription  sarifText              `json:"fullDescription"`
	HelpURI          string                 `json:"helpUri,omitempty"`
	Properties       map[string]interface{} `json:"properties,omitempty"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifText       `json:"message"`
	Locations []sarifLocation `json:"locations"`
	Properties map[string]interface{} `json:"properties,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           *sarifRegion          `json:"region,omitempty"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine   int `json:"startLine,omitempty"`
	StartColumn int `json:"startColumn,omitempty"`
}

func sarifLevel(s modules.Severity) string {
	switch s {
	case modules.SeverityCritical, modules.SeverityHigh:
		return "error"
	case modules.SeverityMedium, modules.SeverityLow:
		return "warning"
	default:
		return "note"
	}
}

// Render implements Reporter.
func (s *SARIFReporter) Render(w io.Writer, r *Report) error {
	rulesSeen := map[string]bool{}
	var rules []sarifRule
	var results []sarifResult

	for _, f := range r.Result.Findings {
		ruleID := f.RuleID
		if ruleID == "" {
			ruleID = f.ID
		}
		if !rulesSeen[ruleID] {
			rulesSeen[ruleID] = true
			helpURI := ""
			if len(f.References) > 0 {
				helpURI = f.References[0]
			}
			rules = append(rules, sarifRule{
				ID:               ruleID,
				Name:             f.ID,
				ShortDescription: sarifText{Text: f.Title},
				FullDescription:  sarifText{Text: f.Description},
				HelpURI:          helpURI,
				Properties: map[string]interface{}{
					"security-severity": f.RiskScore,
					"owasp":             f.OWASP,
					"cwe":               f.CWE,
					"mitre-atlas":       f.MITRE,
				},
			})
		}

		var region *sarifRegion
		if f.Line > 0 {
			region = &sarifRegion{StartLine: f.Line, StartColumn: f.Column}
		}
		uri := f.FilePath
		if uri == "" {
			uri = "unknown"
		}

		results = append(results, sarifResult{
			RuleID:  ruleID,
			Level:   sarifLevel(f.Severity),
			Message: sarifText{Text: f.Title + " — " + f.Evidence},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: uri},
					Region:           region,
				},
			}},
			Properties: map[string]interface{}{
				"severity":   string(f.Severity),
				"confidence": string(f.Confidence),
				"finding_id": f.ID,
			},
		})
	}

	log := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "SEMAR",
				Version:        r.Meta.ToolVersion,
				InformationURI: "https://github.com/masriyan/semar",
				Rules:          rules,
			}},
			Results: results,
		}},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}
