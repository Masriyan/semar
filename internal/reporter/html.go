package reporter

import (
	"encoding/json"
	"html/template"
	"io"
	"math"

	"github.com/masriyan/semar/internal/modules"
	"github.com/masriyan/semar/internal/modules/compliance"
)

// HTMLReporter renders a standalone, offline-capable glassmorphism dashboard.
type HTMLReporter struct{}

type htmlData struct {
	Title          string
	Org            string
	Assessor       string
	Classification string
	Agent          string
	Target         string
	Timestamp      string
	Duration       string
	Version        string
	ScanID         string
	RiskScore      float64
	RiskLevel      string
	RiskColor      string
	GaugeDash      string // SVG stroke-dasharray for the risk arc
	Total          int
	FilesScanned   int
	RulesCount     int
	Severities     []htmlSeverity
	OWASP          []htmlOWASP
	OWASPCoverage  string
	MITRE          []htmlPair
	NIST           []htmlPair
	Modules        []htmlModule
	FindingsJSON   template.JS
}

type htmlSeverity struct {
	Name    string
	Count   int
	Percent float64
	Color   string
}

type htmlOWASP struct {
	ID    string
	Name  string
	Count int
}

type htmlPair struct {
	ID   string
	Name string
}

type htmlModule struct {
	Name     string
	Findings int
	Duration string
}

var sevHex = map[modules.Severity]string{
	modules.SeverityCritical: "#ff4d6d",
	modules.SeverityHigh:     "#ff8c42",
	modules.SeverityMedium:   "#ffd166",
	modules.SeverityLow:      "#06d6a0",
	modules.SeverityInfo:     "#4cc9f0",
}

// Render implements Reporter.
func (h *HTMLReporter) Render(w io.Writer, r *Report) error {
	total := len(r.Result.Findings)

	var sevs []htmlSeverity
	for _, s := range severityOrder {
		n := r.BySeverity[s]
		pct := 0.0
		if total > 0 {
			pct = float64(n) / float64(total) * 100
		}
		sevs = append(sevs, htmlSeverity{Name: string(s), Count: n, Percent: pct, Color: sevHex[s]})
	}

	var owasp []htmlOWASP
	for _, id := range owaspIDs() {
		owasp = append(owasp, htmlOWASP{ID: id, Name: compliance.OWASPLLM[id], Count: r.Compliance.OWASPCounts[id]})
	}

	var mitre []htmlPair
	for _, id := range r.Compliance.MITRETTPs {
		mitre = append(mitre, htmlPair{ID: id, Name: compliance.MITREATLAS[id]})
	}
	var nist []htmlPair
	for _, id := range r.Compliance.NISTControls {
		nist = append(nist, htmlPair{ID: id, Name: compliance.NISTAIRMF[id]})
	}

	var mods []htmlModule
	for name, st := range r.Result.ModuleStats {
		mods = append(mods, htmlModule{Name: name, Findings: st.Findings, Duration: st.Duration.Round(1e6).String()})
	}

	fj, err := json.Marshal(r.Result.Findings)
	if err != nil {
		return err
	}

	title := r.Meta.Title
	if title == "" {
		title = "SEMAR Security Audit Report"
	}

	// Risk gauge: arc length over a circle of radius 80 (circumference ~502.65).
	const circumference = 2 * math.Pi * 80
	filled := circumference * (r.RiskScore / 10.0)
	gaugeDash := formatFloat(filled) + " " + formatFloat(circumference)

	data := htmlData{
		Title:          title,
		Org:            r.Meta.Org,
		Assessor:       r.Meta.Assessor,
		Classification: r.Meta.Classification,
		Agent:          string(r.Target.AgentType),
		Target:         r.Target.RootPath,
		Timestamp:      r.Timestamp.Format("2006-01-02 15:04:05 MST"),
		Duration:       r.Result.Duration().Round(1e6).String(),
		Version:        r.Meta.ToolVersion,
		ScanID:         r.ScanID,
		RiskScore:      r.RiskScore,
		RiskLevel:      string(r.RiskLevel),
		RiskColor:      sevHex[r.RiskLevel],
		GaugeDash:      gaugeDash,
		Total:          total,
		FilesScanned:   r.FilesScanned,
		RulesCount:     r.RulesCount,
		Severities:     sevs,
		OWASP:          owasp,
		OWASPCoverage:  r.Compliance.OWASPCoverage(),
		MITRE:          mitre,
		NIST:           nist,
		Modules:        mods,
		FindingsJSON:   template.JS(fj),
	}

	return htmlTemplate.Execute(w, data)
}

func formatFloat(f float64) string {
	return template.HTMLEscapeString(trimFloat(f))
}

func trimFloat(f float64) string {
	return jsonNumber(f)
}

func jsonNumber(f float64) string {
	b, _ := json.Marshal(math.Round(f*100) / 100)
	return string(b)
}

var htmlTemplate = template.Must(template.New("report").Parse(htmlTemplateSrc))
