package reporter

import (
	"fmt"
	"io"

	"github.com/jung-kurt/gofpdf"

	"github.com/masriyan/semar/internal/modules"
	"github.com/masriyan/semar/internal/modules/compliance"
)

// PDFReporter renders a multi-section executive PDF report.
type PDFReporter struct {
	tr func(string) string
}

// t translates a UTF-8 string into the core-font (Windows-1252) encoding so
// characters like em-dashes and ellipses render correctly.
func (p *PDFReporter) t(s string) string {
	if p.tr == nil {
		return s
	}
	return p.tr(s)
}

// RGB color palette for severities.
var sevRGB = map[modules.Severity][3]int{
	modules.SeverityCritical: {255, 77, 109},
	modules.SeverityHigh:     {255, 140, 66},
	modules.SeverityMedium:   {224, 168, 0},
	modules.SeverityLow:      {6, 180, 130},
	modules.SeverityInfo:     {76, 201, 240},
}

const (
	pdfInk    = 0x1a
	pdfMuted  = 0x6a
	marginX   = 18.0
	contentW  = 174.0 // A4 width (210) - 2*margin
)

// Render implements Reporter.
func (p *PDFReporter) Render(w io.Writer, r *Report) error {
	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.SetMargins(marginX, 18, marginX)
	pdf.SetAutoPageBreak(true, 18)
	p.tr = pdf.UnicodeTranslatorFromDescriptor("")

	p.footer(pdf, r)

	p.coverPage(pdf, r)
	p.executiveSummary(pdf, r)
	p.findings(pdf, r)
	p.complianceAppendix(pdf, r)

	if pdf.Err() {
		return pdf.Error()
	}
	return pdf.Output(w)
}

func (p *PDFReporter) footer(pdf *gofpdf.Fpdf, r *Report) {
	pdf.SetFooterFunc(func() {
		pdf.SetY(-14)
		pdf.SetFont("Helvetica", "", 8)
		pdf.SetTextColor(pdfMuted, pdfMuted, pdfMuted)
		cls := r.Meta.Classification
		if cls == "" {
			cls = "CONFIDENTIAL"
		}
		pdf.CellFormat(contentW/2, 8, p.t("SEMAR "+r.Meta.ToolVersion+" — "+cls), "", 0, "L", false, 0, "")
		pdf.CellFormat(contentW/2, 8, fmt.Sprintf("Page %d", pdf.PageNo()), "", 0, "R", false, 0, "")
	})
}

func (p *PDFReporter) coverPage(pdf *gofpdf.Fpdf, r *Report) {
	pdf.AddPage()

	// Gradient-ish banner block.
	pdf.SetFillColor(109, 40, 217)
	pdf.Rect(0, 0, 210, 80, "F")
	pdf.SetFillColor(37, 99, 235)
	pdf.Rect(0, 60, 210, 20, "F")

	pdf.SetY(26)
	pdf.SetFont("Helvetica", "B", 13)
	pdf.SetTextColor(255, 255, 255)
	pdf.CellFormat(0, 8, "S E M A R", "", 1, "C", false, 0, "")
	pdf.SetFont("Helvetica", "", 9)
	pdf.CellFormat(0, 6, "AI Agent Security Audit Framework", "", 1, "C", false, 0, "")

	pdf.Ln(44)
	pdf.SetTextColor(pdfInk, pdfInk, pdfInk)
	pdf.SetFont("Helvetica", "B", 24)
	title := r.Meta.Title
	if title == "" {
		title = "AI Agent Security Audit Report"
	}
	pdf.MultiCell(0, 11, p.t(title), "", "C", false)
	pdf.Ln(6)

	// Classification banner.
	cls := r.Meta.Classification
	if cls == "" {
		cls = "CONFIDENTIAL"
	}
	pdf.SetFont("Helvetica", "B", 11)
	pdf.SetFillColor(255, 140, 66)
	pdf.SetTextColor(255, 255, 255)
	pdf.CellFormat(0, 9, "  "+cls+"  ", "", 1, "C", true, 0, "")
	pdf.Ln(14)

	// Metadata table.
	pdf.SetTextColor(pdfInk, pdfInk, pdfInk)
	rows := [][2]string{
		{"Organization", orDash(r.Meta.Org)},
		{"Assessor", orDash(r.Meta.Assessor)},
		{"Target", r.Target.RootPath},
		{"Agent Type", string(r.Target.AgentType)},
		{"Scan Date", r.Timestamp.Format("2006-01-02 15:04:05 MST")},
		{"Overall Risk", fmt.Sprintf("%.1f / 10  (%s)", r.RiskScore, r.RiskLevel)},
	}
	for _, row := range rows {
		pdf.SetFont("Helvetica", "B", 10)
		pdf.CellFormat(45, 8, row[0], "", 0, "L", false, 0, "")
		pdf.SetFont("Helvetica", "", 10)
		pdf.MultiCell(contentW-45, 8, p.t(row[1]), "", "L", false)
	}

	pdf.Ln(10)
	pdf.SetFont("Helvetica", "I", 8)
	pdf.SetTextColor(pdfMuted, pdfMuted, pdfMuted)
	pdf.MultiCell(0, 5, p.t("CONFIDENTIALITY NOTICE: This report contains sensitive security information intended only for the named recipient. SEMAR is read-only and never modifies audited systems. \"Sing ngerti kabeh, nanging ora ngancam.\""), "", "C", false)
}

func (p *PDFReporter) sectionTitle(pdf *gofpdf.Fpdf, text string) {
	pdf.SetFont("Helvetica", "B", 15)
	pdf.SetTextColor(109, 40, 217)
	pdf.CellFormat(0, 10, text, "", 1, "L", false, 0, "")
	pdf.SetDrawColor(109, 40, 217)
	pdf.SetLineWidth(0.4)
	y := pdf.GetY()
	pdf.Line(marginX, y, marginX+contentW, y)
	pdf.Ln(4)
	pdf.SetTextColor(pdfInk, pdfInk, pdfInk)
}

func (p *PDFReporter) executiveSummary(pdf *gofpdf.Fpdf, r *Report) {
	pdf.AddPage()
	p.sectionTitle(pdf, "Executive Summary")

	pdf.SetFont("Helvetica", "", 10)
	narrative := fmt.Sprintf(
		"This assessment evaluated the %s agent configuration at the specified target. SEMAR identified %d findings across %d security modules, yielding an overall risk rating of %.1f/10 (%s). The findings span %s OWASP LLM Top 10 categories and reference %d MITRE ATLAS techniques. Immediate attention is recommended for all CRITICAL and HIGH severity items below.",
		r.Target.AgentType, len(r.Result.Findings), len(r.Result.ModuleStats), r.RiskScore, r.RiskLevel,
		r.Compliance.OWASPCoverage(), len(r.Compliance.MITRETTPs))
	pdf.MultiCell(0, 5.5, p.t(narrative), "", "L", false)
	pdf.Ln(4)

	// Severity breakdown table with colored chips.
	pdf.SetFont("Helvetica", "B", 11)
	pdf.CellFormat(0, 8, "Risk Distribution", "", 1, "L", false, 0, "")
	for _, s := range severityOrder {
		c := sevRGB[s]
		n := r.BySeverity[s]
		pdf.SetFillColor(c[0], c[1], c[2])
		pdf.SetTextColor(255, 255, 255)
		pdf.SetFont("Helvetica", "B", 9)
		pdf.CellFormat(28, 7, string(s), "", 0, "C", true, 0, "")
		pdf.SetTextColor(pdfInk, pdfInk, pdfInk)
		pdf.SetFont("Helvetica", "", 9)
		// bar
		barW := 0.0
		if total := len(r.Result.Findings); total > 0 {
			barW = float64(n) / float64(total) * 110
		}
		pdf.CellFormat(3, 7, "", "", 0, "L", false, 0, "")
		x, y := pdf.GetX(), pdf.GetY()
		pdf.SetFillColor(c[0], c[1], c[2])
		if barW > 0 {
			pdf.Rect(x, y+1.5, barW, 4, "F")
		}
		pdf.SetX(x + 112)
		pdf.CellFormat(20, 7, fmt.Sprintf("%d", n), "", 1, "L", false, 0, "")
	}
	pdf.Ln(4)

	// Key findings.
	pdf.SetFont("Helvetica", "B", 11)
	pdf.CellFormat(0, 8, "Key Findings (Critical & High)", "", 1, "L", false, 0, "")
	pdf.SetFont("Helvetica", "", 9)
	count := 0
	for _, f := range r.Result.Findings {
		if !f.Severity.AtLeast(modules.SeverityHigh) || count >= 10 {
			continue
		}
		count++
		c := sevRGB[f.Severity]
		pdf.SetTextColor(c[0], c[1], c[2])
		pdf.SetFont("Helvetica", "B", 9)
		pdf.CellFormat(20, 5.5, string(f.Severity), "", 0, "L", false, 0, "")
		pdf.SetTextColor(pdfInk, pdfInk, pdfInk)
		pdf.SetFont("Helvetica", "", 9)
		pdf.MultiCell(contentW-20, 5.5, p.t(fmt.Sprintf("%s — %s", f.ID, f.Title)), "", "L", false)
	}
	if count == 0 {
		pdf.SetTextColor(6, 180, 130)
		pdf.CellFormat(0, 6, "No critical or high severity findings.", "", 1, "L", false, 0, "")
		pdf.SetTextColor(pdfInk, pdfInk, pdfInk)
	}

	// Compliance posture.
	pdf.Ln(4)
	pdf.SetFont("Helvetica", "B", 11)
	pdf.CellFormat(0, 8, "Compliance Posture", "", 1, "L", false, 0, "")
	pdf.SetFont("Helvetica", "", 9)
	pdf.MultiCell(0, 5.5, fmt.Sprintf("OWASP LLM Top 10: %s categories triggered\nMITRE ATLAS: %d techniques mapped\nNIST AI RMF: %d controls referenced",
		r.Compliance.OWASPCoverage(), len(r.Compliance.MITRETTPs), len(r.Compliance.NISTControls)), "", "L", false)
}

func (p *PDFReporter) findings(pdf *gofpdf.Fpdf, r *Report) {
	pdf.AddPage()
	p.sectionTitle(pdf, "Technical Findings")

	if len(r.Result.Findings) == 0 {
		pdf.SetFont("Helvetica", "", 10)
		pdf.CellFormat(0, 8, "No findings.", "", 1, "L", false, 0, "")
		return
	}

	for _, f := range r.Result.Findings {
		p.findingBlock(pdf, f)
	}
}

func (p *PDFReporter) findingBlock(pdf *gofpdf.Fpdf, f *modules.Finding) {
	c := sevRGB[f.Severity]

	// Keep header + a little body together.
	if pdf.GetY() > 250 {
		pdf.AddPage()
	}

	// Severity badge + title.
	pdf.SetFillColor(c[0], c[1], c[2])
	pdf.SetTextColor(255, 255, 255)
	pdf.SetFont("Helvetica", "B", 9)
	pdf.CellFormat(24, 7, string(f.Severity), "", 0, "C", true, 0, "")
	pdf.SetTextColor(pdfInk, pdfInk, pdfInk)
	pdf.SetFont("Helvetica", "B", 10)
	pdf.CellFormat(3, 7, "", "", 0, "L", false, 0, "")
	pdf.MultiCell(contentW-27, 7, p.t(fmt.Sprintf("%s  %s", f.ID, f.Title)), "", "L", false)

	// Meta line.
	pdf.SetFont("Helvetica", "", 8)
	pdf.SetTextColor(pdfMuted, pdfMuted, pdfMuted)
	loc := f.FilePath
	if f.Line > 0 {
		loc = fmt.Sprintf("%s:%d", f.FilePath, f.Line)
	}
	meta := fmt.Sprintf("Risk %.1f/10  |  Confidence %s  |  %s", f.RiskScore, f.Confidence, loc)
	pdf.MultiCell(0, 4.5, p.t(meta), "", "L", false)
	refLine := fmt.Sprintf("OWASP: %s   CWE: %s   MITRE: %s   NIST: %s",
		join(f.OWASP), join(f.CWE), join(f.MITRE), join(f.NIST))
	pdf.MultiCell(0, 4.5, p.t(refLine), "", "L", false)

	pdf.SetTextColor(pdfInk, pdfInk, pdfInk)
	pdf.SetFont("Helvetica", "", 9)
	p.labeled(pdf, "Description", f.Description)
	p.labeled(pdf, "Impact", f.Impact)
	p.labeled(pdf, "Evidence", f.Evidence)

	// Remediation highlighted box.
	if f.Remediation != "" {
		pdf.SetFillColor(235, 250, 244)
		x, y := marginX, pdf.GetY()+1
		pdf.SetXY(x, y)
		pdf.SetFont("Helvetica", "B", 9)
		pdf.SetTextColor(6, 130, 95)
		pdf.MultiCell(contentW, 5, p.t("Remediation: "+f.Remediation), "", "L", true)
		pdf.SetTextColor(pdfInk, pdfInk, pdfInk)
	}

	pdf.Ln(2)
	pdf.SetDrawColor(220, 220, 228)
	pdf.SetLineWidth(0.2)
	y := pdf.GetY()
	pdf.Line(marginX, y, marginX+contentW, y)
	pdf.Ln(3)
}

func (p *PDFReporter) labeled(pdf *gofpdf.Fpdf, label, body string) {
	if body == "" {
		return
	}
	pdf.SetFont("Helvetica", "B", 9)
	pdf.CellFormat(0, 5, label, "", 1, "L", false, 0, "")
	pdf.SetFont("Helvetica", "", 9)
	pdf.MultiCell(0, 4.6, p.t(body), "", "L", false)
	pdf.Ln(1)
}

func (p *PDFReporter) complianceAppendix(pdf *gofpdf.Fpdf, r *Report) {
	pdf.AddPage()
	p.sectionTitle(pdf, "Appendix A — Compliance Mapping")

	// OWASP table.
	pdf.SetFont("Helvetica", "B", 10)
	pdf.CellFormat(0, 8, "OWASP LLM Top 10 (2025)", "", 1, "L", false, 0, "")
	pdf.SetFont("Helvetica", "B", 8)
	pdf.SetFillColor(240, 240, 246)
	pdf.CellFormat(22, 7, "Category", "1", 0, "L", true, 0, "")
	pdf.CellFormat(110, 7, "Name", "1", 0, "L", true, 0, "")
	pdf.CellFormat(22, 7, "Status", "1", 0, "C", true, 0, "")
	pdf.CellFormat(20, 7, "Count", "1", 1, "C", true, 0, "")
	pdf.SetFont("Helvetica", "", 8)
	for _, id := range owaspIDs() {
		n := r.Compliance.OWASPCounts[id]
		status := "PASS"
		if n > 0 {
			status = "FAIL"
			pdf.SetTextColor(255, 77, 109)
		} else {
			pdf.SetTextColor(6, 150, 110)
		}
		pdf.CellFormat(22, 6, id, "1", 0, "L", false, 0, "")
		pdf.SetTextColor(pdfInk, pdfInk, pdfInk)
		pdf.CellFormat(110, 6, p.t(compliance.OWASPLLM[id]), "1", 0, "L", false, 0, "")
		if n > 0 {
			pdf.SetTextColor(255, 77, 109)
		} else {
			pdf.SetTextColor(6, 150, 110)
		}
		pdf.CellFormat(22, 6, status, "1", 0, "C", false, 0, "")
		pdf.SetTextColor(pdfInk, pdfInk, pdfInk)
		pdf.CellFormat(20, 6, fmt.Sprintf("%d", n), "1", 1, "C", false, 0, "")
	}

	// MITRE table.
	if len(r.Compliance.MITRETTPs) > 0 {
		pdf.Ln(6)
		pdf.SetFont("Helvetica", "B", 10)
		pdf.CellFormat(0, 8, "MITRE ATLAS Techniques", "", 1, "L", false, 0, "")
		pdf.SetFont("Helvetica", "", 8)
		for _, id := range r.Compliance.MITRETTPs {
			pdf.SetFont("Helvetica", "B", 8)
			pdf.CellFormat(34, 6, id, "1", 0, "L", false, 0, "")
			pdf.SetFont("Helvetica", "", 8)
			pdf.CellFormat(contentW-34, 6, p.t(compliance.MITREATLAS[id]), "1", 1, "L", false, 0, "")
		}
	}

	// Methodology appendix.
	pdf.Ln(8)
	p.sectionTitle(pdf, "Appendix B — Scan Methodology")
	pdf.SetFont("Helvetica", "", 9)
	pdf.MultiCell(0, 5, p.t(fmt.Sprintf(
		"Modules executed: %d\nRules evaluated: %d\nFiles scanned: %d\nScan duration: %s\nScan ID: %s\n\nSEMAR performs static, read-only analysis of AI agent configurations. Findings are deterministic: identical inputs produce identical output and ordering. Secrets are redacted at detection time and never stored in full.",
		len(r.Result.ModuleStats), r.RulesCount, r.FilesScanned, r.Result.Duration().Round(1e6), r.ScanID)), "", "L", false)
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}
