package promptinjection

import (
	"context"
	"fmt"

	"github.com/masriyan/semar/internal/modules"
)

// Analyzer maps the prompt-injection surface of an agent.
type Analyzer struct{}

// NewAnalyzer constructs a prompt-injection Analyzer.
func NewAnalyzer() *Analyzer { return &Analyzer{} }

func (a *Analyzer) Name() string               { return "prompt-injection/analyzer" }
func (a *Analyzer) Description() string         { return "Maps prompt-injection and jailbreak surface in system prompts, context files, and tool descriptions" }
func (a *Analyzer) Severity() modules.Severity  { return modules.SeverityHigh }

func (a *Analyzer) Rules() []string {
	ids := make([]string, 0, len(InjectionPatterns))
	for _, p := range InjectionPatterns {
		ids = append(ids, p.ID)
	}
	return ids
}

// Run implements modules.Module.
func (a *Analyzer) Run(ctx context.Context, target *modules.ScanTarget) ([]*modules.Finding, error) {
	findings := make([]*modules.Finding, 0)

	sources := map[string]string{}
	for path, raw := range target.RawFiles {
		if isContextFile(path) {
			sources[path] = string(raw)
		}
	}
	if target.SystemPrompt != "" {
		sources["<system-prompt>"] = target.SystemPrompt
	}
	for _, td := range target.ToolDefs {
		if td.Description != "" {
			sources[fmt.Sprintf("<tool:%s>", td.Name)] = td.Description
		}
	}

	for path, content := range sources {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}
		findings = append(findings, a.analyze(path, content)...)
	}

	return findings, nil
}

func (a *Analyzer) analyze(path, content string) []*modules.Finding {
	var matched []InjectionPattern
	var findings []*modules.Finding

	for _, p := range InjectionPatterns {
		loc := p.Pattern.FindStringIndex(content)
		if loc == nil {
			continue
		}
		matched = append(matched, p)
		line, col := modules.LineColForIndex(content, loc[0])

		findings = append(findings, &modules.Finding{
			ID:          "SEMAR-PI-" + p.ID[3:],
			RuleID:      "prompt-injection/" + p.ID,
			Title:       p.Name,
			Severity:    p.Severity,
			Confidence:  modules.ConfidenceMedium,
			Category:    "prompt-injection",
			FilePath:    path,
			Line:        line,
			Column:      col,
			Snippet:     truncate(modules.LineContaining(content, loc[0]), 160),
			Description: p.Description,
			Impact:      "An attacker controlling this content can manipulate the agent into ignoring its safety constraints or leaking data.",
			Evidence:    fmt.Sprintf("Pattern %s (%s) matched at %s:%d", p.ID, p.Name, path, line),
			OWASP:       p.OWASP,
			MITRE:       p.MITRE,
			CWE:         []string{"CWE-77", "CWE-1427"},
			NIST:        []string{"MEASURE-2.6", "MANAGE-2.4"},
			Remediation: "Treat all loaded context as untrusted. Sanitize tool descriptions and context files, and apply prompt-injection guardrails / output filtering.",
			References:  []string{"https://owasp.org/www-project-top-10-for-large-language-model-applications/"},
		})
	}

	// Compound score for this source.
	score := llm01Score(matched)
	if len(matched) > 1 && score >= 4.0 {
		findings = append(findings, &modules.Finding{
			ID:          "SEMAR-PI-000",
			RuleID:      "prompt-injection/compound-llm01",
			Title:       "Multiple prompt-injection indicators in one source",
			Severity:    severityForScore(score),
			Confidence:  modules.ConfidenceHigh,
			Category:    "prompt-injection",
			FilePath:    path,
			Description: fmt.Sprintf("%d distinct prompt-injection patterns matched in this source, producing an OWASP LLM01 score of %.1f/10.", len(matched), score),
			Impact:      "Compounded injection indicators strongly suggest a deliberately crafted malicious prompt.",
			Evidence:    fmt.Sprintf("LLM01 score %.1f from %d matched patterns", score, len(matched)),
			OWASP:       []string{"LLM01"},
			MITRE:       []string{"AML.T0054"},
			NIST:        []string{"MEASURE-2.6"},
			Remediation: "Quarantine and review this source. Do not load it into the agent context until cleared.",
			RiskScore:   score,
		})
	}

	return findings
}

func isContextFile(path string) bool {
	for _, suffix := range []string{"CLAUDE.md", ".cursorrules", "copilot-instructions.md", "system_prompt.txt", "instructions.md", ".md"} {
		if len(path) >= len(suffix) && path[len(path)-len(suffix):] == suffix {
			return true
		}
	}
	return false
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
