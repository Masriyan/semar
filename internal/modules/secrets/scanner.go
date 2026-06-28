package secrets

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/masriyan/semar/internal/modules"
)

// Scanner detects secrets and credentials across all target files.
type Scanner struct{}

// NewScanner constructs a secrets Scanner.
func NewScanner() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string             { return "secrets/scanner" }
func (s *Scanner) Description() string       { return "Detects API keys, tokens, and credentials in agent configuration and context files" }
func (s *Scanner) Severity() modules.Severity { return modules.SeverityCritical }

func (s *Scanner) Rules() []string {
	rules := make([]string, 0, len(Patterns)+1)
	for _, p := range Patterns {
		rules = append(rules, p.FindingID)
	}
	rules = append(rules, "SEMAR-SEC-006")
	return rules
}

// keyNameHint matches variable names that suggest a secret value follows.
var keyNameHint = regexp.MustCompile(`(?i)(key|secret|token|password|passwd|credential|auth)`)

// highEntropyCandidate matches long unbroken token-like strings.
var highEntropyCandidate = regexp.MustCompile(`[A-Za-z0-9+/_\-]{20,}`)

// Run implements modules.Module.
func (s *Scanner) Run(ctx context.Context, target *modules.ScanTarget) ([]*modules.Finding, error) {
	findings := make([]*modules.Finding, 0)
	seen := make(map[string]bool)

	scan := func(path, content string) {
		findings = append(findings, s.scanContent(path, content, seen)...)
	}

	for path, raw := range target.RawFiles {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}
		scan(path, string(raw))
	}

	if target.SystemPrompt != "" {
		scan("<system-prompt>", target.SystemPrompt)
	}
	for name, val := range target.EnvVars {
		scan("<env>", name+"="+val)
	}

	return findings, nil
}

func (s *Scanner) scanContent(path, content string, seen map[string]bool) []*modules.Finding {
	var findings []*modules.Finding

	// 1. Provider-specific pattern matching.
	for _, p := range Patterns {
		loc := p.Regex.FindStringIndex(content)
		if loc == nil {
			continue
		}
		match := content[loc[0]:loc[1]]
		line, col := modules.LineColForIndex(content, loc[0])
		lineText := modules.LineContaining(content, loc[0])

		confidence := modules.ConfidenceHigh
		if modules.IsPlaceholderContext(lineText) {
			confidence = modules.ConfidenceLow
		}

		key := fmt.Sprintf("%s|%s|%d", p.FindingID, path, line)
		if seen[key] {
			continue
		}
		seen[key] = true

		findings = append(findings, &modules.Finding{
			ID:          p.FindingID,
			RuleID:      p.RuleID,
			Title:       p.Name + " detected",
			Severity:    p.Severity,
			Confidence:  confidence,
			Category:    "secrets",
			FilePath:    path,
			Line:        line,
			Column:      col,
			Snippet:     redactLine(lineText, match),
			Description: p.Description,
			Impact:      p.Impact,
			Evidence:    fmt.Sprintf("Pattern %q matched at %s:%d (value redacted: %s, entropy %.2f)", p.Name, path, line, modules.Redact(match), ShannonEntropy(match)),
			OWASP:       p.OWASP,
			MITRE:       p.MITRE,
			CWE:         p.CWE,
			NIST:        p.NIST,
			Remediation: p.Remediation,
			References:  []string{"https://owasp.org/www-project-top-10-for-large-language-model-applications/"},
			FalsePositiveRisk: "LOW — pattern is provider-specific. Placeholder/example values are downgraded to LOW confidence.",
		})
	}

	// 2. Generic high-entropy detection.
	for _, loc := range highEntropyCandidate.FindAllStringIndex(content, -1) {
		match := content[loc[0]:loc[1]]
		lineText := modules.LineContaining(content, loc[0])

		// Skip if already covered by a provider pattern on this line.
		if coveredByProvider(match) {
			continue
		}

		entropy := ShannonEntropy(match)
		threshold := 4.5
		if keyNameHint.MatchString(lineText) {
			threshold = 3.8
		}
		if entropy < threshold || len(match) < 20 {
			continue
		}
		if modules.IsPlaceholderContext(lineText) {
			continue
		}

		line, col := modules.LineColForIndex(content, loc[0])
		key := fmt.Sprintf("SEMAR-SEC-006|%s|%d|%s", path, line, modules.Redact(match))
		if seen[key] {
			continue
		}
		seen[key] = true

		confidence := modules.ConfidenceMedium
		if keyNameHint.MatchString(lineText) {
			confidence = modules.ConfidenceHigh
		}

		findings = append(findings, &modules.Finding{
			ID:          "SEMAR-SEC-006",
			RuleID:      "secrets/high-entropy-string",
			Title:       "High-entropy string (likely secret)",
			Severity:    modules.SeverityHigh,
			Confidence:  confidence,
			Category:    "secrets",
			FilePath:    path,
			Line:        line,
			Column:      col,
			Snippet:     redactLine(lineText, match),
			Description: "A high-entropy string was detected that is statistically likely to be a secret or credential.",
			Impact:      "If this is a credential, exposure may allow unauthorized access to a connected service.",
			Evidence:    modules.RedactEntropy(entropy, len(match)),
			OWASP:       []string{"LLM02"},
			CWE:         []string{"CWE-312"},
			NIST:        []string{"MANAGE-2.4"},
			Remediation: "Verify whether this value is a secret. If so, remove it from the file and load it from a secrets manager or environment variable.",
			FalsePositiveRisk: "MEDIUM — hashes, UUIDs, and base64 assets can trigger entropy detection.",
		})
	}

	return findings
}

func coveredByProvider(match string) bool {
	for _, p := range Patterns {
		if p.Regex.MatchString(match) {
			return true
		}
	}
	return false
}

// redactLine replaces the secret substring within a line with its redacted form.
func redactLine(line, secret string) string {
	line = strings.TrimSpace(line)
	if secret == "" {
		return line
	}
	return strings.ReplaceAll(line, secret, modules.Redact(secret))
}
