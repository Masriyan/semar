// Package network checks egress policy, TLS posture, and SSRF risk.
package network

import (
	"context"
	"regexp"
	"strings"

	"github.com/masriyan/semar/internal/modules"
)

// Checker evaluates network and egress configuration.
type Checker struct{}

// NewChecker constructs a network Checker.
func NewChecker() *Checker { return &Checker{} }

func (c *Checker) Name() string              { return "network/checker" }
func (c *Checker) Description() string        { return "Checks egress policy, cleartext endpoints, SSRF risk, and TLS verification" }
func (c *Checker) Severity() modules.Severity { return modules.SeverityHigh }

func (c *Checker) Rules() []string {
	return []string{"SEMAR-NET-002", "SEMAR-NET-003", "SEMAR-NET-005", "SEMAR-NET-007"}
}

var (
	httpURL       = regexp.MustCompile(`http://[a-zA-Z0-9.\-:/]+`)
	privateIP     = regexp.MustCompile(`\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|127\.0\.0\.1|localhost)\b`)
	metadataIP    = regexp.MustCompile(`169\.254\.169\.254`)
	tlsDisableNeg = regexp.MustCompile(`(?i)(insecure\s*[=:]\s*true|verify_ssl\s*[=:]\s*false|verifyssl\s*[=:]\s*false|rejectUnauthorized\s*[=:]\s*false)`)
)

// Run implements modules.Module.
func (c *Checker) Run(ctx context.Context, target *modules.ScanTarget) ([]*modules.Finding, error) {
	findings := make([]*modules.Finding, 0)

	for path, raw := range target.RawFiles {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}
		content := string(raw)

		if loc := httpURL.FindStringIndex(content); loc != nil {
			line, _ := modules.LineColForIndex(content, loc[0])
			findings = append(findings, mk("SEMAR-NET-002", "network/cleartext-http",
				"Cleartext HTTP endpoint in configuration",
				modules.SeverityMedium, path, line,
				"A cleartext http:// endpoint was found; traffic can be intercepted or tampered with.",
				[]string{"LLM03"}, []string{"CWE-319"},
				"Use HTTPS for all endpoints."))
		}

		if loc := metadataIP.FindStringIndex(content); loc != nil {
			line, _ := modules.LineColForIndex(content, loc[0])
			findings = append(findings, mk("SEMAR-NET-007", "network/cloud-metadata",
				"Cloud metadata endpoint reachable from agent context",
				modules.SeverityHigh, path, line,
				"The cloud metadata IP 169.254.169.254 is referenced; SSRF to it can leak instance credentials.",
				[]string{"LLM02"}, []string{"CWE-918"},
				"Block egress to 169.254.169.254 and use IMDSv2 with hop limit 1."))
		} else if loc := privateIP.FindStringIndex(content); loc != nil && isAllowlistContext(content, loc[0]) {
			line, _ := modules.LineColForIndex(content, loc[0])
			findings = append(findings, mk("SEMAR-NET-003", "network/private-ip-allowed",
				"Private/internal IP in allowed domains (SSRF risk)",
				modules.SeverityHigh, path, line,
				"A private IP range appears in network allowlist context, enabling SSRF to internal services.",
				[]string{"LLM02"}, []string{"CWE-918"},
				"Remove private/internal ranges from the egress allowlist."))
		}

		if loc := tlsDisableNeg.FindStringIndex(content); loc != nil {
			line, _ := modules.LineColForIndex(content, loc[0])
			findings = append(findings, mk("SEMAR-NET-005", "network/tls-verification-disabled",
				"TLS verification disabled",
				modules.SeverityHigh, path, line,
				"TLS certificate verification is disabled, exposing connections to MITM attacks.",
				[]string{"LLM03"}, []string{"CWE-295"},
				"Enable TLS verification; never set insecure/verify_ssl=false in production."))
		}
	}

	return findings, nil
}

func isAllowlistContext(content string, idx int) bool {
	line := strings.ToLower(modules.LineContaining(content, idx))
	return strings.Contains(line, "allow") || strings.Contains(line, "domain") || strings.Contains(line, "host") || strings.Contains(line, "url") || strings.Contains(line, "endpoint")
}

func mk(id, rule, title string, sev modules.Severity, path string, line int, desc string, owasp, cwe []string, rem string) *modules.Finding {
	return &modules.Finding{
		ID:          id,
		RuleID:      rule,
		Title:       title,
		Severity:    sev,
		Confidence:  modules.ConfidenceMedium,
		Category:    "network",
		FilePath:    path,
		Line:        line,
		Description: desc,
		Impact:      "Network misconfiguration can enable data exfiltration, SSRF, or interception.",
		OWASP:       owasp,
		CWE:         cwe,
		NIST:        []string{"MANAGE-2.4"},
		Remediation: rem,
		References:  []string{"https://owasp.org/www-project-top-10-for-large-language-model-applications/"},
	}
}
