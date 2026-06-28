package secrets

import (
	"regexp"

	"github.com/masriyan/semar/internal/modules"
)

// SecretPattern describes a named credential pattern.
type SecretPattern struct {
	FindingID   string
	RuleID      string
	Name        string
	Regex       *regexp.Regexp
	Severity    modules.Severity
	OWASP       []string
	MITRE       []string
	CWE         []string
	NIST        []string
	Description string
	Impact      string
	Remediation string
}

// Patterns is the built-in library of provider-specific secret patterns.
var Patterns = []SecretPattern{
	{
		FindingID:   "SEMAR-SEC-001",
		RuleID:      "secrets/anthropic-api-key",
		Name:        "Anthropic API key",
		Regex:       regexp.MustCompile(`sk-ant-[a-zA-Z0-9_\-]{20,}`),
		Severity:    modules.SeverityCritical,
		OWASP:       []string{"LLM02", "LLM07"},
		MITRE:       []string{"AML.T0040"},
		CWE:         []string{"CWE-312", "CWE-798"},
		NIST:        []string{"GOVERN-1.1", "MANAGE-2.4"},
		Description: "An Anthropic API key (sk-ant-*) was detected in plaintext. These keys grant full API access and must never be stored in files that may be committed or shared.",
		Impact:      "An attacker with this key can make unlimited API calls, incur cost, and access conversation history on behalf of the owner.",
		Remediation: "Remove the key from the file, rotate it at console.anthropic.com, and load it from an environment variable.",
	},
	{
		FindingID:   "SEMAR-SEC-002",
		RuleID:      "secrets/openai-api-key",
		Name:        "OpenAI API key",
		Regex:       regexp.MustCompile(`sk-(proj-)?[a-zA-Z0-9]{20,}`),
		Severity:    modules.SeverityCritical,
		OWASP:       []string{"LLM02", "LLM07"},
		MITRE:       []string{"AML.T0040"},
		CWE:         []string{"CWE-312", "CWE-798"},
		NIST:        []string{"GOVERN-1.1", "MANAGE-2.4"},
		Description: "An OpenAI API key (sk-*) was detected in plaintext.",
		Impact:      "An attacker can make billed API calls and access account resources.",
		Remediation: "Remove and rotate the key at platform.openai.com; load it from an environment variable.",
	},
	{
		FindingID:   "SEMAR-SEC-003",
		RuleID:      "secrets/aws-access-key",
		Name:        "AWS access key ID",
		Regex:       regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		Severity:    modules.SeverityCritical,
		OWASP:       []string{"LLM02"},
		CWE:         []string{"CWE-312", "CWE-798"},
		NIST:        []string{"MANAGE-2.4"},
		Description: "An AWS access key ID (AKIA*) was detected.",
		Impact:      "Combined with a secret key, this grants programmatic access to AWS resources.",
		Remediation: "Deactivate the key in IAM, rotate, and use instance roles or environment-based credentials.",
	},
	{
		FindingID:   "SEMAR-SEC-004",
		RuleID:      "secrets/gcp-service-account",
		Name:        "GCP service account JSON",
		Regex:       regexp.MustCompile(`"type"\s*:\s*"service_account"`),
		Severity:    modules.SeverityHigh,
		OWASP:       []string{"LLM02"},
		CWE:         []string{"CWE-312"},
		NIST:        []string{"MANAGE-2.4"},
		Description: "An embedded GCP service account key file was detected.",
		Impact:      "Service account keys grant long-lived access to GCP resources.",
		Remediation: "Remove the embedded key, rotate it, and use workload identity federation.",
	},
	{
		FindingID:   "SEMAR-SEC-005",
		RuleID:      "secrets/github-token",
		Name:        "GitHub token",
		Regex:       regexp.MustCompile(`gh[pousr]_[a-zA-Z0-9]{36,}|github_pat_[a-zA-Z0-9_]{82}`),
		Severity:    modules.SeverityHigh,
		OWASP:       []string{"LLM02", "LLM03"},
		CWE:         []string{"CWE-312", "CWE-798"},
		NIST:        []string{"MANAGE-2.4"},
		Description: "A GitHub personal access token or app token was detected.",
		Impact:      "An attacker can access repositories and CI/CD with the token's scopes.",
		Remediation: "Revoke the token in GitHub settings and use short-lived, scoped credentials.",
	},
	{
		FindingID:   "SEMAR-SEC-008",
		RuleID:      "secrets/private-key",
		Name:        "Private key material (PEM)",
		Regex:       regexp.MustCompile(`-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----`),
		Severity:    modules.SeverityCritical,
		OWASP:       []string{"LLM02"},
		CWE:         []string{"CWE-312", "CWE-321"},
		NIST:        []string{"MANAGE-2.4"},
		Description: "PEM-encoded private key material was detected.",
		Impact:      "Private keys enable impersonation, decryption, and signing.",
		Remediation: "Remove the key, rotate the associated credential, and store keys in a secrets manager.",
	},
}
