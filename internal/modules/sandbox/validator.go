// Package sandbox validates runtime isolation and container escape risk.
package sandbox

import (
	"context"
	"os"
	"strings"

	"github.com/masriyan/semar/internal/modules"
)

// Validator checks runtime sandbox and container hardening.
type Validator struct{}

// NewValidator constructs a sandbox Validator.
func NewValidator() *Validator { return &Validator{} }

func (v *Validator) Name() string              { return "sandbox/validator" }
func (v *Validator) Description() string        { return "Validates runtime isolation, container escape risk, and resource limits" }
func (v *Validator) Severity() modules.Severity { return modules.SeverityHigh }

func (v *Validator) Rules() []string {
	return []string{"SEMAR-SBX-002", "SEMAR-SBX-003", "SEMAR-SBX-005", "SEMAR-SBX-006"}
}

// Run implements modules.Module.
func (v *Validator) Run(ctx context.Context, target *modules.ScanTarget) ([]*modules.Finding, error) {
	findings := make([]*modules.Finding, 0)

	// Scan declarative files (docker-compose, Dockerfile, k8s) for risky settings.
	for path, raw := range target.RawFiles {
		content := string(raw)
		lower := strings.ToLower(content)

		if strings.Contains(content, "/var/run/docker.sock") {
			findings = append(findings, sbx("SEMAR-SBX-002", "sandbox/docker-socket",
				"Docker socket mounted (container escape risk)",
				modules.SeverityCritical, path,
				"Mounting /var/run/docker.sock grants control of the Docker daemon, enabling host takeover.",
				"Do not mount the Docker socket into agent containers."))
		}
		if strings.Contains(lower, "privileged: true") || strings.Contains(lower, "--privileged") {
			findings = append(findings, sbx("SEMAR-SBX-003", "sandbox/privileged",
				"Privileged container mode enabled",
				modules.SeverityCritical, path,
				"Privileged mode disables most isolation, enabling host access.",
				"Run containers unprivileged; add only the specific capabilities required."))
		}
		if strings.Contains(lower, "network_mode: host") || strings.Contains(lower, "--network=host") || strings.Contains(lower, "--network host") {
			findings = append(findings, sbx("SEMAR-SBX-006", "sandbox/host-network",
				"Host network mode enabled",
				modules.SeverityHigh, path,
				"Host network mode removes network isolation between the container and host.",
				"Use bridge networking with explicit published ports."))
		}
		if strings.Contains(lower, "user: root") || strings.Contains(lower, "user: \"0\"") || strings.Contains(lower, "uid=0") {
			findings = append(findings, sbx("SEMAR-SBX-005", "sandbox/run-as-root",
				"Agent runs as root (UID 0)",
				modules.SeverityHigh, path,
				"Running as root amplifies the impact of any escape or vulnerability.",
				"Run as a dedicated non-root user with a high UID."))
		}
	}

	// Runtime self-check: are WE running as root? (informational about host posture)
	if os.Geteuid() == 0 && target.RootPath != "" {
		findings = append(findings, sbx("SEMAR-SBX-005", "sandbox/run-as-root",
			"Scan executed as root (UID 0)",
			modules.SeverityLow, "<runtime>",
			"The audited environment is running with root privileges.",
			"Run agents under a dedicated non-root user."))
	}

	return findings, nil
}

func sbx(id, rule, title string, sev modules.Severity, path, desc, rem string) *modules.Finding {
	return &modules.Finding{
		ID:          id,
		RuleID:      rule,
		Title:       title,
		Severity:    sev,
		Confidence:  modules.ConfidenceMedium,
		Category:    "sandbox",
		FilePath:    path,
		Description: desc,
		Impact:      "Weak runtime isolation enables container escape and host compromise.",
		OWASP:       []string{"LLM06"},
		CWE:         []string{"CWE-250", "CWE-269"},
		NIST:        []string{"MANAGE-3.1"},
		Remediation: rem,
	}
}
