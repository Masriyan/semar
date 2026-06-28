// Package iam audits agent identity, permissions, and least-privilege posture.
package iam

import (
	"context"
	"strings"

	"github.com/masriyan/semar/internal/modules"
)

// Auditor checks IAM and permission configuration.
type Auditor struct{}

// NewAuditor constructs an IAM Auditor.
func NewAuditor() *Auditor { return &Auditor{} }

func (a *Auditor) Name() string              { return "iam/auditor" }
func (a *Auditor) Description() string        { return "Audits agent permissions, tool scope, and least-privilege posture" }
func (a *Auditor) Severity() modules.Severity { return modules.SeverityHigh }

func (a *Auditor) Rules() []string {
	return []string{"SEMAR-IAM-002", "SEMAR-IAM-003", "SEMAR-IAM-005", "SEMAR-IAM-006"}
}

// sensitivePaths are directories an agent should rarely have read access to.
var sensitivePaths = []string{"~/.ssh", "/etc", "~/.aws", "~/.config/gcloud", "~/.kube"}

// destructiveTools are tool-name fragments implying state-changing actions.
var destructiveTools = []string{"delete", "remove", "write", "exec", "shell", "bash", "rm", "drop"}

// Run implements modules.Module.
func (a *Auditor) Run(ctx context.Context, target *modules.ScanTarget) ([]*modules.Finding, error) {
	findings := make([]*modules.Finding, 0)

	// IAM-003: read access to sensitive directories.
	for _, raw := range target.RawFiles {
		content := string(raw)
		for _, p := range sensitivePaths {
			if strings.Contains(content, p) {
				findings = append(findings, &modules.Finding{
					ID:          "SEMAR-IAM-003",
					RuleID:      "iam/sensitive-path-access",
					Title:       "Agent configured with access to sensitive directory",
					Severity:    modules.SeverityHigh,
					Confidence:  modules.ConfidenceMedium,
					Category:    "iam",
					Description: "The agent configuration references a sensitive directory (" + p + ").",
					Impact:      "Read access to credential stores enables theft of SSH keys, cloud credentials, or secrets.",
					Evidence:    "Reference to sensitive path: " + p,
					OWASP:       []string{"LLM06"},
					CWE:         []string{"CWE-552"},
					NIST:        []string{"GOVERN-1.1", "MANAGE-2.4"},
					Remediation: "Remove access to credential directories; scope the agent to project paths only.",
				})
				break
			}
		}
	}

	// IAM-005 / IAM-006: destructive tools without approval.
	hasApproval := false
	if target.Configs != nil {
		if v, ok := target.Configs["requireApproval"]; ok {
			if b, ok := v.(bool); ok {
				hasApproval = b
			}
		}
	}
	for _, td := range target.ToolDefs {
		name := strings.ToLower(td.Name)
		for _, d := range destructiveTools {
			if strings.Contains(name, d) && !hasApproval {
				findings = append(findings, &modules.Finding{
					ID:          "SEMAR-IAM-005",
					RuleID:      "iam/no-approval-destructive",
					Title:       "No human approval required for destructive tool",
					Severity:    modules.SeverityHigh,
					Confidence:  modules.ConfidenceMedium,
					Category:    "iam",
					Description: "Tool '" + td.Name + "' can perform destructive actions without a human approval gate.",
					Impact:      "An injected or erroneous instruction can trigger irreversible actions.",
					Evidence:    "Destructive tool '" + td.Name + "' with requireApproval=false",
					OWASP:       []string{"LLM06"},
					CWE:         []string{"CWE-862"},
					NIST:        []string{"MANAGE-3.1"},
					Remediation: "Require human-in-the-loop approval for delete/write/execute tools.",
				})
				break
			}
		}
	}

	// IAM-002: many tools but no rate limiting.
	if len(target.ToolDefs) > 0 {
		if _, ok := configKey(target, "rateLimit"); !ok {
			findings = append(findings, &modules.Finding{
				ID:          "SEMAR-IAM-002",
				RuleID:      "iam/no-rate-limit",
				Title:       "No rate limiting configured for tool calls",
				Severity:    modules.SeverityMedium,
				Confidence:  modules.ConfidenceLow,
				Category:    "iam",
				Description: "No rate limit is configured for agent tool invocations.",
				Impact:      "Unbounded tool calls can cause cost blowup or denial of service.",
				OWASP:       []string{"LLM10"},
				NIST:        []string{"MANAGE-4.1"},
				Remediation: "Configure a per-session rate limit for tool invocations.",
			})
		}
	}

	return findings, nil
}

func configKey(target *modules.ScanTarget, key string) (interface{}, bool) {
	if target.Configs == nil {
		return nil, false
	}
	v, ok := target.Configs[key]
	return v, ok
}
