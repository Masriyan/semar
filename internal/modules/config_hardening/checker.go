package confighardening

import (
	"context"
	"strings"

	"github.com/masriyan/semar/internal/modules"
)

// Checker evaluates configuration hardening rules against a target.
type Checker struct{}

// NewChecker constructs a config-hardening Checker.
func NewChecker() *Checker { return &Checker{} }

func (c *Checker) Name() string              { return "config/hardening" }
func (c *Checker) Description() string        { return "Checks agent configuration for insecure defaults and overly broad permissions" }
func (c *Checker) Severity() modules.Severity { return modules.SeverityHigh }

func (c *Checker) Rules() []string {
	return []string{
		"SEMAR-CFG-001", "SEMAR-CFG-002", "SEMAR-CFG-003", "SEMAR-CFG-004", "SEMAR-CFG-005",
		"SEMAR-CFG-010", "SEMAR-CFG-012", "SEMAR-CFG-013", "SEMAR-CFG-014", "SEMAR-CFG-015", "SEMAR-CFG-016",
	}
}

// Run implements modules.Module.
func (c *Checker) Run(ctx context.Context, target *modules.ScanTarget) ([]*modules.Finding, error) {
	findings := make([]*modules.Finding, 0)
	cfg := target.Configs
	if cfg == nil {
		cfg = map[string]interface{}{}
	}

	// CFG-001: Bash tool enabled without allowlist.
	if v, ok := get(cfg, "tools.bash.enabled"); ok && asBool(v) {
		if _, hasList := get(cfg, "tools.bash.allowedCommands"); !hasList {
			findings = append(findings, finding(
				"SEMAR-CFG-001", "config/bash-no-allowlist",
				"Bash tool enabled without command allowlist",
				modules.SeverityHigh, []string{"LLM06", "LLM08"},
				"The bash tool is enabled without an allowlist, permitting arbitrary command execution.",
				"Set tools.bash.allowedCommands to an explicit allowlist of permitted commands.",
			))
		}
	}

	// CFG-002: preview/experimental model.
	if v, ok := get(cfg, "model"); ok {
		m := strings.ToLower(asString(v))
		if strings.Contains(m, "preview") || strings.Contains(m, "experimental") {
			f := finding("SEMAR-CFG-002", "config/preview-model",
				"Model set to unreleased/preview version",
				modules.SeverityLow, nil,
				"A preview/experimental model is configured; these may have different safety behaviors.",
				"Pin to a stable, released model for production use.")
			findings = append(findings, f)
		}
	}

	// CFG-003: network access without domain allowlist.
	if v, ok := get(cfg, "permissions.network"); ok && asBool(v) {
		if _, hasList := get(cfg, "permissions.allowedDomains"); !hasList {
			f := finding("SEMAR-CFG-003", "config/network-no-allowlist",
				"Network access enabled without domain restrictions",
				modules.SeverityHigh, []string{"LLM02"},
				"Unrestricted network access enables SSRF and data exfiltration.",
				"Restrict permissions.allowedDomains to an explicit allowlist.")
			f.CWE = []string{"CWE-918"}
			findings = append(findings, f)
		}
	}

	// CFG-004: overly broad file write permissions.
	if v, ok := get(cfg, "permissions.writeFiles"); ok {
		s := asString(v)
		if asBool(v) || s == "*" || strings.HasPrefix(s, "/") || strings.Contains(s, "..") {
			f := finding("SEMAR-CFG-004", "config/broad-write",
				"File write permissions too broad",
				modules.SeverityCritical, []string{"LLM08"},
				"Overly broad write permissions enable filesystem-based attacks.",
				"Scope write permissions to a specific project subdirectory.")
			f.CWE = []string{"CWE-732"}
			findings = append(findings, f)
		}
	}

	// CFG-014: temperature too high.
	if v, ok := get(cfg, "temperature"); ok {
		if t, ok := asFloat(v); ok && t > 1.5 {
			findings = append(findings, finding(
				"SEMAR-CFG-014", "config/high-temperature",
				"Temperature set above 1.5 (unpredictable behavior)",
				modules.SeverityLow, nil,
				"A very high temperature increases unpredictable and potentially unsafe outputs.",
				"Use a temperature <= 1.0 for predictable, safety-aligned behavior.",
			))
		}
	}

	// CFG-013: logging disabled.
	if v, ok := get(cfg, "logging.enabled"); ok && !asBool(v) {
		findings = append(findings, finding(
			"SEMAR-CFG-013", "config/logging-disabled",
			"Logging disabled (audit trail gap)",
			modules.SeverityMedium, nil,
			"Disabled logging removes the audit trail needed for incident response.",
			"Enable structured logging and forward logs to a central store.",
		))
	}

	// CFG-015: auto-approve without human-in-the-loop.
	for _, key := range []string{"autoApprove", "auto_approve", "permissions.autoApprove", "yolo"} {
		if v, ok := get(cfg, key); ok && asBool(v) {
			findings = append(findings, finding(
				"SEMAR-CFG-015", "config/auto-approve",
				"Auto-approve enabled without human-in-the-loop",
				modules.SeverityHigh, []string{"LLM06"},
				"Auto-approving tool calls removes the human checkpoint before destructive actions.",
				"Require human approval for destructive or high-impact tool calls.",
			))
			break
		}
	}

	// MCP server checks (CFG-005, CFG-010, CFG-016).
	for _, mcp := range target.MCPServers {
		if mcp.Host == "0.0.0.0" {
			f := finding("SEMAR-CFG-005", "config/mcp-bind-all",
				"MCP server bound to 0.0.0.0 (all interfaces)",
				modules.SeverityHigh, nil,
				"An MCP server bound to 0.0.0.0 is exposed to the entire network.",
				"Bind the MCP server to 127.0.0.1 unless remote access is required and authenticated.")
			f.FilePath = mcp.SourceFile
			findings = append(findings, f)
		}
		if mcp.URL != "" && strings.HasPrefix(mcp.URL, "http://") {
			f := finding("SEMAR-CFG-016", "config/mcp-remote-cleartext",
				"MCP server / system prompt loaded over cleartext HTTP",
				modules.SeverityHigh, []string{"LLM03"},
				"Loading remote MCP/config over HTTP allows interception and tampering without integrity checks.",
				"Use HTTPS and verify a checksum/signature for remote resources.")
			f.FilePath = mcp.SourceFile
			findings = append(findings, f)
		}
	}

	return findings, nil
}
