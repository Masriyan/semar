package supplychain

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/masriyan/semar/internal/modules"
)

// Auditor checks supply-chain hygiene for agent dependencies and MCP servers.
type Auditor struct {
	// EnableCVELookup enables live OSV.dev queries (network access).
	EnableCVELookup bool
	client          *http.Client
}

// NewAuditor constructs a supply-chain Auditor.
func NewAuditor(enableCVE bool) *Auditor {
	return &Auditor{EnableCVELookup: enableCVE, client: http.DefaultClient}
}

func (a *Auditor) Name() string              { return "supply-chain/auditor" }
func (a *Auditor) Description() string        { return "Audits dependency pinning, source trust, and known CVEs for agent components" }
func (a *Auditor) Severity() modules.Severity { return modules.SeverityHigh }

func (a *Auditor) Rules() []string {
	return []string{"SEMAR-SCA-001", "SEMAR-SCA-002", "SEMAR-SCA-003", "SEMAR-SCA-007"}
}

// Run implements modules.Module.
func (a *Auditor) Run(ctx context.Context, target *modules.ScanTarget) ([]*modules.Finding, error) {
	findings := make([]*modules.Finding, 0)

	// MCP server source/pinning checks.
	for _, mcp := range target.MCPServers {
		pkg, version := parsePackageSpec(mcp)
		if pkg == "" {
			continue
		}
		if version == "" || version == "latest" || strings.HasPrefix(version, "^") || strings.HasPrefix(version, "~") {
			findings = append(findings, sca("SEMAR-SCA-001", "supply-chain/unpinned",
				"MCP server package not pinned to an exact version",
				modules.SeverityMedium, mcp.SourceFile,
				fmt.Sprintf("MCP server %q uses an unpinned version (%q), allowing silent upstream changes.", pkg, version),
				"Pin dependencies to exact versions and verify integrity hashes."))
		}
		if a.EnableCVELookup {
			if vulns, err := lookupCVE(ctx, a.client, pkg, strings.TrimLeft(version, "^~"), "npm"); err == nil && len(vulns) > 0 {
				ids := make([]string, 0, len(vulns))
				for _, v := range vulns {
					ids = append(ids, v.ID)
				}
				findings = append(findings, sca("SEMAR-SCA-003", "supply-chain/known-cve",
					"MCP server package has known CVEs",
					modules.SeverityHigh, mcp.SourceFile,
					fmt.Sprintf("Package %s@%s has known vulnerabilities: %s", pkg, version, strings.Join(ids, ", ")),
					"Upgrade to a patched version; review the OSV advisories."))
			}
		}
	}

	// Lockfile presence check (SCA-007) for JS/TS agent dirs.
	hasManifest, hasLock := false, false
	for path := range target.RawFiles {
		base := path[strings.LastIndexByte(path, '/')+1:]
		switch base {
		case "package.json":
			hasManifest = true
		case "package-lock.json", "yarn.lock", "pnpm-lock.yaml":
			hasLock = true
		}
	}
	if hasManifest && !hasLock {
		findings = append(findings, sca("SEMAR-SCA-007", "supply-chain/no-lockfile",
			"Dependencies not locked (no lockfile present)",
			modules.SeverityMedium, "package.json",
			"package.json exists without a lockfile, so installed versions are non-deterministic.",
			"Commit a lockfile (package-lock.json / yarn.lock / pnpm-lock.yaml)."))
	}

	return findings, nil
}

// parsePackageSpec extracts an npm-style package@version from an MCP entry.
func parsePackageSpec(mcp modules.MCPServerConfig) (pkg, version string) {
	// Common pattern: command "npx" args ["-y", "@scope/pkg@1.2.3"]
	for _, arg := range mcp.Args {
		if strings.HasPrefix(arg, "-") {
			continue
		}
		if strings.Contains(arg, "@") && !strings.HasPrefix(arg, "@") {
			parts := strings.SplitN(arg, "@", 2)
			return parts[0], parts[1]
		}
		if at := strings.LastIndexByte(arg, '@'); at > 0 {
			return arg[:at], arg[at+1:]
		}
		if arg != "" {
			return arg, ""
		}
	}
	return "", ""
}

func sca(id, rule, title string, sev modules.Severity, path, desc, rem string) *modules.Finding {
	return &modules.Finding{
		ID:          id,
		RuleID:      rule,
		Title:       title,
		Severity:    sev,
		Confidence:  modules.ConfidenceMedium,
		Category:    "supply-chain",
		FilePath:    path,
		Description: desc,
		Impact:      "Supply-chain weaknesses allow malicious or vulnerable code into the agent runtime.",
		OWASP:       []string{"LLM03"},
		CWE:         []string{"CWE-1104", "CWE-829"},
		NIST:        []string{"GOVERN-6.1", "MAP-2.3"},
		Remediation: rem,
		References:  []string{"https://osv.dev"},
	}
}
