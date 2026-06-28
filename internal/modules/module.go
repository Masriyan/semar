// Package modules defines the core interfaces and shared types used by every
// SEMAR scan module. The types here form the contract between the scan engine,
// the individual detection modules, and the reporters.
package modules

import "context"

// Module is the core interface every scan module must implement.
// All modules run concurrently via the engine's worker pool.
type Module interface {
	// Name returns the unique identifier for this module.
	// Format: "category/module-name" e.g. "secrets/api-keys"
	Name() string

	// Description returns a human-readable explanation of what this module checks.
	Description() string

	// Severity returns the baseline severity if ANY finding is triggered.
	// Individual findings can override this.
	Severity() Severity

	// Run executes the module scan against the provided ScanTarget.
	// Must respect context cancellation.
	// Returns a slice of findings (empty slice = clean, not nil).
	Run(ctx context.Context, target *ScanTarget) ([]*Finding, error)

	// Rules returns the list of rule IDs this module implements.
	// Used for --rule filtering and documentation generation.
	Rules() []string
}

// AgentType enumerates the AI agent ecosystems SEMAR can audit.
type AgentType string

const (
	AgentClaudeCode AgentType = "claude-code"
	AgentCodex      AgentType = "codex"
	AgentCursor     AgentType = "cursor"
	AgentHermes     AgentType = "hermes"
	AgentCopilot    AgentType = "github-copilot"
	AgentOpenClaw   AgentType = "openclaw"
	AgentGenericMCP AgentType = "generic-mcp"
	AgentUnknown    AgentType = "unknown"
)

// Severity levels, ordered from most to least severe.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL" // CVSS 9.0-10.0 — Immediate action required
	SeverityHigh     Severity = "HIGH"     // CVSS 7.0-8.9  — Fix before next deployment
	SeverityMedium   Severity = "MEDIUM"   // CVSS 4.0-6.9  — Fix in current sprint
	SeverityLow      Severity = "LOW"      // CVSS 0.1-3.9  — Fix in backlog
	SeverityInfo     Severity = "INFO"     // No score      — Informational only
)

// Rank returns a numeric ordering for a severity (higher = more severe).
func (s Severity) Rank() int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}

// AtLeast reports whether s is at least as severe as min.
func (s Severity) AtLeast(min Severity) bool {
	return s.Rank() >= min.Rank()
}

// ParseSeverity converts a string to a Severity, defaulting to INFO.
func ParseSeverity(s string) Severity {
	switch Severity(s) {
	case SeverityCritical:
		return SeverityCritical
	case SeverityHigh:
		return SeverityHigh
	case SeverityMedium:
		return SeverityMedium
	case SeverityLow:
		return SeverityLow
	default:
		return SeverityInfo
	}
}

// Confidence expresses how certain a module is about a finding.
type Confidence string

const (
	ConfidenceHigh   Confidence = "HIGH"
	ConfidenceMedium Confidence = "MEDIUM"
	ConfidenceLow    Confidence = "LOW"
)

// ToolDefinition is a normalized representation of an agent tool/function.
type ToolDefinition struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Parameters  map[string]interface{} `json:"parameters,omitempty"`
	SourceFile  string                 `json:"source_file,omitempty"`
}

// MCPServerConfig is a normalized MCP server entry.
type MCPServerConfig struct {
	Name       string            `json:"name"`
	Command    string            `json:"command,omitempty"`
	Args       []string          `json:"args,omitempty"`
	URL        string            `json:"url,omitempty"`
	Host       string            `json:"host,omitempty"`
	Env        map[string]string `json:"env,omitempty"`
	SourceFile string            `json:"source_file,omitempty"`
}

// ScanTarget represents the normalized, parsed target being audited.
type ScanTarget struct {
	AgentType    AgentType              // Detected agent type
	AgentVersion string                 // Detected agent version (if available)
	RootPath     string                 // Root path of agent installation
	Configs      map[string]interface{} // Normalized config key-value pairs
	RawFiles     map[string][]byte      // Raw file contents by relative path
	EnvVars      map[string]string      // Environment variables (if --scan-env flag)
	SystemPrompt string                 // System prompt content (if found)
	ToolDefs     []ToolDefinition       // Tool/function definitions
	MCPServers   []MCPServerConfig      // MCP server configurations
	Metadata     map[string]string      // Additional metadata
}

// Location describes where a finding was detected.
type Location struct {
	File    string `json:"file"`
	Line    int    `json:"line"`
	Column  int    `json:"column"`
	Snippet string `json:"snippet,omitempty"`
}

// Finding represents a single security issue discovered during a scan.
type Finding struct {
	// Identity
	ID     string `json:"id"`
	RuleID string `json:"rule_id"`
	Title  string `json:"title"`

	// Classification
	Severity   Severity   `json:"severity"`
	Confidence Confidence `json:"confidence"`
	Category   string     `json:"category"`

	// Location
	FilePath string `json:"file_path"`
	Line     int    `json:"line"`
	Column   int    `json:"column"`
	Snippet  string `json:"snippet,omitempty"`

	// Description
	Description string `json:"description"`
	Impact      string `json:"impact"`
	Evidence    string `json:"evidence"`

	// Classification references
	OWASP []string `json:"owasp,omitempty"`
	MITRE []string `json:"mitre,omitempty"`
	CWE   []string `json:"cwe,omitempty"`
	NIST  []string `json:"nist,omitempty"`

	// Remediation
	Remediation     string   `json:"remediation"`
	RemediationCode string   `json:"remediation_code,omitempty"`
	References      []string `json:"references,omitempty"`

	// Scoring
	RiskScore           float64 `json:"risk_score"`
	ExploitabilityScore float64 `json:"exploitability_score"`
	ImpactScore         float64 `json:"impact_score"`
	CVSSVector          string  `json:"cvss_vector,omitempty"`

	// Context
	Tags              []string `json:"tags,omitempty"`
	FalsePositiveRisk string   `json:"false_positive_risk,omitempty"`
}
