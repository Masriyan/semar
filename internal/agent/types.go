// Package agent detects AI agent types and builds a normalized ScanTarget.
package agent

import "github.com/masriyan/semar/internal/modules"

// Signature describes the filesystem markers that identify an agent type.
type Signature struct {
	Type    modules.AgentType
	Name    string
	Files   []string // relative paths that, if present, indicate this agent
	Dirs    []string // directories that indicate this agent
	Weight  int      // confidence weight when matched
}

// Signatures is the ordered fingerprint library used for auto-detection.
var Signatures = []Signature{
	{Type: modules.AgentClaudeCode, Name: "Claude Code", Files: []string{".claude/settings.json", "CLAUDE.md", ".claude/settings.local.json", ".mcp.json"}, Dirs: []string{".claude"}, Weight: 10},
	{Type: modules.AgentCursor, Name: "Cursor IDE", Files: []string{".cursorrules", ".cursor/mcp.json", ".cursor/rules"}, Dirs: []string{".cursor"}, Weight: 10},
	{Type: modules.AgentCopilot, Name: "GitHub Copilot", Files: []string{".github/copilot-instructions.md", "copilot-instructions.md"}, Weight: 9},
	{Type: modules.AgentCodex, Name: "OpenAI Codex", Files: []string{"openai.json", ".codex/config.json", "assistant.json"}, Dirs: []string{".codex"}, Weight: 8},
	{Type: modules.AgentHermes, Name: "Hermes", Files: []string{"hermes.json", "hermes.yaml", "inference.yaml"}, Weight: 7},
	{Type: modules.AgentGenericMCP, Name: "Generic MCP", Files: []string{"mcp.json", ".mcp.json", "mcp_config.json"}, Weight: 5},
}
