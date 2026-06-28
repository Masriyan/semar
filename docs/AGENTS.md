# Supported Agents

SEMAR auto-detects the agent type from filesystem markers (highest-weight match
wins). Use `--agent <type>` to override detection.

| Type | Detection markers | Config locations checked | Notable checks |
|------|-------------------|--------------------------|----------------|
| `claude-code` | `.claude/settings.json`, `CLAUDE.md`, `.mcp.json` | `.claude/*.json`, `CLAUDE.md`, `mcpServers` blocks | bash allowlist, write perms, MCP host, auto-approve, system-prompt injection |
| `cursor` | `.cursorrules`, `.cursor/mcp.json` | `.cursor/`, `.cursorrules` | rules-file injection, MCP config |
| `github-copilot` | `copilot-instructions.md` | `.github/copilot-instructions.md` | instruction-file injection |
| `codex` | `openai.json`, `.codex/` | assistant/tool definitions | tool-description injection, secrets |
| `hermes` | `hermes.json`, `inference.yaml` | inference server config | endpoint TLS, secrets |
| `generic-mcp` | `mcp.json`, `mcp_config.json` | any MCP manifest | MCP host/auth, supply chain |

## Detection method

`internal/agent/detector.go` scans `root` for each signature's files (full
weight) and directories (half weight) and returns the highest-scoring type, or
`unknown` if nothing matches. Detection is read-only and non-recursive for the
marker check; the full file walk happens during `config.Load`.

## Known false positives

- `CLAUDE.md`/instruction files often contain *examples* of injection strings for
  documentation. SEMAR downgrades placeholder/example context for secrets, but
  prompt-injection patterns in docs may still surface — review context.
- High-entropy detection can flag UUIDs, hashes, and base64 assets.

## Agent-specific remediation notes

- **Claude Code:** prefer `.claude/settings.local.json` (gitignored) for any
  machine-specific values; never put credentials in `CLAUDE.md`.
- **Cursor:** treat `.cursorrules` as untrusted input when shared across a team.
- **MCP (all):** bind servers to `127.0.0.1`, pin package versions, require HTTPS.
