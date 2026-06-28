# SEMAR Architecture

```
                ┌──────────────┐
   target dir → │ config.Load  │ → ScanTarget (RawFiles, Configs, MCPServers,
                │  + detector  │              ToolDefs, SystemPrompt, AgentType)
                └──────┬───────┘
                       │
                ┌──────▼───────┐   worker pool (errgroup + semaphore)
                │   engine     │ ──┬─ secrets        ─┐
                │   .Run(ctx)  │   ├─ config          │
                └──────┬───────┘   ├─ prompt-injection│ each implements
                       │           ├─ iam             │ modules.Module
                       │           ├─ supply-chain    │
                       │           ├─ network         │
                       │           └─ sandbox        ─┘
                       │                  │
                       │            []*Finding (scored via scorer)
                ┌──────▼───────┐
                │  reporter    │ → terminal | json | sarif | markdown | html | csv
                │  .Build/.For │   (+ compliance.Summarize cross-references frameworks)
                └──────────────┘
```

## Data flow

1. **Load** — `internal/config` walks the target, reads files into `RawFiles`,
   parses JSON/YAML/.env into a merged `Configs` map, extracts `mcpServers`
   blocks and tool definitions, and locates the system prompt.
2. **Detect** — `internal/agent` fingerprints the agent type from filesystem markers.
3. **Scan** — `internal/engine` runs every selected module concurrently. Module
   panics are recovered; module errors are non-fatal (partial results are kept).
4. **Score** — `internal/scorer` assigns CVSS-like risk/exploitability/impact
   scores per finding and an aggregate scan risk.
5. **Report** — `internal/reporter` renders deterministic output; `compliance`
   maps findings to OWASP LLM Top 10, MITRE ATLAS, NIST AI RMF.

## Design principles

- **Read-only.** SEMAR never writes to the target. (Semar philosophy.)
- **Deterministic.** Findings are sorted by severity → ID → file → line, so the
  same input always yields the same output and ordering.
- **Redaction at the source.** Secrets are redacted inside the module before a
  `Finding` is ever constructed — never in the reporter.
- **Interface-first.** Every module implements `modules.Module`; adding a module
  means implementing the interface and registering it in
  `internal/engine/registry.go`.

## Writing a custom module

```go
type MyModule struct{}
func (m *MyModule) Name() string                { return "category/my-check" }
func (m *MyModule) Description() string          { return "..." }
func (m *MyModule) Severity() modules.Severity   { return modules.SeverityMedium }
func (m *MyModule) Rules() []string              { return []string{"SEMAR-XXX-001"} }
func (m *MyModule) Run(ctx context.Context, t *modules.ScanTarget) ([]*modules.Finding, error) {
    // inspect t.RawFiles / t.Configs / t.MCPServers; return findings (never nil)
}
```

Register it in `registrations` in `internal/engine/registry.go`.

## Performance

Modules run in parallel bounded by `--workers` (default `NumCPU`). File reads are
capped at 5 MB and `node_modules`, `.git`, `vendor`, etc. are skipped. Typical
agent directories scan in milliseconds.
