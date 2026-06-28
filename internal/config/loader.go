// Package config loads and normalizes agent configuration into a ScanTarget.
package config

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/masriyan/semar/internal/agent"
	"github.com/masriyan/semar/internal/modules"
)

// Options controls how a target is loaded.
type Options struct {
	ForceAgent  modules.AgentType // if set, skip auto-detection
	ScanEnv     bool              // include environment variables
	MaxFileSize int64             // skip files larger than this (bytes); 0 = 5MB default
}

// skipDirs are directories never worth scanning.
var skipDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, "dist": true,
	"bin": true, ".cache": true, "__pycache__": true,
}

// configExts are file extensions parsed as structured config.
var configExts = map[string]bool{
	".json": true, ".yaml": true, ".yml": true, ".env": true, ".toml": true, ".ini": true, ".conf": true,
}

// Load walks root, reads relevant files, and produces a normalized ScanTarget.
func Load(root string, opts Options) (*modules.ScanTarget, error) {
	maxSize := opts.MaxFileSize
	if maxSize == 0 {
		maxSize = 5 << 20 // 5MB
	}

	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}

	target := &modules.ScanTarget{
		RootPath: abs,
		Configs:  map[string]interface{}{},
		RawFiles: map[string][]byte{},
		EnvVars:  map[string]string{},
		Metadata: map[string]string{},
	}

	merged := map[string]interface{}{}

	walkErr := filepath.WalkDir(abs, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable entries
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		info, err := d.Info()
		if err != nil || info.Size() > maxSize {
			return nil
		}

		rel, _ := filepath.Rel(abs, path)
		rel = filepath.ToSlash(rel)

		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		target.RawFiles[rel] = data

		ext := strings.ToLower(filepath.Ext(path))
		base := d.Name()
		if configExts[ext] {
			parseInto(merged, base, ext, data)
		}
		if base == "CLAUDE.md" || base == ".cursorrules" || base == "copilot-instructions.md" || base == "system_prompt.txt" {
			if target.SystemPrompt == "" {
				target.SystemPrompt = string(data)
			}
		}
		return nil
	})
	if walkErr != nil {
		return nil, walkErr
	}

	target.Configs = merged

	// Agent type.
	if opts.ForceAgent != "" {
		target.AgentType = opts.ForceAgent
	} else {
		t, name := agent.Detect(abs)
		target.AgentType = t
		target.Metadata["agent_name"] = name
	}

	// Extract MCP servers and tool definitions from merged config.
	target.MCPServers = extractMCPServers(target.RawFiles)
	target.ToolDefs = extractToolDefs(merged)

	if opts.ScanEnv {
		for _, kv := range os.Environ() {
			if i := strings.IndexByte(kv, '='); i > 0 {
				target.EnvVars[kv[:i]] = kv[i+1:]
			}
		}
	}

	return target, nil
}

// parseInto parses a config blob and merges top-level keys into dst.
func parseInto(dst map[string]interface{}, base, ext string, data []byte) {
	switch ext {
	case ".json":
		var v map[string]interface{}
		if json.Unmarshal(data, &v) == nil {
			mergeMap(dst, v)
		}
	case ".yaml", ".yml":
		var v map[string]interface{}
		if yaml.Unmarshal(data, &v) == nil {
			mergeMap(dst, normalizeYAML(v))
		}
	case ".env":
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if i := strings.IndexByte(line, '='); i > 0 {
				key := strings.TrimSpace(line[:i])
				val := strings.Trim(strings.TrimSpace(line[i+1:]), `"'`)
				dst[key] = val
			}
		}
	}
}

func mergeMap(dst, src map[string]interface{}) {
	for k, v := range src {
		dst[k] = v
	}
}
