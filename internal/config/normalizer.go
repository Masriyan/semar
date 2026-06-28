package config

import (
	"encoding/json"
	"strings"

	"github.com/masriyan/semar/internal/modules"
)

// normalizeYAML converts map[interface{}]interface{} (yaml.v2 style) into
// map[string]interface{} recursively. yaml.v3 already returns string keys, but
// this guards nested cases.
func normalizeYAML(v interface{}) map[string]interface{} {
	out := map[string]interface{}{}
	m, ok := v.(map[string]interface{})
	if !ok {
		return out
	}
	for k, val := range m {
		out[k] = normalizeValue(val)
	}
	return out
}

func normalizeValue(v interface{}) interface{} {
	switch t := v.(type) {
	case map[string]interface{}:
		out := map[string]interface{}{}
		for k, val := range t {
			out[k] = normalizeValue(val)
		}
		return out
	case map[interface{}]interface{}:
		out := map[string]interface{}{}
		for k, val := range t {
			out[toString(k)] = normalizeValue(val)
		}
		return out
	case []interface{}:
		for i, e := range t {
			t[i] = normalizeValue(e)
		}
		return t
	default:
		return v
	}
}

func toString(v interface{}) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// extractMCPServers scans raw JSON/YAML files for an "mcpServers" object and
// normalizes each entry.
func extractMCPServers(rawFiles map[string][]byte) []modules.MCPServerConfig {
	var servers []modules.MCPServerConfig

	for path, data := range rawFiles {
		if !strings.HasSuffix(path, ".json") {
			continue
		}
		var root map[string]json.RawMessage
		if json.Unmarshal(data, &root) != nil {
			continue
		}
		raw, ok := root["mcpServers"]
		if !ok {
			continue
		}
		var entries map[string]struct {
			Command string            `json:"command"`
			Args    []string          `json:"args"`
			URL     string            `json:"url"`
			Host    string            `json:"host"`
			Env     map[string]string `json:"env"`
		}
		if json.Unmarshal(raw, &entries) != nil {
			continue
		}
		for name, e := range entries {
			servers = append(servers, modules.MCPServerConfig{
				Name:       name,
				Command:    e.Command,
				Args:       e.Args,
				URL:        e.URL,
				Host:       e.Host,
				Env:        e.Env,
				SourceFile: path,
			})
		}
	}
	return servers
}

// extractToolDefs pulls tool/function definitions from common config shapes.
func extractToolDefs(cfg map[string]interface{}) []modules.ToolDefinition {
	var defs []modules.ToolDefinition

	add := func(raw interface{}) {
		list, ok := raw.([]interface{})
		if !ok {
			return
		}
		for _, item := range list {
			m, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			td := modules.ToolDefinition{}
			if n, ok := m["name"].(string); ok {
				td.Name = n
			}
			if d, ok := m["description"].(string); ok {
				td.Description = d
			}
			if td.Name != "" {
				defs = append(defs, td)
			}
		}
	}

	add(cfg["tools"])
	add(cfg["functions"])
	return defs
}
