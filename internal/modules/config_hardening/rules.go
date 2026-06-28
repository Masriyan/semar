// Package confighardening evaluates agent configuration against hardening rules.
package confighardening

import (
	"strings"

	"github.com/masriyan/semar/internal/modules"
)

// get performs a dotted-path lookup in a nested config map.
// Returns the value and whether it was found.
func get(cfg map[string]interface{}, path string) (interface{}, bool) {
	parts := strings.Split(path, ".")
	var cur interface{} = cfg
	for _, p := range parts {
		m, ok := cur.(map[string]interface{})
		if !ok {
			return nil, false
		}
		cur, ok = m[p]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

// asBool coerces a config value to a bool.
func asBool(v interface{}) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return strings.EqualFold(t, "true") || t == "1"
	default:
		return false
	}
}

// asString coerces a config value to its string form.
func asString(v interface{}) string {
	switch t := v.(type) {
	case string:
		return t
	default:
		return ""
	}
}

// asFloat coerces a numeric config value.
func asFloat(v interface{}) (float64, bool) {
	switch t := v.(type) {
	case float64:
		return t, true
	case int:
		return float64(t), true
	default:
		return 0, false
	}
}

// finding is a small constructor that fills common config-finding fields.
func finding(id, ruleID, title string, sev modules.Severity, owasp []string, desc, remediation string) *modules.Finding {
	return &modules.Finding{
		ID:          id,
		RuleID:      ruleID,
		Title:       title,
		Severity:    sev,
		Confidence:  modules.ConfidenceMedium,
		Category:    "config",
		OWASP:       owasp,
		NIST:        []string{"GOVERN-2.2", "MANAGE-3.1"},
		Description: desc,
		Remediation: remediation,
		References:  []string{"https://owasp.org/www-project-top-10-for-large-language-model-applications/"},
	}
}
