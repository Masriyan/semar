package engine

import (
	"strings"

	"github.com/masriyan/semar/internal/modules"
	confighardening "github.com/masriyan/semar/internal/modules/config_hardening"
	"github.com/masriyan/semar/internal/modules/iam"
	"github.com/masriyan/semar/internal/modules/network"
	promptinjection "github.com/masriyan/semar/internal/modules/prompt_injection"
	"github.com/masriyan/semar/internal/modules/sandbox"
	"github.com/masriyan/semar/internal/modules/secrets"
	supplychain "github.com/masriyan/semar/internal/modules/supply_chain"
)

// ModuleKey is the short CLI name for a module.
type registration struct {
	key    string
	factory func(opts RegistryOptions) modules.Module
}

// RegistryOptions influence module construction.
type RegistryOptions struct {
	EnableCVELookup bool
}

var registrations = []registration{
	{"secrets", func(RegistryOptions) modules.Module { return secrets.NewScanner() }},
	{"config", func(RegistryOptions) modules.Module { return confighardening.NewChecker() }},
	{"prompt-injection", func(RegistryOptions) modules.Module { return promptinjection.NewAnalyzer() }},
	{"iam", func(RegistryOptions) modules.Module { return iam.NewAuditor() }},
	{"supply-chain", func(o RegistryOptions) modules.Module { return supplychain.NewAuditor(o.EnableCVELookup) }},
	{"network", func(RegistryOptions) modules.Module { return network.NewChecker() }},
	{"sandbox", func(RegistryOptions) modules.Module { return sandbox.NewValidator() }},
}

// AllModuleKeys returns the CLI names of every available module, in order.
func AllModuleKeys() []string {
	keys := make([]string, 0, len(registrations))
	for _, r := range registrations {
		keys = append(keys, r.key)
	}
	return keys
}

// Select builds the module set, honoring include/exclude lists. Empty include
// means "all". Names are matched case-insensitively.
func Select(include, exclude []string, opts RegistryOptions) []modules.Module {
	inc := toSet(include)
	exc := toSet(exclude)

	var mods []modules.Module
	for _, r := range registrations {
		if len(inc) > 0 && !inc[r.key] {
			continue
		}
		if exc[r.key] {
			continue
		}
		mods = append(mods, r.factory(opts))
	}
	return mods
}

func toSet(items []string) map[string]bool {
	set := map[string]bool{}
	for _, it := range items {
		it = strings.TrimSpace(strings.ToLower(it))
		if it != "" {
			set[it] = true
		}
	}
	return set
}
