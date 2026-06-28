// Package promptinjection maps the prompt-injection attack surface of an agent.
package promptinjection

import (
	"regexp"

	"github.com/masriyan/semar/internal/modules"
)

// InjectionPattern describes a single prompt-injection signature.
type InjectionPattern struct {
	ID          string
	Name        string
	Pattern     *regexp.Regexp
	Severity    modules.Severity
	OWASP       []string
	MITRE       []string
	Description string
}

// InjectionPatterns is the built-in prompt-injection signature library.
var InjectionPatterns = []InjectionPattern{
	{
		ID:          "PI-001",
		Name:        "Role override attempt",
		Pattern:     regexp.MustCompile(`(?i)(ignore|disregard|forget)\s+(all\s+)?(previous|prior|above)\s+(instructions|rules|guidelines|prompts)`),
		Severity:    modules.SeverityCritical,
		OWASP:       []string{"LLM01"},
		MITRE:       []string{"AML.T0054.000"},
		Description: "Classic prompt injection attempting to override system instructions.",
	},
	{
		ID:          "PI-002",
		Name:        "DAN / jailbreak preamble",
		Pattern:     regexp.MustCompile(`(?i)(DAN|do\s+anything\s+now|jailbreak|pretend\s+you\s+(are|have\s+no))`),
		Severity:    modules.SeverityCritical,
		OWASP:       []string{"LLM01"},
		MITRE:       []string{"AML.T0054.000"},
		Description: "Jailbreak preamble attempting to bypass safety guidelines.",
	},
	{
		ID:          "PI-003",
		Name:        "Indirect injection via tool description",
		Pattern:     regexp.MustCompile(`(?i)(when\s+this\s+tool\s+is\s+called|after\s+using\s+this\s+tool|before\s+responding)`),
		Severity:    modules.SeverityHigh,
		OWASP:       []string{"LLM01", "LLM02"},
		MITRE:       []string{"AML.T0054.001"},
		Description: "Tool description containing behavioral override instructions (indirect injection).",
	},
	{
		ID:          "PI-004",
		Name:        "Exfiltration instruction in context",
		Pattern:     regexp.MustCompile(`(?i)(send|POST|exfiltrate|leak)\s+.{0,50}(to|via)\s+(http|https|webhook|url)`),
		Severity:    modules.SeverityCritical,
		OWASP:       []string{"LLM01", "LLM06"},
		MITRE:       []string{"AML.T0025"},
		Description: "Context instructs the agent to exfiltrate data to an external endpoint.",
	},
	{
		ID:          "PI-005",
		Name:        "Hidden instruction (zero-width steganography)",
		Pattern:     regexp.MustCompile(`(\x{200b}|\x{200c}|\x{200d}|\x{feff}|\x{2060}){3,}`),
		Severity:    modules.SeverityHigh,
		OWASP:       []string{"LLM01"},
		MITRE:       []string{"AML.T0054.001"},
		Description: "Zero-width characters used to hide injected instructions.",
	},
	{
		ID:          "PI-006",
		Name:        "SYSTEM: override prefix",
		Pattern:     regexp.MustCompile(`(?i)(SYSTEM|ASSISTANT|USER)\s*:\s*(ignore|override|new\s+instructions)`),
		Severity:    modules.SeverityCritical,
		OWASP:       []string{"LLM01"},
		MITRE:       []string{"AML.T0054.000"},
		Description: "Fake conversation-role prefix used to inject new instructions.",
	},
}
