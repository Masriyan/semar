// Package compliance cross-references findings to security frameworks.
package compliance

// OWASPLLM maps OWASP LLM Top 10 (2025) category IDs to their names.
var OWASPLLM = map[string]string{
	"LLM01": "Prompt Injection",
	"LLM02": "Sensitive Information Disclosure",
	"LLM03": "Supply Chain Vulnerabilities",
	"LLM04": "Data and Model Poisoning",
	"LLM05": "Improper Output Handling",
	"LLM06": "Excessive Agency",
	"LLM07": "System Prompt Leakage",
	"LLM08": "Vector and Embedding Weaknesses",
	"LLM09": "Misinformation",
	"LLM10": "Unbounded Consumption",
}

// MITREATLAS maps the relevant subset of ATLAS TTPs to their names.
var MITREATLAS = map[string]string{
	"AML.T0054":     "LLM Prompt Injection",
	"AML.T0054.000": "Direct Prompt Injection",
	"AML.T0054.001": "Indirect Prompt Injection",
	"AML.T0048":     "Discover ML Artifacts",
	"AML.T0040":     "ML Model Inference API Access",
	"AML.T0025":     "Exfiltration via ML Inference API",
}

// NISTAIRMF maps relevant NIST AI RMF 1.0 controls to descriptions.
var NISTAIRMF = map[string]string{
	"GOVERN-1.1":  "Legal and regulatory requirements are understood and managed",
	"GOVERN-2.2":  "Roles and responsibilities for AI risk are documented",
	"GOVERN-6.1":  "Third-party / supply-chain risks are managed",
	"MAP-1.1":     "Context and intended use are established",
	"MAP-2.3":     "Scientific integrity and TEVV considerations are mapped",
	"MAP-5.1":     "Impacts to individuals and society are characterized",
	"MEASURE-2.5": "AI system is evaluated for validity and reliability",
	"MEASURE-2.6": "AI system is evaluated for safety and security",
	"MEASURE-2.13": "Effectiveness of monitoring is measured",
	"MANAGE-2.4":  "Mechanisms to sustain AI risk management are in place",
	"MANAGE-3.1":  "AI risks from third parties are managed",
	"MANAGE-4.1":  "Post-deployment monitoring plans are implemented",
}
