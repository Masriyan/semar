package promptinjection

import "github.com/masriyan/semar/internal/modules"

// llm01Score converts a set of matched patterns in one source into an OWASP
// LLM01 score (0-10). Multiple matches compound but saturate at 10.
func llm01Score(matches []InjectionPattern) float64 {
	var score float64
	for _, m := range matches {
		switch m.Severity {
		case modules.SeverityCritical:
			score += 5.0
		case modules.SeverityHigh:
			score += 3.0
		case modules.SeverityMedium:
			score += 1.5
		default:
			score += 0.5
		}
	}
	if score > 10 {
		score = 10
	}
	return score
}

// severityForScore maps an aggregate LLM01 score to a finding severity.
func severityForScore(score float64) modules.Severity {
	switch {
	case score >= 7.0:
		return modules.SeverityCritical
	case score >= 4.0:
		return modules.SeverityHigh
	case score > 0:
		return modules.SeverityMedium
	default:
		return modules.SeverityInfo
	}
}
