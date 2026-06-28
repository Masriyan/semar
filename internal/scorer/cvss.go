package scorer

import "github.com/masriyan/semar/internal/modules"

// Score computes risk, exploitability, and impact scores for a finding if they
// are not already set, and returns the finding for convenience. It mutates the
// finding in place.
func Score(f *modules.Finding) *modules.Finding {
	mult := ConfidenceMultiplier[f.Confidence]
	if mult == 0 {
		mult = 0.85
	}

	if f.RiskScore == 0 {
		base := SeverityWeight[f.Severity]
		f.RiskScore = round1(base * mult)
	}
	if f.ImpactScore == 0 {
		f.ImpactScore = round1(SeverityWeight[f.Severity])
	}
	if f.ExploitabilityScore == 0 {
		f.ExploitabilityScore = round1(f.RiskScore * 0.9)
	}
	return f
}

// RiskLevel maps an aggregate score to a textual risk level.
func RiskLevel(score float64) modules.Severity {
	switch {
	case score >= 9.0:
		return modules.SeverityCritical
	case score >= 7.0:
		return modules.SeverityHigh
	case score >= 4.0:
		return modules.SeverityMedium
	case score > 0:
		return modules.SeverityLow
	default:
		return modules.SeverityInfo
	}
}

// Aggregate computes an overall scan risk score (0-10). The score is dominated
// by the most severe findings but rises with the volume of issues.
func Aggregate(findings []*modules.Finding) float64 {
	if len(findings) == 0 {
		return 0
	}
	var max, sum float64
	for _, f := range findings {
		if f.RiskScore > max {
			max = f.RiskScore
		}
		sum += f.RiskScore
	}
	avg := sum / float64(len(findings))
	// Weighted blend: 70% worst-case, 30% average pressure.
	score := max*0.7 + avg*0.3
	if score > 10 {
		score = 10
	}
	return round1(score)
}

func round1(v float64) float64 {
	return float64(int(v*10+0.5)) / 10
}
