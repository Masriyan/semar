// Package scorer provides CVSS-like risk scoring for findings and aggregate
// risk computation for an entire scan result.
package scorer

import "github.com/masriyan/semar/internal/modules"

// SeverityWeight maps a severity to its baseline numeric risk score (0-10).
var SeverityWeight = map[modules.Severity]float64{
	modules.SeverityCritical: 9.5,
	modules.SeverityHigh:     7.5,
	modules.SeverityMedium:   5.0,
	modules.SeverityLow:      2.5,
	modules.SeverityInfo:     0.0,
}

// ConfidenceMultiplier adjusts a score based on detection confidence.
var ConfidenceMultiplier = map[modules.Confidence]float64{
	modules.ConfidenceHigh:   1.0,
	modules.ConfidenceMedium: 0.85,
	modules.ConfidenceLow:    0.65,
}
