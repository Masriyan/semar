package telemetry

import "time"

// Metrics collects aggregate statistics about a scan run.
type Metrics struct {
	FilesScanned   int
	RulesEvaluated int
	ModulesRun     int
	StartTime      time.Time
	EndTime        time.Time
}

// Duration returns the elapsed scan time.
func (m *Metrics) Duration() time.Duration {
	if m.EndTime.IsZero() {
		return time.Since(m.StartTime)
	}
	return m.EndTime.Sub(m.StartTime)
}
