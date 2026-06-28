// Package engine orchestrates all scan modules with controlled concurrency.
package engine

import (
	"time"

	"github.com/masriyan/semar/internal/modules"
)

// ScanResult is the unified output of an engine run.
type ScanResult struct {
	Findings    []*modules.Finding
	ModuleStats map[string]ModuleStat
	StartTime   time.Time
	EndTime     time.Time
	Error       error
}

// Duration returns the wall-clock scan duration.
func (r *ScanResult) Duration() time.Duration {
	return r.EndTime.Sub(r.StartTime)
}

// ModuleStat captures per-module execution statistics.
type ModuleStat struct {
	Name     string
	Duration time.Duration
	Findings int
	Error    error
}

// Progress is emitted on the progress channel for real-time terminal output.
type Progress struct {
	Module   string
	Step     int
	Total    int
	Status   string // "running", "done", "error"
	Findings int
}
