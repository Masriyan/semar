package engine

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"golang.org/x/sync/errgroup"

	"github.com/masriyan/semar/internal/modules"
	"github.com/masriyan/semar/internal/scorer"
)

// Engine orchestrates all scan modules with controlled concurrency.
//
// Design principles:
//   - All modules run in parallel (bounded by workers count).
//   - Context cancellation propagates to all modules immediately.
//   - Module panics are recovered and converted to errors.
//   - Results are collected in a thread-safe manner.
//   - Progress is reported via channel for real-time terminal output.
type Engine struct {
	modules  []modules.Module
	workers  int
	timeout  time.Duration
	logger   zerolog.Logger
	progress chan<- Progress
}

// Config configures a new Engine.
type Config struct {
	Modules  []modules.Module
	Workers  int
	Timeout  time.Duration
	Logger   zerolog.Logger
	Progress chan<- Progress
}

// New builds an Engine from a Config, applying sane defaults.
func New(cfg Config) *Engine {
	if cfg.Workers <= 0 {
		cfg.Workers = 1
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Minute
	}
	return &Engine{
		modules:  cfg.Modules,
		workers:  cfg.Workers,
		timeout:  cfg.Timeout,
		logger:   cfg.Logger,
		progress: cfg.Progress,
	}
}

// Run executes every configured module against target, returning the merged,
// scored, and deterministically-ordered result set.
func (e *Engine) Run(ctx context.Context, target *modules.ScanTarget) (*ScanResult, error) {
	ctx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()

	result := &ScanResult{
		StartTime:   time.Now(),
		ModuleStats: make(map[string]ModuleStat),
	}

	var (
		mu       sync.Mutex
		findings []*modules.Finding
	)

	sem := make(chan struct{}, e.workers)
	g, ctx := errgroup.WithContext(ctx)

	for i, mod := range e.modules {
		g.Go(func() error {
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return nil
			}
			defer func() { <-sem }()

			e.emit(Progress{Module: mod.Name(), Step: i + 1, Total: len(e.modules), Status: "running"})

			start := time.Now()

			var modFindings []*modules.Finding
			var modErr error

			func() {
				defer func() {
					if r := recover(); r != nil {
						modErr = fmt.Errorf("module %s panicked: %v", mod.Name(), r)
						e.logger.Error().Str("module", mod.Name()).Interface("panic", r).Msg("module panic recovered")
					}
				}()
				modFindings, modErr = mod.Run(ctx, target)
			}()

			for _, f := range modFindings {
				scorer.Score(f)
			}

			stat := ModuleStat{
				Name:     mod.Name(),
				Duration: time.Since(start),
				Findings: len(modFindings),
				Error:    modErr,
			}

			mu.Lock()
			findings = append(findings, modFindings...)
			result.ModuleStats[mod.Name()] = stat
			mu.Unlock()

			status := "done"
			if modErr != nil {
				status = "error"
				e.logger.Warn().Str("module", mod.Name()).Err(modErr).Msg("module error (non-fatal)")
			}
			e.emit(Progress{Module: mod.Name(), Step: i + 1, Total: len(e.modules), Status: status, Findings: len(modFindings)})

			return nil // never cancel siblings; partial results are valuable
		})
	}

	if err := g.Wait(); err != nil {
		result.Error = err
	}

	sortFindings(findings)
	result.EndTime = time.Now()
	result.Findings = findings

	return result, nil
}

func (e *Engine) emit(p Progress) {
	if e.progress != nil {
		e.progress <- p
	}
}

// sortFindings produces deterministic output: severity desc, then ID, then file.
func sortFindings(findings []*modules.Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if a.Severity.Rank() != b.Severity.Rank() {
			return a.Severity.Rank() > b.Severity.Rank()
		}
		if a.ID != b.ID {
			return a.ID < b.ID
		}
		if a.FilePath != b.FilePath {
			return a.FilePath < b.FilePath
		}
		return a.Line < b.Line
	})
}
