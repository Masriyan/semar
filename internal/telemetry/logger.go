// Package telemetry provides structured logging and scan metrics for SEMAR.
package telemetry

import (
	"io"
	"os"
	"time"

	"github.com/rs/zerolog"
)

// Options configures the logger.
type Options struct {
	Level  string // debug, info, warn, error
	Format string // text, json
	NoColor bool
	Writer io.Writer
}

// New constructs a zerolog.Logger from the given options.
func New(opts Options) zerolog.Logger {
	w := opts.Writer
	if w == nil {
		w = os.Stderr
	}

	level := parseLevel(opts.Level)

	if opts.Format == "json" {
		return zerolog.New(w).Level(level).With().Timestamp().Logger()
	}

	cw := zerolog.ConsoleWriter{
		Out:        w,
		TimeFormat: time.RFC3339,
		NoColor:    opts.NoColor,
	}
	return zerolog.New(cw).Level(level).With().Timestamp().Logger()
}

func parseLevel(s string) zerolog.Level {
	switch s {
	case "debug":
		return zerolog.DebugLevel
	case "warn":
		return zerolog.WarnLevel
	case "error":
		return zerolog.ErrorLevel
	case "info", "":
		return zerolog.InfoLevel
	default:
		return zerolog.InfoLevel
	}
}
