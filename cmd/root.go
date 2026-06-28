// Package cmd implements the SEMAR command-line interface.
package cmd

import (
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"

	"github.com/masriyan/semar/internal/telemetry"
)

// Build metadata, injected via -ldflags by main.
var (
	Version = "v0.1.0-dev"
	Commit  = "none"
	Date    = "unknown"
)

// global flags
var (
	flagConfig    string
	flagLogLevel  string
	flagLogFormat string
	flagNoColor   bool
	flagQuiet     bool
	flagVerbose   bool
)

var logger zerolog.Logger

var rootCmd = &cobra.Command{
	Use:   "semar",
	Short: "SEMAR — AI Agent Security Audit Framework",
	Long: `SEMAR (Sistem Evaluasi Multi-Agen untuk Risk, konfigurasi & keAmanan aI)
is an enterprise-grade CLI that audits AI agent configurations for security risks:
secrets, prompt-injection surface, excessive permissions, supply-chain weaknesses,
network egress, and runtime sandbox hardening.

"Sing ngerti kabeh, nanging ora ngancam" — knows everything, but never threatens.`,
	SilenceUsage:  true,
	SilenceErrors: true,
	Run: func(cmd *cobra.Command, args []string) {
		PrintBanner(cmd.OutOrStdout(), flagNoColor)
		_ = cmd.Help()
	},
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		level := flagLogLevel
		if flagVerbose {
			level = "debug"
		}
		if flagQuiet {
			level = "error"
		}
		logger = telemetry.New(telemetry.Options{
			Level:   level,
			Format:  flagLogFormat,
			NoColor: flagNoColor,
		})
	},
}

func init() {
	pf := rootCmd.PersistentFlags()
	pf.StringVar(&flagConfig, "config", ".semar.yml", "path to semar config file")
	pf.StringVar(&flagLogLevel, "log-level", "info", "log level: debug, info, warn, error")
	pf.StringVar(&flagLogFormat, "log-format", "text", "log format: text, json")
	pf.BoolVar(&flagNoColor, "no-color", false, "disable colored output")
	pf.BoolVar(&flagQuiet, "quiet", false, "suppress all output except findings")
	pf.BoolVarP(&flagVerbose, "verbose", "v", false, "verbose output (log-level debug)")

	rootCmd.AddCommand(auditCmd, scanCmd, reportCmd, listCmd, versionCmd)
}

// Execute runs the root command. Returns the process exit code.
func Execute() int {
	if err := rootCmd.Execute(); err != nil {
		if ec, ok := err.(*exitError); ok {
			logger.Error().Msg(ec.msg)
			return ec.code
		}
		// cobra/flag errors → config error
		logger.Error().Err(err).Msg("command failed")
		return 3
	}
	return exitCode
}

// exitCode is set by subcommands (audit) to reflect findings thresholds.
var exitCode int

// exitError carries an explicit exit code from a subcommand.
type exitError struct {
	code int
	msg  string
}

func (e *exitError) Error() string { return e.msg }
