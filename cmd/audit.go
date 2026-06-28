package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/masriyan/semar/internal/config"
	"github.com/masriyan/semar/internal/engine"
	"github.com/masriyan/semar/internal/modules"
	"github.com/masriyan/semar/internal/reporter"
)

// audit flags
var (
	flagTarget         string
	flagAgent          string
	flagModules        []string
	flagExcludeModules []string
	flagSeverity       string
	flagScanEnv        bool
	flagTimeout        time.Duration
	flagWorkers        int
	flagCVELookup      bool

	flagOutput    string
	flagFile      string
	flagOutputDir string
	flagFormats   []string

	flagFailOn      string
	flagFailOnCount int

	flagTitle          string
	flagOrg            string
	flagAssessor       string
	flagClassification string
)

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Run a full security audit of an AI agent setup",
	RunE:  runAudit,
}

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Alias for audit",
	RunE:  runAudit,
}

func init() {
	for _, c := range []*cobra.Command{auditCmd, scanCmd} {
		f := c.Flags()
		f.StringVar(&flagTarget, "target", ".", "target path to audit")
		f.StringVar(&flagAgent, "agent", "", "force agent type (claude-code|codex|cursor|hermes|copilot|generic-mcp)")
		f.StringSliceVar(&flagModules, "modules", nil, "comma-separated modules to run (default: all)")
		f.StringSliceVar(&flagExcludeModules, "exclude-modules", nil, "modules to skip")
		f.StringVar(&flagSeverity, "severity", "LOW", "minimum severity to report (CRITICAL|HIGH|MEDIUM|LOW|INFO)")
		f.BoolVar(&flagScanEnv, "scan-env", false, "also scan environment variables")
		f.DurationVar(&flagTimeout, "timeout", 5*time.Minute, "maximum scan duration")
		f.IntVar(&flagWorkers, "workers", runtime.NumCPU(), "number of parallel scan workers")
		f.BoolVar(&flagCVELookup, "cve-lookup", false, "enable live OSV.dev CVE lookups (network)")

		f.StringVarP(&flagOutput, "output", "o", "terminal", "output format: terminal|json|sarif|markdown|html|pdf|csv")
		f.StringVarP(&flagFile, "file", "f", "", "write output to file (default: stdout)")
		f.StringVar(&flagOutputDir, "output-dir", "", "write multiple format outputs to directory")
		f.StringSliceVar(&flagFormats, "formats", nil, "generate multiple formats, e.g. json,sarif,html")

		f.StringVar(&flagFailOn, "fail-on", "", "exit 1 if any finding >= severity")
		f.IntVar(&flagFailOnCount, "fail-on-count", 0, "exit 1 if total findings >= count")

		f.StringVar(&flagTitle, "title", "SEMAR Security Audit Report", "report title")
		f.StringVar(&flagOrg, "org", "", "organization name for report header")
		f.StringVar(&flagAssessor, "assessor", "", "assessor name for report")
		f.StringVar(&flagClassification, "classification", "CONFIDENTIAL", "report classification")
	}
}

func runAudit(cmd *cobra.Command, args []string) error {
	start := time.Now()

	// Show the banner on an interactive run (to stderr, keeping stdout clean
	// for machine-readable formats piped elsewhere).
	if !flagQuiet {
		PrintBanner(os.Stderr, flagNoColor)
	}

	// 1. Load & normalize target.
	logger.Info().Str("target", flagTarget).Msg("loading target")
	target, err := config.Load(flagTarget, config.Options{
		ForceAgent: modules.AgentType(flagAgent),
		ScanEnv:    flagScanEnv,
	})
	if err != nil {
		return &exitError{code: 2, msg: fmt.Sprintf("failed to load target: %v", err)}
	}
	logger.Info().Str("agent", string(target.AgentType)).Int("files", len(target.RawFiles)).Msg("target loaded")

	// 2. Build module set.
	mods := engine.Select(flagModules, flagExcludeModules, engine.RegistryOptions{EnableCVELookup: flagCVELookup})
	if len(mods) == 0 {
		return &exitError{code: 3, msg: "no modules selected"}
	}
	rulesCount := 0
	for _, m := range mods {
		rulesCount += len(m.Rules())
	}

	// 3. Run engine.
	eng := engine.New(engine.Config{
		Modules: mods,
		Workers: flagWorkers,
		Timeout: flagTimeout,
		Logger:  logger,
	})
	result, err := eng.Run(context.Background(), target)
	if err != nil {
		return &exitError{code: 2, msg: fmt.Sprintf("scan failed: %v", err)}
	}

	// 4. Filter by minimum severity.
	minSev := modules.ParseSeverity(flagSeverity)
	result.Findings = filterSeverity(result.Findings, minSev)

	// 5. Assemble report.
	meta := reporter.Meta{
		Title:          flagTitle,
		Org:            flagOrg,
		Assessor:       flagAssessor,
		Classification: flagClassification,
		ToolVersion:    Version,
	}
	rep := reporter.Build(meta, newScanID(), target, result, rulesCount)

	// 6. Render output(s).
	if err := renderOutputs(rep); err != nil {
		return &exitError{code: 2, msg: err.Error()}
	}

	logger.Info().Dur("duration", time.Since(start)).Int("findings", len(result.Findings)).Msg("audit complete")

	// 7. Exit-code thresholds.
	exitCode = computeExitCode(result.Findings)
	return nil
}

func renderOutputs(rep *reporter.Report) error {
	formats := flagFormats
	if len(formats) == 0 {
		formats = []string{flagOutput}
	}

	for _, format := range formats {
		format = strings.TrimSpace(format)
		rp, err := reporter.For(format, flagNoColor)
		if err != nil {
			return err
		}

		out := os.Stdout
		var closer func()

		switch {
		case flagOutputDir != "":
			if err := os.MkdirAll(flagOutputDir, 0o755); err != nil {
				return err
			}
			path := filepath.Join(flagOutputDir, "semar-report."+ext(format))
			fp, err := os.Create(path)
			if err != nil {
				return err
			}
			out = fp
			closer = func() { fp.Close() }
			logger.Info().Str("file", path).Msg("wrote report")
		case flagFile != "" && len(formats) == 1:
			fp, err := os.Create(flagFile)
			if err != nil {
				return err
			}
			out = fp
			closer = func() { fp.Close() }
			logger.Info().Str("file", flagFile).Msg("wrote report")
		}

		if err := rp.Render(out, rep); err != nil {
			if closer != nil {
				closer()
			}
			return err
		}
		if closer != nil {
			closer()
		}
	}
	return nil
}

func ext(format string) string {
	switch format {
	case "markdown", "md":
		return "md"
	case "terminal":
		return "txt"
	default:
		return format
	}
}

func filterSeverity(findings []*modules.Finding, min modules.Severity) []*modules.Finding {
	out := make([]*modules.Finding, 0, len(findings))
	for _, f := range findings {
		if f.Severity.AtLeast(min) {
			out = append(out, f)
		}
	}
	return out
}

func computeExitCode(findings []*modules.Finding) int {
	if flagFailOnCount > 0 && len(findings) >= flagFailOnCount {
		return 1
	}
	if flagFailOn != "" {
		threshold := modules.ParseSeverity(flagFailOn)
		for _, f := range findings {
			if f.Severity.AtLeast(threshold) {
				return 1
			}
		}
	}
	return 0
}

func newScanID() string {
	return fmt.Sprintf("scan-%d", time.Now().UnixNano())
}
