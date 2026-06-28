package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/masriyan/semar/internal/engine"
	"github.com/masriyan/semar/internal/modules"
	"github.com/masriyan/semar/internal/reporter"
)

var (
	flagReportInput  string
	flagReportOutput string
	flagReportFile   string
)

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Generate a report from a previous SEMAR JSON scan result",
	RunE:  runReport,
}

func init() {
	f := reportCmd.Flags()
	f.StringVar(&flagReportInput, "input", "", "path to a SEMAR JSON results file (required)")
	f.StringVarP(&flagReportOutput, "output", "o", "terminal", "output format: terminal|json|sarif|markdown|html|pdf|csv")
	f.StringVarP(&flagReportFile, "file", "f", "", "write output to file (default: stdout)")
	_ = reportCmd.MarkFlagRequired("input")
}

// minimalJSON mirrors the relevant parts of the SEMAR JSON schema for re-render.
type minimalJSON struct {
	Scan struct {
		Target struct {
			Path         string `json:"path"`
			AgentType    string `json:"agent_type"`
			AgentVersion string `json:"agent_version"`
		} `json:"target"`
	} `json:"scan"`
	Findings []*modules.Finding `json:"findings"`
}

func runReport(cmd *cobra.Command, args []string) error {
	data, err := os.ReadFile(flagReportInput)
	if err != nil {
		return &exitError{code: 2, msg: fmt.Sprintf("cannot read input: %v", err)}
	}
	var in minimalJSON
	if err := json.Unmarshal(data, &in); err != nil {
		return &exitError{code: 2, msg: fmt.Sprintf("invalid SEMAR JSON: %v", err)}
	}

	target := &modules.ScanTarget{
		RootPath:     in.Scan.Target.Path,
		AgentType:    modules.AgentType(in.Scan.Target.AgentType),
		AgentVersion: in.Scan.Target.AgentVersion,
		RawFiles:     map[string][]byte{},
	}
	result := &engine.ScanResult{
		Findings:    in.Findings,
		ModuleStats: map[string]engine.ModuleStat{},
		StartTime:   time.Now(),
		EndTime:     time.Now(),
	}

	rep := reporter.Build(reporter.Meta{ToolVersion: Version}, "report", target, result, 0)

	rp, err := reporter.For(flagReportOutput, flagNoColor)
	if err != nil {
		return &exitError{code: 3, msg: err.Error()}
	}

	out := os.Stdout
	if flagReportFile != "" {
		fp, err := os.Create(flagReportFile)
		if err != nil {
			return &exitError{code: 2, msg: err.Error()}
		}
		defer fp.Close()
		out = fp
	}
	if err := rp.Render(out, rep); err != nil {
		return &exitError{code: 2, msg: err.Error()}
	}
	return nil
}
