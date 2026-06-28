package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/masriyan/semar/internal/engine"
	"github.com/masriyan/semar/internal/modules"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show version, build info, and supported agents",
	RunE: func(cmd *cobra.Command, args []string) error {
		w := cmd.OutOrStdout()
		PrintBanner(w, flagNoColor)
		fmt.Fprintf(w, "SEMAR %s\n", Version)
		fmt.Fprintf(w, "  commit: %s\n", Commit)
		fmt.Fprintf(w, "  built:  %s\n", Date)
		fmt.Fprintln(w, "\nSupported agents:")
		for _, a := range []modules.AgentType{
			modules.AgentClaudeCode, modules.AgentCodex, modules.AgentCursor,
			modules.AgentHermes, modules.AgentCopilot, modules.AgentGenericMCP,
		} {
			fmt.Fprintf(w, "  - %s\n", a)
		}
		fmt.Fprintln(w, "\nScan modules:")
		for _, m := range engine.AllModuleKeys() {
			fmt.Fprintf(w, "  - %s\n", m)
		}
		return nil
	},
}
