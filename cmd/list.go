package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/masriyan/semar/internal/engine"
	"github.com/masriyan/semar/internal/modules"
)

var listCmd = &cobra.Command{
	Use:   "list [agents|modules|rules]",
	Short: "List supported agents, scan modules, or rules",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		w := cmd.OutOrStdout()
		switch args[0] {
		case "agents":
			for _, a := range []modules.AgentType{
				modules.AgentClaudeCode, modules.AgentCodex, modules.AgentCursor,
				modules.AgentHermes, modules.AgentCopilot, modules.AgentGenericMCP,
			} {
				fmt.Fprintln(w, a)
			}
		case "modules":
			for _, m := range engine.Select(nil, nil, engine.RegistryOptions{}) {
				fmt.Fprintf(w, "%-22s %s\n", m.Name(), m.Description())
			}
		case "rules":
			for _, m := range engine.Select(nil, nil, engine.RegistryOptions{}) {
				fmt.Fprintf(w, "# %s\n", m.Name())
				for _, r := range m.Rules() {
					fmt.Fprintf(w, "  %s\n", r)
				}
			}
		default:
			return &exitError{code: 3, msg: fmt.Sprintf("unknown list target %q (use: agents, modules, rules)", args[0])}
		}
		return nil
	},
}
