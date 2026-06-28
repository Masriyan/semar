// Command semar is the entry point for the SEMAR AI agent security auditor.
package main

import (
	"os"

	"github.com/masriyan/semar/cmd"
)

// Build metadata injected via -ldflags.
var (
	version = "v0.1.0-dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	cmd.Version = version
	cmd.Commit = commit
	cmd.Date = date
	os.Exit(cmd.Execute())
}
