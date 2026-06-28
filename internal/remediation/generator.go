// Package remediation generates prioritized remediation playbooks from findings.
package remediation

import (
	"fmt"
	"io"
	"sort"

	"github.com/masriyan/semar/internal/modules"
)

// Item is a single remediation action.
type Item struct {
	FindingID   string
	Title       string
	Severity    modules.Severity
	Steps       string
	Priority    int // 1 = highest
}

// Generate produces a severity-ordered remediation playbook.
func Generate(findings []*modules.Finding) []Item {
	items := make([]Item, 0, len(findings))
	for _, f := range findings {
		items = append(items, Item{
			FindingID: f.ID,
			Title:     f.Title,
			Severity:  f.Severity,
			Steps:     f.Remediation,
			Priority:  6 - f.Severity.Rank(),
		})
	}
	sort.SliceStable(items, func(i, j int) bool {
		return items[i].Priority < items[j].Priority
	})
	return items
}

// WritePlaybook renders the playbook as Markdown.
func WritePlaybook(w io.Writer, findings []*modules.Finding) {
	items := Generate(findings)
	fmt.Fprintln(w, "# SEMAR Remediation Playbook")
	fmt.Fprintln(w)
	for i, it := range items {
		fmt.Fprintf(w, "## %d. [%s] %s (%s)\n", i+1, it.Severity, it.Title, it.FindingID)
		if it.Steps != "" {
			fmt.Fprintf(w, "%s\n\n", it.Steps)
		}
	}
}
