package agent

import (
	"os"
	"path/filepath"

	"github.com/masriyan/semar/internal/modules"
)

// Detect inspects root and returns the most likely agent type and a
// human-readable label. Returns AgentUnknown if nothing matches.
func Detect(root string) (modules.AgentType, string) {
	bestScore := 0
	best := modules.AgentUnknown
	bestName := "Unknown"

	for _, sig := range Signatures {
		score := 0
		for _, f := range sig.Files {
			if fileExists(filepath.Join(root, f)) {
				score += sig.Weight
			}
		}
		for _, d := range sig.Dirs {
			if dirExists(filepath.Join(root, d)) {
				score += sig.Weight / 2
			}
		}
		if score > bestScore {
			bestScore = score
			best = sig.Type
			bestName = sig.Name
		}
	}

	return best, bestName
}

func fileExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}

func dirExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && info.IsDir()
}
