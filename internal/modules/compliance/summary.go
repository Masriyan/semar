package compliance

import (
	"sort"

	"github.com/masriyan/semar/internal/modules"
)

// Summary is the aggregated compliance posture across all findings. It is
// computed at report time (compliance cross-references existing findings rather
// than scanning independently).
type Summary struct {
	OWASPTriggered []string       // sorted OWASP category IDs with >=1 finding
	OWASPCounts    map[string]int // category -> finding count
	MITRETTPs      []string       // sorted ATLAS TTPs referenced
	NISTControls   []string       // sorted NIST controls referenced
}

// OWASPCoverage returns "n/10".
func (s Summary) OWASPCoverage() string {
	return itoa(len(s.OWASPTriggered)) + "/10"
}

// Summarize builds a compliance Summary from a finding set.
func Summarize(findings []*modules.Finding) Summary {
	owaspCounts := map[string]int{}
	mitre := map[string]bool{}
	nist := map[string]bool{}

	for _, f := range findings {
		for _, o := range f.OWASP {
			owaspCounts[o]++
		}
		for _, m := range f.MITRE {
			mitre[m] = true
		}
		for _, n := range f.NIST {
			nist[n] = true
		}
	}

	return Summary{
		OWASPTriggered: sortedKeys(owaspCounts),
		OWASPCounts:    owaspCounts,
		MITRETTPs:      sortedBoolKeys(mitre),
		NISTControls:   sortedBoolKeys(nist),
	}
}

func sortedKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sortedBoolKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
