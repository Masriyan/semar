package modules

import "strings"

// LineColForIndex returns the 1-based line and column for a byte offset in s.
func LineColForIndex(s string, idx int) (line, col int) {
	if idx < 0 || idx > len(s) {
		return 0, 0
	}
	line = 1
	col = 1
	for i := range idx {
		if s[i] == '\n' {
			line++
			col = 1
		} else {
			col++
		}
	}
	return line, col
}

// LineContaining returns the full text of the line containing byte offset idx.
func LineContaining(s string, idx int) string {
	if idx < 0 || idx > len(s) {
		return ""
	}
	start := strings.LastIndexByte(s[:idx], '\n') + 1
	end := strings.IndexByte(s[idx:], '\n')
	if end == -1 {
		return s[start:]
	}
	return s[start : idx+end]
}

// IsPlaceholderContext reports whether the surrounding line looks like an
// example, placeholder, or test fixture rather than a real secret.
func IsPlaceholderContext(line string) bool {
	l := strings.ToLower(line)
	for _, marker := range []string{"example", "placeholder", "your-key", "your_key", "yourkey", "xxx", "fake", "dummy", "sample", "<", "redacted"} {
		if strings.Contains(l, marker) {
			return true
		}
	}
	return false
}
