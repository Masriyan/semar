package modules

import (
	"fmt"
	"strings"
)

// Redact masks a sensitive value, showing only the first and last few
// characters. SEMAR never includes a full secret in any Finding field.
//
//	Redact("sk-ant-abc...XYZ") => "sk-a****WXYZ"
//
// Short values (<= 8 chars) are fully masked.
func Redact(secret string) string {
	s := strings.TrimSpace(secret)
	if len(s) <= 8 {
		return strings.Repeat("*", len(s))
	}
	return s[:4] + "****" + s[len(s)-4:]
}

// RedactEntropy returns a description for a high-entropy string without
// revealing it, used when the secret type is unknown.
func RedactEntropy(entropy float64, length int) string {
	return fmt.Sprintf("<high-entropy string: entropy=%.2f, length=%d>", entropy, length)
}
