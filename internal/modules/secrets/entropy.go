// Package secrets implements the SEMAR secrets & credentials scanner.
package secrets

import "math"

// ShannonEntropy returns the Shannon entropy in bits per character for s.
func ShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	var freq [256]float64
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	n := float64(len(s))
	var entropy float64
	for _, c := range freq {
		if c == 0 {
			continue
		}
		p := c / n
		entropy -= p * math.Log2(p)
	}
	return entropy
}
