// Package supplychain audits agent dependencies and supply-chain integrity.
package supplychain

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"time"
)

// CVEResult is a single vulnerability returned by OSV.dev.
type CVEResult struct {
	ID      string `json:"id"`
	Summary string `json:"summary"`
}

// osvResponse models the OSV.dev query response.
type osvResponse struct {
	Vulns []CVEResult `json:"vulns"`
}

// lookupCVE queries the OSV.dev API for known vulnerabilities affecting a
// package version. Returns an empty (non-nil) slice when none are found.
func lookupCVE(ctx context.Context, client *http.Client, pkg, version, ecosystem string) ([]CVEResult, error) {
	payload := map[string]interface{}{
		"version": version,
		"package": map[string]string{
			"name":      pkg,
			"ecosystem": ecosystem,
		},
	}
	buf, err := json.Marshal(payload)
	if err != nil {
		return []CVEResult{}, err
	}

	reqCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, "https://api.osv.dev/v1/query", bytes.NewReader(buf))
	if err != nil {
		return []CVEResult{}, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return []CVEResult{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return []CVEResult{}, nil
	}

	var out osvResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return []CVEResult{}, err
	}
	if out.Vulns == nil {
		return []CVEResult{}, nil
	}
	return out.Vulns, nil
}
