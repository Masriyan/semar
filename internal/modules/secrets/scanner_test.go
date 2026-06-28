package secrets_test

import (
	"context"
	"strings"
	"testing"

	"github.com/masriyan/semar/internal/modules"
	"github.com/masriyan/semar/internal/modules/secrets"
)

func TestSecretsScanner_AnthropicAPIKey(t *testing.T) {
	realKey := "sk-ant-api03-realKEY1234567890abcdefABCDEF1234567890abcdefABCDEF1234567890abcd"
	tests := []struct {
		name           string
		content        string
		expectedID     string
		expectFindings bool
	}{
		{"detect bare API key", "ANTHROPIC_API_KEY=" + realKey, "SEMAR-SEC-001", true},
		{"detect API key in JSON", `{"apiKey": "` + realKey + `"}`, "SEMAR-SEC-001", true},
		{"skip obvious placeholder", "ANTHROPIC_API_KEY=sk-ant-your-key-here", "", false},
		{"skip commented example", "# Example: ANTHROPIC_API_KEY=sk-ant-xxx", "", false},
	}

	scanner := secrets.NewScanner()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target := &modules.ScanTarget{
				RawFiles: map[string][]byte{"test.env": []byte(tt.content)},
			}
			findings, err := scanner.Run(context.Background(), target)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.expectFindings {
				if len(findings) == 0 {
					t.Fatalf("expected findings, got none")
				}
				// the provider finding (not entropy) should be present with HIGH confidence
				var got *modules.Finding
				for _, f := range findings {
					if f.ID == tt.expectedID {
						got = f
					}
				}
				if got == nil {
					t.Fatalf("expected finding %s, got %+v", tt.expectedID, findings)
				}
				if got.Confidence != modules.ConfidenceHigh {
					t.Errorf("expected HIGH confidence, got %s", got.Confidence)
				}
				if strings.Contains(got.Evidence, "realKEY") || strings.Contains(got.Snippet, "realKEY") {
					t.Errorf("secret not redacted: evidence=%q snippet=%q", got.Evidence, got.Snippet)
				}
			} else {
				for _, f := range findings {
					if f.ID == "SEMAR-SEC-001" && f.Confidence == modules.ConfidenceHigh {
						t.Errorf("expected no high-confidence SEC-001 finding, got %+v", f)
					}
				}
			}
		})
	}
}

func TestShannonEntropy(t *testing.T) {
	if e := secrets.ShannonEntropy("aaaaaaaa"); e != 0 {
		t.Errorf("expected 0 entropy for uniform string, got %f", e)
	}
	if e := secrets.ShannonEntropy("sk-ant-api03-9aZ8xQ2vL"); e < 3.0 {
		t.Errorf("expected high entropy for random-ish string, got %f", e)
	}
}
