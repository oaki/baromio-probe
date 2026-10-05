package http

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/oaki/baromio-probe/internal/allowlist"
)

type contractCase struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Response struct {
		Status int    `json:"status"`
		Body   string `json:"body"`
	} `json:"response"`
	Keyword     string `json:"keyword"`
	KeywordType string `json:"keyword_type"`
	Expect      struct {
		IsUp      bool `json:"is_up"`
		ErrorCode *int `json:"error_code"`
	} `json:"expect"`
}

type contractFile struct {
	Cases []contractCase `json:"cases"`
}

// TestCheckCasesContract runs contract/check-cases.json - fixtures shared
// with Baromio's own HttpMonitorChecker::buildResult tests, so the two
// implementations cannot drift silently (docs/design-plans/2026-10-05-private-probe.md §7.2).
func TestCheckCasesContract(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "contract", "check-cases.json"))
	if err != nil {
		t.Fatalf("reading contract file: %v", err)
	}

	var file contractFile
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatalf("parsing contract file: %v", err)
	}

	if len(file.Cases) == 0 {
		t.Fatal("expected at least one contract case")
	}

	allow, err := allowlist.Parse("127.0.0.0/8")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, tc := range file.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.Response.Status)
				w.Write([]byte(tc.Response.Body))
			}))
			defer srv.Close()

			result := Check(context.Background(), Request{
				URL:            srv.URL,
				Keyword:        tc.Type == "keyword",
				KeywordValue:   tc.Keyword,
				KeywordType:    tc.KeywordType,
				TimeoutSeconds: 5,
			}, allow)

			if result.IsUp != tc.Expect.IsUp {
				t.Errorf("expected is_up=%v, got %v", tc.Expect.IsUp, result.IsUp)
			}

			gotCode := int(result.ErrorCode)
			if tc.Expect.ErrorCode == nil {
				if gotCode != 0 {
					t.Errorf("expected no error code, got %d", gotCode)
				}
			} else if gotCode != *tc.Expect.ErrorCode {
				t.Errorf("expected error_code=%d, got %d", *tc.Expect.ErrorCode, gotCode)
			}
		})
	}
}
