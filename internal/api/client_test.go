package api

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/oaki/baromio-probe/internal/identity"
)

func testIdentity(t *testing.T) *identity.Identity {
	t.Helper()
	id, err := identity.LoadOrGenerate(t.TempDir())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	id.ProbeID = "11111111-1111-1111-1111-111111111111"
	return id
}

func TestEnrollSendsTheExpectedBody(t *testing.T) {
	var gotBody EnrollRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(EnrollResponse{ProbeID: "new-probe-id"})
	}))
	defer srv.Close()

	client := New(srv.URL, testIdentity(t), "test")

	resp, err := client.Enroll(EnrollRequest{EnrollmentToken: "tok", PublicKey: "pub-key-b64"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.ProbeID != "new-probe-id" {
		t.Errorf("expected probe id from response, got %q", resp.ProbeID)
	}
	if gotBody.EnrollmentToken != "tok" {
		t.Errorf("expected enrollment_token to be sent, got %+v", gotBody)
	}
}

func TestEnrollReturnsTheServerErrorMessage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusGone)
		json.NewEncoder(w).Encode(map[string]string{"message": "This token expired before a Probe used it."})
	}))
	defer srv.Close()

	client := New(srv.URL, testIdentity(t), "test")

	_, err := client.Enroll(EnrollRequest{EnrollmentToken: "expired"})
	if err == nil {
		t.Fatal("expected an error")
	}
	if got := err.Error(); got == "" {
		t.Error("expected a non-empty error message")
	}
}

func TestReportSignsTheRequestVerifiably(t *testing.T) {
	id := testIdentity(t)
	var gotSignature, gotTimestamp, gotProbeID string
	var gotPath string
	var gotBody []byte

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSignature = r.Header.Get("X-Baromio-Signature")
		gotTimestamp = r.Header.Get("X-Baromio-Timestamp")
		gotProbeID = r.Header.Get("X-Baromio-Probe")
		gotPath = r.URL.Path
		gotBody = mustReadAll(r)

		json.NewEncoder(w).Encode(ReportResponse{Accepted: 1})
	}))
	defer srv.Close()

	client := New(srv.URL, id, "test")

	_, err := client.Report(ReportRequest{Results: []ReportResult{{ID: "r1", MonitorID: "m1", IsUp: true}}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if gotProbeID != id.ProbeID {
		t.Errorf("expected X-Baromio-Probe %q, got %q", id.ProbeID, gotProbeID)
	}

	bodyHash := sha256.Sum256(gotBody)
	signed := "v1\nPOST\n" + gotPath + "\n" + gotTimestamp + "\n" + hex.EncodeToString(bodyHash[:])

	sigBytes, err := base64.StdEncoding.DecodeString(gotSignature)
	if err != nil {
		t.Fatalf("signature is not valid base64: %v", err)
	}

	if !ed25519.Verify(id.PublicKey, []byte(signed), sigBytes) {
		t.Error("expected the signature to verify against the identity's public key and the documented signed-string format")
	}
}

func TestConfigSendsIfNoneMatchAndHandles304(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == `"5"` {
			w.Header().Set("ETag", `"5"`)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"5"`)
		json.NewEncoder(w).Encode(ConfigResponse{ConfigVersion: 5})
	}))
	defer srv.Close()

	client := New(srv.URL, testIdentity(t), "test")

	cfg, etag, notModified, err := client.Config(`"5"`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !notModified {
		t.Error("expected notModified=true on a matching ETag")
	}
	if cfg != nil {
		t.Error("expected a nil config on 304")
	}
	if etag != `"5"` {
		t.Errorf("expected ETag to be echoed back, got %q", etag)
	}
}

func TestConfigReturnsTheMonitorListOnChange(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"6"`)
		json.NewEncoder(w).Encode(ConfigResponse{ConfigVersion: 6})
	}))
	defer srv.Close()

	client := New(srv.URL, testIdentity(t), "test")

	cfg, _, notModified, err := client.Config(`"5"`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if notModified {
		t.Error("expected notModified=false when the version changed")
	}
	if cfg == nil || cfg.ConfigVersion != 6 {
		t.Errorf("expected config version 6, got %+v", cfg)
	}
}

func TestEveryRequestIdentifiesItselfAndAsksForJSON(t *testing.T) {
	var gotAgents, gotAccepts []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAgents = append(gotAgents, r.Header.Get("User-Agent"))
		gotAccepts = append(gotAccepts, r.Header.Get("Accept"))
		switch r.URL.Path {
		case "/api/v1/probe/enroll":
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(EnrollResponse{ProbeID: "new-probe-id"})
		case "/api/v1/probe/config":
			json.NewEncoder(w).Encode(ConfigResponse{ConfigVersion: 1})
		default:
			json.NewEncoder(w).Encode(ReportResponse{})
		}
	}))
	defer srv.Close()

	client := New(srv.URL, testIdentity(t), "1.2.3")

	if _, err := client.Enroll(EnrollRequest{EnrollmentToken: "tok"}); err != nil {
		t.Fatalf("enroll: unexpected error: %v", err)
	}
	if _, _, _, err := client.Config(""); err != nil {
		t.Fatalf("config: unexpected error: %v", err)
	}
	if _, err := client.Report(ReportRequest{}); err != nil {
		t.Fatalf("report: unexpected error: %v", err)
	}

	if len(gotAgents) != 3 {
		t.Fatalf("expected 3 requests, got %d", len(gotAgents))
	}
	for i, agent := range gotAgents {
		if agent != "Baromio-Probe/1.2.3" {
			t.Errorf("request %d: expected User-Agent Baromio-Probe/1.2.3, got %q", i, agent)
		}
		// Without it Laravel answers a failed validation with a 302 to the homepage.
		if gotAccepts[i] != "application/json" {
			t.Errorf("request %d: expected Accept application/json, got %q", i, gotAccepts[i])
		}
	}
}

func mustReadAll(r *http.Request) []byte {
	defer r.Body.Close()
	data, _ := io.ReadAll(r.Body)
	return data
}
