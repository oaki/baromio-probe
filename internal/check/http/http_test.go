package http

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/oaki/baromio-probe/internal/allowlist"
)

func loopbackAllowlist(t *testing.T) *allowlist.Allowlist {
	t.Helper()
	a, err := allowlist.Parse("127.0.0.0/8")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return a
}

func TestCheckHttpTypeUsesHead(t *testing.T) {
	var sawMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawMethod = r.Method
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	result := Check(context.Background(), Request{URL: srv.URL, TimeoutSeconds: 5}, loopbackAllowlist(t))

	if sawMethod != http.MethodHead {
		t.Errorf("expected a HEAD request, server saw %q", sawMethod)
	}
	if !result.IsUp {
		t.Errorf("expected IsUp=true, got result %+v", result)
	}
}

func TestCheckFallsBackToGetOn405(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	result := Check(context.Background(), Request{URL: srv.URL, TimeoutSeconds: 5}, loopbackAllowlist(t))

	if calls != 2 {
		t.Errorf("expected a HEAD then a GET, got %d requests", calls)
	}
	if !result.IsUp {
		t.Errorf("expected IsUp=true after GET fallback, got %+v", result)
	}
}

func TestCheckHttpStatusAboveThreshholdIsDown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	result := Check(context.Background(), Request{URL: srv.URL, TimeoutSeconds: 5}, loopbackAllowlist(t))

	if result.IsUp {
		t.Error("expected IsUp=false for a 500 response")
	}
	if result.ErrorCode == 0 {
		t.Error("expected a non-zero HttpError error code")
	}
}

func TestCheckKeywordExistsPasses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html>Welcome to the site</html>"))
	}))
	defer srv.Close()

	result := Check(context.Background(), Request{
		URL: srv.URL, Keyword: true, KeywordValue: "Welcome", KeywordType: "exists", TimeoutSeconds: 5,
	}, loopbackAllowlist(t))

	if !result.IsUp {
		t.Errorf("expected IsUp=true when the keyword is present, got %+v", result)
	}
}

func TestCheckKeywordExistsFailsWhenMissing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html>nothing here</html>"))
	}))
	defer srv.Close()

	result := Check(context.Background(), Request{
		URL: srv.URL, Keyword: true, KeywordValue: "Welcome", KeywordType: "exists", TimeoutSeconds: 5,
	}, loopbackAllowlist(t))

	if result.IsUp {
		t.Error("expected IsUp=false when the required keyword is missing")
	}
	if result.ErrorCode != 3 { // MissingKeyword
		t.Errorf("expected MissingKeyword(3), got %d", result.ErrorCode)
	}
}

func TestCheckKeywordNotExistsFailsWhenPresent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html>under maintenance</html>"))
	}))
	defer srv.Close()

	result := Check(context.Background(), Request{
		URL: srv.URL, Keyword: true, KeywordValue: "maintenance", KeywordType: "not_exists", TimeoutSeconds: 5,
	}, loopbackAllowlist(t))

	if result.IsUp {
		t.Error("expected IsUp=false when the forbidden keyword is present")
	}
	if result.ErrorCode != 4 { // FoundKeyword
		t.Errorf("expected FoundKeyword(4), got %d", result.ErrorCode)
	}
}

func TestCheckKeywordFollowsRedirectsWithinAllowlist(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("final destination"))
	}))
	defer target.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer redirector.Close()

	result := Check(context.Background(), Request{
		URL: redirector.URL, Keyword: true, KeywordValue: "final", KeywordType: "exists", TimeoutSeconds: 5,
	}, loopbackAllowlist(t))

	if !result.IsUp {
		t.Errorf("expected the redirect to be followed and succeed, got %+v", result)
	}
}

func TestCheckRefusesARedirectOutsideTheAllowlist(t *testing.T) {
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://8.8.8.8/", http.StatusFound)
	}))
	defer redirector.Close()

	result := Check(context.Background(), Request{
		URL: redirector.URL, Keyword: true, KeywordValue: "x", KeywordType: "exists", TimeoutSeconds: 5,
	}, loopbackAllowlist(t))

	if result.IsUp {
		t.Error("expected the check to fail: redirect target is outside the allowlist")
	}
	if result.ErrorCode != 13 { // RefusedCheck
		t.Errorf("expected RefusedCheck(13), got %d", result.ErrorCode)
	}
}
