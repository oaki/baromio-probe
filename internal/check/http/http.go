// Package http checks an http or keyword monitor, matching
// App\Services\Monitors\HttpMonitorChecker's semantics exactly so a Private
// Location monitor's incidents read like a fleet monitor's
// (docs/design-plans/2026-10-05-private-probe.md §7.2).
package http

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/oaki/baromio-probe/internal/allowlist"
	"github.com/oaki/baromio-probe/internal/errmap"
)

// Request is one http/keyword check to run.
type Request struct {
	URL            string
	Keyword        bool // true for a keyword-type monitor, false for plain http
	KeywordValue   string
	KeywordType    string // "exists" or "not_exists"
	TimeoutSeconds int
	Headers        map[string]string
	UserAgent      string // sent unless Headers sets its own User-Agent
}

// TLSInfo is the leaf certificate's expiry and issuer, read from the HTTPS
// handshake - nil for a plain HTTP target.
type TLSInfo struct {
	ExpiresAtUnix int64
	Issuer        string
}

// Result is the check verdict, mirroring CheckResult on the Baromio side.
type Result struct {
	IsUp           bool
	StatusCode     int
	ErrorCode      errmap.Code
	ResponseTimeMs int
	Method         string
	FallbackUsed   bool
	KeywordFound   *bool
	TLS            *TLSInfo
}

// Check runs one http/keyword check. Every redirect hop is resolved and
// checked against allow before it is followed; a hop outside it fails the
// check with RefusedCheck rather than being silently skipped (ADR-0028).
func Check(ctx context.Context, req Request, allow *allowlist.Allowlist) Result {
	timeout := time.Duration(req.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 15 * time.Second
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var tlsInfo *TLSInfo
	client := &http.Client{
		CheckRedirect: func(hopReq *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			if !hostAllowed(ctx, allow, hopReq.URL.Hostname(), hopReq.URL.Port()) {
				return errRefused
			}
			return nil
		},
		Transport: &http.Transport{
			DialContext: (&net.Dialer{Timeout: timeout}).DialContext,
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				conn, err := tls.Dial(network, addr, &tls.Config{ServerName: hostOnly(addr)})
				if err != nil {
					return nil, err
				}
				if state := conn.ConnectionState(); len(state.PeerCertificates) > 0 {
					leaf := state.PeerCertificates[0]
					tlsInfo = &TLSInfo{ExpiresAtUnix: leaf.NotAfter.Unix(), Issuer: leaf.Issuer.CommonName}
				}
				return conn, nil
			},
		},
	}

	start := time.Now()

	if req.Keyword {
		resp, err := doRequest(ctx, client, http.MethodGet, req)
		elapsed := time.Since(start)
		if err != nil {
			return errorResult(err)
		}
		defer resp.Body.Close()
		result := buildResult(req, resp, elapsed, tlsInfo)
		result.Method = http.MethodGet
		return result
	}

	// Plain http: HEAD first, no redirects followed; GET fallback on 405.
	noRedirectClient := *client
	noRedirectClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}

	resp, err := doRequest(ctx, &noRedirectClient, http.MethodHead, req)
	if err != nil {
		return errorResult(err)
	}

	method := http.MethodHead
	fallbackUsed := false

	if resp.StatusCode == http.StatusMethodNotAllowed {
		resp.Body.Close()
		resp, err = doRequest(ctx, client, http.MethodGet, req)
		if err != nil {
			return errorResult(err)
		}
		method = http.MethodGet
		fallbackUsed = true
	}
	defer resp.Body.Close()

	elapsed := time.Since(start)

	result := buildResult(req, resp, elapsed, tlsInfo)
	result.Method = method
	result.FallbackUsed = fallbackUsed

	return result
}

func doRequest(ctx context.Context, client *http.Client, method string, req Request) (*http.Response, error) {
	httpReq, err := http.NewRequestWithContext(ctx, method, req.URL, nil)
	if err != nil {
		return nil, err
	}

	if req.UserAgent != "" {
		httpReq.Header.Set("User-Agent", req.UserAgent)
	}

	for name, value := range req.Headers {
		httpReq.Header.Set(name, value)
	}

	return client.Do(httpReq)
}

func buildResult(req Request, resp *http.Response, elapsed time.Duration, tlsInfo *TLSInfo) Result {
	isUp := resp.StatusCode < 400
	var errorCode errmap.Code
	if !isUp {
		errorCode = errmap.HTTPError
	}

	var keywordFound *bool

	if isUp && req.Keyword && req.KeywordValue != "" {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MB cap, never stored
		found := strings.Contains(strings.ToLower(string(body)), strings.ToLower(req.KeywordValue))
		keywordFound = &found

		switch req.KeywordType {
		case "exists":
			if !found {
				isUp = false
				errorCode = errmap.MissingKeyword
			}
		case "not_exists":
			if found {
				isUp = false
				errorCode = errmap.FoundKeyword
			}
		}
	}

	return Result{
		IsUp:           isUp,
		StatusCode:     resp.StatusCode,
		ErrorCode:      errorCode,
		ResponseTimeMs: int(elapsed.Milliseconds()),
		KeywordFound:   keywordFound,
		TLS:            tlsInfo,
	}
}

func errorResult(err error) Result {
	if err == errRefused || strings.Contains(err.Error(), "refused check") {
		return Result{IsUp: false, ErrorCode: errmap.RefusedCheck}
	}

	return Result{IsUp: false, ErrorCode: errmap.FromError(err)}
}

var errRefused = &refusedError{}

type refusedError struct{}

func (*refusedError) Error() string { return "refused check: target outside the Probe allowlist" }

func hostAllowed(ctx context.Context, allow *allowlist.Allowlist, host, port string) bool {
	if allow == nil {
		return true
	}

	if allow.AllowsHostPort(host, port) {
		return true
	}

	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return false
	}

	return allow.AllowsResolvedIPs(host, ips, port)
}

func hostOnly(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}

	return host
}
