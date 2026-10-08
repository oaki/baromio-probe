// Package api is the signed HTTP client for Baromio's Probe-facing endpoints
// (ADR-0054 §5): enroll once, then poll config and post report forever.
package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/oaki/baromio-probe/internal/identity"
)

// Client talks to Baromio's Probe API.
type Client struct {
	baseURL    string
	httpClient *http.Client
	identity   *identity.Identity
	userAgent  string
}

// New builds a Client against baseURL (e.g. https://baromio.io) using id for
// request signing on every endpoint except Enroll. Every request carries
// "User-Agent: Baromio-Probe/<version>" so the Cloudflare rule in front of
// Baromio can recognise Probe traffic instead of Go's default agent.
func New(baseURL string, id *identity.Identity, version string) *Client {
	return &Client{
		baseURL:    baseURL,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		identity:   id,
		userAgent:  "Baromio-Probe/" + version,
	}
}

// EnrollRequest is the one-time enrollment body.
type EnrollRequest struct {
	EnrollmentToken string `json:"enrollment_token"`
	PublicKey       string `json:"public_key"`
	Hostname        string `json:"hostname,omitempty"`
	Version         string `json:"version,omitempty"`
	Platform        string `json:"platform,omitempty"`
}

// EnrollResponse is what Baromio returns on a successful enrollment.
type EnrollResponse struct {
	ProbeID  string `json:"probe_id"`
	Location struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"location"`
	ConfigVersion         int   `json:"config_version"`
	ReportIntervalSeconds int   `json:"report_interval_seconds"`
	ServerTime            int64 `json:"server_time"`
}

// Enroll redeems a one-time Enrollment Token. Unsigned - there is no Probe
// identity on the server yet for this call to sign as.
func (c *Client) Enroll(req EnrollRequest) (*EnrollResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("encoding enroll request: %w", err)
	}

	httpReq, err := c.newRequest(http.MethodPost, "/api/v1/probe/enroll", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("enroll request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusCreated {
		return nil, apiError(resp.StatusCode, respBody)
	}

	var out EnrollResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, fmt.Errorf("decoding enroll response: %w", err)
	}

	return &out, nil
}

// ReportResult is one buffered check result sent in a report.
type ReportResult struct {
	ID           string         `json:"id"`
	MonitorID    string         `json:"monitor_id"`
	CheckedAt    int64          `json:"checked_at"`
	IsUp         bool           `json:"is_up"`
	StatusCode   *int           `json:"status_code,omitempty"`
	ErrorCode    *int           `json:"error_code,omitempty"`
	Method       string         `json:"method,omitempty"`
	FallbackUsed bool           `json:"fallback_used,omitempty"`
	TimingsMs    map[string]int `json:"timings_ms,omitempty"`
	TLS          *struct {
		ExpiresAt int64  `json:"expires_at,omitempty"`
		Issuer    string `json:"issuer,omitempty"`
	} `json:"tls,omitempty"`
	KeywordFound *bool `json:"keyword_found,omitempty"`
}

// ReportRequest is the body of POST /api/v1/probe/report.
type ReportRequest struct {
	Version           string         `json:"version,omitempty"`
	Platform          string         `json:"platform,omitempty"`
	SentAt            int64          `json:"sent_at,omitempty"`
	DroppedResults    int            `json:"dropped_results,omitempty"`
	Results           []ReportResult `json:"results"`
	BlockedMonitorIDs []string       `json:"blocked_monitor_ids,omitempty"`
}

// ReportResponse is what Baromio returns on a report.
type ReportResponse struct {
	ConfigVersion int   `json:"config_version"`
	ServerTime    int64 `json:"server_time"`
	Accepted      int   `json:"accepted"`
	Ignored       int   `json:"ignored"`
	Update        any   `json:"update"`
}

// Report posts buffered results, signed with the Probe's identity.
func (c *Client) Report(req ReportRequest) (*ReportResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("encoding report request: %w", err)
	}

	resp, respBody, err := c.doSigned(http.MethodPost, "/api/v1/probe/report", body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, apiError(resp.StatusCode, respBody)
	}

	var out ReportResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, fmt.Errorf("decoding report response: %w", err)
	}

	return &out, nil
}

// ConfigMonitor is one monitor entry in a Config response.
type ConfigMonitor struct {
	ID              string            `json:"id"`
	Type            string            `json:"type"`
	IntervalSeconds int               `json:"interval_seconds"`
	TimeoutSeconds  int               `json:"timeout_seconds"`
	URL             string            `json:"url,omitempty"`
	Headers         map[string]string `json:"headers,omitempty"`
	Keyword         string            `json:"keyword,omitempty"`
	KeywordType     string            `json:"keyword_type,omitempty"`
	Host            string            `json:"host,omitempty"`
	Port            int               `json:"port,omitempty"`
}

// ConfigResponse is the http/keyword/tcp-only monitor list for this Probe's
// Private Location.
type ConfigResponse struct {
	ConfigVersion int             `json:"config_version"`
	Monitors      []ConfigMonitor `json:"monitors"`
}

// Config polls the current config. etag is the previously-seen ETag (empty
// on first call); notModified is true on a 304, in which case cfg is nil and
// the Probe should keep its cached config.
func (c *Client) Config(etag string) (cfg *ConfigResponse, newEtag string, notModified bool, err error) {
	httpReq, err := c.newRequest(http.MethodGet, "/api/v1/probe/config", nil)
	if err != nil {
		return nil, "", false, err
	}

	if etag != "" {
		httpReq.Header.Set("If-None-Match", etag)
	}

	c.sign(httpReq, nil)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, "", false, fmt.Errorf("config request failed: %w", err)
	}
	defer resp.Body.Close()

	newEtag = resp.Header.Get("ETag")

	if resp.StatusCode == http.StatusNotModified {
		return nil, newEtag, true, nil
	}

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, "", false, apiError(resp.StatusCode, body)
	}

	var out ConfigResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, "", false, fmt.Errorf("decoding config response: %w", err)
	}

	return &out, newEtag, false, nil
}

func (c *Client) doSigned(method, path string, body []byte) (*http.Response, []byte, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}

	httpReq, err := c.newRequest(method, path, reader)
	if err != nil {
		return nil, nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	c.sign(httpReq, body)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, nil, fmt.Errorf("request to %s failed: %w", path, err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	return resp, respBody, nil
}

// newRequest builds a request to path on baseURL carrying the Probe's
// User-Agent and asking for JSON, so a failed validation comes back as a 422
// body instead of Laravel's redirect to the homepage.
func (c *Client) newRequest(method, path string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequest(method, c.baseURL+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Accept", "application/json")

	return req, nil
}

// sign attaches the X-Baromio-Probe/Timestamp/Signature headers, matching
// App\Services\Probes\ProbeSignatureVerifier::signedString exactly: "v1\n" +
// METHOD + "\n" + path (no query string) + "\n" + timestamp + "\n" +
// hex(sha256(body)).
func (c *Client) sign(req *http.Request, body []byte) {
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	bodyHash := sha256.Sum256(body)

	signed := "v1\n" + req.Method + "\n" + req.URL.Path + "\n" + timestamp + "\n" + hex.EncodeToString(bodyHash[:])

	req.Header.Set("X-Baromio-Probe", c.identity.ProbeID)
	req.Header.Set("X-Baromio-Timestamp", timestamp)
	req.Header.Set("X-Baromio-Signature", c.identity.Sign([]byte(signed)))
}

func apiError(status int, body []byte) error {
	var parsed struct {
		Message string `json:"message"`
	}
	_ = json.Unmarshal(body, &parsed)

	if parsed.Message != "" {
		return fmt.Errorf("baromio API returned %d: %s", status, parsed.Message)
	}

	return fmt.Errorf("baromio API returned %d", status)
}
