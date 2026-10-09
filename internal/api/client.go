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

	"github.com/oaki/baromio-probe/internal/buffer"
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

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))

	if resp.StatusCode != http.StatusCreated {
		return nil, apiError(resp.StatusCode, respBody)
	}

	var out EnrollResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, fmt.Errorf("decoding enroll response: %w", err)
	}

	return &out, nil
}

// MaxResultsPerReport mirrors ReportProbeResultsRequest::MAX_RESULTS on the
// Baromio side: a report carrying more is refused with 413 (§5.3).
const MaxResultsPerReport = 500

// maxResponseBytes bounds any response read from Baromio, so a misbehaving
// server or a proxy in between cannot make the Probe buffer without limit.
const maxResponseBytes = 8 << 20

// ReportRequest is the body of POST /api/v1/probe/report. Results are the
// buffered entries as stored, so nothing a check recorded (TLS included) is
// lost in a translation step on the way out.
type ReportRequest struct {
	Version           string         `json:"version,omitempty"`
	Platform          string         `json:"platform,omitempty"`
	SentAt            int64          `json:"sent_at,omitempty"`
	DroppedResults    int            `json:"dropped_results,omitempty"`
	Results           []buffer.Entry `json:"results"`
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
	if req.Results == nil {
		req.Results = []buffer.Entry{}
	}

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
	ID              string  `json:"id"`
	Type            string  `json:"type"`
	IntervalSeconds int     `json:"interval_seconds"`
	TimeoutSeconds  int     `json:"timeout_seconds"`
	URL             string  `json:"url,omitempty"`
	Headers         Headers `json:"headers,omitempty"`
	Keyword         string  `json:"keyword,omitempty"`
	KeywordType     string  `json:"keyword_type,omitempty"`
	Host            string  `json:"host,omitempty"`
	Port            int     `json:"port,omitempty"`
}

// Headers is a monitor's custom request headers, keyed by name. Baromio sends
// them the way it stores them (§5.4): a list of {"name", "value"} objects,
// an empty list when there are none - not a JSON object.
type Headers map[string]string

// UnmarshalJSON decodes Baromio's header list into a name -> value map.
func (h *Headers) UnmarshalJSON(data []byte) error {
	var list []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	}
	if err := json.Unmarshal(data, &list); err != nil {
		return fmt.Errorf("headers: expected a list of {name, value} objects: %w", err)
	}

	decoded := make(Headers, len(list))
	for _, header := range list {
		decoded[header.Name] = header.Value
	}
	*h = decoded

	return nil
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

	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))

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

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))

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
