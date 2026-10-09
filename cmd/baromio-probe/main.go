// Command baromio-probe is a customer-installed agent that checks internal
// services unreachable from the public internet and reports results back to
// Baromio over an outbound-only connection (ADR-0053, ADR-0054). See
// docs/design-plans/2026-10-05-private-probe.md in the Baromio repo for the
// full protocol this implements.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/oaki/baromio-probe/internal/allowlist"
	"github.com/oaki/baromio-probe/internal/api"
	"github.com/oaki/baromio-probe/internal/buffer"
	httpcheck "github.com/oaki/baromio-probe/internal/check/http"
	"github.com/oaki/baromio-probe/internal/check/tcp"
	"github.com/oaki/baromio-probe/internal/config"
	"github.com/oaki/baromio-probe/internal/identity"
	"github.com/oaki/baromio-probe/internal/scheduler"
)

// Version is set at build time via -ldflags "-X main.Version=...".
var Version = "dev"

// reportInterval matches config/probe.php's report_interval_seconds on the
// Baromio side (ADR-0054 decision 2). It is also returned on enroll, but a
// restarted, already-enrolled Probe has no enroll call to read it from, so
// it is a constant here rather than persisted state.
const reportInterval = 60 * time.Second

// backlogDrainDelay paces the follow-up batches after an outage, well inside
// the report endpoint's 120 requests/minute throttle.
const backlogDrainDelay = 2 * time.Second

// configPollInterval is how often the Probe checks for a changed config,
// independent of the fixed report cadence.
const configPollInterval = 60 * time.Second

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	if err := run(logger); err != nil {
		logger.Error("baromio-probe exited", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	allow, err := allowlist.Parse(cfg.Allow)
	if err != nil {
		return fmt.Errorf("parsing BAROMIO_ALLOW: %w", err)
	}

	id, err := identity.LoadOrGenerate(cfg.DataDir)
	if err != nil {
		return fmt.Errorf("loading identity: %w", err)
	}

	client := api.New(cfg.URL, id, Version)

	if !id.IsEnrolled() {
		if cfg.EnrollToken == "" {
			return fmt.Errorf("not enrolled and BAROMIO_ENROLL_TOKEN is unset: provide a fresh Enrollment Token")
		}

		hostname, _ := os.Hostname()

		resp, err := client.Enroll(api.EnrollRequest{
			EnrollmentToken: cfg.EnrollToken,
			PublicKey:       id.PublicKeyBase64(),
			Hostname:        hostname,
			Version:         Version,
			Platform:        runtime.GOOS + "/" + runtime.GOARCH,
		})
		if err != nil {
			return fmt.Errorf("enrolling: %w", err)
		}

		id.ProbeID = resp.ProbeID
		if err := id.Save(cfg.DataDir); err != nil {
			return fmt.Errorf("saving identity after enrollment: %w", err)
		}

		logger.Info("enrolled", "probe_id", id.ProbeID, "location", resp.Location.Name)
	}

	buf, err := buffer.Open(cfg.DataDir)
	if err != nil {
		return fmt.Errorf("opening result buffer: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	state := &probeState{logger: logger, buf: buf, allow: allow}

	sched := scheduler.New(state.check)
	defer sched.Stop()

	go pollConfig(ctx, logger, client, sched, state)
	go reportLoop(ctx, logger, client, buf, state)

	<-ctx.Done()
	logger.Info("shutting down")

	return nil
}

// probeState holds the mutable, shared state the scheduler's check
// callback and the config poller both touch: the allowlist (fixed) and the
// set of monitor ids currently refused by it (changes as config changes).
type probeState struct {
	logger *slog.Logger
	buf    *buffer.Buffer
	allow  *allowlist.Allowlist

	blockedMu sync.Mutex
	blocked   []string
}

func pollConfig(ctx context.Context, logger *slog.Logger, client *api.Client, sched *scheduler.Scheduler, state *probeState) {
	var etag string

	poll := func() {
		cfg, newEtag, notModified, err := client.Config(etag)
		if err != nil {
			logger.Warn("config poll failed", "error", err)
			return
		}
		if notModified {
			return
		}
		etag = newEtag

		var monitors []scheduler.MonitorConfig
		var blocked []string

		for _, m := range cfg.Monitors {
			if !targetAllowed(state.allow, m) {
				blocked = append(blocked, m.ID)
				continue
			}

			monitors = append(monitors, scheduler.MonitorConfig{
				ID: m.ID, Type: m.Type,
				IntervalSeconds: m.IntervalSeconds, TimeoutSeconds: m.TimeoutSeconds,
				URL: m.URL, Headers: m.Headers,
				Keyword: m.Keyword, KeywordType: m.KeywordType,
				Host: m.Host, Port: m.Port,
			})
		}

		state.setBlocked(blocked)
		sched.SetMonitors(ctx, monitors)

		logger.Info("config updated", "config_version", cfg.ConfigVersion, "monitors", len(monitors), "blocked", len(blocked))
	}

	poll()

	ticker := time.NewTicker(configPollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			poll()
		}
	}
}

func targetAllowed(allow *allowlist.Allowlist, m api.ConfigMonitor) bool {
	if m.Type == "tcp" {
		return allow.AllowsTarget(m.Host, strconv.Itoa(m.Port), lookupHost)
	}

	host, port, err := allowlist.TargetFromURL(m.URL)
	if err != nil {
		return false
	}

	return allow.AllowsTarget(host, port, lookupHost)
}

// lookupHost resolves with a short timeout so one slow name cannot stall the
// whole config update.
func lookupHost(host string) ([]net.IP, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	return net.DefaultResolver.LookupIP(ctx, "ip", host)
}

func (s *probeState) setBlocked(ids []string) {
	// Stored for reportLoop to read; a simple field write is fine since the
	// scheduler/report goroutines never write it concurrently, only read.
	s.blockedMu.Lock()
	s.blocked = ids
	s.blockedMu.Unlock()
}

func (s *probeState) check(ctx context.Context, cfg scheduler.MonitorConfig) bool {
	entry := buffer.Entry{
		ID:        buffer.NewID(),
		MonitorID: cfg.ID,
		CheckedAt: time.Now().Unix(),
	}

	switch cfg.Type {
	case "tcp":
		result := tcp.Check(ctx, cfg.Host, cfg.Port, s.allow)
		entry.IsUp = result.IsUp
		entry.TimingsMs = map[string]int{"total": result.ResponseTimeMs}
		if result.ErrorCode != 0 {
			code := int(result.ErrorCode)
			entry.ErrorCode = &code
		}
	default:
		result := httpcheck.Check(ctx, httpcheck.Request{
			URL: cfg.URL, Keyword: cfg.Type == "keyword", KeywordValue: cfg.Keyword,
			KeywordType: cfg.KeywordType, TimeoutSeconds: cfg.TimeoutSeconds, Headers: cfg.Headers,
			UserAgent: "Baromio-Probe/" + Version,
		}, s.allow)

		entry.IsUp = result.IsUp
		entry.Method = result.Method
		entry.FallbackUsed = result.FallbackUsed
		entry.KeywordFound = result.KeywordFound
		entry.TimingsMs = map[string]int{"total": result.ResponseTimeMs}

		if result.StatusCode != 0 {
			code := result.StatusCode
			entry.StatusCode = &code
		}
		if result.ErrorCode != 0 {
			code := int(result.ErrorCode)
			entry.ErrorCode = &code
		}
		if result.TLS != nil {
			entry.TLS = &buffer.TLSEntry{ExpiresAt: result.TLS.ExpiresAtUnix, Issuer: result.TLS.Issuer}
		}
	}

	if _, err := s.buf.Append(entry); err != nil {
		s.logger.Warn("buffering result failed", "monitor_id", cfg.ID, "error", err)
	}

	return entry.IsUp
}

func reportLoop(ctx context.Context, logger *slog.Logger, client *api.Client, buf *buffer.Buffer, state *probeState) {
	backoff := api.NewBackoff(5*time.Second, 5*time.Minute)

	// sendOnce posts the oldest batch of buffered results. ok is false on a
	// failure; more is true when a backlog is still waiting behind the batch.
	sendOnce := func() (ok, more bool) {
		entries, more, err := buf.Batch(api.MaxResultsPerReport)
		if err != nil {
			logger.Warn("reading buffer failed", "error", err)
			return false, false
		}

		ids := make(map[string]bool, len(entries))
		for _, e := range entries {
			ids[e.ID] = true
		}

		state.blockedMu.Lock()
		blocked := state.blocked
		state.blockedMu.Unlock()

		resp, err := client.Report(api.ReportRequest{
			Version: Version, Platform: runtime.GOOS + "/" + runtime.GOARCH,
			SentAt: time.Now().Unix(), Results: entries, BlockedMonitorIDs: blocked,
		})
		if err != nil {
			logger.Warn("report failed, will retry", "error", err)
			return false, false
		}

		if err := buf.Remove(ids); err != nil {
			logger.Warn("clearing reported results failed", "error", err)
		}

		logger.Info("reported", "accepted", resp.Accepted, "ignored", resp.Ignored, "backlog", more)
		return true, more
	}

	timer := time.NewTimer(reportInterval)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			ok, more := sendOnce()
			switch {
			case !ok:
				timer.Reset(backoff.Next())
			case more:
				backoff.Reset()
				timer.Reset(backlogDrainDelay)
			default:
				backoff.Reset()
				timer.Reset(reportInterval)
			}
		}
	}
}
