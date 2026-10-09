// Package allowlist checks a monitor's target - and every redirect hop -
// against the operator-configured BAROMIO_ALLOW ranges. A target outside it
// is never checked at all, the ADR-0028 split
// (docs/design-plans/2026-10-05-private-probe.md §7.2).
package allowlist

import (
	"context"
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// Rule is one parsed entry from BAROMIO_ALLOW: a CIDR range, a bare
// hostname, or a host:port pair.
type Rule struct {
	cidr *net.IPNet
	host string
	port string // empty means "any port"
}

// Allowlist is the full set of rules a check target must match at least one
// of.
type Allowlist struct {
	rules []Rule
}

// Parse builds an Allowlist from a comma-separated BAROMIO_ALLOW value.
func Parse(raw string) (*Allowlist, error) {
	var rules []Rule

	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		if _, cidr, err := net.ParseCIDR(entry); err == nil {
			rules = append(rules, Rule{cidr: cidr})
			continue
		}

		host, port, err := net.SplitHostPort(entry)
		if err == nil {
			rules = append(rules, Rule{host: strings.ToLower(host), port: port})
			continue
		}

		rules = append(rules, Rule{host: strings.ToLower(entry)})
	}

	return &Allowlist{rules: rules}, nil
}

// AllowsHostPort reports whether host (a hostname or a literal IP) and port
// match at least one rule. port may be empty when the caller has no port to
// check (e.g. a bare host rule for an HTTP target).
func (a *Allowlist) AllowsHostPort(host, port string) bool {
	host = strings.ToLower(host)
	ip := net.ParseIP(host)

	for _, rule := range a.rules {
		if rule.cidr != nil {
			if ip != nil && rule.cidr.Contains(ip) {
				return true
			}
			continue
		}

		if rule.host != host {
			continue
		}

		if rule.port == "" || rule.port == port {
			return true
		}
	}

	return false
}

// AllowsResolvedIPs reports whether every one of ips is covered by at least
// one CIDR rule, or whether host itself matches a bare host-based rule. Every
// resolved IP must be checked, not just the first, since DNS can return
// several and a redirect can follow any of them.
func (a *Allowlist) AllowsResolvedIPs(host string, ips []net.IP, port string) bool {
	if a.AllowsHostPort(host, port) {
		return true
	}

	if len(ips) == 0 {
		return false
	}

	for _, ip := range ips {
		if !a.allowsIP(ip) {
			return false
		}
	}

	return true
}

// AllowsTarget is the check to use before a monitor is run: a host or literal
// IP that the allowlist names is allowed outright, and any other hostname is
// resolved with lookup and allowed only when every address it resolves to
// falls inside an allowed range. A hostname that does not resolve is refused.
func (a *Allowlist) AllowsTarget(host, port string, lookup func(string) ([]net.IP, error)) bool {
	if a.AllowsHostPort(host, port) {
		return true
	}

	if net.ParseIP(host) != nil {
		return false
	}

	ips, err := lookup(host)
	if err != nil {
		return false
	}

	return a.AllowsResolvedIPs(host, ips, port)
}

func (a *Allowlist) allowsIP(ip net.IP) bool {
	for _, rule := range a.rules {
		if rule.cidr != nil && rule.cidr.Contains(ip) {
			return true
		}
	}

	return false
}

// SplitHostPortOrDefault splits a host:port pair, defaulting port to
// defaultPort when hostPort carries none.
func SplitHostPortOrDefault(hostPort string, defaultPort int) (host, port string) {
	h, p, err := net.SplitHostPort(hostPort)
	if err != nil {
		return hostPort, strconv.Itoa(defaultPort)
	}

	return h, p
}

// ErrRefused is wrapped by every refusal so a caller can tell "the allowlist
// said no" from an ordinary network failure. Its text carries "refused check",
// which the http check maps to the RefusedCheck error code.
var ErrRefused = errors.New("refused check: target outside the Probe allowlist")

// TargetFromURL returns the host and port a URL will actually connect to, with
// the scheme's default port filled in. It uses the standard parser, so
// "http://10.0.0.1:80@169.254.169.254/" is read as host 169.254.169.254, and it
// refuses anything that is not plain http(s) or that carries userinfo, since a
// monitor URL never needs credentials in it.
func TargetFromURL(raw string) (host, port string, err error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", "", err
	}

	if u.Scheme != "http" && u.Scheme != "https" {
		return "", "", errors.New("only http and https URLs can be checked")
	}

	if u.User != nil {
		return "", "", errors.New("a URL with credentials in it cannot be checked")
	}

	host = u.Hostname()
	if host == "" {
		return "", "", errors.New("the URL has no host")
	}

	port = u.Port()
	if port == "" {
		port = "80"
		if u.Scheme == "https" {
			port = "443"
		}
	}

	return host, port, nil
}

// DialContext returns a dial function that enforces the allowlist on the
// address it really connects to. A host or literal IP the allowlist names is
// dialed as asked. Any other name is resolved here, refused unless every
// address falls in an allowed range, and the connection goes to one of those
// vetted addresses, so a name that resolves differently a moment later (DNS
// rebinding) cannot lead the Probe somewhere else.
func (a *Allowlist) DialContext(d *net.Dialer, lookup func(ctx context.Context, host string) ([]net.IP, error)) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}

		if a.AllowsHostPort(host, port) {
			return d.DialContext(ctx, network, addr)
		}

		if net.ParseIP(host) != nil {
			return nil, ErrRefused
		}

		ips, err := lookup(ctx, host)
		if err != nil {
			return nil, err
		}

		if len(ips) == 0 {
			return nil, ErrRefused
		}

		for _, ip := range ips {
			if !a.allowsIP(ip) {
				return nil, ErrRefused
			}
		}

		var lastErr error
		for _, ip := range ips {
			conn, err := d.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if err == nil {
				return conn, nil
			}
			lastErr = err
		}

		return nil, lastErr
	}
}

// SystemLookup resolves host with the system resolver, for use as DialContext's lookup.
func SystemLookup(ctx context.Context, host string) ([]net.IP, error) {
	return net.DefaultResolver.LookupIP(ctx, "ip", host)
}
