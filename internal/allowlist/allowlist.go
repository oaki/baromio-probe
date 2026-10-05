// Package allowlist checks a monitor's target - and every redirect hop -
// against the operator-configured BAROMIO_ALLOW ranges. A target outside it
// is never checked at all, the ADR-0028 split
// (docs/design-plans/2026-10-05-private-probe.md §7.2).
package allowlist

import (
	"net"
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
