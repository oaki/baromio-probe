package allowlist

import (
	"net"
	"testing"
)

func TestAllowsHostPortWithinCidr(t *testing.T) {
	a, err := Parse("10.0.0.0/8,172.16.0.0/12,192.168.0.0/16")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !a.AllowsHostPort("10.0.0.5", "") {
		t.Error("expected 10.0.0.5 to be allowed under 10.0.0.0/8")
	}

	if a.AllowsHostPort("8.8.8.8", "") {
		t.Error("expected 8.8.8.8 to be refused: outside every CIDR range")
	}
}

func TestAllowsBareHost(t *testing.T) {
	a, err := Parse("db.internal.example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !a.AllowsHostPort("db.internal.example.com", "5432") {
		t.Error("expected the bare host rule to allow any port")
	}

	if a.AllowsHostPort("other.internal.example.com", "5432") {
		t.Error("expected a different host to be refused")
	}
}

func TestAllowsBareHostIsCaseInsensitive(t *testing.T) {
	a, err := Parse("DB.Internal.Example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !a.AllowsHostPort("db.internal.example.com", "") {
		t.Error("expected the host match to be case-insensitive")
	}
}

func TestAllowsHostPortPair(t *testing.T) {
	a, err := Parse("db.internal.example.com:5432")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !a.AllowsHostPort("db.internal.example.com", "5432") {
		t.Error("expected the exact host:port pair to be allowed")
	}

	if a.AllowsHostPort("db.internal.example.com", "5433") {
		t.Error("expected a different port on the same host to be refused")
	}
}

func TestAllowsResolvedIpsRequiresEveryIpToMatch(t *testing.T) {
	a, err := Parse("10.0.0.0/8")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ips := []net.IP{net.ParseIP("10.0.0.5"), net.ParseIP("8.8.8.8")}

	if a.AllowsResolvedIPs("example.internal", ips, "") {
		t.Error("expected refusal: one of the resolved IPs falls outside every CIDR range")
	}
}

func TestAllowsResolvedIpsAllowsWhenEveryIpMatches(t *testing.T) {
	a, err := Parse("10.0.0.0/8")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ips := []net.IP{net.ParseIP("10.0.0.5"), net.ParseIP("10.1.2.3")}

	if !a.AllowsResolvedIPs("example.internal", ips, "") {
		t.Error("expected every resolved IP within the CIDR range to be allowed")
	}
}

func TestSplitHostPortOrDefault(t *testing.T) {
	host, port := SplitHostPortOrDefault("example.com:8080", 443)
	if host != "example.com" || port != "8080" {
		t.Errorf("expected example.com:8080, got %s:%s", host, port)
	}

	host, port = SplitHostPortOrDefault("example.com", 443)
	if host != "example.com" || port != "443" {
		t.Errorf("expected default port 443, got %s:%s", host, port)
	}
}
