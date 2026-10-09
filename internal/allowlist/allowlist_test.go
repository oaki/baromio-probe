package allowlist

import (
	"context"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
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

func fakeLookup(ips ...string) func(string) ([]net.IP, error) {
	return func(string) ([]net.IP, error) {
		out := make([]net.IP, 0, len(ips))
		for _, s := range ips {
			out = append(out, net.ParseIP(s))
		}
		return out, nil
	}
}

func TestAllowsTargetResolvesAHostnameIntoAnAllowedCidr(t *testing.T) {
	a, _ := Parse("10.0.0.0/8")

	if !a.AllowsTarget("intranet.example", "", fakeLookup("10.1.2.3")) {
		t.Error("expected a hostname resolving into an allowed CIDR to be allowed")
	}
}

func TestAllowsTargetRefusesAHostnameResolvingOutside(t *testing.T) {
	a, _ := Parse("10.0.0.0/8")

	if a.AllowsTarget("public.example", "", fakeLookup("93.184.216.34")) {
		t.Error("expected a hostname resolving outside the allowlist to be refused")
	}
}

func TestAllowsTargetRefusesWhenOneAddressIsOutside(t *testing.T) {
	a, _ := Parse("10.0.0.0/8")

	if a.AllowsTarget("mixed.example", "", fakeLookup("10.0.0.1", "93.184.216.34")) {
		t.Error("expected every resolved address to need allowing")
	}
}

func TestAllowsTargetRefusesWhenResolutionFails(t *testing.T) {
	a, _ := Parse("10.0.0.0/8")

	lookup := func(string) ([]net.IP, error) { return nil, net.UnknownNetworkError("nope") }
	if a.AllowsTarget("gone.example", "", lookup) {
		t.Error("expected a hostname that does not resolve to be refused")
	}
}

func TestAllowsTargetSkipsDnsForAnExplicitHost(t *testing.T) {
	a, _ := Parse("listed.example")

	lookup := func(string) ([]net.IP, error) { t.Fatal("lookup must not run for a listed host"); return nil, nil }
	if !a.AllowsTarget("listed.example", "", lookup) {
		t.Error("expected an explicitly listed host to be allowed")
	}
}

func TestTargetFromURLReadsHostAndPort(t *testing.T) {
	host, port, err := TargetFromURL("https://intranet.example:8443/health?x=1")
	if err != nil || host != "intranet.example" || port != "8443" {
		t.Fatalf("got %q %q %v", host, port, err)
	}

	host, port, err = TargetFromURL("http://10.0.0.5/")
	if err != nil || host != "10.0.0.5" || port != "80" {
		t.Fatalf("expected default port 80, got %q %q %v", host, port, err)
	}

	_, port, _ = TargetFromURL("https://intranet.example/")
	if port != "443" {
		t.Errorf("expected default port 443, got %q", port)
	}
}

func TestTargetFromURLRefusesUserinfoAndOddSchemes(t *testing.T) {
	for _, raw := range []string{
		"http://10.0.0.1:80@169.254.169.254/latest/meta-data/",
		"http://user@10.0.0.1/",
		"ftp://10.0.0.1/",
		"file:///etc/passwd",
		"//10.0.0.1/",
		"10.0.0.1",
		"",
	} {
		if _, _, err := TargetFromURL(raw); err == nil {
			t.Errorf("expected %q to be refused", raw)
		}
	}
}

func listenOnLoopback(t *testing.T) (port string, accepted *int32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var n int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			atomic.AddInt32(&n, 1)
			c.Close()
		}
	}()
	_, p, _ := net.SplitHostPort(ln.Addr().String())
	return p, &n
}

func ctxLookup(ips ...string) func(context.Context, string) ([]net.IP, error) {
	f := fakeLookup(ips...)
	return func(_ context.Context, h string) ([]net.IP, error) { return f(h) }
}

func TestDialContextConnectsToAVettedAddress(t *testing.T) {
	port, accepted := listenOnLoopback(t)
	a, _ := Parse("127.0.0.0/8")
	dial := a.DialContext(&net.Dialer{Timeout: time.Second}, ctxLookup("127.0.0.1"))

	conn, err := dial(context.Background(), "tcp", "service.internal:"+port)
	if err != nil {
		t.Fatalf("expected the connection to be made: %v", err)
	}
	conn.Close()
	time.Sleep(50 * time.Millisecond)
	if atomic.LoadInt32(accepted) != 1 {
		t.Error("expected exactly one connection to the vetted address")
	}
}

func TestDialContextRefusesAnAddressOutsideTheAllowlist(t *testing.T) {
	a, _ := Parse("127.0.0.0/8")
	dial := a.DialContext(&net.Dialer{Timeout: time.Second}, ctxLookup("169.254.169.254"))

	_, err := dial(context.Background(), "tcp", "rebind.example:80")
	if err == nil || !strings.Contains(err.Error(), "refused check") {
		t.Errorf("expected a refused check, got %v", err)
	}
}

func TestDialContextRefusesWhenAnyResolvedAddressIsOutside(t *testing.T) {
	port, accepted := listenOnLoopback(t)
	a, _ := Parse("127.0.0.0/8")
	dial := a.DialContext(&net.Dialer{Timeout: time.Second}, ctxLookup("127.0.0.1", "93.184.216.34"))

	if _, err := dial(context.Background(), "tcp", "mixed.example:"+port); err == nil {
		t.Error("expected a mixed answer to be refused")
	}
	if atomic.LoadInt32(accepted) != 0 {
		t.Error("a refused target must not be dialed at all")
	}
}

func TestDialContextRefusesALiteralIPOutsideTheAllowlist(t *testing.T) {
	a, _ := Parse("10.0.0.0/8")
	dial := a.DialContext(&net.Dialer{Timeout: time.Second}, ctxLookup())

	if _, err := dial(context.Background(), "tcp", "169.254.169.254:80"); err == nil {
		t.Error("expected a literal address outside the allowlist to be refused")
	}
}

func TestDialContextDialsAListedHostByName(t *testing.T) {
	port, _ := listenOnLoopback(t)
	a, _ := Parse("localhost")
	lookup := func(context.Context, string) ([]net.IP, error) {
		t.Fatal("a listed host is not vetted by address")
		return nil, nil
	}
	dial := a.DialContext(&net.Dialer{Timeout: time.Second}, lookup)

	conn, err := dial(context.Background(), "tcp", "localhost:"+port)
	if err != nil {
		t.Fatalf("expected a listed host to be dialed: %v", err)
	}
	conn.Close()
}
