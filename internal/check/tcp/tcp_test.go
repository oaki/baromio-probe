package tcp

import (
	"context"
	"net"
	"testing"

	"github.com/oaki/baromio-probe/internal/allowlist"
)

func TestCheckSucceedsAgainstAnOpenPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer ln.Close()

	addr := ln.Addr().(*net.TCPAddr)

	result := Check(context.Background(), "127.0.0.1", addr.Port, nil)

	if !result.IsUp {
		t.Errorf("expected IsUp=true against an open port, got %+v", result)
	}
}

func TestCheckFailsAgainstARefusedPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	addr := ln.Addr().(*net.TCPAddr)
	ln.Close() // closed immediately: nothing listens here any more

	result := Check(context.Background(), "127.0.0.1", addr.Port, nil)

	if result.IsUp {
		t.Error("expected IsUp=false against a closed port")
	}
	if result.ErrorCode == 0 {
		t.Error("expected a non-zero error code")
	}
}

func TestCheckRefusesATargetOutsideTheAllowlistWithoutDialing(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer ln.Close()

	dialed := make(chan struct{}, 1)
	go func() {
		if c, err := ln.Accept(); err == nil {
			c.Close()
			dialed <- struct{}{}
		}
	}()

	allow, _ := allowlist.Parse("10.0.0.0/8")
	result := Check(context.Background(), "127.0.0.1", ln.Addr().(*net.TCPAddr).Port, allow)

	if result.IsUp || result.ErrorCode != 13 {
		t.Errorf("expected RefusedCheck(13) and not up, got %+v", result)
	}
	select {
	case <-dialed:
		t.Error("a refused target must not be dialed")
	default:
	}
}

func TestCheckConnectsWhenTheTargetIsAllowed(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer ln.Close()

	allow, _ := allowlist.Parse("127.0.0.0/8")
	result := Check(context.Background(), "127.0.0.1", ln.Addr().(*net.TCPAddr).Port, allow)

	if !result.IsUp {
		t.Errorf("expected an allowed target to be reachable, got %+v", result)
	}
}
