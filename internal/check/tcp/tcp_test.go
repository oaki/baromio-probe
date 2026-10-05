package tcp

import (
	"net"
	"testing"
)

func TestCheckSucceedsAgainstAnOpenPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer ln.Close()

	addr := ln.Addr().(*net.TCPAddr)

	result := Check("127.0.0.1", addr.Port)

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

	result := Check("127.0.0.1", addr.Port)

	if result.IsUp {
		t.Error("expected IsUp=false against a closed port")
	}
	if result.ErrorCode == 0 {
		t.Error("expected a non-zero error code")
	}
}
