package errmap

import (
	"context"
	"errors"
	"net"
	"syscall"
	"testing"
)

func TestFromErrorNilIsUnknown(t *testing.T) {
	if got := FromError(nil); got != Unknown {
		t.Errorf("expected Unknown for nil, got %d", got)
	}
}

func TestFromErrorDnsFailure(t *testing.T) {
	err := &net.DNSError{Err: "no such host", Name: "nonexistent.invalid", IsNotFound: true}

	if got := FromError(err); got != DNSLookupFailed {
		t.Errorf("expected DNSLookupFailed, got %d", got)
	}
}

func TestFromErrorDeadlineExceeded(t *testing.T) {
	if got := FromError(context.DeadlineExceeded); got != GatewayTimeout {
		t.Errorf("expected GatewayTimeout, got %d", got)
	}
}

func TestFromErrorConnectionRefused(t *testing.T) {
	err := &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}

	if got := FromError(err); got != ConnectionRefused {
		t.Errorf("expected ConnectionRefused, got %d", got)
	}
}

func TestFromErrorTimeoutOpError(t *testing.T) {
	err := &net.OpError{Op: "dial", Err: timeoutError{}}

	if got := FromError(err); got != ConnectionTimeout {
		t.Errorf("expected ConnectionTimeout, got %d", got)
	}
}

func TestFromErrorFallsBackToUnknown(t *testing.T) {
	if got := FromError(errors.New("something unexpected")); got != Unknown {
		t.Errorf("expected Unknown fallback, got %d", got)
	}
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }
