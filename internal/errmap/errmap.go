// Package errmap maps a Go check error to the MonitorErrorCode Baromio
// already uses for its own fleet checks (app/Enums/MonitorErrorCode.php),
// so a Private Location incident reads identically to a fleet one
// (docs/design-plans/2026-10-05-private-probe.md §7.3).
package errmap

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"syscall"
)

// Code mirrors App\Enums\MonitorErrorCode. Only the values a Probe can ever
// produce are listed as named constants; the rest exist only on the
// Baromio side.
type Code int

const (
	Unknown           Code = 0
	HTTPError         Code = 1
	GatewayTimeout    Code = 2
	MissingKeyword    Code = 3
	FoundKeyword      Code = 4
	ConnectionRefused Code = 5
	ConnectionTimeout Code = 6
	DNSLookupFailed   Code = 7
	SSLError          Code = 9
	RefusedCheck      Code = 13
)

// FromError classifies err into the closest MonitorErrorCode. RefusedCheck
// is never produced here - the caller sets it directly when the allowlist,
// not the network, is what refused the check.
func FromError(err error) Code {
	if err == nil {
		return Unknown
	}

	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return DNSLookupFailed
	}

	var tlsErr *tls.CertificateVerificationError
	if errors.As(err, &tlsErr) {
		return SSLError
	}

	if errors.Is(err, context.DeadlineExceeded) {
		return GatewayTimeout
	}

	var opErr *net.OpError
	if errors.As(err, &opErr) {
		if opErr.Timeout() {
			return ConnectionTimeout
		}

		if errors.Is(opErr.Err, syscall.ECONNREFUSED) {
			return ConnectionRefused
		}
	}

	return Unknown
}
