// Package tcp checks a tcp monitor by connecting to host:port, matching
// App\Services\Monitors\TcpMonitorChecker's semantics
// (docs/design-plans/2026-10-05-private-probe.md §7.2).
package tcp

import (
	"context"
	"errors"
	"net"
	"strconv"
	"time"

	"github.com/oaki/baromio-probe/internal/allowlist"
	"github.com/oaki/baromio-probe/internal/errmap"
)

// Timeout is the fixed TCP connect timeout, matching the PHP checker's 5s.
const Timeout = 5 * time.Second

// Result is the check verdict.
type Result struct {
	IsUp           bool
	ResponseTimeMs int
	ErrorCode      errmap.Code
}

// Check connects to host:port. With a non-nil allow the address actually dialed
// is vetted against it (a name is resolved once, here, and the vetted address
// is the one connected to); a refused target is never dialed at all.
func Check(ctx context.Context, host string, port int, allow *allowlist.Allowlist) Result {
	dialer := &net.Dialer{Timeout: Timeout}
	dial := dialer.DialContext
	if allow != nil {
		dial = allow.DialContext(dialer, allowlist.SystemLookup)
	}

	start := time.Now()
	conn, err := dial(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	elapsed := time.Since(start)

	if err != nil {
		if errors.Is(err, allowlist.ErrRefused) {
			return Result{IsUp: false, ResponseTimeMs: int(elapsed.Milliseconds()), ErrorCode: errmap.RefusedCheck}
		}

		return Result{
			IsUp:           false,
			ResponseTimeMs: int(elapsed.Milliseconds()),
			ErrorCode:      errmap.FromError(err),
		}
	}

	conn.Close()

	return Result{IsUp: true, ResponseTimeMs: int(elapsed.Milliseconds())}
}
