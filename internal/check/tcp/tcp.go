// Package tcp checks a tcp monitor by connecting to host:port, matching
// App\Services\Monitors\TcpMonitorChecker's semantics
// (docs/design-plans/2026-10-05-private-probe.md §7.2).
package tcp

import (
	"net"
	"strconv"
	"time"

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

// Check connects to host:port. The caller is responsible for the allowlist
// check before calling this - a refused target is never dialed at all.
func Check(host string, port int) Result {
	start := time.Now()
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), Timeout)
	elapsed := time.Since(start)

	if err != nil {
		return Result{
			IsUp:           false,
			ResponseTimeMs: int(elapsed.Milliseconds()),
			ErrorCode:      errmap.FromError(err),
		}
	}

	conn.Close()

	return Result{IsUp: true, ResponseTimeMs: int(elapsed.Milliseconds())}
}
