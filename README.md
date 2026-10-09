# baromio-probe

A customer-installed agent that checks internal services unreachable from
the public internet, and reports results back to
[Baromio](https://baromio.io) over an outbound-only connection. The full
design (ADR-0053, ADR-0054) lives in Baromio's own repository, not here.

The Probe never accepts an inbound connection. It polls its config, checks
the monitors it's told about, and posts results - all outbound.

## Install

Get an Enrollment Token from your Baromio dashboard's Private Locations
page first - it is valid for one hour and single-use.

### Docker

```bash
docker run -d --name baromio-probe --restart unless-stopped \
  -v baromio-probe:/var/lib/baromio-probe \
  -e BAROMIO_ENROLL_TOKEN=<your-token> \
  -e BAROMIO_ALLOW=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,fc00::/7 \
  ghcr.io/oaki/baromio-probe:0.1
```

The volume is required: without it, a restarted container loses its
identity and needs a fresh Enrollment Token.

### Binary (Linux)

Download `baromio-probe` for your architecture (`amd64` or `arm64`) from
the [releases page](https://github.com/oaki/baromio-probe/releases),
verify it with `cosign` (see below), then:

```bash
export BAROMIO_ENROLL_TOKEN=<your-token>
export BAROMIO_ALLOW=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,fc00::/7
export BAROMIO_DATA_DIR=/var/lib/baromio-probe
./baromio-probe
```

A `systemd` unit example is in [`systemd/baromio-probe.service`](systemd/baromio-probe.service).

## Configuration

| Variable | Required | Description |
|----------|----------|-------------|
| `BAROMIO_ENROLL_TOKEN` | Only on first start | One-time, one-hour Enrollment Token from the dashboard |
| `BAROMIO_ALLOW` | Yes | Comma-separated CIDR ranges, hosts, or `host:port` pairs this Probe is allowed to check |
| `BAROMIO_URL` | No | Baromio API base, defaults to `https://baromio.io` |
| `BAROMIO_DATA_DIR` | No | Where the Probe's identity and result buffer live, defaults to `/var/lib/baromio-probe` |

`BAROMIO_DATA_DIR` must persist across restarts (a Docker volume, or a real
directory for the binary) - it holds the Ed25519 key pair generated on
first start and the id Baromio assigned on enrollment. Losing it means
re-enrolling with a fresh token.

## What it checks

Only `http`, `keyword`, and `tcp` monitors (the types that can run without a
browser) - matching exactly how Baromio's own fleet checks them: HEAD first
for `http` with a GET fallback on 405, full redirect-following GET for
`keyword`, a plain TCP connect for `tcp`. A monitor's target - and every
redirect hop it follows - must fall inside `BAROMIO_ALLOW` or the Probe
refuses to check it at all. A hostname is allowed when it is listed in
`BAROMIO_ALLOW` itself, or when every address it resolves to falls inside an
allowed range; a name that does not resolve is refused. The Probe reports a
refused monitor to Baromio, which shows it as blocked.

## Verifying a release

Every release is signed keylessly with [cosign](https://github.com/sigstore/cosign)
and carries a CycloneDX SBOM.

```bash
cosign verify-blob \
  --certificate-identity-regexp 'https://github.com/oaki/baromio-probe/.github/workflows/release.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --signature baromio-probe_linux_amd64.sig \
  --certificate baromio-probe_linux_amd64.pem \
  baromio-probe_linux_amd64
```

## Security

See [SECURITY.md](SECURITY.md) for the disclosure address and supported
version policy.

## Development

```bash
go build ./...
go vet ./...
go test -race ./...
```

Standard library only - no third-party dependencies in the binary.
