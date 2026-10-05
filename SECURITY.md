# Security Policy

## Reporting a vulnerability

<!-- TODO: confirm a real, monitored disclosure address before publishing this file. -->
Email **security@baromio.io** with a description and, if possible, steps to
reproduce. Please do not open a public issue for a suspected vulnerability.

## Supported versions

Only the latest released minor version is actively supported. An older
version is reported as needing an update by the Probe itself and by the
Baromio dashboard, but a fix is only ever released against the latest line.

## What this Probe can and cannot do

- It executes nothing it is sent over the wire: only the three check types
  (`http`, `keyword`, `tcp`), no shell, no script, no arbitrary code path.
- A stolen Probe identity (its Ed25519 private key) reaches only that one
  Probe's own Private Location: its config and its own past results. It
  cannot read or act on any other account's data.
- It never accepts an inbound connection and opens no listening port.
- `BAROMIO_ALLOW` is enforced on every check, including every redirect hop a
  check follows - a target outside it is never dialed or requested at all.

## Disclosure and advisories

A confirmed vulnerability gets a GitHub Security Advisory on this repository
and, if actively exploited, follows the CRA reporting obligation that
applies to products with digital elements since 2026-09-11.
