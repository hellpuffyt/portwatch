# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- macOS: IPv6 wildcard listeners (`lsof` prints `*` for both families)
  were reported as a second `0.0.0.0` row; the `TYPE` column now decides.
- macOS: process names were truncated to 9 characters and kept `lsof`'s
  `\x20` escapes (`Brave\x20`); `lsof` now runs with `+c 0` and escapes
  are decoded.
- macOS and Linux: connected UDP client sockets (DNS lookups, QUIC) were
  reported as listeners, making two back-to-back scans differ; sockets
  with a peer are now skipped.
- macOS: `lsof` is run from `/usr/sbin/lsof` when present instead of the
  first `lsof` on `PATH`.
- `cargo doc` failed under `-D warnings` (links to cfg-gated/private items).
- CLI tests that compare two live scans failed on a busy machine; they
  now tolerate genuine churn between scans (retrying, and accepting the
  documented exit code 2 where only the JSON shape is under test).

### Added

- README: a Privileges section describing what an unprivileged scan sees
  on each OS. `SECURITY.md`, `.editorconfig`,
  `docs/PRODUCTION_READINESS.md`.

## [0.1.0] - 2026-09-01

First release.

### Added

- `portwatch scan`, `snapshot`, `diff`, `update` and `history`: inventory
  every listening TCP/UDP socket and its owning process, save it as a JSON
  snapshot, and report what changed since a previous one.
- A diff keyed on `(protocol, address, port)` rather than on the pid, so a
  service restart is reported as a single `OwnerChanged` event naming the
  old and new pid, instead of a removal plus an addition.
- Multi-owner-aware diffing: a `(protocol, address, port)` key can have more
  than one simultaneous owner (UDP multicast listeners bound with
  `SO_REUSEADDR` - mDNS, SSDP - commonly do), and the diff engine compares
  the full owner set at each key rather than assuming exactly one.
- Three real platform backends behind one `PortSource` trait:
  - **Linux** - parses `/proc/net/{tcp,tcp6,udp,udp6}` and resolves owners
    by walking `/proc/<pid>/fd`.
  - **Windows** - calls `GetExtendedTcpTable`/`GetExtendedUdpTable` (the IP
    Helper API) directly via FFI, and `CreateToolhelp32Snapshot` for
    process names.
  - **macOS** - runs `lsof -nP -iTCP`/`-iUDP` and parses its columns,
    correctly handling command names that contain spaces.
- An append-only, changes-only history log (`portwatch update --log`), one
  JSON line per diff that actually found something.
- Text-table and `--json` output for every command.
- A dependency-free ISO-8601 UTC timestamp formatter.
- 71 tests: unit tests for every pure module, a full-pipeline test that
  scans a fixture `/proc` tree end to end, fixture-driven macOS `lsof`
  parser tests against real captured output, live FFI tests on Windows,
  and CLI integration tests against the built binary.

[0.1.0]: https://github.com/hellpuffyt/portwatch/releases/tag/v0.1.0
