# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
