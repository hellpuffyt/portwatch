# Production readiness — portwatch

Audit date: 2026-10-22. Branch: `audit/production-readiness`.
Tested commit: `bc6228d` (the final commit adds only this file).

## Scope

`portwatch` lists listening TCP/UDP sockets with their owning processes,
saves them as a JSON snapshot, diffs a live scan against the snapshot
(identity = protocol + address + port; owner sets compared so shared
ports do not flip-flop), and appends non-empty diffs to a JSONL history.
Backends: Linux (`/proc/net/*` + `/proc/<pid>/fd`), Windows (IP Helper
API via `windows-sys`, `unsafe` FFI), macOS (`lsof`). Each backend is
compiled only on its own OS.

## Platforms, prerequisites and privileges

- Rust 1.87+ (declared `rust-version`); not run on 1.87 locally.
- **Verified here: macOS 27 (Apple M5) only.** The Linux and Windows
  backends were type-checked and linted for their targets from this host
  (`cargo clippy --target x86_64-unknown-linux-gnu|x86_64-pc-windows-msvc
  --all-targets -- -D warnings`, exit 0) but their tests and live scans
  were **not run** — that happens in CI on `ubuntu-latest` /
  `windows-latest`.
- No root needed for anything, including the tests. Visibility without
  root: Linux shows every socket but no owner for other users' sockets;
  macOS `lsof` omits other users' sockets; Windows shows all. Documented
  in the README "Privileges" section.

## Clean-clone verification (literal README steps)

```
git clone -b audit/production-readiness <repo> portwatch && cd portwatch
cargo install --locked --path . --root <scratch>/inst   # exit 0
cargo test                                               # exit 0 — 80 passed, 0 failed, 0 ignored
cargo clippy --all-targets -- -D warnings                # exit 0
cargo fmt --all -- --check                               # exit 0
cargo run --example diff_two_snapshots                   # exit 0, output identical to the README
portwatch snapshot; portwatch diff; portwatch update; portwatch history   # exit 0 each; "no changes"
```

(`--root` only avoids installing into the shared host's `~/.cargo/bin`.)
A live `scan --json` on the audit host returned 35 listening entries, 20
of them IPv6 wildcards that were previously mislabelled `0.0.0.0`.

## Commands and results (audit host)

| Command | Exit | Result |
| --- | --- | --- |
| `cargo fmt --all -- --check` | 0 | clean |
| `cargo clippy --all-targets --all-features --locked -- -D warnings` | 0 | clean |
| `cargo clippy --target x86_64-unknown-linux-gnu --all-targets --locked -- -D warnings` | 0 | clean |
| `cargo clippy --target x86_64-pc-windows-msvc --all-targets --locked -- -D warnings` | 0 | clean |
| `cargo test --all-targets --locked` (baseline) | 101 | 74 passed, **3 failed**, 0 ignored (live-scan CLI tests, see #5) |
| `cargo test --all-targets --locked` (after; run 3×) | 0 | 80 passed, 0 failed, 0 ignored each time |
| `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --locked` (baseline) | 101 | 3 broken intra-doc links |
| same (after) | 0 | clean |
| `cargo audit --db <local advisory-db> --no-fetch` | 0 | 0 vulnerabilities |
| `cargo deny check` | — | not configured |

On macOS the 80 tests are: lib 60 (model/diff/format/storage/timefmt/
macos), binary unit tests 6, `tests/cli.rs` 14. Linux-only tests
(`src/linux.rs`, including the new connected-UDP test) do not compile on
macOS and were not executed.

## CI status

Default branch: `success` (run on `22177b8`, 2026-09-01).
Audit branch: pending until pushed. Actions pinned by tag; unchanged.

## Bugs found and fixed (each with a regression test)

| # | Severity | Defect | Fix | Regression test |
| --- | --- | --- | --- | --- |
| 1 | Medium (wrong inventory) | macOS: `lsof` prints the wildcard as `*` for IPv4 and IPv6 alike; every IPv6 wildcard listener was reported as a duplicate `0.0.0.0` row (identity collisions in the diff). | Use the `TYPE` column to choose `::`. | `macos::tests::ipv6_wildcard_is_not_reported_as_ipv4` |
| 2 | Medium (wrong inventory) | macOS: names truncated to 9 chars and left escaped (`Brave\x20`), contrary to the README claim "never truncated or misread". | `lsof +c 0`; decode `\xNN`. | `macos::tests::lsof_escaped_command_names_are_decoded` |
| 3 | Medium (false positives) | Connected UDP client sockets (DNS lookups, QUIC) counted as listeners on macOS and Linux, so back-to-back scans differed. | Skip UDP rows with a peer (`->` / non-zero `rem_address` port). | `macos::tests::connected_udp_rows_are_not_listeners`, `linux::tests::connected_udp_sockets_are_not_reported_as_listeners` (Linux; CI only) |
| 4 | Low (hardening) | `lsof` resolved through `PATH` although the tool is typically run as root from cron. | Prefer `/usr/sbin/lsof`. | live scan on macOS |
| 5 | Test reliability | Three CLI tests assumed the live port table cannot change between two scans; they failed on this shared host when another process opened listeners. | Retry up to 5 times requiring one clean diff (a real "changes on unchanged table" bug still fails every attempt); the JSON-shape test accepts the documented exit 2. | `tests/cli.rs` |
| 6 | Docs | `cargo doc -D warnings` failed; README claimed the macOS fixtures were real captured output, but they contain literal spaces in `COMMAND`, which `lsof` never prints. | Docs corrected. | `cargo doc` above |

## Security review

- `unsafe` exists only in the Windows backend (FFI); not exercised here.
- External command: `lsof` with fixed arguments, no shell, absolute
  path preferred. Output parsing is total (malformed rows are skipped).
- Snapshot/history are read/written only at the user-given paths;
  corrupt snapshots produce exit 1 (existing tests).
- Secret scan of the tree and full history: no hits.
- Workflow permissions: `contents: read`.

## Known limitations

- Linux and Windows behaviour not verified on this host (see above).
- Windows UDP table has no peer, so connected UDP sockets still appear.
- macOS visibility is limited to the caller's own processes unless run as
  root.
- `cargo deny` not configured.

## Acceptance checklist

| Item | Expected behaviour | Command / test | Result | Actual | Reference |
| --- | --- | --- | --- | --- | --- |
| Inventory (macOS) | Listening TCP + bound UDP with owner, correct family | live `scan --json`; `macos` tests | pass | 35 entries, 20 `::` | `src/macos.rs` |
| Inventory (Linux) | `/proc` parsing + owner resolution | `linux` tests | not run here (CI) | — | `src/linux.rs` |
| Inventory (Windows) | IP Helper tables | Windows CI | not run here | — | `src/windows.rs` |
| Diff identity | Restart = one `OwnerChanged`; shared ports stable | `diff` unit tests, example | pass | example output matches README | `src/diff.rs` |
| Exit codes | 0 no change, 1 error, 2 changes | `tests/cli.rs` | pass | — | `src/main.rs` |
| Snapshot/history files | Round trip, append-only log | `storage` tests, quick start | pass | — | `src/storage.rs` |
| Unprivileged operation | No root needed; tests run unprivileged | full suite as normal user | pass | — | README "Privileges" |
| Lint/docs | fmt, clippy (3 targets), rustdoc | table above | pass | clean | — |

## Classification proposal

**Partially Verified** — macOS behaviour and all platform-independent
logic verified with three real macOS inventory defects fixed; the Linux
and Windows backends could not be executed on this host and await the
audit branch's CI run.
