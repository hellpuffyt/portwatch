# portwatch

Inventory listening TCP/UDP ports and the processes that own them, and
report exactly what changed since the last snapshot.

```bash
cargo install --path .
```

```bash
portwatch snapshot                # today: saves portwatch-state.json
# ... a week later ...
portwatch diff                    # what moved?
```

## Why this and not the 1000 `netstat` clones

`netstat`, `ss`, and `lsof -i` all answer "what is listening *right now*".
That's not the question that matters for a machine you don't watch every
hour: the useful finding is never "port 31337 is open", it's "**port
31337 was not open yesterday**", or "**nginx used to own port 443 and now
something else does**". Answering that means diffing two points in time,
which means a snapshot format, an identity rule for what counts as "the
same" listener across two scans, and a decision about what to do when a
port has more than one owner at once. That's the actual engineering here,
and it's what turns up real bugs the trivial version doesn't have to face
(see below).

Two decisions carry the design:

**A listener's identity is `(protocol, address, port)`, not its pid.**
Process ids get recycled on every restart. Key on the pid and a routine
`systemctl restart nginx` looks like a removal plus an addition. portwatch
keys on the socket, so a restart is a single, high-signal `OwnerChanged`
event naming the old and new pid - which is also what it looks like when
something *replaces* a service on a well-known port, the case this tool
actually exists to catch:

```text
~ tcp/0.0.0.0:443 owner changed: nginx (1200) -> nginx (1955)
```

**A port can have more than one simultaneous owner, and the diff has to
handle that correctly.** This one wasn't a design decision up front - it
was a bug I hit while dogfooding the first version on my own machine.
Windows was reporting the UDP mDNS port (`:5353`) as owned by two
different processes (`steamwebhelper.exe` and `brave.exe`, both bound
with `SO_REUSEADDR` the way multicast listeners commonly are), and my
first diff engine assumed one owner per port. Whichever process the OS
enumerated *second* silently overwrote the first in an internal map, so
between two back-to-back scans where literally nothing had changed, the
diff reported the port's owner flip-flopping between the two processes
purely from OS table-enumeration order. The fix (in
[`src/diff.rs`](src/diff.rs)) compares the full *set* of owners at each
key: a stable shared port produces no changes regardless of scan order,
a co-owner joining or leaving is `Added`/`Removed`, and only a clean
single-owner-to-single-owner handoff is reported as `OwnerChanged`. It's
covered by four tests built directly from that failure
(`src/diff.rs::tests`, search `shared_port`).

## Commands

```text
portwatch scan       [--json]                 print current listening ports
portwatch snapshot    [--state PATH] [--json]  capture and save a baseline
portwatch diff        [--state PATH] [--json]  compare live ports to the baseline
portwatch update      [--state PATH] [--log PATH] [--json]   diff, then re-save the baseline
portwatch history     [--log PATH] [--json]    print previously logged changes
```

| Flag | Effect |
| --- | --- |
| `--state PATH` | snapshot file to read/write (default `portwatch-state.json`) |
| `--log PATH` | append-only history log for `update`/`history` (default `portwatch-history.jsonl`) |
| `--json` | machine-readable JSON instead of a table/text report |

Exit codes are part of the interface:

| Code | Meaning |
| --- | --- |
| 0 | success; for `diff`/`update`, no changes were found |
| 1 | an error occurred (I/O, unsupported platform, unreadable snapshot) |
| 2 | success; for `diff`/`update`, at least one change was found |

That makes `diff`/`update` drop straight into a cron line or a CI step:
`portwatch update --state /var/lib/portwatch/state.json || alert-ops`.

## Real output

`portwatch scan` on the machine this README was written on (121 rows in
full; here are the first ten):

```text
PROTO  ADDRESS                    PORT   STATE   PROCESS
tcp    0.0.0.0                    135    LISTEN  svchost.exe (2380)
tcp    0.0.0.0                    445    LISTEN  System (4)
tcp    0.0.0.0                    2179   LISTEN  vmms.exe (3988)
tcp    0.0.0.0                    5040   LISTEN  svchost.exe (12152)
tcp    0.0.0.0                    7070   LISTEN  AnyDesk.exe (6416)
tcp    0.0.0.0                    7680   LISTEN  svchost.exe (24092)
tcp    0.0.0.0                    27036  LISTEN  steam.exe (13236)
tcp    0.0.0.0                    49664  LISTEN  lsass.exe (1904)
tcp    0.0.0.0                    49665  LISTEN  wininit.exe (2032)
tcp    0.0.0.0                    49666  LISTEN  svchost.exe (3332)
```

`cargo run --example diff_two_snapshots` builds two snapshots in code (no
live system access) and diffs them - actual output:

```text
~ tcp/0.0.0.0:80 owner changed: nginx (1200) -> nginx (1955)
- tcp/0.0.0.0:5432 no longer listening (was postgres (1400))
+ tcp/0.0.0.0:9090 now listening (metrics-exporter (2001))

1 added, 1 removed, 1 owner change(s)
```

## Platform support, honestly

One `PortSource` trait, three real backends - no `netstat`-parsing
fallback pretending to be a syscall:

| | Linux | Windows | macOS |
| --- | --- | --- | --- |
| Mechanism | reads `/proc/net/{tcp,tcp6,udp,udp6}`, walks `/proc/<pid>/fd` for ownership | calls `GetExtendedTcpTable`/`GetExtendedUdpTable` (IP Helper API) directly via FFI, `CreateToolhelp32Snapshot` for names | runs `lsof -nP -iTCP` / `-iUDP` and parses its columns |
| Sees all ports unprivileged | mostly - fd ownership needs matching uid or root | yes | no - only sockets the caller can see |
| IPv4-mapped IPv6 (`::ffff:127.0.0.1`) | parsed correctly | parsed correctly | parsed correctly |

Sharp edges, stated rather than hidden:

- **Linux:** a socket whose owning process you can't read `/proc/<pid>/fd`
  for (different user, no permission) is still reported, with `pid` and
  `process_name` left `null` - never silently dropped. This is exercised
  end-to-end by a test that scans a fixture `/proc` tree containing
  exactly that case (`src/linux.rs::full_scan_over_fixture_proc_tree_*`).
- **macOS:** `lsof`'s `COMMAND` column can itself contain spaces
  (`Google Chrome Helper`, `com.docker.backend`); the parser peels known
  fields off the *end* of each line rather than splitting naively, so
  the command name is never truncated or misread. Verified against real
  captured `lsof -F`-free column output in `tests/fixtures/macos/`.
- **Windows:** a UDP port can have more than one simultaneous owner (see
  the shared-port story above) - the diff engine, not the source, is
  where that gets handled correctly.
- **UDP has no "LISTEN" state anywhere.** portwatch treats every UDP
  socket the OS reports as bound as a "listener" for diffing purposes.
  On Windows this includes ephemeral outbound sockets a browser opens
  and closes constantly (observed directly while writing this README -
  a machine with an active browser produces UDP diff noise on high
  ephemeral ports between any two scans a few seconds apart). If that
  matters to you, filter `--json` output by port range before comparing.

## The snapshot format

Plain JSON, safe to commit or diff with `git diff`:

```json
{
  "captured_at_unix": 1735689600,
  "hostname": "web-01",
  "entries": [
    {
      "protocol": "tcp",
      "local_addr": "0.0.0.0",
      "local_port": 22,
      "state": "Listen",
      "pid": 900,
      "process_name": "sshd"
    }
  ]
}
```

`portwatch update` also appends one line of JSON per non-empty diff to a
history log (`portwatch-history.jsonl` by default) - an append-only audit
trail of exactly which ports changed and when, without needing a
database.

## As a library

```rust
use portwatch::diff::diff;
use portwatch::format;
use portwatch::model::{PortEntry, Protocol, Snapshot, TcpState};
use std::net::{IpAddr, Ipv4Addr};

fn entry(port: u16, pid: u32, name: &str) -> PortEntry {
    PortEntry {
        protocol: Protocol::Tcp,
        local_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        local_port: port,
        state: Some(TcpState::Listen),
        pid: Some(pid),
        process_name: Some(name.to_string()),
    }
}

let before = Snapshot::new(0, "host".into(), vec![entry(22, 900, "sshd")]);
let after = Snapshot::new(1, "host".into(), vec![
    entry(22, 900, "sshd"),
    entry(31337, 4400, "nc"),
]);

let report = diff(&before, &after);
println!("{}", format::diff_report(&report));
assert_eq!(report.added_count(), 1);
```

Implement `portwatch::source::PortSource` to plug in another platform
backend, or build `portwatch::model::Snapshot` values by hand (as above)
to drive the diff engine from fixed data - which is exactly how the test
suite exercises it.

## Development

```bash
cargo test                            # 71 tests: unit + full-pipeline fixtures + CLI
cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check
```

Runtime dependencies are `serde`/`serde_json` (the snapshot format) plus,
Windows-only, `windows-sys` (the IP Helper FFI bindings) - nothing else.
The argument parser, the diff engine, and the ISO-8601 timestamp
formatter are all hand-rolled in this repo rather than pulled in, so
there's nothing to audit that isn't right here.

The Linux and macOS backends type-check and run their fixture-driven
tests under `cargo check --target <triple> --tests` even when built on a
different host (that's how they were developed and verified here, on
Windows); CI runs each backend's real test suite natively on its own OS.

## License

MIT - see [LICENSE](LICENSE).
