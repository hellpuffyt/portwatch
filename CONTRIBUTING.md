# Contributing

Thanks for taking a look.

## Getting set up

```bash
git clone https://github.com/hellpuffyt/portwatch
cd portwatch
cargo build
```

Nothing else needed - the only runtime dependencies are `serde`/`serde_json`
plus, on Windows, `windows-sys`, and there's no build script.

## Before opening a pull request

All of these must pass; CI runs the equivalent commands on Linux, Windows
and macOS.

```bash
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check
```

If you don't have easy access to all three OSes, you can still type-check
(including test code) the other two platform backends from any machine
with the corresponding Rust target installed:

```bash
rustup target add x86_64-unknown-linux-gnu x86_64-apple-darwin
cargo check --target x86_64-unknown-linux-gnu --tests
cargo check --target x86_64-apple-darwin --tests
```

This won't run those backends' tests (no linker for a foreign target),
but it catches type errors and, importantly, compiles their `#[cfg(test)]`
modules - including the fixture-driven tests - so a change that breaks the
Linux or macOS backend is caught even from a Windows dev machine. This
repo was built exactly this way.

## Design constraints

These are the rules the project is built around. A change that breaks one
of them is not a trade-off to discuss - it's a different tool.

- **The core never learns what platform it's on.** Enumeration lives
  behind `source::PortSource`; `diff`, `format`, and `storage` are pure
  functions over `PortEntry`/`Snapshot` values. This is what lets the
  Linux and macOS backends' logic be exercised on any host (see above),
  and it's why every platform parser (`parse_proc_net`, `parse_line`,
  `convert_port`, ...) is a free function over plain data rather than a
  method that reads a file or shells out.
- **A port can have more than one owner. Design for it, don't special-case
  it away.** `src/diff.rs` was rewritten once already because an earlier
  version assumed one owner per `(protocol, address, port)` key and
  produced spurious "owner changed" noise on a real machine with a shared
  UDP port. See the README's "Why this and not the 1000 clones" section
  for the full story, and `src/diff.rs::tests` (search `shared_port`) for
  the tests that pin the fix down. Any change to the diff engine needs a
  test that covers a key with more than one simultaneous owner.
- **Never invent an owner.** A field the platform couldn't resolve (`pid`,
  `process_name`) stays `None` all the way to the output. Filling it with
  an empty string or a guess puts a false statement in what's meant to be
  a security-relevant inventory.
- **Never silently drop an entry you can parse the identity of.** The
  `/proc/net/*` and `lsof` line parsers skip individual malformed *lines*
  defensively (a future kernel or `lsof` quirk shouldn't take the tool
  down), but that's a last resort, not a normal code path - it should
  never trigger on real, well-formed input, which is why every parser has
  fixture tests built from real captured output.

## Adding to a platform backend

1. Keep the split that's already there: pure parsing functions that take
   `&str` (or, for Linux, an injectable `root: &Path`) and return
   `Vec<PortEntry>`/`RawSocket`, plus a thin `PortSource` impl that does
   the actual file read / FFI call / subprocess spawn and calls them. Only
   the thin part may touch the live system.
2. Prefer a fixture over a synthetic string when you can get one: the
   Linux backend's `tests/fixtures/linux/root/` is a fake `/proc` tree
   (see its `README.md`) that exercises the *file-walking* code too, not
   just string parsing, and the macOS backend's tests parse real captured
   `lsof` output from `tests/fixtures/macos/`.
3. Cover the edge cases that actually bite: an unattributed socket (no
   matching fd/permission), an IPv4-mapped IPv6 address, a non-`LISTEN`
   TCP state that must be excluded, a command name with spaces in it (on
   macOS).

## Changing the snapshot format

`model::Snapshot`/`PortEntry` are `serde`-derived with no manual
versioning field. Adding an optional field is safe (old snapshot files
still deserialize; the new field is absent). Changing an existing field's
type or meaning is a breaking change to every snapshot file anyone has
saved - avoid it, and if it's unavoidable, say so loudly in the
changelog.

## Reporting a bug

The most useful thing you can attach is the raw platform output that
produced the wrong result - the `/proc/net/tcp` lines, the `lsof -nP -iTCP`
block, or (on Windows) enough detail to reproduce the `GetExtendedTcpTable`
call (which process, which port). Every parser is a pure function over
exactly that kind of text or struct, so a paste of it turns directly into
a new fixture-based test. Include your OS, and whether you ran with
elevated privileges, since that affects what a backend can resolve.
