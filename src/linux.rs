//! Linux port source: parses `/proc/net/{tcp,tcp6,udp,udp6}` for the
//! socket table and walks `/proc/<pid>/fd/*` to resolve each socket's
//! inode back to the owning process, the same technique `ss`/`lsof` use.
//!
//! The parsing functions here take plain strings and are exercised with
//! static fixtures in the test module below, independent of whether the
//! machine running the tests is actually Linux. Only the thin file-system
//! walking in [`LinuxSource::scan`] is Linux-only and unverifiable on
//! this dev machine; it is a direct, minimal wrapper around the parsers.

use crate::model::{PortEntry, Protocol, TcpState};
use crate::source::PortSource;
use std::collections::HashMap;
use std::fs;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Parse the 8-hex-character IPv4 address field used in `/proc/net/tcp`.
/// The kernel writes the address as it sits in memory (native/little-
/// endian byte order on every Linux architecture portwatch targets), so
/// the byte sequence read left-to-right from the hex digits has to be
/// reversed to get the address in normal (network) byte order.
fn parse_ipv4_hex(hex: &str) -> Option<Ipv4Addr> {
    if hex.len() != 8 {
        return None;
    }
    let mut bytes = [0u8; 4];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    bytes.reverse();
    Some(Ipv4Addr::from(bytes))
}

/// Parse the 32-hex-character IPv6 address field. Same byte-order
/// quirk as IPv4, applied independently within each of the four
/// 32-bit words that make up the address.
fn parse_ipv6_hex(hex: &str) -> Option<Ipv6Addr> {
    if hex.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for word in 0..4 {
        let word_hex = &hex[word * 8..word * 8 + 8];
        for i in 0..4 {
            out[word * 4 + i] =
                u8::from_str_radix(&word_hex[(3 - i) * 2..(3 - i) * 2 + 2], 16).ok()?;
        }
    }
    Some(Ipv6Addr::from(out))
}

fn parse_addr_port(field: &str, v6: bool) -> Option<(IpAddr, u16)> {
    let (addr_hex, port_hex) = field.split_once(':')?;
    let addr = if v6 {
        IpAddr::V6(parse_ipv6_hex(addr_hex)?)
    } else {
        IpAddr::V4(parse_ipv4_hex(addr_hex)?)
    };
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    Some((addr, port))
}

/// One row of `/proc/net/{tcp,udp}[6]`, before process ownership has been
/// resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RawSocket {
    local_addr: IpAddr,
    local_port: u16,
    state: u32,
    inode: u64,
}

/// Parse the body of a `/proc/net/tcp`-style file (header line included
/// or not; it is detected and skipped either way).
fn parse_proc_net(content: &str, v6: bool) -> Vec<RawSocket> {
    let mut out = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("sl") {
            continue;
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        // sl local_address rem_address st tx_queue:rx_queue tr:tm->when
        // retrnsmt uid timeout inode ...
        if fields.len() < 10 {
            continue;
        }
        let Some((local_addr, local_port)) = parse_addr_port(fields[1], v6) else {
            continue;
        };
        let Ok(state) = u32::from_str_radix(fields[3], 16) else {
            continue;
        };
        let Ok(inode) = fields[9].parse::<u64>() else {
            continue;
        };
        out.push(RawSocket {
            local_addr,
            local_port,
            state,
            inode,
        });
    }
    out
}

/// Build an `inode -> pid` map by walking `/proc/<pid>/fd/*` and
/// following each entry that is a `socket:[N]` symlink. Processes whose
/// fd directory can't be listed (already exited, or no permission) are
/// silently skipped, matching what `ss`/`lsof` do when run unprivileged.
///
/// Each fd entry is resolved with [`fs::read_link`] first, since on a
/// real kernel `/proc/<pid>/fd/N` is a symlink whose target can't be
/// read as regular file content. If that fails, we fall back to reading
/// the entry as a plain file: git cannot portably commit a real symlink
/// for the test fixtures below, so the fixture tree represents each fd
/// as a regular file containing the link target text instead, and this
/// fallback is what lets that fixture exercise the exact same code path.
fn socket_owners(root: &std::path::Path) -> HashMap<u64, u32> {
    let mut owners = HashMap::new();
    let Ok(proc_entries) = fs::read_dir(root.join("proc")) else {
        return owners;
    };
    for proc_entry in proc_entries.flatten() {
        let Ok(pid) = proc_entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let fd_dir = proc_entry.path().join("fd");
        let Ok(fds) = fs::read_dir(&fd_dir) else {
            continue;
        };
        for fd in fds.flatten() {
            let target = fs::read_link(fd.path())
                .map(|p| p.to_string_lossy().into_owned())
                .or_else(|_| fs::read_to_string(fd.path()).map(|s| s.trim().to_string()));
            let Ok(target) = target else {
                continue;
            };
            if let Some(inode) = parse_socket_inode(&target) {
                owners.entry(inode).or_insert(pid);
            }
        }
    }
    owners
}

/// Extract the inode number from a `socket:[12345]` symlink target.
fn parse_socket_inode(target: &str) -> Option<u64> {
    let inner = target.strip_prefix("socket:[")?.strip_suffix(']')?;
    inner.parse().ok()
}

fn process_name(root: &std::path::Path, pid: u32) -> Option<String> {
    fs::read_to_string(root.join("proc").join(pid.to_string()).join("comm"))
        .ok()
        .map(|s| s.trim().to_string())
}

/// Reads the listening-socket tables from a `/proc`-shaped directory
/// tree. Defaults to the real `/proc`; [`LinuxSource::with_root`] points
/// it at a fixture tree instead, which is how the tests below exercise
/// the full scan pipeline - file walking included - without needing to
/// run on an actual Linux kernel.
pub struct LinuxSource {
    root: std::path::PathBuf,
}

impl Default for LinuxSource {
    fn default() -> Self {
        LinuxSource {
            root: std::path::PathBuf::from("/"),
        }
    }
}

impl LinuxSource {
    #[must_use]
    pub fn with_root(root: impl Into<std::path::PathBuf>) -> Self {
        LinuxSource { root: root.into() }
    }
}

impl PortSource for LinuxSource {
    fn scan(&self) -> io::Result<Vec<PortEntry>> {
        let owners = socket_owners(&self.root);
        let mut name_cache: HashMap<u32, Option<String>> = HashMap::new();
        let mut entries = Vec::new();

        let files: [(&str, Protocol, bool); 4] = [
            ("tcp", Protocol::Tcp, false),
            ("tcp6", Protocol::Tcp, true),
            ("udp", Protocol::Udp, false),
            ("udp6", Protocol::Udp, true),
        ];

        let mut any_ok = false;
        let mut last_err = None;
        for (name, protocol, v6) in files {
            match fs::read_to_string(self.root.join("proc/net").join(name)) {
                Ok(content) => {
                    any_ok = true;
                    for raw in parse_proc_net(&content, v6) {
                        let pid = owners.get(&raw.inode).copied();
                        let process_name = pid.and_then(|p| {
                            name_cache
                                .entry(p)
                                .or_insert_with(|| process_name(&self.root, p))
                                .clone()
                        });
                        entries.push(PortEntry {
                            protocol,
                            local_addr: raw.local_addr,
                            local_port: raw.local_port,
                            state: matches!(protocol, Protocol::Tcp)
                                .then(|| TcpState::from_linux_code(raw.state)),
                            pid,
                            process_name,
                        });
                    }
                }
                Err(e) => last_err = Some(e),
            }
        }

        if !any_ok {
            if let Some(e) = last_err {
                return Err(e);
            }
        }
        Ok(entries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TCP_HEADER: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode";

    #[test]
    fn parses_ipv4_loopback() {
        assert_eq!(parse_ipv4_hex("0100007F"), Some(Ipv4Addr::LOCALHOST));
    }

    #[test]
    fn parses_ipv4_any() {
        assert_eq!(parse_ipv4_hex("00000000"), Some(Ipv4Addr::UNSPECIFIED));
    }

    #[test]
    fn rejects_wrong_length_ipv4_hex() {
        assert_eq!(parse_ipv4_hex("ABCD"), None);
    }

    #[test]
    fn parses_ipv6_unspecified() {
        assert_eq!(
            parse_ipv6_hex("0000000000000000000000000000000000"),
            None,
            "34 hex chars is the wrong length and must be rejected"
        );
        let all_zero_32 = "0".repeat(32);
        assert_eq!(parse_ipv6_hex(&all_zero_32), Some(Ipv6Addr::UNSPECIFIED));
    }

    #[test]
    fn parses_ipv6_loopback() {
        // ::1 as four 8-hex-char words, each the byte-reversed form of
        // the word's 4 real address bytes: word0=00000000 word1=00000000
        // word2=00000000 word3=01000000 (the address's real last byte,
        // 0x01, is written first within its own little-endian word).
        let hex = ["00000000", "00000000", "00000000", "01000000"].concat();
        assert_eq!(hex.len(), 32);
        assert_eq!(parse_ipv6_hex(&hex), Some(Ipv6Addr::LOCALHOST));
    }

    #[test]
    fn parses_addr_port_field() {
        let (addr, port) = parse_addr_port("0100007F:1F90", false).unwrap();
        assert_eq!(addr, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(port, 8080);
    }

    #[test]
    fn parse_addr_port_rejects_missing_colon() {
        assert!(parse_addr_port("0100007F", false).is_none());
    }

    #[test]
    fn parses_single_listening_tcp_row() {
        let content = format!(
            "{TCP_HEADER}\n   0: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0"
        );
        let rows = parse_proc_net(&content, false);
        assert_eq!(rows.len(), 1);
        let r = &rows[0];
        assert_eq!(r.local_addr, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(r.local_port, 8080);
        assert_eq!(r.state, 0x0A);
        assert_eq!(r.inode, 12345);
    }

    #[test]
    fn skips_header_and_blank_lines() {
        let content = format!("{TCP_HEADER}\n\n");
        assert_eq!(parse_proc_net(&content, false).len(), 0);
    }

    #[test]
    fn skips_malformed_rows_without_panicking() {
        let content = format!("{TCP_HEADER}\n   0: not-a-valid-row\n");
        assert_eq!(parse_proc_net(&content, false).len(), 0);
    }

    #[test]
    fn parses_multiple_rows_with_mixed_states() {
        let content = format!(
            "{TCP_HEADER}\n\
             0: 0100007F:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 111 1 0 100 0 0 10 0\n\
             1: 0100007F:0050 0100007F:8000 01 00000000:00000000 00:00000000 00000000     0        0 222 1 0 100 0 0 10 0\n"
        );
        let rows = parse_proc_net(&content, false);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].local_port, 22);
        assert_eq!(rows[0].state, 0x0A);
        assert_eq!(rows[1].local_port, 80);
        assert_eq!(rows[1].state, 0x01);
    }

    #[test]
    fn parse_socket_inode_extracts_number() {
        assert_eq!(parse_socket_inode("socket:[98765]"), Some(98765));
        assert_eq!(parse_socket_inode("/dev/null"), None);
        assert_eq!(parse_socket_inode("socket:[abc]"), None);
    }

    /// Exercises the whole `LinuxSource` pipeline - reading the four
    /// `/proc/net/*` files, walking `/proc/<pid>/fd`, and resolving
    /// `/proc/<pid>/comm` - against a fixture tree that stands in for a
    /// real `/proc`, so the file-system plumbing is under test on every
    /// CI runner regardless of its actual operating system.
    /// See `tests/fixtures/linux/root/README.md` for the fixture's story.
    #[test]
    fn full_scan_over_fixture_proc_tree_resolves_known_sockets() {
        let root =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/linux/root");
        let source = LinuxSource::with_root(root);
        let entries = source.scan().expect("fixture scan should succeed");

        // 11 rows total across tcp(5) + tcp6(2) + udp(3) + udp6(1).
        assert_eq!(entries.len(), 11);

        let find = |proto: Protocol, addr: &str, port: u16| {
            entries
                .iter()
                .find(|e| {
                    e.protocol == proto && e.local_addr.to_string() == addr && e.local_port == port
                })
                .unwrap_or_else(|| panic!("missing {proto}/{addr}:{port}"))
        };

        // systemd-resolved's stub resolver: TCP and UDP 127.0.0.53:53,
        // both attributed to pid 812 via inode 25142 / 25143.
        let tcp_resolved = find(Protocol::Tcp, "127.0.0.53", 53);
        assert_eq!(tcp_resolved.pid, Some(812));
        assert_eq!(
            tcp_resolved.process_name.as_deref(),
            Some("systemd-resolve")
        );
        assert_eq!(tcp_resolved.state, Some(TcpState::Listen));

        let udp_resolved = find(Protocol::Udp, "127.0.0.53", 53);
        assert_eq!(udp_resolved.pid, Some(812));
        assert_eq!(
            udp_resolved.process_name.as_deref(),
            Some("systemd-resolve")
        );

        // postgres on the loopback-only default port, via inode 31980 in
        // pid 1103's fd table.
        let pg = find(Protocol::Tcp, "127.0.0.1", 5432);
        assert_eq!(pg.pid, Some(1103));
        assert_eq!(pg.process_name.as_deref(), Some("postgres"));

        // sshd's socket (inode 22765) has no owning fd in the fixture,
        // which is what an unprivileged scan looks like for a process
        // whose fds you can't read.
        let sshd = find(Protocol::Tcp, "0.0.0.0", 22);
        assert_eq!(sshd.pid, None);
        assert_eq!(sshd.process_name, None);
        assert_eq!(sshd.state, Some(TcpState::Listen));

        // An IPv4-mapped IPv6 address in the tcp6 table parses correctly.
        let mapped = find(Protocol::Tcp, "::ffff:127.0.0.1", 6268);
        assert_eq!(mapped.pid, None);

        // The one non-LISTEN row (an ESTABLISHED outbound connection)
        // is still returned by scan() - filtering to "is listening" is
        // the diff engine's job, not the source's.
        let established = entries
            .iter()
            .find(|e| e.state == Some(TcpState::Established))
            .expect("established row present");
        assert_eq!(established.local_port, 0xC1B2);
    }
}
