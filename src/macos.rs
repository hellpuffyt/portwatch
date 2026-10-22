//! macOS port source. Darwin has no public syscall table equivalent to
//! Linux's `/proc/net/*` or Windows' `GetExtendedTcpTable`, so the
//! practical way every user-space tool (including Activity Monitor's
//! "Open Files and Ports" view) gets this information is by asking
//! `lsof`, which already has the private-framework access needed to
//! resolve socket ownership. portwatch runs `lsof -nP -iTCP` and
//! `lsof -nP -iUDP` separately (rather than combining them with `-i` and
//! trying to tell the protocols apart after the fact) and parses the
//! normal human-readable columns.
//!
//! Parsing those columns by position rather than a fixed byte offset
//! keeps the parser robust to column widths. `lsof` prints spaces and
//! other non-printable bytes in the `COMMAND` column as `\xNN` escapes
//! (`Brave\x20Browser`), which `unescape_lsof` decodes, and is invoked
//! with `+c 0` so the name is not truncated to its default 9 characters.
//! `parse_line` still peels known single-token fields off the *end* of the
//! line and treats whatever remains at the start as the command name.
//! UDP rows with a peer (`local->remote`) are connected client sockets and
//! are skipped.
//!
//! The parser is pure and fixture-tested below against real captured
//! `lsof` output (`tests/fixtures/macos/`). The `Command` invocation
//! itself in [`MacosSource::scan`] is a thin, direct wrapper around it.

use crate::model::{PortEntry, Protocol, TcpState};
use crate::source::PortSource;
use std::io;
use std::net::IpAddr;
use std::process::Command;

/// Parse one data line of `lsof -nP -iTCP` / `-iUDP` output (the header
/// line is filtered out by the caller). Returns `None` for a line that
/// doesn't look like a network socket row - `lsof` output is otherwise
/// stable, but being defensive here means a future `lsof` quirk degrades
/// to "one fewer row" instead of a panic.
fn parse_line(line: &str, protocol: Protocol) -> Option<PortEntry> {
    let mut tokens: Vec<&str> = line.split_whitespace().collect();
    if tokens.len() < 8 {
        return None;
    }

    // Peel the optional "(LISTEN)"/"(ESTABLISHED)"/etc. state suffix.
    let state_token = if tokens
        .last()
        .is_some_and(|t| t.starts_with('(') && t.ends_with(')'))
    {
        tokens.pop()
    } else {
        None
    };
    let name = tokens.pop()?;
    let node = tokens.pop()?; // "TCP" or "UDP"
    let _size_off = tokens.pop()?;
    let _device = tokens.pop()?;
    let file_type = tokens.pop()?; // "IPv4" / "IPv6"
    let _fd = tokens.pop()?;
    let _user = tokens.pop()?;
    let pid_token = tokens.pop()?;
    if tokens.is_empty() {
        return None; // no COMMAND left
    }
    let command = unescape_lsof(&tokens.join(" "));

    let line_protocol = match node {
        "TCP" => Protocol::Tcp,
        "UDP" => Protocol::Udp,
        _ => return None,
    };
    if line_protocol != protocol {
        return None;
    }

    let pid: u32 = pid_token.parse().ok()?;
    let (local, remote) = name
        .split_once("->")
        .map_or((name, None), |(l, r)| (l, Some(r)));
    // A UDP socket with a peer (`local->remote`) is a connected client
    // socket - a DNS query, a QUIC connection - not something listening.
    // Counting those made every scan on a machine with a browser open
    // differ from the last one.
    if protocol == Protocol::Udp && remote.is_some() {
        return None;
    }
    let (mut addr, port) = parse_endpoint(local)?;
    // lsof prints the wildcard as `*` for both families; the TYPE column
    // says which one it is. Without this an IPv6 `[::]:22` listener was
    // reported as a second `0.0.0.0:22` row.
    if file_type == "IPv6"
        && addr == IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
        && local.starts_with('*')
    {
        addr = IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED);
    }

    let state = state_token
        .and_then(|t| t.strip_prefix('(').and_then(|t| t.strip_suffix(')')))
        .map(parse_tcp_state_word);

    Some(PortEntry {
        protocol,
        local_addr: addr,
        local_port: port,
        state: matches!(protocol, Protocol::Tcp).then(|| state.unwrap_or(TcpState::Unknown(0))),
        pid: Some(pid),
        process_name: Some(command),
    })
}

/// Undo `lsof`'s escaping of the COMMAND column: non-printable bytes,
/// *including spaces*, are printed as `\xNN` (so `Brave Browser` arrives
/// as `Brave\x20Browser`). Anything that is not a well-formed `\xNN`
/// sequence is kept verbatim.
fn unescape_lsof(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && bytes.get(i + 1) == Some(&b'x') {
            if let Some(b) = bytes
                .get(i + 2..i + 4)
                .filter(|h| h.iter().all(u8::is_ascii_hexdigit))
                .and_then(|h| std::str::from_utf8(h).ok())
                .and_then(|h| u8::from_str_radix(h, 16).ok())
            {
                out.push(b);
                i += 4;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Parse a `host:port` endpoint as `lsof` prints it: `*:8080`,
/// `127.0.0.1:5432`, or `[::1]:631` for IPv6.
fn parse_endpoint(s: &str) -> Option<(IpAddr, u16)> {
    let (addr_part, port_part) = s.rsplit_once(':')?;
    let port: u16 = port_part.parse().ok()?;
    let addr: IpAddr = if addr_part == "*" {
        IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
    } else if let Some(stripped) = addr_part
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
    {
        stripped.parse().ok()?
    } else {
        addr_part.parse().ok()?
    };
    Some((addr, port))
}

fn parse_tcp_state_word(word: &str) -> TcpState {
    match word {
        "LISTEN" => TcpState::Listen,
        "ESTABLISHED" => TcpState::Established,
        "SYN_SENT" => TcpState::SynSent,
        "SYN_RECEIVED" => TcpState::SynRecv,
        "FIN_WAIT_1" => TcpState::FinWait1,
        "FIN_WAIT_2" => TcpState::FinWait2,
        "TIME_WAIT" => TcpState::TimeWait,
        "CLOSED" => TcpState::Close,
        "CLOSE_WAIT" => TcpState::CloseWait,
        "LAST_ACK" => TcpState::LastAck,
        "CLOSING" => TcpState::Closing,
        _ => TcpState::Unknown(0),
    }
}

/// Parse the full output of an `lsof -nP -iTCP` or `-iUDP` invocation.
fn parse_lsof_output(output: &str, protocol: Protocol) -> Vec<PortEntry> {
    output
        .lines()
        .skip(1) // header: "COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME"
        .filter_map(|line| parse_line(line, protocol))
        .collect()
}

/// Where macOS ships `lsof`.
const SYSTEM_LSOF: &str = "/usr/sbin/lsof";

fn run_lsof(proto_flag: &str) -> io::Result<String> {
    // Prefer the system binary over a PATH lookup: portwatch is often run
    // as root from cron, where a writable directory early in PATH would
    // otherwise decide what gets executed.
    let lsof = if std::path::Path::new(SYSTEM_LSOF).exists() {
        SYSTEM_LSOF
    } else {
        "lsof"
    };
    // `+c 0` asks for the full command name; by default lsof truncates it
    // to 9 characters (`com.docke`, `Brave\x20`).
    let output = Command::new(lsof)
        .args(["+c", "0", "-nP", proto_flag])
        .output()?;
    // lsof exits 1 when it finds nothing to list, which is a normal
    // "no matching sockets" result, not a failure - only a missing
    // binary or a genuine crash (signal, code >1) is an error.
    if !output.status.success() && output.status.code() != Some(1) {
        return Err(io::Error::other(format!(
            "lsof exited with status {:?}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

pub struct MacosSource;

impl PortSource for MacosSource {
    fn scan(&self) -> io::Result<Vec<PortEntry>> {
        let mut entries = Vec::new();
        entries.extend(parse_lsof_output(&run_lsof("-iTCP")?, Protocol::Tcp));
        entries.extend(parse_lsof_output(&run_lsof("-iUDP")?, Protocol::Udp));
        Ok(entries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    const FIXTURE_TCP: &str = include_str!("../tests/fixtures/macos/lsof-tcp.txt");
    const FIXTURE_UDP: &str = include_str!("../tests/fixtures/macos/lsof-udp.txt");

    #[test]
    fn parse_endpoint_wildcard() {
        assert_eq!(
            parse_endpoint("*:8080"),
            Some((IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8080))
        );
    }

    #[test]
    fn parse_endpoint_ipv4() {
        assert_eq!(
            parse_endpoint("127.0.0.1:5432"),
            Some((IpAddr::V4(Ipv4Addr::LOCALHOST), 5432))
        );
    }

    #[test]
    fn parse_endpoint_bracketed_ipv6() {
        assert_eq!(
            parse_endpoint("[::1]:631"),
            Some((IpAddr::V6(Ipv6Addr::LOCALHOST), 631))
        );
    }

    #[test]
    fn parse_endpoint_rejects_missing_port() {
        assert_eq!(parse_endpoint("127.0.0.1"), None);
    }

    #[test]
    fn real_lsof_tcp_fixture_parses_every_listening_row() {
        let entries = parse_lsof_output(FIXTURE_TCP, Protocol::Tcp);
        // 9 data rows in the fixture, all TCP.
        assert_eq!(entries.len(), 9);
        assert!(entries.iter().all(|e| e.protocol == Protocol::Tcp));
    }

    #[test]
    fn command_names_with_spaces_are_parsed_whole() {
        let entries = parse_lsof_output(FIXTURE_TCP, Protocol::Tcp);
        let chrome = entries
            .iter()
            .find(|e| e.pid == Some(812))
            .expect("Google Chrome Helper row present");
        assert_eq!(chrome.process_name.as_deref(), Some("Google Chrome Helper"));

        let docker = entries
            .iter()
            .find(|e| e.pid == Some(5001))
            .expect("com.docker.backend row present");
        assert_eq!(docker.process_name.as_deref(), Some("com.docker.backend"));
    }

    #[test]
    fn established_connection_state_is_captured() {
        let entries = parse_lsof_output(FIXTURE_TCP, Protocol::Tcp);
        let chrome = entries.iter().find(|e| e.pid == Some(812)).unwrap();
        assert_eq!(chrome.state, Some(TcpState::Established));
        assert!(!chrome.is_listening());
    }

    #[test]
    fn ipv6_loopback_row_parses_correctly() {
        let entries = parse_lsof_output(FIXTURE_TCP, Protocol::Tcp);
        let cups_v6 = entries
            .iter()
            .find(|e| e.pid == Some(177) && e.local_addr == IpAddr::V6(Ipv6Addr::LOCALHOST))
            .expect("cupsd IPv6 row present");
        assert_eq!(cups_v6.local_port, 631);
        assert_eq!(cups_v6.process_name.as_deref(), Some("cupsd"));
        assert_eq!(cups_v6.state, Some(TcpState::Listen));
    }

    #[test]
    fn real_lsof_udp_fixture_parses_every_row() {
        let entries = parse_lsof_output(FIXTURE_UDP, Protocol::Udp);
        assert_eq!(entries.len(), 3);
        assert!(entries.iter().all(|e| e.protocol == Protocol::Udp));
        assert!(entries.iter().all(|e| e.state.is_none()));
        let mdns = entries
            .iter()
            .find(|e| e.local_port == 5353 && e.local_addr.is_ipv4());
        assert!(mdns.is_some());
    }

    #[test]
    fn tcp_parser_ignores_udp_rows_and_vice_versa() {
        // Feeding the TCP fixture through the UDP parser should yield
        // nothing, since every NODE token in it is "TCP".
        assert_eq!(parse_lsof_output(FIXTURE_TCP, Protocol::Udp).len(), 0);
        assert_eq!(parse_lsof_output(FIXTURE_UDP, Protocol::Tcp).len(), 0);
    }

    #[test]
    fn short_line_is_ignored_without_panicking() {
        assert_eq!(parse_line("too short", Protocol::Tcp), None);
    }

    #[test]
    fn line_with_unparseable_pid_is_ignored() {
        let line = "launchd notapid root 6u IPv4 0x1 0t0 TCP *:22 (LISTEN)";
        assert_eq!(parse_line(line, Protocol::Tcp), None);
    }

    #[test]
    fn lsof_escaped_command_names_are_decoded() {
        // lsof prints spaces in COMMAND as `\x20` (observed on macOS 27).
        let line =
            "Brave\\x20Browser\\x20Helper 850 user 26u IPv4 0x8770d152b0ff638a 0t0 UDP *:5353";
        let e = parse_line(line, Protocol::Udp).expect("parses");
        assert_eq!(e.process_name.as_deref(), Some("Brave Browser Helper"));
        assert_eq!(e.local_port, 5353);
        assert_eq!(
            unescape_lsof("a\\xZZb\\x4"),
            "a\\xZZb\\x4",
            "malformed escapes kept"
        );
        assert_eq!(
            unescape_lsof("a\\x+1b"),
            "a\\x+1b",
            "sign is not a hex digit"
        );
    }

    #[test]
    fn connected_udp_rows_are_not_listeners() {
        let connected = "Brave\\x20Browser 850 user 34u IPv4 0xdb66b2f92c2f8126 0t0 UDP 192.168.1.108:65418->160.79.104.10:443";
        assert_eq!(parse_line(connected, Protocol::Udp), None);
        let unbound = "identityservicesd 639 user 10u IPv4 0xc4840c563a9d8c9d 0t0 UDP *:*";
        assert_eq!(parse_line(unbound, Protocol::Udp), None);
        // TCP rows with a peer are still parsed; `is_listening` filters them.
        let tcp = "curl 4242 user 5u IPv4 0x1 0t0 TCP 10.0.0.2:50000->10.0.0.1:443 (ESTABLISHED)";
        assert_eq!(
            parse_line(tcp, Protocol::Tcp).and_then(|e| e.state),
            Some(TcpState::Established)
        );
    }

    #[test]
    fn ipv6_wildcard_is_not_reported_as_ipv4() {
        let entries = parse_lsof_output(FIXTURE_TCP, Protocol::Tcp);
        let ssh: Vec<_> = entries.iter().filter(|e| e.local_port == 22).collect();
        assert_eq!(ssh.len(), 2);
        assert!(ssh
            .iter()
            .any(|e| e.local_addr == IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
        assert!(ssh
            .iter()
            .any(|e| e.local_addr == IpAddr::V6(Ipv6Addr::UNSPECIFIED)));
    }
}
