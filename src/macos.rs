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
//! Parsing those columns by position rather than a fixed byte offset is
//! required because the `COMMAND` column can itself contain spaces
//! (`"Google Chrome Helper"`, `com.docker.backend`) - see
//! [`parse_line`], which instead peels known single-token fields off the
//! *end* of the line and treats whatever remains at the start as the
//! command name.
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
    let _file_type = tokens.pop()?; // "IPv4" / "IPv6"
    let _fd = tokens.pop()?;
    let _user = tokens.pop()?;
    let pid_token = tokens.pop()?;
    if tokens.is_empty() {
        return None; // no COMMAND left
    }
    let command = tokens.join(" ");

    let line_protocol = match node {
        "TCP" => Protocol::Tcp,
        "UDP" => Protocol::Udp,
        _ => return None,
    };
    if line_protocol != protocol {
        return None;
    }

    let pid: u32 = pid_token.parse().ok()?;
    let (local, _remote) = name
        .split_once("->")
        .map_or((name, None), |(l, r)| (l, Some(r)));
    let (addr, port) = parse_endpoint(local)?;

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

fn run_lsof(proto_flag: &str) -> io::Result<String> {
    let output = Command::new("lsof").args(["-nP", proto_flag]).output()?;
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
}
