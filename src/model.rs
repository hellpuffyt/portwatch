//! Core data model: a listening-port entry and a snapshot of the machine's
//! listening sockets at one point in time.

use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::fmt;
use std::net::IpAddr;

/// Transport-layer protocol a socket is bound on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Protocol::Tcp => write!(f, "tcp"),
            Protocol::Udp => write!(f, "udp"),
        }
    }
}

/// TCP connection state, as reported by the kernel. UDP sockets have no
/// connection state and are always represented as `None` on a `PortEntry`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TcpState {
    Listen,
    Established,
    SynSent,
    SynRecv,
    FinWait1,
    FinWait2,
    TimeWait,
    Close,
    CloseWait,
    LastAck,
    Closing,
    NewSynRecv,
    Unknown(u32),
}

impl TcpState {
    /// Parse the hex state code used in `/proc/net/tcp*` (also mirrored by
    /// the Windows `MIB_TCP_STATE` enum's numeric values for the states
    /// they share).
    #[must_use]
    pub fn from_linux_code(code: u32) -> Self {
        match code {
            0x01 => TcpState::Established,
            0x02 => TcpState::SynSent,
            0x03 => TcpState::SynRecv,
            0x04 => TcpState::FinWait1,
            0x05 => TcpState::FinWait2,
            0x06 => TcpState::TimeWait,
            0x07 => TcpState::Close,
            0x08 => TcpState::CloseWait,
            0x09 => TcpState::LastAck,
            0x0A => TcpState::Listen,
            0x0B => TcpState::Closing,
            0x0C => TcpState::NewSynRecv,
            other => TcpState::Unknown(other),
        }
    }

    #[must_use]
    pub fn is_listening(self) -> bool {
        matches!(self, TcpState::Listen)
    }

    /// Map the `MIB_TCP_STATE` values used by the Windows IP Helper API
    /// (`GetExtendedTcpTable`), which use a different numbering than
    /// Linux's `/proc/net/tcp`.
    #[must_use]
    pub fn from_windows_code(code: u32) -> Self {
        match code {
            // 1 = CLOSED, 12 = DELETE_TCB: both mean "not a live socket
            // anymore" for our purposes, so they share a variant.
            1 | 12 => TcpState::Close,
            2 => TcpState::Listen,
            3 => TcpState::SynSent,
            4 => TcpState::SynRecv,
            5 => TcpState::Established,
            6 => TcpState::FinWait1,
            7 => TcpState::FinWait2,
            8 => TcpState::CloseWait,
            9 => TcpState::Closing,
            10 => TcpState::LastAck,
            11 => TcpState::TimeWait,
            other => TcpState::Unknown(other),
        }
    }
}

impl fmt::Display for TcpState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            TcpState::Listen => "LISTEN",
            TcpState::Established => "ESTABLISHED",
            TcpState::SynSent => "SYN_SENT",
            TcpState::SynRecv => "SYN_RECV",
            TcpState::FinWait1 => "FIN_WAIT1",
            TcpState::FinWait2 => "FIN_WAIT2",
            TcpState::TimeWait => "TIME_WAIT",
            TcpState::Close => "CLOSE",
            TcpState::CloseWait => "CLOSE_WAIT",
            TcpState::LastAck => "LAST_ACK",
            TcpState::Closing => "CLOSING",
            TcpState::NewSynRecv => "NEW_SYN_RECV",
            TcpState::Unknown(code) => return write!(f, "UNKNOWN({code})"),
        };
        write!(f, "{s}")
    }
}

/// One listening (or, for TCP, otherwise-live) socket and whatever the
/// operating system was willing to tell us about the process that owns it.
///
/// `pid` and `process_name` are `None` when the lookup could not be
/// completed - typically because the socket is owned by a process the
/// caller does not have permission to inspect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortEntry {
    pub protocol: Protocol,
    pub local_addr: IpAddr,
    pub local_port: u16,
    /// `None` for UDP sockets, which have no connection state.
    pub state: Option<TcpState>,
    pub pid: Option<u32>,
    pub process_name: Option<String>,
}

impl PortEntry {
    /// The identity used to match an entry across two snapshots: protocol,
    /// bind address and port. Two entries with the same key but a
    /// different `pid`/`process_name` represent the same socket changing
    /// owner between scans, which is exactly the signal portwatch exists
    /// to surface.
    #[must_use]
    pub fn key(&self) -> (Protocol, IpAddr, u16) {
        (self.protocol, self.local_addr, self.local_port)
    }

    #[must_use]
    pub fn is_listening(&self) -> bool {
        match self.protocol {
            Protocol::Udp => true,
            Protocol::Tcp => self.state.is_some_and(TcpState::is_listening),
        }
    }
}

impl PartialOrd for PortEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PortEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        self.key().cmp(&other.key())
    }
}

/// A full capture of listening sockets at one instant, plus enough context
/// to know where and when it was taken.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    /// Seconds since the Unix epoch (UTC). Stored as an integer rather
    /// than a formatted string so equality and ordering stay exact.
    pub captured_at_unix: u64,
    pub hostname: String,
    pub entries: Vec<PortEntry>,
}

impl Snapshot {
    #[must_use]
    pub fn new(captured_at_unix: u64, hostname: String, mut entries: Vec<PortEntry>) -> Self {
        entries.sort();
        Snapshot {
            captured_at_unix,
            hostname,
            entries,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn entry(port: u16, pid: Option<u32>) -> PortEntry {
        PortEntry {
            protocol: Protocol::Tcp,
            local_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            local_port: port,
            state: Some(TcpState::Listen),
            pid,
            process_name: pid.map(|p| format!("proc{p}")),
        }
    }

    #[test]
    fn tcp_state_roundtrips_known_codes() {
        for code in 0x01u32..=0x0C {
            let state = TcpState::from_linux_code(code);
            assert!(!matches!(state, TcpState::Unknown(_)), "code {code:#x}");
        }
        assert_eq!(TcpState::from_linux_code(0xFF), TcpState::Unknown(0xFF));
    }

    #[test]
    fn windows_tcp_state_codes_map_to_known_states() {
        for code in 1u32..=12 {
            let state = TcpState::from_windows_code(code);
            assert!(!matches!(state, TcpState::Unknown(_)), "code {code}");
        }
        assert_eq!(TcpState::from_windows_code(2), TcpState::Listen);
        assert_eq!(TcpState::from_windows_code(5), TcpState::Established);
        assert_eq!(TcpState::from_windows_code(999), TcpState::Unknown(999));
    }

    #[test]
    fn listen_state_is_listening_others_are_not() {
        assert!(TcpState::Listen.is_listening());
        assert!(!TcpState::Established.is_listening());
        assert!(!TcpState::TimeWait.is_listening());
    }

    #[test]
    fn udp_entries_are_always_listening() {
        let mut e = entry(53, Some(1));
        e.protocol = Protocol::Udp;
        e.state = None;
        assert!(e.is_listening());
    }

    #[test]
    fn tcp_entry_listening_depends_on_state() {
        let mut e = entry(80, Some(1));
        assert!(e.is_listening());
        e.state = Some(TcpState::Established);
        assert!(!e.is_listening());
    }

    #[test]
    fn key_ignores_pid_and_process_name() {
        let a = entry(22, Some(1));
        let b = entry(22, Some(2));
        assert_eq!(a.key(), b.key());
        assert_ne!(a, b);
    }

    #[test]
    fn snapshot_new_sorts_entries_by_key() {
        let snap = Snapshot::new(
            0,
            "host".into(),
            vec![entry(443, Some(1)), entry(22, Some(2)), entry(80, Some(3))],
        );
        let ports: Vec<u16> = snap.entries.iter().map(|e| e.local_port).collect();
        assert_eq!(ports, vec![22, 80, 443]);
    }

    #[test]
    fn tcp_state_display_matches_conventional_names() {
        assert_eq!(TcpState::Listen.to_string(), "LISTEN");
        assert_eq!(TcpState::CloseWait.to_string(), "CLOSE_WAIT");
        assert_eq!(TcpState::Unknown(99).to_string(), "UNKNOWN(99)");
    }

    #[test]
    fn protocol_display() {
        assert_eq!(Protocol::Tcp.to_string(), "tcp");
        assert_eq!(Protocol::Udp.to_string(), "udp");
    }
}
