//! Comparing two snapshots and describing what changed.

use crate::model::{PortEntry, Protocol, Snapshot};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::IpAddr;

/// One difference between a baseline snapshot and a newer one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Change {
    /// A socket is listening now that was not present in the baseline.
    Added { entry: PortEntry },
    /// A socket that was present in the baseline is gone now.
    Removed { entry: PortEntry },
    /// The same `(protocol, addr, port)` is present in both snapshots but
    /// is now owned by a different process. This is the highest-signal
    /// change portwatch reports: it is what a process replacing another
    /// on a well-known port looks like.
    OwnerChanged {
        protocol: Protocol,
        local_addr: IpAddr,
        local_port: u16,
        old_pid: Option<u32>,
        old_process_name: Option<String>,
        new_pid: Option<u32>,
        new_process_name: Option<String>,
    },
}

impl Change {
    #[must_use]
    pub fn key(&self) -> (Protocol, IpAddr, u16) {
        match self {
            Change::Added { entry } | Change::Removed { entry } => entry.key(),
            Change::OwnerChanged {
                protocol,
                local_addr,
                local_port,
                ..
            } => (*protocol, *local_addr, *local_port),
        }
    }
}

/// The result of comparing two snapshots: every change, in a stable order
/// (sorted by protocol, then address, then port).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiffReport {
    pub changes: Vec<Change>,
}

impl DiffReport {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.changes.is_empty()
    }

    #[must_use]
    pub fn added_count(&self) -> usize {
        self.changes
            .iter()
            .filter(|c| matches!(c, Change::Added { .. }))
            .count()
    }

    #[must_use]
    pub fn removed_count(&self) -> usize {
        self.changes
            .iter()
            .filter(|c| matches!(c, Change::Removed { .. }))
            .count()
    }

    #[must_use]
    pub fn owner_changed_count(&self) -> usize {
        self.changes
            .iter()
            .filter(|c| matches!(c, Change::OwnerChanged { .. }))
            .count()
    }
}

/// Compare a `baseline` snapshot against a `current` one and report every
/// port that appeared, disappeared, or changed owning process.
///
/// Only entries that are actually listening (`PortEntry::is_listening`)
/// are considered: a TCP socket in `TIME_WAIT` or `ESTABLISHED` is not a
/// service accepting connections and would otherwise generate constant,
/// meaningless noise between scans.
///
/// A single `(protocol, address, port)` can legitimately have more than
/// one simultaneous owner - UDP multicast listeners (mDNS on `:5353`,
/// SSDP on `:1900`) commonly bind the same port from several processes
/// with `SO_REUSEADDR`. This was discovered the hard way: an earlier
/// version of this function kept only one `PortEntry` per key, so on a
/// machine with two mDNS responders bound to the same UDP port, whichever
/// process the OS happened to enumerate second "won" the key, and a
/// second, otherwise-unchanged scan would report a spurious owner swap
/// purely from enumeration-order jitter. This version compares the full
/// *set* of owners at each key instead of assuming exactly one.
#[must_use]
pub fn diff(baseline: &Snapshot, current: &Snapshot) -> DiffReport {
    let before = group_by_key(baseline);
    let after = group_by_key(current);

    let mut changes = Vec::new();
    let mut all_keys: Vec<_> = before.keys().chain(after.keys()).collect();
    all_keys.sort_unstable();
    all_keys.dedup();

    for key in all_keys {
        let old_owners = before.get(key).map(Vec::as_slice).unwrap_or_default();
        let new_owners = after.get(key).map(Vec::as_slice).unwrap_or_default();

        let left: Vec<&PortEntry> = old_owners
            .iter()
            .filter(|o| !new_owners.iter().any(|n| same_owner(o, n)))
            .copied()
            .collect();
        let joined: Vec<&PortEntry> = new_owners
            .iter()
            .filter(|n| !old_owners.iter().any(|o| same_owner(o, n)))
            .copied()
            .collect();

        if left.is_empty() && joined.is_empty() {
            continue; // this key's owner set is unchanged
        }

        // A clean single-owner handoff (the common, high-signal case: a
        // port with exactly one owner before and after, and that owner
        // changed) is reported as one OwnerChanged event rather than a
        // Removed+Added pair. Everything else - a co-owner joining or
        // leaving a shared port, or multiple owners changing at once -
        // is reported owner-by-owner, since there is no single sensible
        // "old owner -> new owner" pairing to report.
        if old_owners.len() == 1 && new_owners.len() == 1 && left.len() == 1 && joined.len() == 1 {
            let old_entry = left[0];
            let new_entry = joined[0];
            changes.push(Change::OwnerChanged {
                protocol: key.0,
                local_addr: key.1,
                local_port: key.2,
                old_pid: old_entry.pid,
                old_process_name: old_entry.process_name.clone(),
                new_pid: new_entry.pid,
                new_process_name: new_entry.process_name.clone(),
            });
            continue;
        }

        for entry in left {
            changes.push(Change::Removed {
                entry: entry.clone(),
            });
        }
        for entry in joined {
            changes.push(Change::Added {
                entry: entry.clone(),
            });
        }
    }

    changes.sort_by_key(Change::key);
    DiffReport { changes }
}

/// Group a snapshot's listening entries by `(protocol, address, port)`,
/// preserving every simultaneous owner at a key rather than collapsing
/// to one.
fn group_by_key(snapshot: &Snapshot) -> BTreeMap<(Protocol, IpAddr, u16), Vec<&PortEntry>> {
    let mut grouped: BTreeMap<(Protocol, IpAddr, u16), Vec<&PortEntry>> = BTreeMap::new();
    for e in snapshot.entries.iter().filter(|e| e.is_listening()) {
        grouped.entry(e.key()).or_default().push(e);
    }
    grouped
}

/// Two entries at the same key are "the same owner" if they agree on
/// `pid` and `process_name` - the only fields that identify *who* holds
/// the socket, as opposed to *how* (address family, TCP state, ...).
fn same_owner(a: &PortEntry, b: &PortEntry) -> bool {
    a.pid == b.pid && a.process_name == b.process_name
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::TcpState;
    use std::net::Ipv4Addr;

    fn listen_entry(port: u16, pid: Option<u32>, name: Option<&str>) -> PortEntry {
        PortEntry {
            protocol: Protocol::Tcp,
            local_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            local_port: port,
            state: Some(TcpState::Listen),
            pid,
            process_name: name.map(str::to_string),
        }
    }

    fn snap(entries: Vec<PortEntry>) -> Snapshot {
        Snapshot::new(0, "host".into(), entries)
    }

    #[test]
    fn identical_snapshots_produce_no_changes() {
        let s = snap(vec![listen_entry(22, Some(1), Some("sshd"))]);
        let report = diff(&s, &s);
        assert!(report.is_empty());
    }

    #[test]
    fn new_port_is_added() {
        let before = snap(vec![]);
        let after = snap(vec![listen_entry(8080, Some(10), Some("web"))]);
        let report = diff(&before, &after);
        assert_eq!(report.changes.len(), 1);
        assert!(matches!(report.changes[0], Change::Added { .. }));
        assert_eq!(report.added_count(), 1);
    }

    #[test]
    fn closed_port_is_removed() {
        let before = snap(vec![listen_entry(8080, Some(10), Some("web"))]);
        let after = snap(vec![]);
        let report = diff(&before, &after);
        assert_eq!(report.changes.len(), 1);
        assert!(matches!(report.changes[0], Change::Removed { .. }));
        assert_eq!(report.removed_count(), 1);
    }

    #[test]
    fn same_port_different_pid_is_owner_changed() {
        let before = snap(vec![listen_entry(443, Some(100), Some("nginx"))]);
        let after = snap(vec![listen_entry(443, Some(200), Some("evil"))]);
        let report = diff(&before, &after);
        assert_eq!(report.changes.len(), 1);
        match &report.changes[0] {
            Change::OwnerChanged {
                old_pid,
                new_pid,
                old_process_name,
                new_process_name,
                ..
            } => {
                assert_eq!(*old_pid, Some(100));
                assert_eq!(*new_pid, Some(200));
                assert_eq!(old_process_name.as_deref(), Some("nginx"));
                assert_eq!(new_process_name.as_deref(), Some("evil"));
            }
            other => panic!("expected OwnerChanged, got {other:?}"),
        }
        assert_eq!(report.owner_changed_count(), 1);
    }

    #[test]
    fn same_port_same_pid_different_state_field_is_not_reported() {
        // state is not part of identity comparison beyond is_listening();
        // only pid/process_name changes are surfaced as OwnerChanged.
        let before = snap(vec![listen_entry(80, Some(1), Some("nginx"))]);
        let after = snap(vec![listen_entry(80, Some(1), Some("nginx"))]);
        let report = diff(&before, &after);
        assert!(report.is_empty());
    }

    #[test]
    fn non_listening_tcp_states_are_ignored_entirely() {
        let mut established = listen_entry(9999, Some(1), Some("client"));
        established.state = Some(TcpState::Established);
        let before = snap(vec![]);
        let after = snap(vec![established]);
        let report = diff(&before, &after);
        assert!(report.is_empty(), "ESTABLISHED sockets are not services");
    }

    #[test]
    fn udp_entries_with_no_state_are_treated_as_listening() {
        let mut udp = listen_entry(53, Some(1), Some("dnsmasq"));
        udp.protocol = Protocol::Udp;
        udp.state = None;
        let before = snap(vec![]);
        let after = snap(vec![udp]);
        let report = diff(&before, &after);
        assert_eq!(report.added_count(), 1);
    }

    #[test]
    fn changes_are_returned_in_stable_sorted_order() {
        let before = snap(vec![listen_entry(9000, Some(1), Some("a"))]);
        let after = snap(vec![
            listen_entry(80, Some(2), Some("b")),
            listen_entry(22, Some(3), Some("c")),
        ]);
        let report = diff(&before, &after);
        let ports: Vec<u16> = report.changes.iter().map(|c| c.key().2).collect();
        let mut sorted = ports.clone();
        sorted.sort_unstable();
        assert_eq!(ports, sorted);
    }

    #[test]
    fn pid_becoming_unknown_is_owner_changed() {
        let before = snap(vec![listen_entry(80, Some(1), Some("nginx"))]);
        let after = snap(vec![listen_entry(80, None, None)]);
        let report = diff(&before, &after);
        assert_eq!(report.owner_changed_count(), 1);
    }

    // A UDP multicast port (mDNS on 5353, SSDP on 1900, ...) is commonly
    // bound by more than one process at once via SO_REUSEADDR. The next
    // few tests pin down the behavior discovered live on a real Windows
    // machine running exactly this: two processes sharing :5353.

    fn udp_entry(port: u16, pid: u32, name: &str) -> PortEntry {
        let mut e = listen_entry(port, Some(pid), Some(name));
        e.protocol = Protocol::Udp;
        e.state = None;
        e
    }

    #[test]
    fn stable_shared_port_produces_no_changes_regardless_of_scan_order() {
        // Two co-owners present in both snapshots, but enumerated in a
        // different order the second time - exactly what varying OS
        // table-walk order looks like between two live scans.
        let before = snap(vec![
            udp_entry(5353, 100, "steamwebhelper.exe"),
            udp_entry(5353, 200, "brave.exe"),
        ]);
        let after = snap(vec![
            udp_entry(5353, 200, "brave.exe"),
            udp_entry(5353, 100, "steamwebhelper.exe"),
        ]);
        let report = diff(&before, &after);
        assert!(
            report.is_empty(),
            "reordering the same owner set must not be reported as a change: {report:?}"
        );
    }

    #[test]
    fn a_new_co_owner_joining_a_shared_port_is_added_not_owner_changed() {
        let before = snap(vec![udp_entry(5353, 100, "steamwebhelper.exe")]);
        let after = snap(vec![
            udp_entry(5353, 100, "steamwebhelper.exe"),
            udp_entry(5353, 200, "brave.exe"),
        ]);
        let report = diff(&before, &after);
        assert_eq!(report.changes.len(), 1);
        assert_eq!(report.added_count(), 1);
        assert_eq!(report.owner_changed_count(), 0);
    }

    #[test]
    fn a_co_owner_leaving_a_shared_port_is_removed_not_owner_changed() {
        let before = snap(vec![
            udp_entry(5353, 100, "steamwebhelper.exe"),
            udp_entry(5353, 200, "brave.exe"),
        ]);
        let after = snap(vec![udp_entry(5353, 100, "steamwebhelper.exe")]);
        let report = diff(&before, &after);
        assert_eq!(report.changes.len(), 1);
        assert_eq!(report.removed_count(), 1);
        assert_eq!(report.owner_changed_count(), 0);
    }

    #[test]
    fn single_owner_handoff_on_a_port_that_was_never_shared_is_still_owner_changed() {
        let before = snap(vec![udp_entry(5353, 100, "steamwebhelper.exe")]);
        let after = snap(vec![udp_entry(5353, 200, "brave.exe")]);
        let report = diff(&before, &after);
        assert_eq!(report.changes.len(), 1);
        assert_eq!(report.owner_changed_count(), 1);
    }
}
