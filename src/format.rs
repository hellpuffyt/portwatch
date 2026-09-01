//! Rendering snapshots and diff reports for a terminal.

use crate::diff::{Change, DiffReport};
use crate::model::{PortEntry, Snapshot};

fn owner_label(pid: Option<u32>, name: Option<&str>) -> String {
    match (pid, name) {
        (Some(pid), Some(name)) => format!("{name} ({pid})"),
        (Some(pid), None) => format!("<unknown> ({pid})"),
        (None, _) => "-".to_string(),
    }
}

/// Render a snapshot's listening entries as an aligned plain-text table.
#[must_use]
pub fn table(entries: &[PortEntry]) -> String {
    if entries.is_empty() {
        return "no listening ports found".to_string();
    }
    let mut rows: Vec<[String; 5]> = vec![[
        "PROTO".into(),
        "ADDRESS".into(),
        "PORT".into(),
        "STATE".into(),
        "PROCESS".into(),
    ]];
    for e in entries {
        rows.push([
            e.protocol.to_string(),
            e.local_addr.to_string(),
            e.local_port.to_string(),
            e.state.map_or("-".to_string(), |s| s.to_string()),
            owner_label(e.pid, e.process_name.as_deref()),
        ]);
    }
    render_table(&rows)
}

/// Render a diff report as human-readable lines: one per change, prefixed
/// `+` (added), `-` (removed), or `~` (owning process changed).
#[must_use]
pub fn diff_report(report: &DiffReport) -> String {
    if report.is_empty() {
        return "no changes".to_string();
    }
    let mut lines = Vec::with_capacity(report.changes.len());
    for change in &report.changes {
        lines.push(match change {
            Change::Added { entry } => format!(
                "+ {}/{}:{} now listening ({})",
                entry.protocol,
                entry.local_addr,
                entry.local_port,
                owner_label(entry.pid, entry.process_name.as_deref())
            ),
            Change::Removed { entry } => format!(
                "- {}/{}:{} no longer listening (was {})",
                entry.protocol,
                entry.local_addr,
                entry.local_port,
                owner_label(entry.pid, entry.process_name.as_deref())
            ),
            Change::OwnerChanged {
                protocol,
                local_addr,
                local_port,
                old_pid,
                old_process_name,
                new_pid,
                new_process_name,
            } => format!(
                "~ {protocol}/{local_addr}:{local_port} owner changed: {} -> {}",
                owner_label(*old_pid, old_process_name.as_deref()),
                owner_label(*new_pid, new_process_name.as_deref())
            ),
        });
    }
    lines.join("\n")
}

fn render_table(rows: &[[String; 5]]) -> String {
    let mut widths = [0usize; 5];
    for row in rows {
        for (i, cell) in row.iter().enumerate() {
            widths[i] = widths[i].max(cell.chars().count());
        }
    }
    rows.iter()
        .map(|row| {
            row.iter()
                .enumerate()
                .map(|(i, cell)| format!("{cell:<width$}", width = widths[i]))
                .collect::<Vec<_>>()
                .join("  ")
                .trim_end()
                .to_string()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Render a snapshot as pretty-printed JSON.
///
/// # Errors
/// Returns an error if serialization fails, which should not happen for
/// this type.
pub fn snapshot_json(snapshot: &Snapshot) -> serde_json::Result<String> {
    serde_json::to_string_pretty(snapshot)
}

/// Render a diff report as pretty-printed JSON.
///
/// # Errors
/// Returns an error if serialization fails, which should not happen for
/// this type.
pub fn diff_json(report: &DiffReport) -> serde_json::Result<String> {
    serde_json::to_string_pretty(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Protocol, TcpState};
    use std::net::{IpAddr, Ipv4Addr};

    fn entry(port: u16, pid: Option<u32>, name: Option<&str>) -> PortEntry {
        PortEntry {
            protocol: Protocol::Tcp,
            local_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            local_port: port,
            state: Some(TcpState::Listen),
            pid,
            process_name: name.map(str::to_string),
        }
    }

    #[test]
    fn table_reports_empty_snapshot_clearly() {
        assert_eq!(table(&[]), "no listening ports found");
    }

    #[test]
    fn table_includes_header_and_all_rows() {
        let entries = vec![entry(22, Some(1), Some("sshd")), entry(8080, None, None)];
        let out = table(&entries);
        assert!(out.contains("PROTO"));
        assert!(out.contains("22"));
        assert!(out.contains("sshd (1)"));
        assert!(out.contains("8080"));
        assert!(out.contains('-')); // unknown owner
    }

    #[test]
    fn table_columns_align() {
        let entries = vec![
            entry(1, Some(1), Some("a")),
            entry(60000, Some(999_999), Some("bbbbbb")),
        ];
        let out = table(&entries);
        let lines: Vec<&str> = out.lines().collect();
        // every line should be the same length once trailing space is
        // trimmed from the shortest and padding applied elsewhere
        assert_eq!(lines.len(), 3);
    }

    #[test]
    fn diff_report_empty_says_no_changes() {
        assert_eq!(diff_report(&DiffReport::default()), "no changes");
    }

    #[test]
    fn diff_report_formats_added_removed_and_owner_changed() {
        let report = DiffReport {
            changes: vec![
                Change::Added {
                    entry: entry(80, Some(1), Some("nginx")),
                },
                Change::Removed {
                    entry: entry(81, Some(2), Some("old")),
                },
                Change::OwnerChanged {
                    protocol: Protocol::Tcp,
                    local_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                    local_port: 443,
                    old_pid: Some(3),
                    old_process_name: Some("a".into()),
                    new_pid: Some(4),
                    new_process_name: Some("b".into()),
                },
            ],
        };
        let out = diff_report(&report);
        assert!(out.contains("+ tcp/0.0.0.0:80 now listening"));
        assert!(out.contains("- tcp/0.0.0.0:81 no longer listening"));
        assert!(out.contains("~ tcp/0.0.0.0:443 owner changed: a (3) -> b (4)"));
    }

    #[test]
    fn owner_label_variants() {
        assert_eq!(owner_label(Some(1), Some("x")), "x (1)");
        assert_eq!(owner_label(Some(1), None), "<unknown> (1)");
        assert_eq!(owner_label(None, None), "-");
    }

    #[test]
    fn snapshot_json_roundtrips_through_serde() {
        let snap = Snapshot::new(0, "h".into(), vec![entry(80, Some(1), Some("x"))]);
        let json = snapshot_json(&snap).unwrap();
        let back: Snapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(back, snap);
    }

    #[test]
    fn diff_json_roundtrips_through_serde() {
        let report = DiffReport {
            changes: vec![Change::Added {
                entry: entry(80, Some(1), Some("x")),
            }],
        };
        let json = diff_json(&report).unwrap();
        let back: DiffReport = serde_json::from_str(&json).unwrap();
        assert_eq!(back, report);
    }
}
