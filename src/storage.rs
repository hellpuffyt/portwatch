//! Persisting and loading snapshots, and appending diff results to an
//! optional history log.

use crate::diff::{Change, DiffReport};
use crate::model::Snapshot;
use crate::timefmt::format_unix;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{self, Write};
use std::path::Path;

/// Load a snapshot previously written by [`save_snapshot`].
///
/// # Errors
/// Returns an error if the file does not exist, cannot be read, or does
/// not contain valid snapshot JSON.
pub fn load_snapshot(path: &Path) -> io::Result<Snapshot> {
    let content = fs::read_to_string(path).map_err(|e| {
        if e.kind() == io::ErrorKind::NotFound {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "no snapshot found at {} - run `portwatch snapshot` first",
                    path.display()
                ),
            )
        } else {
            e
        }
    })?;
    serde_json::from_str(&content).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{} does not contain a valid snapshot: {e}", path.display()),
        )
    })
}

/// Write a snapshot to `path`, creating parent directories as needed and
/// overwriting anything already there. Writes to a temporary sibling
/// file first and renames it into place, so a crash or a concurrent
/// `portwatch` run never leaves a truncated, unreadable state file.
///
/// # Errors
/// Returns an error if the parent directory can't be created, the
/// temporary file can't be written, or serialization fails.
pub fn save_snapshot(path: &Path, snapshot: &Snapshot) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    let json = serde_json::to_string_pretty(snapshot)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let tmp_path = path.with_extension("json.tmp");
    fs::write(&tmp_path, json)?;
    fs::rename(&tmp_path, path)?;
    Ok(())
}

/// One line of the append-only history log: a diff summary tied to the
/// timestamps of the two snapshots it was computed from.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryRecord {
    pub baseline_captured_at_unix: u64,
    pub current_captured_at_unix: u64,
    pub added: usize,
    pub removed: usize,
    pub owner_changed: usize,
    pub changes: Vec<Change>,
}

impl HistoryRecord {
    #[must_use]
    pub fn from_report(baseline: &Snapshot, current: &Snapshot, report: &DiffReport) -> Self {
        HistoryRecord {
            baseline_captured_at_unix: baseline.captured_at_unix,
            current_captured_at_unix: current.captured_at_unix,
            added: report.added_count(),
            removed: report.removed_count(),
            owner_changed: report.owner_changed_count(),
            changes: report.changes.clone(),
        }
    }
}

/// Append one JSON line describing a diff to a history log file,
/// creating it (and its parent directory) if it doesn't exist yet.
/// Only records with at least one change are written, so a quiet
/// machine produces a quiet log.
///
/// # Errors
/// Returns an error if the parent directory can't be created, the file
/// can't be opened for appending, or serialization fails.
pub fn append_history(path: &Path, record: &HistoryRecord) -> io::Result<()> {
    if record.changes.is_empty() {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    let line =
        serde_json::to_string(record).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    writeln!(file, "{line}")?;
    Ok(())
}

/// Human-readable one-line label for a history record, used by
/// `portwatch history`.
#[must_use]
pub fn describe_record(record: &HistoryRecord) -> String {
    format!(
        "{} -> {}: +{} -{} ~{}",
        format_unix(record.baseline_captured_at_unix),
        format_unix(record.current_captured_at_unix),
        record.added,
        record.removed,
        record.owner_changed
    )
}

/// Read every record from a history log file. Returns an empty list if
/// the file does not exist yet.
///
/// # Errors
/// Returns an error if the file exists but cannot be read, or contains
/// a line that is not valid JSON.
pub fn read_history(path: &Path) -> io::Result<Vec<HistoryRecord>> {
    match fs::read_to_string(path) {
        Ok(content) => content
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| {
                serde_json::from_str(l)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
            })
            .collect(),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diff::diff;
    use crate::model::{PortEntry, Protocol, TcpState};
    use std::net::{IpAddr, Ipv4Addr};
    use tempfile::tempdir;

    fn entry(port: u16, pid: u32) -> PortEntry {
        PortEntry {
            protocol: Protocol::Tcp,
            local_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            local_port: port,
            state: Some(TcpState::Listen),
            pid: Some(pid),
            process_name: Some(format!("proc{pid}")),
        }
    }

    #[test]
    fn save_then_load_roundtrips() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("state.json");
        let snap = Snapshot::new(1000, "host".into(), vec![entry(80, 1)]);
        save_snapshot(&path, &snap).unwrap();
        let loaded = load_snapshot(&path).unwrap();
        assert_eq!(loaded, snap);
    }

    #[test]
    fn load_missing_file_gives_helpful_error() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("nope.json");
        let err = load_snapshot(&path).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        assert!(err.to_string().contains("portwatch snapshot"));
    }

    #[test]
    fn load_invalid_json_gives_helpful_error() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("bad.json");
        fs::write(&path, "not json").unwrap();
        let err = load_snapshot(&path).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn save_creates_parent_directories() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("nested/dir/state.json");
        let snap = Snapshot::new(0, "h".into(), vec![]);
        save_snapshot(&path, &snap).unwrap();
        assert!(path.exists());
    }

    #[test]
    fn save_overwrites_existing_file_atomically() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("state.json");
        save_snapshot(&path, &Snapshot::new(1, "h".into(), vec![entry(1, 1)])).unwrap();
        save_snapshot(&path, &Snapshot::new(2, "h".into(), vec![entry(2, 2)])).unwrap();
        let loaded = load_snapshot(&path).unwrap();
        assert_eq!(loaded.captured_at_unix, 2);
        assert!(!path.with_extension("json.tmp").exists());
    }

    #[test]
    fn append_history_skips_empty_reports() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("history.jsonl");
        let a = Snapshot::new(1, "h".into(), vec![entry(1, 1)]);
        let report = diff(&a, &a);
        let record = HistoryRecord::from_report(&a, &a, &report);
        append_history(&path, &record).unwrap();
        assert!(!path.exists(), "no-change reports should not be logged");
    }

    #[test]
    fn append_history_writes_and_reads_back() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("history.jsonl");
        let a = Snapshot::new(1, "h".into(), vec![entry(1, 1)]);
        let b = Snapshot::new(2, "h".into(), vec![entry(1, 1), entry(2, 2)]);
        let report = diff(&a, &b);
        let record = HistoryRecord::from_report(&a, &b, &report);
        append_history(&path, &record).unwrap();
        append_history(&path, &record).unwrap();
        let records = read_history(&path).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].added, 1);
    }

    #[test]
    fn read_history_missing_file_is_empty() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("none.jsonl");
        assert_eq!(read_history(&path).unwrap().len(), 0);
    }

    #[test]
    fn describe_record_formats_summary_line() {
        let record = HistoryRecord {
            baseline_captured_at_unix: 0,
            current_captured_at_unix: 86400,
            added: 2,
            removed: 1,
            owner_changed: 3,
            changes: vec![],
        };
        let line = describe_record(&record);
        assert_eq!(
            line,
            "1970-01-01T00:00:00Z -> 1970-01-02T00:00:00Z: +2 -1 ~3"
        );
    }
}
