//! Using portwatch as a library: build two snapshots by hand and diff
//! them, with no live system access at all. This is the same code path
//! `portwatch diff` uses internally, just driven directly.
//!
//! Run with: `cargo run --example diff_two_snapshots`

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

fn main() {
    let baseline = Snapshot::new(
        1_735_689_600, // 2025-01-01T00:00:00Z
        "web-01".to_string(),
        vec![
            entry(22, 512, "sshd"),
            entry(80, 1200, "nginx"),
            entry(5432, 1400, "postgres"),
        ],
    );

    // Since the baseline: nginx restarted under a new pid (still an
    // OwnerChanged event - a pid swap on port 80 is exactly the signal
    // portwatch exists to surface, redeploy or not), postgres is gone,
    // and a new port 9090 appeared.
    let current = Snapshot::new(
        1_735_776_000, // 2025-01-02T00:00:00Z
        "web-01".to_string(),
        vec![
            entry(22, 512, "sshd"),
            entry(80, 1955, "nginx"),
            entry(9090, 2001, "metrics-exporter"),
        ],
    );

    let report = diff(&baseline, &current);
    println!("{}", format::diff_report(&report));
    println!(
        "\n{} added, {} removed, {} owner change(s)",
        report.added_count(),
        report.removed_count(),
        report.owner_changed_count()
    );
}
