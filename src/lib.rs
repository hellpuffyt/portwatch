//! Core library behind the `portwatch` CLI: inventory the machine's
//! listening TCP/UDP ports and their owning processes, persist that as a
//! snapshot, and diff two snapshots to report what changed.
//!
//! The library is organized so the parts that are pure logic (data
//! model, diff engine, timestamp formatting, snapshot storage, output
//! formatting) are fully unit-tested independent of any operating
//! system, while the platform-specific "go actually ask the kernel"
//! backends live behind the [`source::PortSource`] trait in their own
//! modules ([`linux`], [`windows`], [`macos`]).

pub mod diff;
pub mod format;
pub mod model;
pub mod source;
pub mod storage;
pub mod timefmt;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "windows")]
pub mod windows;

#[cfg(target_os = "macos")]
pub mod macos;

use std::time::{SystemTime, UNIX_EPOCH};

/// Current time as seconds since the Unix epoch, saturating to 0 if the
/// system clock is somehow set before 1970.
#[must_use]
pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Best-effort local hostname, falling back to `"unknown"` if none of
/// the usual environment variables are set.
#[must_use]
pub fn hostname() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "unknown".to_string())
}

/// Capture a live snapshot using the platform's [`source::PortSource`].
///
/// # Errors
/// Returns an error if the underlying OS query fails (e.g. `/proc` is
/// unreadable, or the IP Helper / `lsof` call fails).
pub fn capture() -> std::io::Result<model::Snapshot> {
    let entries = source::live_source().scan()?;
    Ok(model::Snapshot::new(now_unix(), hostname(), entries))
}
