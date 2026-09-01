//! The seam between "parse a list of listening sockets" (fully tested,
//! platform-independent) and "actually go get that list from this
//! operating system" (platform-specific, exercised by the CLI at runtime
//! and by live integration tests gated to the OS they can run on).

use crate::model::PortEntry;
use std::io;

/// Something that can produce the current list of listening sockets on
/// this machine. The live implementations are platform-specific; the
/// trait exists so the rest of portwatch (diff engine, formatting,
/// snapshot storage) never has to know or care which one is in use.
pub trait PortSource {
    /// Enumerate the current sockets on this machine.
    ///
    /// # Errors
    /// Returns an error if the underlying OS query fails (e.g. `/proc`
    /// is unreadable, an FFI call fails, or an external tool like `lsof`
    /// can't be run).
    fn scan(&self) -> io::Result<Vec<PortEntry>>;
}

/// The real, platform-appropriate `PortSource` for the machine portwatch
/// is running on.
#[cfg(target_os = "linux")]
#[must_use]
pub fn live_source() -> Box<dyn PortSource> {
    Box::new(crate::linux::LinuxSource::default())
}

#[cfg(target_os = "windows")]
#[must_use]
pub fn live_source() -> Box<dyn PortSource> {
    Box::new(crate::windows::WindowsSource)
}

#[cfg(target_os = "macos")]
#[must_use]
pub fn live_source() -> Box<dyn PortSource> {
    Box::new(crate::macos::MacosSource)
}

#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
#[must_use]
pub fn live_source() -> Box<dyn PortSource> {
    struct Unsupported;
    impl PortSource for Unsupported {
        fn scan(&self) -> io::Result<Vec<PortEntry>> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "portwatch has no port source implemented for this operating system",
            ))
        }
    }
    Box::new(Unsupported)
}
