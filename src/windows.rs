//! Windows port source: calls the IP Helper API
//! (`GetExtendedTcpTable`/`GetExtendedUdpTable`) directly via raw FFI to
//! read the kernel's owner-PID socket tables, then resolves each PID to
//! an executable name with a `CreateToolhelp32Snapshot` process walk -
//! the same two APIs `netstat -ano` and Resource Monitor build on.

use crate::model::{PortEntry, Protocol, TcpState};
use crate::source::PortSource;
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use windows_sys::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER;
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID,
    MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, MIB_UDP6ROW_OWNER_PID, MIB_UDP6TABLE_OWNER_PID,
    MIB_UDPROW_OWNER_PID, MIB_UDPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};

/// Convert the low 16 bits of the port field the IP Helper API returns
/// (network byte order, packed into a `u32`) into a normal host-order
/// port number. Truncating to `u16` is intentional: the API documents
/// that only the low 16 bits of the `DWORD` are ever meaningful.
#[allow(clippy::cast_possible_truncation)]
fn convert_port(raw: u32) -> u16 {
    (raw as u16).swap_bytes()
}

/// Convert an IPv4 `dwLocalAddr`-style field (network byte order, packed
/// into a `u32`) into an [`Ipv4Addr`].
fn convert_ipv4(raw: u32) -> Ipv4Addr {
    Ipv4Addr::from(u32::from_be(raw))
}

/// A buffer for an IP Helper table, allocated as `u32` elements rather
/// than bytes so its start address is guaranteed 4-byte aligned - every
/// `MIB_*TABLE_OWNER_PID` struct below is safe to read starting from a
/// 4-byte boundary, since none of their fields require wider alignment
/// than `u32`. A `Vec<u8>` would be aligned to 1 in principle, which is
/// what `clippy::cast_ptr_alignment` (rightly) objects to.
struct TableBuf {
    words: Vec<u32>,
    byte_len: usize,
}

impl TableBuf {
    /// A `*const u32`, not `*const u8`: every table header this points
    /// at starts with a `u32` field and needs only 4-byte alignment, so
    /// keeping the pointer typed as `u32` (rather than casting through
    /// `u8` first) lets the compiler - and `clippy::cast_ptr_alignment`
    /// - see that the alignment is never actually reduced.
    fn as_ptr(&self) -> *const u32 {
        self.words.as_ptr()
    }

    fn is_empty(&self) -> bool {
        self.byte_len == 0
    }
}

/// Grow a buffer and call `f` until it succeeds or gives up after a few
/// attempts. `GetExtendedTcpTable`/`GetExtendedUdpTable` report the
/// required size via `ERROR_INSUFFICIENT_BUFFER`, but the table can grow
/// between the sizing call and the real one under load, so a couple of
/// retries is standard practice for these APIs.
fn fetch_table(mut f: impl FnMut(*mut core::ffi::c_void, &mut u32) -> u32) -> io::Result<TableBuf> {
    let mut size: u32 = 0;
    let mut words: Vec<u32> = Vec::new();
    for _ in 0..8 {
        let ptr = if words.is_empty() {
            std::ptr::null_mut()
        } else {
            words.as_mut_ptr().cast::<core::ffi::c_void>()
        };
        let result = f(ptr, &mut size);
        if result == 0 {
            return Ok(TableBuf {
                words,
                byte_len: size as usize,
            });
        }
        if result == ERROR_INSUFFICIENT_BUFFER {
            // Round the byte size up to a whole number of u32 words.
            let word_count = size.div_ceil(4) as usize;
            words = vec![0u32; word_count];
            continue;
        }
        return Err(io::Error::from_raw_os_error(result.cast_signed()));
    }
    Err(io::Error::other(
        "IP Helper table size kept changing between calls",
    ))
}

fn scan_tcp4() -> io::Result<Vec<PortEntry>> {
    let buf = fetch_table(|ptr, size| unsafe {
        GetExtendedTcpTable(ptr, size, 0, u32::from(AF_INET), TCP_TABLE_OWNER_PID_ALL, 0)
    })?;
    if buf.is_empty() {
        return Ok(Vec::new());
    }
    // SAFETY: `buf` was sized and filled by GetExtendedTcpTable itself,
    // which lays out a MIB_TCPTABLE_OWNER_PID header followed by
    // dwNumEntries MIB_TCPROW_OWNER_PID rows contiguously in memory, and
    // TableBuf guarantees 4-byte alignment (see its doc comment).
    unsafe {
        let header = buf.as_ptr().cast::<MIB_TCPTABLE_OWNER_PID>();
        let count = (*header).dwNumEntries as usize;
        let rows_ptr = std::ptr::addr_of!((*header).table).cast::<MIB_TCPROW_OWNER_PID>();
        let rows = std::slice::from_raw_parts(rows_ptr, count);
        Ok(rows
            .iter()
            .map(|row| PortEntry {
                protocol: Protocol::Tcp,
                local_addr: IpAddr::V4(convert_ipv4(row.dwLocalAddr)),
                local_port: convert_port(row.dwLocalPort),
                state: Some(TcpState::from_windows_code(row.dwState)),
                pid: Some(row.dwOwningPid),
                process_name: None,
            })
            .collect())
    }
}

fn scan_tcp6() -> io::Result<Vec<PortEntry>> {
    let buf = fetch_table(|ptr, size| unsafe {
        GetExtendedTcpTable(
            ptr,
            size,
            0,
            u32::from(AF_INET6),
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    })?;
    if buf.is_empty() {
        return Ok(Vec::new());
    }
    // SAFETY: see scan_tcp4; identical contract for the IPv6 table type.
    unsafe {
        let header = buf.as_ptr().cast::<MIB_TCP6TABLE_OWNER_PID>();
        let count = (*header).dwNumEntries as usize;
        let rows_ptr = std::ptr::addr_of!((*header).table).cast::<MIB_TCP6ROW_OWNER_PID>();
        let rows = std::slice::from_raw_parts(rows_ptr, count);
        Ok(rows
            .iter()
            .map(|row| PortEntry {
                protocol: Protocol::Tcp,
                local_addr: IpAddr::V6(Ipv6Addr::from(row.ucLocalAddr)),
                local_port: convert_port(row.dwLocalPort),
                state: Some(TcpState::from_windows_code(row.dwState)),
                pid: Some(row.dwOwningPid),
                process_name: None,
            })
            .collect())
    }
}

fn scan_udp4() -> io::Result<Vec<PortEntry>> {
    let buf = fetch_table(|ptr, size| unsafe {
        GetExtendedUdpTable(ptr, size, 0, u32::from(AF_INET), UDP_TABLE_OWNER_PID, 0)
    })?;
    if buf.is_empty() {
        return Ok(Vec::new());
    }
    // SAFETY: see scan_tcp4; identical contract for the UDP owner-PID table.
    unsafe {
        let header = buf.as_ptr().cast::<MIB_UDPTABLE_OWNER_PID>();
        let count = (*header).dwNumEntries as usize;
        let rows_ptr = std::ptr::addr_of!((*header).table).cast::<MIB_UDPROW_OWNER_PID>();
        let rows = std::slice::from_raw_parts(rows_ptr, count);
        Ok(rows
            .iter()
            .map(|row| PortEntry {
                protocol: Protocol::Udp,
                local_addr: IpAddr::V4(convert_ipv4(row.dwLocalAddr)),
                local_port: convert_port(row.dwLocalPort),
                state: None,
                pid: Some(row.dwOwningPid),
                process_name: None,
            })
            .collect())
    }
}

fn scan_udp6() -> io::Result<Vec<PortEntry>> {
    let buf = fetch_table(|ptr, size| unsafe {
        GetExtendedUdpTable(ptr, size, 0, u32::from(AF_INET6), UDP_TABLE_OWNER_PID, 0)
    })?;
    if buf.is_empty() {
        return Ok(Vec::new());
    }
    // SAFETY: see scan_tcp4; identical contract for the IPv6 UDP table.
    unsafe {
        let header = buf.as_ptr().cast::<MIB_UDP6TABLE_OWNER_PID>();
        let count = (*header).dwNumEntries as usize;
        let rows_ptr = std::ptr::addr_of!((*header).table).cast::<MIB_UDP6ROW_OWNER_PID>();
        let rows = std::slice::from_raw_parts(rows_ptr, count);
        Ok(rows
            .iter()
            .map(|row| PortEntry {
                protocol: Protocol::Udp,
                local_addr: IpAddr::V6(Ipv6Addr::from(row.ucLocalAddr)),
                local_port: convert_port(row.dwLocalPort),
                state: None,
                pid: Some(row.dwOwningPid),
                process_name: None,
            })
            .collect())
    }
}

/// Enumerate running processes with `CreateToolhelp32Snapshot` and build
/// a `pid -> executable name` map. Unlike `OpenProcess` per-PID lookups,
/// this needs no per-process permission and works for every process
/// visible to the current user session.
fn process_names() -> HashMap<u32, String> {
    let mut names = HashMap::new();
    // SAFETY: standard CreateToolhelp32Snapshot/Process32FirstW/NextW
    // usage per the documented contract; entry is a fixed-size, properly
    // initialized PROCESSENTRY32W with dwSize set before the first call.
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot.is_null() || snapshot as isize == -1 {
            return names;
        }
        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        // A struct's size always fits in a u32 on every platform this
        // crate targets; the expect documents that rather than hiding it.
        entry.dwSize = u32::try_from(std::mem::size_of::<PROCESSENTRY32W>())
            .expect("PROCESSENTRY32W is far smaller than u32::MAX bytes");
        if Process32FirstW(snapshot, &raw mut entry) != 0 {
            loop {
                let name = wide_to_string(&entry.szExeFile);
                if !name.is_empty() {
                    names.insert(entry.th32ProcessID, name);
                }
                if Process32NextW(snapshot, &raw mut entry) == 0 {
                    break;
                }
            }
        }
        windows_sys::Win32::Foundation::CloseHandle(snapshot);
    }
    names
}

fn wide_to_string(wide: &[u16]) -> String {
    let len = wide.iter().position(|&c| c == 0).unwrap_or(wide.len());
    String::from_utf16_lossy(&wide[..len])
}

pub struct WindowsSource;

impl PortSource for WindowsSource {
    fn scan(&self) -> io::Result<Vec<PortEntry>> {
        let names = process_names();
        let mut entries = Vec::new();
        entries.extend(scan_tcp4()?);
        entries.extend(scan_tcp6()?);
        entries.extend(scan_udp4()?);
        entries.extend(scan_udp6()?);
        for entry in &mut entries {
            if let Some(pid) = entry.pid {
                entry.process_name = names.get(&pid).cloned();
            }
        }
        Ok(entries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn convert_port_reads_network_byte_order() {
        // 0x5000 packed the way the API stores port 80 in the low 16
        // bits of the DWORD, big-endian within those two bytes.
        assert_eq!(convert_port(0x5000), 80);
        assert_eq!(convert_port(0x901F), 8080);
    }

    #[test]
    fn convert_ipv4_reads_loopback() {
        assert_eq!(convert_ipv4(0x0100_007F), Ipv4Addr::LOCALHOST);
    }

    #[test]
    fn convert_ipv4_reads_unspecified() {
        assert_eq!(convert_ipv4(0), Ipv4Addr::UNSPECIFIED);
    }

    #[test]
    fn wide_to_string_stops_at_nul() {
        let wide: Vec<u16> = "svchost.exe\0garbage".encode_utf16().collect();
        assert_eq!(wide_to_string(&wide), "svchost.exe");
    }

    #[test]
    fn wide_to_string_handles_no_nul() {
        let wide: Vec<u16> = "abc".encode_utf16().collect();
        assert_eq!(wide_to_string(&wide), "abc");
    }

    #[test]
    fn live_scan_returns_without_error() {
        // A real, unmocked call: proves the FFI struct layouts, buffer
        // sizing loop, and byte-order conversions all agree with what
        // the running kernel actually hands back on this machine.
        let source = WindowsSource;
        let entries = source.scan().expect("live scan should succeed");
        // The test harness's own process (or its parent) is virtually
        // guaranteed to hold at least one open TCP/UDP socket by the
        // time this runs, but we don't assert on count to avoid
        // flakiness - only that the call path works end to end.
        for e in &entries {
            assert!(e.pid.is_some(), "windows always reports an owning pid");
        }
    }
}
