//! A tiny, dependency-free Unix-timestamp <-> UTC civil date/time
//! converter, so snapshot files don't need to pull in a full date/time
//! crate just to print `captured_at` in a human-readable form.
//!
//! The civil-from-days / days-from-civil conversion is Howard Hinnant's
//! well-known constant-time algorithm
//! (<https://howardhinnant.github.io/date_algorithms.html>), valid for
//! the proleptic Gregorian calendar.

/// Format a Unix timestamp (seconds since 1970-01-01T00:00:00Z) as
/// `YYYY-MM-DDTHH:MM:SSZ`.
#[must_use]
pub fn format_unix(secs: u64) -> String {
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let (year, month, day) = civil_from_days(i64::try_from(days).unwrap_or(i64::MAX));
    let hour = time_of_day / 3600;
    let minute = (time_of_day % 3600) / 60;
    let second = time_of_day % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

// The casts below are exact by construction, not lossy: `doe` is proven
// to lie in [0, 146096] by the surrounding era arithmetic (comment
// inline), `yoe` in [0, 399], `doy` in [0, 365], `d` in [1, 31] and `m`
// in [1, 12] - all well within the target integer types. This holds for
// every `z` a `u64` Unix-seconds-derived day count can produce, which is
// the only input this private function is ever called with.
#[allow(
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::cast_possible_truncation
)]
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    let year = if m <= 2 { y + 1 } else { y };
    (year, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_zero_is_1970_01_01() {
        assert_eq!(format_unix(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn known_timestamp_formats_correctly() {
        // 2024-01-01T00:00:00Z
        assert_eq!(format_unix(1_704_067_200), "2024-01-01T00:00:00Z");
    }

    #[test]
    fn mid_day_time_of_day_is_correct() {
        // 2024-06-15T13:45:30Z
        assert_eq!(format_unix(1_718_459_130), "2024-06-15T13:45:30Z");
    }

    #[test]
    fn leap_day_is_handled() {
        // 2024-02-29T12:00:00Z (2024 is a leap year)
        assert_eq!(format_unix(1_709_208_000), "2024-02-29T12:00:00Z");
    }

    #[test]
    fn end_of_year_rolls_to_next_year() {
        // 2023-12-31T23:59:59Z
        assert_eq!(format_unix(1_704_067_199), "2023-12-31T23:59:59Z");
    }

    #[test]
    fn century_boundary_handles_non_leap_century_year() {
        // 2100-03-01T00:00:00Z (2100 is NOT a leap year in Gregorian calendar)
        assert_eq!(format_unix(4_107_542_400), "2100-03-01T00:00:00Z");
    }
}
