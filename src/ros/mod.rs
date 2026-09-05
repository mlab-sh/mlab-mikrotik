//! The RouterOS side of the CLI: what to talk to, and how.

pub mod client;
pub mod config;
pub mod version;

pub use client::Client;
pub use config::{Profile, Scheme};

use serde_json::Value;

/// A field of a RouterOS object as a display string, empty when it is missing.
///
/// The REST API answers in kebab-case (`board-name`, `cpu-load`) and encodes
/// every value as a string, including numbers and booleans; this module is the
/// one place that assumption lives.
pub fn field(v: &Value, key: &str) -> String {
    match v.get(key) {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Null) | None => String::new(),
        Some(other) => other.to_string(),
    }
}

/// The first field of `keys` that carries something.
pub fn first_field(v: &Value, keys: &[&str]) -> String {
    for k in keys {
        let s = field(v, k);
        if !s.is_empty() {
            return s;
        }
    }
    String::new()
}

/// A boolean field. Absent reads as false, which is what RouterOS means: a
/// property it does not send is one that does not apply.
pub fn flag(v: &Value, key: &str) -> bool {
    match v.get(key) {
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => matches!(s.as_str(), "true" | "yes" | "1"),
        _ => false,
    }
}

/// A numeric field, whatever it arrived as.
pub fn num(v: &Value, key: &str) -> Option<f64> {
    match v.get(key) {
        Some(Value::Number(n)) => n.as_f64(),
        Some(Value::String(s)) => s.trim().parse().ok(),
        _ => None,
    }
}

/// The state of a row that can be turned off, as one word.
///
/// RouterOS says `disabled` where most APIs say `enabled`, and separately says
/// `running` for whether it is actually up. Collapsing both into one column is
/// what makes an interface list readable.
pub fn state(v: &Value) -> String {
    if flag(v, "disabled") {
        "disabled".to_string()
    } else if v.get("running").is_some() {
        if flag(v, "running") {
            "running".to_string()
        } else {
            "down".to_string()
        }
    } else {
        "enabled".to_string()
    }
}

/// A MAC address in one shape, so two menus can be joined on it.
///
/// `/ip/arp` and `/interface/bridge/host` do not always agree on case, and a
/// join on the raw string silently loses half the rows.
pub fn mac(v: &Value, key: &str) -> String {
    field(v, key).trim().to_uppercase()
}

/// Seconds since the Unix epoch, for stamping a snapshot.
pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Format a Unix timestamp in seconds as UTC ISO 8601.
///
/// The same helper as the other mlab CLIs, for the same reason: a dated file
/// has to sort lexicographically and mean the same thing in every timezone.
pub fn iso8601(epoch: i64) -> String {
    let days = epoch.div_euclid(86_400);
    let rem = epoch.rem_euclid(86_400);
    let (h, m, sec) = (rem / 3600, (rem % 3600) / 60, rem % 60);

    // Howard Hinnant's civil_from_days: shift the era so March starts the
    // year, which makes the leap day the last day and removes every special
    // case.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mth = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(mth <= 2);

    format!("{y:04}-{mth:02}-{d:02}T{h:02}:{m:02}:{sec:02}Z")
}

/// Bytes as a human size. RouterOS reports memory and counters in bytes.
pub fn bytes(n: f64) -> String {
    match n {
        b if b >= 1e12 => format!("{:.1} TB", b / 1e12),
        b if b >= 1e9 => format!("{:.1} GB", b / 1e9),
        b if b >= 1e6 => format!("{:.1} MB", b / 1e6),
        b if b >= 1e3 => format!("{:.1} kB", b / 1e3),
        b => format!("{b:.0} B"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_missing_field_reads_as_empty_rather_than_null() {
        let v = json!({"board-name": "hEX S", "cpu-count": 2, "nothing": null});
        assert_eq!(field(&v, "board-name"), "hEX S");
        assert_eq!(field(&v, "nope"), "");
        assert_eq!(field(&v, "nothing"), "");
    }

    #[test]
    fn a_non_string_field_is_still_printable() {
        // RouterOS sends strings, but a firmware that sends a number should
        // not blank the field out.
        assert_eq!(field(&json!({"cpu-count": 2}), "cpu-count"), "2");
        assert_eq!(num(&json!({"cpu-load": "17"}), "cpu-load"), Some(17.0));
        assert!(flag(&json!({"disabled": "true"}), "disabled"));
        assert!(!flag(&json!({}), "disabled"));
    }

    #[test]
    fn state_separates_switched_off_from_merely_down() {
        assert_eq!(
            state(&json!({"disabled": "true", "running": "false"})),
            "disabled"
        );
        assert_eq!(
            state(&json!({"disabled": "false", "running": "true"})),
            "running"
        );
        assert_eq!(
            state(&json!({"disabled": "false", "running": "false"})),
            "down"
        );
        assert_eq!(
            state(&json!({"disabled": "false"})),
            "enabled",
            "a row with no running property is not down, it just does not say"
        );
    }

    #[test]
    fn macs_are_normalized_so_two_menus_can_be_joined() {
        assert_eq!(
            mac(&json!({"mac-address": "aa:bb:cc:00:11:22"}), "mac-address"),
            "AA:BB:CC:00:11:22"
        );
        assert_eq!(mac(&json!({}), "mac-address"), "");
    }

    #[test]
    fn sizes_read_as_sizes() {
        assert_eq!(bytes(0.0), "0 B");
        assert_eq!(bytes(1_500_000.0), "1.5 MB");
        assert_eq!(bytes(2_000_000_000.0), "2.0 GB");
    }

    #[test]
    fn epoch_seconds_become_utc_iso8601() {
        assert_eq!(iso8601(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso8601(1_759_148_439), "2025-09-29T12:20:39Z");
    }

    #[test]
    fn the_march_shift_handles_leap_days_and_year_ends() {
        assert_eq!(iso8601(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(iso8601(1_583_020_800), "2020-03-01T00:00:00Z");
        assert_eq!(iso8601(1_609_459_199), "2020-12-31T23:59:59Z");
    }

    #[test]
    fn first_field_skips_the_empty_ones() {
        let v = json!({"host-name": "", "comment": "imprimante"});
        assert_eq!(first_field(&v, &["host-name", "comment"]), "imprimante");
        assert_eq!(first_field(&v, &["nope"]), "");
    }
}
