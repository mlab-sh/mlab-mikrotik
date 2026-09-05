//! The fields that must never be written to disk, and how to remove them.
//!
//! One list, used by everything that writes, so a field cannot be redacted in
//! one place and stored in another.
//!
//! This matters more on RouterOS than on most platforms: the built-in `read`
//! group carries the `sensitive` policy, so an account chosen for its name
//! gets pre-shared keys, IPsec secrets, RADIUS shared secrets and VPN
//! passwords back in clear text without asking for them. See the Account page
//! in the wiki.

use serde_json::Value;

/// Field names holding an actual secret.
///
/// Deliberately an explicit list rather than a substring rule. `key` alone
/// would match `key-type`, `host-key-size` and `public-key`, none of which is
/// a secret, and a redactor that noisy gets switched off.
pub const SECRET_FIELDS: [&str; 16] = [
    "password",
    "passphrase",
    "pre-shared-key",
    "wpa-pre-shared-key",
    "wpa2-pre-shared-key",
    "authentication-password",
    "encryption-password",
    "auth-password",
    "secret",
    "secrets",
    "private-key",
    "shared-secret",
    "eap-password",
    "mschap2-password",
    "wireguard-private-key",
    "supplicant-identity-password",
];

/// What replaces a secret: its length, and nothing else.
///
/// A length is not a secret, and it is exactly what a strength check needs —
/// so a redacted snapshot can still be audited for a short pre-shared key. The
/// value itself never reaches the disk.
pub fn marker(len: usize) -> String {
    format!("<redacted:{len}>")
}

/// Replace every secret in a document, at any depth.
///
/// Returns how many were replaced, which is itself worth recording: it is the
/// measure of what this account was handed.
pub fn redact(v: &mut Value) -> usize {
    match v {
        Value::Object(map) => {
            let mut n = 0;
            for (k, val) in map.iter_mut() {
                if SECRET_FIELDS.contains(&k.as_str()) {
                    if let Some(s) = val.as_str() {
                        // A value RouterOS already masked is not a secret we
                        // are holding, and marking it would claim we saw one.
                        if !s.is_empty() && !s.chars().all(|c| c == '*') {
                            *val = Value::String(marker(s.chars().count()));
                            n += 1;
                            continue;
                        }
                    }
                }
                n += redact(val);
            }
            n
        }
        Value::Array(items) => items.iter_mut().map(redact).sum(),
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_secret_is_replaced_by_its_length_and_nothing_else() {
        let mut v = json!({"passphrase": "hunter2!"});
        assert_eq!(redact(&mut v), 1);
        assert_eq!(v["passphrase"], json!("<redacted:8>"));
    }

    #[test]
    fn secrets_are_found_however_deeply_they_sit() {
        let mut v = json!({"a": [{"b": {"wpa2-pre-shared-key": "abcdef"}}]});
        assert_eq!(redact(&mut v), 1);
        assert_eq!(v["a"][0]["b"]["wpa2-pre-shared-key"], json!("<redacted:6>"));
    }

    #[test]
    fn a_key_that_is_not_a_secret_survives() {
        // `key-type`, `host-key-size` and `public-key` are all configuration,
        // and a substring rule on "key" would take every one of them.
        let mut v = json!({
            "key-type": "rsa", "host-key-size": "2048",
            "public-key": "AAAAB3Nza…", "name": "corp"
        });
        assert_eq!(redact(&mut v), 0);
        assert_eq!(v["key-type"], json!("rsa"));
        assert_eq!(v["public-key"], json!("AAAAB3Nza…"));
    }

    #[test]
    fn an_empty_secret_is_left_alone_rather_than_marked() {
        // Marking it would turn "this profile has no key" into "this profile
        // has a key of length zero", which reads as configured.
        let mut v = json!({"passphrase": ""});
        assert_eq!(redact(&mut v), 0);
        assert_eq!(v["passphrase"], json!(""));
    }

    #[test]
    fn a_value_routeros_already_masked_is_not_counted() {
        // Without the `sensitive` policy the router answers `***`. Counting
        // that as a redaction would claim the tool held a secret it never saw.
        let mut v = json!({"passphrase": "***"});
        assert_eq!(redact(&mut v), 0);
        assert_eq!(v["passphrase"], json!("***"));
    }

    #[test]
    fn everything_else_survives_untouched() {
        let mut v = json!({"name": "corp", "authentication-types": "wpa2-psk", "vlan-id": 30});
        assert_eq!(redact(&mut v), 0);
        assert_eq!(v["name"], json!("corp"));
        assert_eq!(v["vlan-id"], json!(30));
    }
}
