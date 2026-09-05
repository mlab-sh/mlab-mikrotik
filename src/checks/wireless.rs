//! Wireless hardening, across the two stacks RouterOS 7 ships.
//!
//! A device carries `/interface/wifi` (the current driver, ex-wifiwave2) or
//! `/interface/wireless` (the legacy one), never both, and a router with no
//! radios carries neither. The two name their properties differently, so both
//! are normalised into one shape before anything is graded.

use super::{finding, Finding, Input, Outcome, Severity};
use crate::ros::{field, first_field};

/// A wireless security configuration, whichever stack described it.
#[derive(Debug, Default)]
struct Profile {
    name: String,
    /// `authentication-types` verbatim, lowercased.
    auth: String,
    /// Every cipher named by either stack, lowercased.
    ciphers: String,
    wps: bool,
    /// `management-protection`: `disabled`, `allowed`, `required`.
    pmf: String,
    /// The pre-shared key, when the account is allowed to read it.
    passphrase: String,
}

pub fn check(i: &Input, o: &mut Outcome) {
    let profiles = profiles(i);

    if profiles.is_empty() {
        // No radios is not the same fact as a refused menu, and the report has
        // to be able to tell them apart.
        let reason = if !i.readable("/interface/wifi") && !i.readable("/interface/wireless") {
            "neither wireless menu could be read"
        } else {
            "this router has no wireless interfaces"
        };
        o.not_applicable("wireless", reason);
        return;
    }

    o.findings.extend(open_networks(&profiles));
    o.findings.extend(weak_ciphers(&profiles));
    o.findings.extend(wps(&profiles));
    o.findings.extend(pmf(&profiles));
    o.findings.extend(passphrases(&profiles));
}

/// Both stacks, normalised.
fn profiles(i: &Input) -> Vec<Profile> {
    let mut out = Vec::new();

    for s in &i.wifi_security {
        out.push(Profile {
            name: field(s, "name"),
            auth: field(s, "authentication-types").to_lowercase(),
            ciphers: format!(
                "{} {}",
                field(s, "encryption"),
                field(s, "group-encryption")
            )
            .to_lowercase(),
            wps: !matches!(field(s, "wps").as_str(), "" | "disable" | "disabled"),
            pmf: field(s, "management-protection").to_lowercase(),
            passphrase: field(s, "passphrase"),
        });
    }

    for s in &i.wireless_security {
        out.push(Profile {
            name: field(s, "name"),
            auth: field(s, "authentication-types").to_lowercase(),
            ciphers: format!(
                "{} {}",
                field(s, "unicast-ciphers"),
                field(s, "group-ciphers")
            )
            .to_lowercase(),
            // The legacy stack calls it `wps-mode`, and `disabled` is off.
            wps: !matches!(field(s, "wps-mode").as_str(), "" | "disabled" | "disable"),
            pmf: field(s, "management-protection").to_lowercase(),
            passphrase: first_field(s, &["wpa2-pre-shared-key", "wpa-pre-shared-key"]),
        });
    }

    out
}

/// A radio with no authentication at all.
fn open_networks(p: &[Profile]) -> Vec<Finding> {
    let open: Vec<&str> = p
        .iter()
        .filter(|p| p.auth.trim().is_empty())
        .map(|p| p.name.as_str())
        .collect();

    if open.is_empty() {
        return Vec::new();
    }
    vec![finding(
        Severity::High,
        "wireless",
        "wireless profiles with no authentication",
        format!(
            "{} — anything in range joins, and every frame is in the clear",
            open.join(", ")
        ),
        "set authentication-types=wpa2-psk,wpa3-psk on the profile",
    )]
}

fn weak_ciphers(p: &[Profile]) -> Vec<Finding> {
    let mut out = Vec::new();

    let tkip: Vec<&str> = p
        .iter()
        .filter(|p| p.ciphers.contains("tkip"))
        .map(|p| p.name.as_str())
        .collect();
    if !tkip.is_empty() {
        out.push(finding(
            Severity::High,
            "wireless",
            "TKIP is still allowed",
            format!(
                "{} — TKIP has been broken for over a decade and its presence also caps the network at 802.11g rates",
                tkip.join(", ")
            ),
            "leave only aes-ccm / ccmp in the cipher list",
        ));
    }

    let wpa1: Vec<&str> = p
        .iter()
        .filter(|p| p.auth.contains("wpa-psk") && !p.auth.contains("wpa2-psk"))
        .map(|p| p.name.as_str())
        .collect();
    if !wpa1.is_empty() {
        out.push(finding(
            Severity::High,
            "wireless",
            "WPA1 is accepted",
            format!("{} accept wpa-psk without wpa2-psk", wpa1.join(", ")),
            "set authentication-types=wpa2-psk,wpa3-psk",
        ));
    }

    // WPA2-PSK is not broken, and calling it a failure would be the kind of
    // noise that gets a report ignored. It is worth one low line, because the
    // gap it leaves — offline cracking of a captured handshake — is exactly
    // what WPA3 closes.
    let no_wpa3: Vec<&str> = p
        .iter()
        .filter(|p| p.auth.contains("wpa2-psk") && !p.auth.contains("wpa3"))
        .map(|p| p.name.as_str())
        .collect();
    if !no_wpa3.is_empty() {
        out.push(finding(
            Severity::Low,
            "wireless",
            "WPA2 only, no WPA3 transition",
            format!(
                "{} — a captured handshake can be attacked offline, which is the one thing WPA3's SAE removes",
                no_wpa3.join(", ")
            ),
            "set authentication-types=wpa2-psk,wpa3-psk once the client estate can cope",
        ));
    }

    out
}

fn wps(p: &[Profile]) -> Vec<Finding> {
    let on: Vec<&str> = p
        .iter()
        .filter(|p| p.wps)
        .map(|p| p.name.as_str())
        .collect();
    if on.is_empty() {
        return Vec::new();
    }
    vec![finding(
        Severity::High,
        "wireless",
        "WPS is enabled",
        format!(
            "{} — the WPS PIN exchange is brute-forceable in hours and hands over the pre-shared key itself",
            on.join(", ")
        ),
        "disable WPS on the profile",
    )]
}

fn pmf(p: &[Profile]) -> Vec<Finding> {
    let off: Vec<&str> = p
        .iter()
        .filter(|p| p.pmf == "disabled")
        .map(|p| p.name.as_str())
        .collect();
    if off.is_empty() {
        return Vec::new();
    }
    vec![finding(
        Severity::Low,
        "wireless",
        "management frame protection is off",
        format!(
            "{} — deauthentication frames are unauthenticated, so any client can be knocked off the network at will",
            off.join(", ")
        ),
        "set management-protection=allowed, then required once the clients cope",
    )]
}

/// Pre-shared key length, when the account is allowed to read it.
///
/// An account without the `sensitive` policy gets `***` or nothing back, and a
/// length taken from that would be a measurement of the mask. Those profiles
/// are left alone rather than guessed at.
fn passphrases(p: &[Profile]) -> Vec<Finding> {
    let short: Vec<String> = p
        .iter()
        .filter(|p| readable_key(&p.passphrase))
        .filter(|p| p.passphrase.chars().count() < 12)
        .map(|p| format!("{} ({} characters)", p.name, p.passphrase.chars().count()))
        .collect();

    if short.is_empty() {
        return Vec::new();
    }
    vec![finding(
        Severity::High,
        "wireless",
        "short pre-shared keys",
        format!(
            "{} — a WPA2 handshake is captured passively and then attacked offline, where length is the only thing that costs the attacker anything",
            short.join(", ")
        ),
        "use a passphrase of 20 characters or more",
    )]
}

/// Whether what came back is the key itself rather than a mask.
fn readable_key(v: &str) -> bool {
    !v.is_empty() && !v.chars().all(|c| c == '*')
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    fn wifi(security: Vec<Value>) -> Input {
        Input {
            wifi: vec![json!({"name": "wifi1"})],
            wifi_security: security,
            ..Default::default()
        }
    }

    #[test]
    fn the_two_stacks_normalise_to_the_same_shape() {
        let modern = wifi(vec![json!({
            "name": "corp", "authentication-types": "wpa2-psk,wpa3-psk",
            "encryption": "ccmp", "wps": "disable", "management-protection": "required",
            "passphrase": "a-long-enough-passphrase"
        })]);
        let legacy = Input {
            wireless: vec![json!({"name": "wlan1"})],
            wireless_security: vec![json!({
                "name": "corp", "authentication-types": "wpa2-psk",
                "unicast-ciphers": "aes-ccm", "wps-mode": "disabled",
                "management-protection": "required",
                "wpa2-pre-shared-key": "a-long-enough-passphrase"
            })],
            ..Default::default()
        };
        assert_eq!(profiles(&modern).len(), 1);
        assert_eq!(profiles(&legacy).len(), 1);
        assert_eq!(profiles(&legacy)[0].name, "corp");
        assert!(!profiles(&legacy)[0].wps);
    }

    #[test]
    fn tkip_is_high_wherever_it_is_named() {
        let i = wifi(vec![
            json!({"name": "old", "authentication-types": "wpa2-psk", "encryption": "tkip,ccmp"}),
        ]);
        let f = weak_ciphers(&profiles(&i));
        assert_eq!(f[0].severity, Severity::High);
        assert!(f[0].title.contains("TKIP"));
    }

    #[test]
    fn wpa2_only_is_a_low_note_not_a_failure() {
        let i = wifi(vec![
            json!({"name": "corp", "authentication-types": "wpa2-psk", "encryption": "ccmp"}),
        ]);
        let f = weak_ciphers(&profiles(&i));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Low);
    }

    #[test]
    fn wpa2_plus_wpa3_says_nothing() {
        let i = wifi(vec![
            json!({"name": "corp", "authentication-types": "wpa2-psk,wpa3-psk", "encryption": "ccmp"}),
        ]);
        assert!(weak_ciphers(&profiles(&i)).is_empty());
    }

    #[test]
    fn a_masked_passphrase_is_never_measured() {
        assert!(!readable_key("***"));
        assert!(!readable_key(""));
        assert!(readable_key("hunter2"));

        let masked = wifi(vec![json!({"name": "corp", "passphrase": "***"})]);
        assert!(
            passphrases(&profiles(&masked)).is_empty(),
            "measuring the mask would report every profile as short"
        );
    }

    #[test]
    fn a_short_readable_key_is_high_and_says_how_short() {
        let i = wifi(vec![json!({"name": "guest", "passphrase": "guest123"})]);
        let f = passphrases(&profiles(&i));
        assert_eq!(f[0].severity, Severity::High);
        assert!(f[0].detail.contains("8 characters"));
    }

    #[test]
    fn a_router_with_no_radios_is_not_applicable_rather_than_clean() {
        let mut o = Outcome::default();
        check(&Input::default(), &mut o);
        assert!(o.findings.is_empty());
        assert_eq!(o.skipped.len(), 1);
        assert!(o.skipped[0].because.contains("no wireless"));
    }
}
