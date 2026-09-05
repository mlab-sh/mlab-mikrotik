//! `wifi` — the radios, their security, and who is associated.
//!
//! RouterOS 7 ships two wireless stacks and a device carries one or the other:
//! `/interface/wifi` (the current driver, called wifiwave2 before 7.13) or
//! `/interface/wireless` (the legacy one). They name their properties
//! differently, and a device that has neither answers `400 no such command` on
//! both — which is a fact worth printing rather than an empty table.

use anyhow::Result;
use serde_json::{json, Value};

use crate::collect::Fetcher;
use crate::ros::{field, first_field, Client};
use crate::ui::render;

pub async fn run(c: &Client) -> Result<()> {
    let mut f = Fetcher::new(c);

    let wifi = f.list("/interface/wifi").await;
    let wifi_security = f.list("/interface/wifi/security").await;
    let wireless = f.list("/interface/wireless").await;
    let wireless_security = f.list("/interface/wireless/security-profiles").await;

    let (stack, radios, profiles) = if !wifi.is_empty() {
        (
            "wifi",
            radio_rows(&wifi, true),
            profile_rows(&wifi_security, true),
        )
    } else if !wireless.is_empty() {
        (
            "wireless",
            radio_rows(&wireless, false),
            profile_rows(&wireless_security, false),
        )
    } else {
        ("none", Vec::new(), Vec::new())
    };

    let registrations = if stack == "wifi" {
        f.list("/interface/wifi/registration-table").await
    } else if stack == "wireless" {
        f.list("/interface/wireless/registration-table").await
    } else {
        Vec::new()
    };

    let clients: Vec<Value> = registrations
        .iter()
        .map(|r| {
            json!({
                "mac": field(r, "mac-address"),
                "interface": field(r, "interface"),
                "signal": first_field(r, &["signal", "signal-strength"]),
                "uptime": field(r, "uptime"),
                "rx": first_field(r, &["rx-rate", "rx-bits-per-second"]),
                "tx": first_field(r, &["tx-rate", "tx-bits-per-second"]),
            })
        })
        .collect();

    if render::is_json() {
        render::print_json(&json!({
            "stack": stack,
            "radios": radios,
            "profiles": profiles,
            "clients": clients,
            "unreadable": f.unreadable,
        }));
        return Ok(());
    }

    f.report();

    if stack == "none" {
        render::heading("Wireless");
        println!();
        println!("  no radios on this router — neither /interface/wifi nor /interface/wireless");
        println!("  carries an interface, which is what a wired-only device looks like");
        return Ok(());
    }

    render::heading(&format!("Radios ({stack} stack)"));
    render::list(&radios, render::RADIO_COLS);
    render::count(radios.len(), "radio");

    render::heading("Security profiles");
    render::list(&profiles, render::WIFI_SECURITY_COLS);
    println!();
    println!("  the key column says whether this account may read the pre-shared key at all —");
    println!("  without the `sensitive` policy it comes back masked, and a length taken from a mask means nothing");

    render::heading("Associated");
    if clients.is_empty() {
        println!();
        println!("  nothing associated right now");
    } else {
        render::list(&clients, render::WIFI_CLIENT_COLS);
        render::count(clients.len(), "client");
    }

    Ok(())
}

fn radio_rows(radios: &[Value], modern: bool) -> Vec<Value> {
    radios
        .iter()
        .map(|r| {
            json!({
                "name": field(r, "name"),
                "ssid": first_field(r, &["ssid", "configuration.ssid"]),
                "band": first_field(r, &["channel.band", "band"]),
                "state": crate::ros::state(r),
                "security": if modern {
                    first_field(r, &["security", "security.name"])
                } else {
                    field(r, "security-profile")
                },
                "mac": field(r, "mac-address"),
            })
        })
        .collect()
}

fn profile_rows(profiles: &[Value], modern: bool) -> Vec<Value> {
    profiles
        .iter()
        .map(|p| {
            let key = if modern {
                field(p, "passphrase")
            } else {
                first_field(p, &["wpa2-pre-shared-key", "wpa-pre-shared-key"])
            };
            json!({
                "name": field(p, "name"),
                "auth": field(p, "authentication-types"),
                "ciphers": if modern {
                    format!("{} {}", field(p, "encryption"), field(p, "group-encryption")).trim().to_string()
                } else {
                    format!("{} {}", field(p, "unicast-ciphers"), field(p, "group-ciphers")).trim().to_string()
                },
                "pmf": field(p, "management-protection"),
                "wps": if modern { field(p, "wps") } else { field(p, "wps-mode") },
                "key": describe_key(&key),
            })
        })
        .collect()
}

/// What can honestly be said about the pre-shared key.
fn describe_key(key: &str) -> String {
    if key.is_empty() {
        "not set".to_string()
    } else if key.chars().all(|c| c == '*') {
        "masked".to_string()
    } else {
        format!("{} characters", key.chars().count())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_masked_key_is_never_reported_as_a_length() {
        assert_eq!(describe_key("***"), "masked");
        assert_eq!(describe_key(""), "not set");
        assert_eq!(describe_key("hunter22"), "8 characters");
    }

    #[test]
    fn both_stacks_produce_the_same_row_shape() {
        let modern = radio_rows(
            &[json!({"name": "wifi1", "ssid": "corp", "disabled": "false", "running": "true"})],
            true,
        );
        let legacy = radio_rows(
            &[
                json!({"name": "wlan1", "ssid": "corp", "disabled": "false", "running": "true", "security-profile": "default"}),
            ],
            false,
        );
        assert_eq!(modern[0]["ssid"], legacy[0]["ssid"]);
        assert_eq!(modern[0]["state"], json!("running"));
        assert_eq!(legacy[0]["security"], json!("default"));
    }
}
