//! `topology` — the neighbours the router can hear, and what they give away.
//!
//! `/ip/neighbor` is filled by three protocols at once: MikroTik's own MNDP,
//! plus CDP and LLDP. Every entry is a device that *announced itself* on a
//! link, which makes this the cheapest map of the adjacent network there
//! is — and the reason discovery on an external interface is a finding rather
//! than a convenience.

use anyhow::Result;
use serde_json::{json, Value};

use crate::collect::Fetcher;
use crate::ros::{field, first_field, Client};
use crate::ui::{self, render};

pub async fn run(c: &Client) -> Result<()> {
    let mut f = Fetcher::new(c);
    let neighbours = f.list("/ip/neighbor").await;
    let discovery = f.get("/ip/neighbor/discovery-settings").await;

    let rows: Vec<Value> = neighbours
        .iter()
        .map(|n| {
            json!({
                "identity": field(n, "identity"),
                "address": first_field(n, &["address4", "address"]),
                "mac": field(n, "mac-address"),
                "interface": first_field(n, &["interface", "interface-name"]),
                "via": field(n, "discovered-by"),
                "platform": platform(n),
                "age": field(n, "age"),
            })
        })
        .collect();

    if render::is_json() {
        render::print_json(&json!({
            "neighbours": rows,
            "discoverySettings": discovery,
            "unreadable": f.unreadable,
        }));
        return Ok(());
    }

    f.report();
    render::heading("Neighbours");
    render::list(&rows, render::NEIGHBOUR_COLS);
    render::count(rows.len(), "neighbour");

    // The interface list this router announces *itself* on is the other half
    // of the picture, and the half that is a decision rather than an
    // observation.
    let on = first_field(
        &discovery,
        &["discover-interface-list", "discover-interface"],
    );
    if !on.is_empty() {
        render::pairs(&[
            ("announcing on", on.clone()),
            ("protocols", field(&discovery, "protocol")),
            ("lldp med", field(&discovery, "lldp-med-net-policy-vlan")),
        ]);
        if on != "none" {
            ui::info(&format!(
                "this router announces itself on {on:?} — every device on those links learns its identity, model and RouterOS version"
            ));
        }
    }

    Ok(())
}

/// What the neighbour says it is.
///
/// MNDP fills `platform` and `board`; LLDP fills `system-description` instead,
/// and it is usually the more precise of the two — it carries the firmware
/// build. Preferring it means a mixed-vendor link reads consistently.
fn platform(n: &Value) -> String {
    let desc = field(n, "system-description");
    if !desc.is_empty() {
        return desc;
    }
    let parts: Vec<String> = ["platform", "board", "version"]
        .iter()
        .map(|k| field(n, k))
        .filter(|s| !s.is_empty())
        .collect();
    parts.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lldp_description_wins_over_the_mndp_fields() {
        let lldp = json!({"system-description": "FortiGate-100F v7.2.11", "platform": "x"});
        assert_eq!(platform(&lldp), "FortiGate-100F v7.2.11");
    }

    #[test]
    fn mndp_fields_are_joined_when_there_is_no_description() {
        let mndp = json!({"platform": "MikroTik", "board": "CRS328", "version": "7.24.2"});
        assert_eq!(platform(&mndp), "MikroTik CRS328 7.24.2");
        assert_eq!(platform(&json!({})), "");
    }
}
