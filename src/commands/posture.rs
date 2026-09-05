//! `posture` — the settings that claim to defend something, and the ones that
//! quietly widen the way in.
//!
//! Every row says what the setting *is*, not what it should be. Where a value
//! is a decision the operator has to make, the row says so and stays neutral;
//! the grading lives in `audit`.

use anyhow::Result;
use serde_json::{json, Value};

use crate::checks::accounts::granted;
use crate::collect::Fetcher;
use crate::ros::{field, flag, Client};
use crate::ui::render;

pub async fn run(c: &Client) -> Result<()> {
    let mut f = Fetcher::new(c);

    let users = f.list("/user").await;
    let groups = f.list("/user/group").await;
    let discovery = f.get("/ip/neighbor/discovery-settings").await;
    let mac_server = f.get("/tool/mac-server").await;
    let mac_winbox = f.get("/tool/mac-server/mac-winbox").await;
    let mac_ping = f.get("/tool/mac-server/ping").await;
    let romon = f.get("/tool/romon").await;
    let btest = f.get("/tool/bandwidth-server").await;
    let ssh = f.get("/ip/ssh").await;
    let ntp = f.get("/system/ntp/client").await;
    let snmp = f.get("/snmp").await;
    let communities = f.list("/snmp/community").await;
    let logging = f.list("/system/logging").await;
    let actions = f.list("/system/logging/action").await;

    let management = vec![
        row(
            "neighbour discovery",
            &field(&discovery, "discover-interface-list"),
            &field(&discovery, "protocol"),
        ),
        row(
            "MAC-telnet",
            &field(&mac_server, "allowed-interface-list"),
            "layer 2 access to the console, no IP needed",
        ),
        row(
            "MAC-Winbox",
            &field(&mac_winbox, "allowed-interface-list"),
            "layer 2 access to Winbox",
        ),
        row(
            "MAC-ping",
            on_off(flag(&mac_ping, "enabled")),
            "answers pings addressed to the MAC",
        ),
        when_on(
            "RoMON",
            flag(&romon, "enabled"),
            if field(&romon, "secrets").is_empty() {
                "no shared secret set"
            } else {
                "shared secret set"
            },
        ),
        when_on(
            "bandwidth test server",
            flag(&btest, "enabled"),
            if flag(&btest, "authenticate") {
                "authenticated"
            } else {
                "unauthenticated — anyone who reaches it can spend this router's uplink"
            },
        ),
    ];

    let crypto = vec![
        row(
            "SSH strong crypto",
            on_off(flag(&ssh, "strong-crypto")),
            &format!("host key {}", field(&ssh, "host-key-type")),
        ),
        row(
            "SSH forwarding",
            match field(&ssh, "forwarding-enabled").as_str() {
                "no" | "" => "off",
                _ => "on",
            },
            "tunnels opened through the router's own SSH",
        ),
        row(
            "NTP client",
            on_off(flag(&ntp, "enabled")),
            &field(&ntp, "status"),
        ),
        when_on(
            "SNMP",
            flag(&snmp, "enabled"),
            &snmp_detail(&snmp, &communities),
        ),
    ];

    // Logging is reported by target rather than by action name: an action
    // called `remote` that writes to memory is the trap worth showing.
    let log_rows: Vec<Value> = logging
        .iter()
        .filter(|l| !flag(l, "disabled"))
        .map(|l| {
            let action = field(l, "action");
            let target = actions
                .iter()
                .find(|a| field(a, "name") == action)
                .map(|a| field(a, "target"))
                .unwrap_or_default();
            json!({
                "topics": field(l, "topics"),
                "action": action,
                "target": target,
                "durable": matches!(target.as_str(), "remote" | "disk"),
            })
        })
        .collect();

    let account_rows: Vec<Value> = users
        .iter()
        .filter(|u| !flag(u, "disabled"))
        .map(|u| {
            let group_name = field(u, "group");
            let policy = groups
                .iter()
                .find(|g| field(g, "name") == group_name)
                .map(|g| field(g, "policy"))
                .unwrap_or_default();
            let g = granted(&policy);
            json!({
                "user": field(u, "name"),
                "group": group_name,
                "from": match field(u, "address").as_str() {
                    "" => "anywhere".to_string(),
                    a => a.to_string(),
                },
                "writes": g.iter().any(|p| p == "write"),
                "secrets": g.iter().any(|p| p == "sensitive"),
                "lastLogin": field(u, "last-logged-in"),
            })
        })
        .collect();

    if render::is_json() {
        render::print_json(&json!({
            "accounts": account_rows,
            "management": management,
            "crypto": crypto,
            "logging": log_rows,
            "unreadable": f.unreadable,
        }));
        return Ok(());
    }

    f.report();

    render::heading("Accounts");
    render::list(&account_rows, render::ACCOUNT_COLS);
    render::count(account_rows.len(), "enabled account");

    render::heading("Management reach");
    render::list(&management, render::POSTURE_COLS);
    println!();
    println!("  `none` is the hardened value for the interface lists; a named list is a decision, `all` is not");

    render::heading("Cryptography and time");
    render::list(&crypto, render::POSTURE_COLS);

    render::heading("Logging");
    render::list(&log_rows, render::LOGGING_COLS);
    let durable = log_rows
        .iter()
        .filter(|l| l["durable"] == json!(true))
        .count();
    println!();
    if durable == 0 {
        println!("  nothing is written to disk or sent to a remote collector — every line here is gone at the next reboot");
    } else {
        println!("  {durable} rule(s) write somewhere that survives a reboot");
    }

    Ok(())
}

fn row(setting: &str, state: &str, detail: &str) -> Value {
    json!({
        "setting": setting,
        "state": if state.is_empty() { "—" } else { state },
        "detail": detail,
    })
}

/// A row whose detail only means something while the feature is on.
///
/// "RoMON off — no shared secret set" reads as a complaint about a feature
/// that is not running; the detail belongs to the `on` case only.
fn when_on(setting: &str, on: bool, detail: &str) -> Value {
    row(setting, on_off(on), if on { detail } else { "" })
}

/// What is worth saying about SNMP in one line: how many communities answer,
/// and whether any of them is v1/v2c, where the community string is the
/// password and it travels in plain text.
fn snmp_detail(_snmp: &Value, communities: &[Value]) -> String {
    let active: Vec<&Value> = communities
        .iter()
        .filter(|c| !flag(c, "disabled"))
        .collect();
    let plaintext = active
        .iter()
        .filter(|c| matches!(field(c, "security").as_str(), "" | "none"))
        .count();
    format!(
        "{} communit{}, {} in plain text (v1/v2c)",
        active.len(),
        if active.len() == 1 { "y" } else { "ies" },
        plaintext
    )
}

fn on_off(b: bool) -> &'static str {
    if b {
        "on"
    } else {
        "off"
    }
}
