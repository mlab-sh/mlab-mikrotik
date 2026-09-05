//! `interfaces` — the ports: what they are, whether they are up, what rides
//! on them, and which of them are dropping packets.

use anyhow::Result;
use clap::Args;
use serde_json::{json, Value};

use crate::collect::Fetcher;
use crate::ros::{field, flag, num, state, Client};
use crate::ui::render;

/// `/interface` carries thirty-odd properties per row, most of them counters
/// nobody reads. Asking for the ones the table needs keeps a chassis switch
/// with hundreds of ports from answering with a megabyte.
const PROPS: [&str; 12] = [
    ".id",
    "name",
    "default-name",
    "type",
    "running",
    "disabled",
    "mac-address",
    "mtu",
    "actual-mtu",
    "comment",
    "last-link-up-time",
    "link-downs",
];

/// The counters, asked for separately so the common case stays cheap.
const COUNTERS: [&str; 8] = [
    "name",
    "rx-error",
    "tx-error",
    "rx-drop",
    "tx-drop",
    "tx-queue-drop",
    "rx-byte",
    "tx-byte",
];

#[derive(Args, Debug)]
pub struct InterfaceArgs {
    /// Include interfaces that are administratively disabled
    #[arg(long)]
    pub all: bool,
    /// Only interfaces of this type (ether, vlan, bridge, l2tp-in, …)
    #[arg(long, value_name = "TYPE")]
    pub kind: Option<String>,
}

pub async fn run(c: &Client, args: &InterfaceArgs) -> Result<()> {
    let mut f = Fetcher::new(c);

    let interfaces = f.list_props("/interface", &PROPS).await;
    let addresses = f.list("/ip/address").await;
    let counters = f.list_props("/interface", &COUNTERS).await;

    // An interface's addresses are the reason anyone reads this table, and
    // they live in a different menu. Joined on the interface name, which is
    // stable, rather than on `.id`, which is not.
    let rows: Vec<Value> = interfaces
        .iter()
        .filter(|i| args.all || !flag(i, "disabled"))
        .filter(|i| match &args.kind {
            Some(k) => field(i, "type").eq_ignore_ascii_case(k),
            None => true,
        })
        .map(|i| {
            let name = field(i, "name");
            let addrs: Vec<String> = addresses
                .iter()
                .filter(|a| {
                    !flag(a, "disabled")
                        && (field(a, "interface") == name || field(a, "actual-interface") == name)
                })
                .map(|a| field(a, "address"))
                .collect();
            json!({
                "name": name,
                "type": field(i, "type"),
                "state": state(i),
                "addresses": addrs.join(" "),
                "mtu": crate::ros::first_field(i, &["actual-mtu", "mtu"]),
                "mac": field(i, "mac-address"),
                "comment": field(i, "comment"),
                "linkDowns": field(i, "link-downs"),
                "lastLinkUp": field(i, "last-link-up-time"),
            })
        })
        .collect();

    if render::is_json() {
        render::print_json(&json!({
            "interfaces": rows,
            "unreadable": f.unreadable,
        }));
        return Ok(());
    }

    f.report();
    render::heading("Interfaces");
    render::list(&rows, render::INTERFACE_COLS);
    render::count(rows.len(), "interface");

    let hidden = interfaces.len() - rows.len();
    if hidden > 0 && !args.all {
        println!("  {hidden} not shown (disabled, or filtered out) — add --all");
    }

    // Errors and drops are the one part of an interface table worth raising
    // on its own: a port that is up and losing packets looks fine above.
    let faulty: Vec<Value> = counters
        .iter()
        .filter(|i| rows.iter().any(|r| r["name"] == json!(field(i, "name"))))
        .filter(|i| errors(i) > 0.0)
        .map(|i| {
            json!({
                "name": field(i, "name"),
                "rxError": field(i, "rx-error"),
                "txError": field(i, "tx-error"),
                "rxDrop": field(i, "rx-drop"),
                "txDrop": field(i, "tx-drop"),
                "queueDrop": field(i, "tx-queue-drop"),
            })
        })
        .collect();

    if !faulty.is_empty() {
        render::heading("Counting errors or drops");
        render::list(&faulty, render::COUNTER_COLS);
        println!();
        println!("  these are cumulative since the counters were last reset, not a rate");
    }

    Ok(())
}

/// Everything an interface counts as not delivered.
fn errors(i: &Value) -> f64 {
    [
        "rx-error",
        "tx-error",
        "rx-drop",
        "tx-drop",
        "tx-queue-drop",
    ]
    .iter()
    .filter_map(|k| num(i, k))
    .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_clean_interface_counts_nothing() {
        let clean = json!({"rx-error": "0", "tx-error": "0", "rx-drop": "0", "tx-drop": "0", "tx-queue-drop": "0"});
        assert_eq!(errors(&clean), 0.0);
        let dropping = json!({"rx-error": "0", "tx-drop": "17"});
        assert_eq!(errors(&dropping), 17.0);
    }
}
