//! `firewall` — the rules, and the one ordering question that can be answered
//! honestly without simulating a packet.
//!
//! What this does **not** do is decide which rules are dead or shadowed. That
//! needs per-packet evaluation of the whole ordered set, and a tool that
//! guesses at it produces confident nonsense. What it does instead is report
//! the shape of each chain and whether it closes.

use anyhow::Result;
use clap::Args;
use serde_json::{json, Value};

use crate::collect::Fetcher;
use crate::ros::{field, first_field, flag, Client};
use crate::ui::render;

#[derive(Args, Debug)]
pub struct FirewallArgs {
    /// Only this chain: input, forward, output, srcnat, dstnat
    #[arg(long, value_name = "CHAIN")]
    pub chain: Option<String>,
    /// Include rules that are administratively disabled
    #[arg(long)]
    pub all: bool,
    /// Show the IPv6 tables instead of the IPv4 ones
    #[arg(long = "ipv6", alias = "6")]
    pub ipv6: bool,
}

pub async fn run(c: &Client, args: &FirewallArgs) -> Result<()> {
    let mut f = Fetcher::new(c);

    let (filter_path, nat_path) = if args.ipv6 {
        ("/ipv6/firewall/filter", "/ipv6/firewall/nat")
    } else {
        ("/ip/firewall/filter", "/ip/firewall/nat")
    };

    let filter = f.list(filter_path).await;
    let nat = f.list(nat_path).await;
    let lists = f
        .list(if args.ipv6 {
            "/ipv6/firewall/address-list"
        } else {
            "/ip/firewall/address-list"
        })
        .await;

    let frows = rules(&filter, args, false);
    let nrows = rules(&nat, args, true);

    if render::is_json() {
        render::print_json(&json!({
            "filter": frows,
            "nat": nrows,
            "addressLists": summarize_lists(&lists),
            "chains": chain_summary(&filter),
            "unreadable": f.unreadable,
        }));
        return Ok(());
    }

    f.report();

    render::heading(if args.ipv6 { "Filter (IPv6)" } else { "Filter" });
    render::list(&frows, render::FILTER_COLS);
    render::count(frows.len(), "rule");

    // The summary is the point of the command: a chain that does not end in a
    // bare refusal lets through everything nothing matched.
    render::heading("Chains");
    render::list(&chain_summary(&filter), render::CHAIN_COLS);
    println!();
    println!("  a chain closes when its last active rule is a drop or reject that matches nothing in particular");
    println!("  rule order beyond that is not analysed — that needs per-packet evaluation, and a guess would be worse than silence");

    if !nrows.is_empty() {
        render::heading("NAT");
        render::list(&nrows, render::NAT_COLS);
        render::count(nrows.len(), "rule");
    }

    if !lists.is_empty() {
        render::heading("Address lists");
        render::list(&summarize_lists(&lists), render::ADDRESS_LIST_COLS);
    }

    Ok(())
}

fn rules(rules: &[Value], args: &FirewallArgs, nat: bool) -> Vec<Value> {
    rules
        .iter()
        .enumerate()
        .filter(|(_, r)| args.all || !flag(r, "disabled"))
        .filter(|(_, r)| match &args.chain {
            Some(c) => field(r, "chain").eq_ignore_ascii_case(c),
            None => true,
        })
        .map(|(n, r)| {
            let mut row = json!({
                "n": n,
                "chain": field(r, "chain"),
                "action": field(r, "action"),
                "src": endpoint(r, "src"),
                "dst": endpoint(r, "dst"),
                "proto": proto(r),
                "state": if flag(r, "disabled") { "disabled" } else { "active" },
                "log": flag(r, "log"),
                "hits": field(r, "packets"),
                "comment": field(r, "comment"),
            });
            if nat {
                row["to"] = json!(format!(
                    "{}{}",
                    field(r, "to-addresses"),
                    match field(r, "to-ports").as_str() {
                        "" => String::new(),
                        p => format!(":{p}"),
                    }
                ));
            }
            row
        })
        .collect()
}

/// One side of a rule, address list included — `dst-address-list=blocked` is
/// as much a destination as `dst-address=10.0.0.0/8`.
fn endpoint(r: &Value, side: &str) -> String {
    let addr = first_field(
        r,
        &[&format!("{side}-address"), &format!("{side}-address-list")],
    );
    let port = field(r, &format!("{side}-port"));
    match (addr.is_empty(), port.is_empty()) {
        (true, true) => String::new(),
        (false, true) => addr,
        (true, false) => format!(":{port}"),
        (false, false) => format!("{addr}:{port}"),
    }
}

fn proto(r: &Value) -> String {
    let p = field(r, "protocol");
    let state = field(r, "connection-state");
    match (p.is_empty(), state.is_empty()) {
        (true, true) => String::new(),
        (false, true) => p,
        (true, false) => state,
        (false, false) => format!("{p} {state}"),
    }
}

/// Per-chain shape: how many rules, and whether it ends in a refusal.
fn chain_summary(filter: &[Value]) -> Vec<Value> {
    let mut chains: Vec<String> = filter.iter().map(|r| field(r, "chain")).collect();
    chains.sort();
    chains.dedup();

    chains
        .into_iter()
        .map(|chain| {
            let active: Vec<&Value> = filter
                .iter()
                .filter(|r| !flag(r, "disabled") && field(r, "chain") == chain)
                .collect();
            let closed = active
                .last()
                .map(|last| {
                    matches!(field(last, "action").as_str(), "drop" | "reject")
                        && crate::checks::segmentation::is_catch_all(last)
                })
                .unwrap_or(false);
            json!({
                "chain": chain,
                "rules": active.len(),
                "accepts": active.iter().filter(|r| field(r, "action") == "accept").count(),
                "refusals": active.iter().filter(|r| matches!(field(r, "action").as_str(), "drop" | "reject")).count(),
                "closes": closed,
            })
        })
        .collect()
}

fn summarize_lists(lists: &[Value]) -> Vec<Value> {
    let mut names: Vec<String> = lists.iter().map(|l| field(l, "list")).collect();
    names.sort();
    names.dedup();

    names
        .into_iter()
        .map(|name| {
            let members: Vec<&Value> = lists.iter().filter(|l| field(l, "list") == name).collect();
            json!({
                "list": name,
                "entries": members.len(),
                "dynamic": members.iter().filter(|m| flag(m, "dynamic")).count(),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_address_list_counts_as_an_endpoint() {
        let r = json!({"dst-address-list": "blocked", "dst-port": "443"});
        assert_eq!(endpoint(&r, "dst"), "blocked:443");
        let bare = json!({"src-address": "10.0.0.0/8"});
        assert_eq!(endpoint(&bare, "src"), "10.0.0.0/8");
        assert_eq!(endpoint(&json!({}), "src"), "");
    }

    #[test]
    fn a_port_with_no_address_still_reads_as_a_port() {
        assert_eq!(endpoint(&json!({"dst-port": "8291"}), "dst"), ":8291");
    }

    #[test]
    fn the_chain_summary_counts_only_active_rules() {
        let filter = vec![
            json!({"chain": "input", "action": "accept", "disabled": "false"}),
            json!({"chain": "input", "action": "drop", "disabled": "true"}),
            json!({"chain": "forward", "action": "drop", "disabled": "false"}),
        ];
        let s = chain_summary(&filter);
        let input = s.iter().find(|c| c["chain"] == "input").unwrap();
        assert_eq!(input["rules"], 1);
        assert_eq!(input["closes"], false, "the closing drop is disabled");
        let forward = s.iter().find(|c| c["chain"] == "forward").unwrap();
        assert_eq!(forward["closes"], true);
    }
}
