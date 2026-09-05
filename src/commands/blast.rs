//! `blast` — what a compromised host on one segment reaches.
//!
//! The router routes between every network it holds an address on. The only
//! thing that stops it is the `forward` chain, so the question "what does a
//! machine on the guest VLAN reach" is answered by two facts: are both
//! segments on this router, and does anything in `forward` say no.
//!
//! **What this does not do** is simulate a packet. Deciding that rule 12 can
//! never match needs per-packet evaluation of the whole ordered set, and a
//! tool that guesses at it produces confident nonsense. So each pair is
//! reported as one of three states, and the middle one is honest about being
//! undecided rather than being rounded to either side.

use anyhow::Result;
use clap::Args;
use serde_json::{json, Value};

use crate::collect::Fetcher;
use crate::ros::{field, first_field, flag, Client};
use crate::ui::render;

#[derive(Args, Debug)]
pub struct BlastArgs {
    /// Only from this segment: an interface name or an address on it
    #[arg(long, value_name = "SEGMENT")]
    pub from: Option<String>,
    /// Print every pair, however many there are
    #[arg(long)]
    pub pairs: bool,
}

/// One network this router is directly attached to.
#[derive(Debug, Clone)]
struct Segment {
    interface: String,
    network: String,
    address: String,
}

pub async fn run(c: &Client, args: &BlastArgs) -> Result<()> {
    let mut f = Fetcher::new(c);
    let addresses = f.list("/ip/address").await;
    let filter = f.list("/ip/firewall/filter").await;

    let segments: Vec<Segment> = addresses
        .iter()
        .filter(|a| !flag(a, "disabled") && !flag(a, "invalid"))
        .map(|a| Segment {
            interface: first_field(a, &["actual-interface", "interface"]),
            network: field(a, "network"),
            address: field(a, "address"),
        })
        .filter(|s| !s.interface.is_empty())
        // A host-route carries no other host: a /32 or a /128 is the router
        // talking to itself, and counting it as a segment inflates the matrix
        // with pairs nobody can be on either end of.
        .filter(|s| !is_host_route(&s.address))
        .collect();

    let forward: Vec<&Value> = filter
        .iter()
        .filter(|r| !flag(r, "disabled") && field(r, "chain") == "forward")
        .collect();

    // The one ordering question that can be answered without simulating a
    // packet: does the chain end by refusing what nothing matched.
    let closes = forward
        .last()
        .map(|last| {
            matches!(field(last, "action").as_str(), "drop" | "reject")
                && crate::checks::segmentation::is_catch_all(last)
        })
        .unwrap_or(false);

    let kept: Vec<&Segment> = segments
        .iter()
        .filter(|s| match &args.from {
            Some(want) => {
                s.interface.eq_ignore_ascii_case(want)
                    || s.address.starts_with(want)
                    || s.network == *want
            }
            None => true,
        })
        .collect();

    let mut pairs: Vec<Value> = Vec::new();
    for from in &kept {
        for to in &segments {
            if from.interface == to.interface {
                continue;
            }
            let naming = rules_naming(&forward, from, to);
            let state = if !naming.is_empty() {
                "filtered"
            } else if closes {
                "blocked"
            } else {
                "open"
            };
            pairs.push(json!({
                "from": format!("{} ({})", from.interface, from.network),
                "to": format!("{} ({})", to.interface, to.network),
                "state": state,
                "rules": naming.len(),
            }));
        }
    }

    if render::is_json() {
        render::print_json(&json!({
            "segments": segments.iter().map(|s| json!({
                "interface": s.interface, "address": s.address, "network": s.network
            })).collect::<Vec<_>>(),
            "forwardRules": forward.len(),
            "forwardCloses": closes,
            "reach": pairs,
            "unreadable": f.unreadable,
        }));
        return Ok(());
    }

    f.report();

    render::heading("Segments on this router");
    let seg_rows: Vec<Value> = segments
        .iter()
        .map(|s| json!({"interface": s.interface, "address": s.address, "network": s.network}))
        .collect();
    render::list(&seg_rows, render::SEGMENT_COLS);
    render::count(segments.len(), "segment");

    render::heading("The forward chain");
    render::pairs(&[
        ("active rules", forward.len().to_string()),
        (
            "ends in a refusal",
            if closes { "yes" } else { "no" }.to_string(),
        ),
    ]);
    if forward.is_empty() {
        println!("  nothing filters traffic between these segments: the router routes, and");
        println!("  every machine on any of them reaches every machine on all the others");
    } else if !closes {
        println!("  the chain does not close, so any pair no rule names is allowed through");
    }

    render::heading("Reach");
    let count = |state: &str| pairs.iter().filter(|p| p["state"] == json!(state)).count();
    let (open, filtered, blocked) = (count("open"), count("filtered"), count("blocked"));

    if pairs.is_empty() {
        println!();
        println!("  only one segment — there is nothing to cross");
    } else {
        // A matrix where every pair says the same thing is one fact, not two
        // hundred rows, and printing it as two hundred rows buries it.
        let uniform = [open, filtered, blocked].iter().filter(|n| **n > 0).count() == 1;
        const MAX_ROWS: usize = 30;

        // `--from` is an explicit request for detail about one segment, so it
        // gets the rows even when they all say the same thing.
        if args.pairs || args.from.is_some() || (!uniform && pairs.len() <= MAX_ROWS) {
            render::list(&pairs, render::REACH_COLS);
        }
        println!();
        println!(
            "  {} ordered pair(s): {open} open, {filtered} filtered, {blocked} blocked",
            pairs.len()
        );
        if uniform {
            println!(
                "  every pair is {} — one fact, not {} of them",
                if open > 0 {
                    "open"
                } else if filtered > 0 {
                    "filtered"
                } else {
                    "blocked"
                },
                pairs.len()
            );
        }
        if !args.pairs && args.from.is_none() && (uniform || pairs.len() > MAX_ROWS) {
            println!("  narrow with --from <interface>, or --pairs for the whole matrix");
        }
    }

    println!();
    println!("  open      no rule names this pair, and the chain does not close");
    println!("  filtered  some rule names one side or the other — read them, order matters");
    println!("  blocked   no rule names this pair, and the chain ends in a refusal");
    println!();
    println!("  `filtered` is deliberately undecided. Saying whether those rules allow or");
    println!("  refuse a given packet needs per-packet evaluation of the whole ordered set,");
    println!("  and a guess would be worse than silence.");

    Ok(())
}

/// Whether an address covers only itself.
///
/// A `/32` or a `/128` is the router talking to itself — a loopback, a
/// borrowed transit address — and no other host can sit on it. Counting one as
/// a segment fills the matrix with pairs nobody can be on either end of.
fn is_host_route(cidr: &str) -> bool {
    match cidr.split_once('/') {
        Some((addr, len)) => len.trim() == if addr.contains(':') { "128" } else { "32" },
        None => false,
    }
}

/// The forward rules that name either side of a pair.
///
/// Matched on the interface, the interface list, and the address or network,
/// because RouterOS rules are written both ways and a rule that names only the
/// network still governs the pair.
fn rules_naming<'a>(forward: &[&'a Value], from: &Segment, to: &Segment) -> Vec<&'a Value> {
    forward
        .iter()
        .filter(|r| {
            let mentions = |side: &Segment, prefix: &str| {
                let iface = field(r, &format!("{prefix}-interface"));
                let list = field(r, &format!("{prefix}-interface-list"));
                let addr = field(r, &format!("{prefix}-address"));
                iface == side.interface
                    || (!list.is_empty() && list == side.interface)
                    || (!addr.is_empty()
                        && (addr == side.network
                            || addr.starts_with(&side.network)
                            || side.address.starts_with(&addr)))
            };
            mentions(from, "in") || mentions(to, "out")
        })
        .copied()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seg(interface: &str, network: &str, address: &str) -> Segment {
        Segment {
            interface: interface.into(),
            network: network.into(),
            address: address.into(),
        }
    }

    #[test]
    fn a_host_route_is_not_a_segment() {
        assert!(is_host_route("45.8.205.249/32"));
        assert!(is_host_route("2001:db8::1/128"));
        assert!(!is_host_route("10.0.1.1/24"));
        assert!(!is_host_route("2001:db8::1/64"));
        assert!(
            !is_host_route("10.0.1.1"),
            "no prefix at all is not a host route"
        );
    }

    #[test]
    fn a_rule_naming_the_inbound_interface_counts() {
        let r = json!({"chain": "forward", "in-interface": "guest", "action": "drop"});
        let rules = vec![&r];
        let g = seg("guest", "10.0.9.0", "10.0.9.1/24");
        let l = seg("lan", "10.0.1.0", "10.0.1.1/24");
        assert_eq!(rules_naming(&rules, &g, &l).len(), 1);
        assert_eq!(
            rules_naming(&rules, &l, &g).len(),
            0,
            "the other direction is a different question"
        );
    }

    #[test]
    fn a_rule_naming_the_network_counts_too() {
        let r = json!({"chain": "forward", "out-address": "10.0.1.0", "action": "accept"});
        let rules = vec![&r];
        let g = seg("guest", "10.0.9.0", "10.0.9.1/24");
        let l = seg("lan", "10.0.1.0", "10.0.1.1/24");
        assert_eq!(rules_naming(&rules, &g, &l).len(), 1);
    }

    #[test]
    fn a_rule_naming_neither_side_is_not_counted() {
        let r = json!({"chain": "forward", "in-interface": "wan", "action": "drop"});
        let rules = vec![&r];
        let g = seg("guest", "10.0.9.0", "10.0.9.1/24");
        let l = seg("lan", "10.0.1.0", "10.0.1.1/24");
        assert!(rules_naming(&rules, &g, &l).is_empty());
    }
}
