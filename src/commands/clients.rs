//! `clients` — what the router knows about who is on the network.
//!
//! Four menus answer that question and none of them alone is the answer: a
//! DHCP lease says what was handed out, ARP says what replied, the bridge
//! table says which port a MAC sits behind, and a neighbour is a device that
//! announced itself. They are joined on the MAC address, which is the only
//! identifier all four carry.

use anyhow::Result;
use clap::Args;
use serde_json::{json, Value};

use crate::collect::{hosts, Fetcher};
use crate::ros::Client;
use crate::ui::render;

#[derive(Args, Debug)]
pub struct ClientArgs {
    /// Only hosts named by this menu: lease, arp, bridge, neighbor
    #[arg(long, value_name = "SOURCE")]
    pub seen_in: Option<String>,
    /// Only hosts with no DHCP lease — on a network that hands out every
    /// address, these are the ones that configured themselves
    #[arg(long)]
    pub static_only: bool,
}

pub async fn run(c: &Client, args: &ClientArgs) -> Result<()> {
    let mut f = Fetcher::new(c);
    let all = hosts(&mut f).await;

    let kept: Vec<&crate::collect::Host> = all
        .iter()
        .filter(|h| match &args.seen_in {
            Some(s) => h.seen_in.iter().any(|x| x.eq_ignore_ascii_case(s)),
            None => true,
        })
        .filter(|h| !args.static_only || !h.seen_in.iter().any(|s| s == "lease"))
        .collect();

    let rows: Vec<Value> = kept
        .iter()
        .map(|h| {
            json!({
                "mac": h.mac,
                "address": h.address,
                "name": h.name,
                "interface": h.interface,
                "seenIn": h.seen_in.join(" "),
                "status": h.status,
                "lastSeen": h.last_seen,
            })
        })
        .collect();

    if render::is_json() {
        render::print_json(&json!({
            "hosts": rows,
            "unreadable": f.unreadable,
        }));
        return Ok(());
    }

    f.report();
    render::heading("Hosts");
    render::list(&rows, render::HOST_COLS);
    render::count(rows.len(), "host");

    // Which menu found what is worth stating plainly: a router with no DHCP
    // server has no leases, and a reader who does not know that reads the
    // empty column as a gap in the data.
    let tally = |s: &str| {
        all.iter()
            .filter(|h| h.seen_in.iter().any(|x| x == s))
            .count()
    };
    println!(
        "  from leases {}, arp {}, bridge {}, neighbours {}",
        tally("lease"),
        tally("arp"),
        tally("bridge"),
        tally("neighbor")
    );

    Ok(())
}
