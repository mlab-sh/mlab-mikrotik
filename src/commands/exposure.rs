//! `exposure` — what this router offers to anything that can reach it.
//!
//! Two layers, reported separately because they fail independently: the
//! services the router itself listens on with their own `available-from`
//! restriction, and the forwards that publish something behind it.

use anyhow::Result;
use serde_json::{json, Value};

use crate::collect::Fetcher;
use crate::ros::{field, flag, Client};
use crate::ui::render;

pub async fn run(c: &Client) -> Result<()> {
    let mut f = Fetcher::new(c);

    let services = f.list("/ip/service").await;
    let nat = f.list("/ip/firewall/nat").await;
    let upnp = f.get("/ip/upnp").await;
    let socks = f.get("/ip/socks").await;
    let proxy = f.get("/ip/proxy").await;
    let dns = f.get("/ip/dns").await;
    let cloud = f.get("/ip/cloud").await;

    let listening: Vec<Value> = services
        .iter()
        .filter(|s| !flag(s, "disabled"))
        .map(|s| {
            json!({
                "service": field(s, "name"),
                "port": field(s, "port"),
                "availableFrom": match field(s, "available-from").as_str() {
                    "" => "anywhere".to_string(),
                    a => a.to_string(),
                },
                "vrf": field(s, "vrf"),
            })
        })
        .collect();

    let forwards: Vec<Value> = nat
        .iter()
        .filter(|r| !flag(r, "disabled") && field(r, "action") == "dst-nat")
        .map(|r| {
            json!({
                "proto": match field(r, "protocol").as_str() {
                    "" => "any".to_string(),
                    p => p.to_string(),
                },
                // A forward with no port matches every port, which is worth
                // saying rather than leaving the column blank.
                "port": match field(r, "dst-port").as_str() {
                    "" => "any".to_string(),
                    p => p.to_string(),
                },
                "from": match field(r, "src-address").as_str() {
                    "" => match field(r, "src-address-list").as_str() {
                        "" => "anywhere".to_string(),
                        l => l.to_string(),
                    },
                    a => a.to_string(),
                },
                "to": format!(
                    "{}{}",
                    field(r, "to-addresses"),
                    match field(r, "to-ports").as_str() {
                        "" => String::new(),
                        p => format!(":{p}"),
                    }
                ),
                "comment": field(r, "comment"),
            })
        })
        .collect();

    let relays = vec![
        toggle(
            "SOCKS proxy",
            flag(&socks, "enabled"),
            &format!("port {}", field(&socks, "port")),
        ),
        toggle(
            "web proxy",
            flag(&proxy, "enabled"),
            &format!("port {}", field(&proxy, "port")),
        ),
        toggle("UPnP", flag(&upnp, "enabled"), ""),
        toggle(
            "DNS answers remote queries",
            flag(&dns, "allow-remote-requests"),
            &format!(
                "cache {} of {}",
                field(&dns, "cache-used"),
                field(&dns, "cache-size")
            ),
        ),
        toggle(
            "MikroTik Cloud DDNS",
            flag(&cloud, "ddns-enabled"),
            &field(&cloud, "public-address"),
        ),
    ];

    if render::is_json() {
        render::print_json(&json!({
            "listening": listening,
            "forwards": forwards,
            "relays": relays,
            "unreadable": f.unreadable,
        }));
        return Ok(());
    }

    f.report();

    render::heading("Listening");
    render::list(&listening, render::SERVICE_COLS);
    render::count(listening.len(), "service");
    let open = listening
        .iter()
        .filter(|s| s["availableFrom"] == json!("anywhere"))
        .count();
    if open > 0 {
        println!(
            "  {open} of them accept connections from any address — whether the firewall stops them is a separate question, see `firewall`"
        );
    }

    render::heading("Published from outside");
    if forwards.is_empty() {
        println!();
        println!("  no dst-nat rule — nothing behind this router is published by NAT");
    } else {
        render::list(&forwards, render::FORWARD_COLS);
        render::count(forwards.len(), "forward");
    }

    render::heading("Relays and reflectors");
    render::list(&relays, render::TOGGLE_COLS);
    println!();
    println!("  these are the features that make a router useful to somebody else");

    Ok(())
}

fn toggle(name: &str, on: bool, detail: &str) -> Value {
    json!({
        "feature": name,
        "state": if on { "on" } else { "off" },
        "detail": if on { detail } else { "" },
    })
}
