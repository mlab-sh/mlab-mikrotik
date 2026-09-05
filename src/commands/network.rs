//! `network` — how the router is segmented: addresses, bridges, VLANs, the
//! DHCP it serves, and where it sends what it cannot deliver locally.
//!
//! Nothing here grades anything; that is phase two's job. What it does is put
//! the five menus that define a segment side by side, because on RouterOS a
//! VLAN is described in three of them at once and reading any one alone gives
//! the wrong answer.

use anyhow::Result;
use clap::Subcommand;
use serde_json::{json, Value};

use crate::collect::Fetcher;
use crate::ros::{field, first_field, flag, Client};
use crate::ui::render;

#[derive(Subcommand, Debug)]
pub enum NetworkCmd {
    /// Addresses, and the interface each one sits on
    #[command(alias = "addr")]
    Addresses,
    /// Bridges, their ports, and whether VLAN filtering is on
    #[command(alias = "bridge")]
    Bridges,
    /// VLAN interfaces, and the bridge VLAN table when there is one
    #[command(alias = "vlan")]
    Vlans,
    /// DHCP servers, their pools, and how much of each pool is used
    Dhcp,
    /// The routing table
    #[command(alias = "route")]
    Routes,
}

pub async fn run(c: &Client, cmd: Option<NetworkCmd>) -> Result<()> {
    match cmd {
        Some(NetworkCmd::Addresses) => addresses(c).await,
        Some(NetworkCmd::Bridges) => bridges(c).await,
        Some(NetworkCmd::Vlans) => vlans(c).await,
        Some(NetworkCmd::Dhcp) => dhcp(c).await,
        Some(NetworkCmd::Routes) => routes(c).await,
        None => overview(c).await,
    }
}

/// The whole shape in one screen: how many of each thing, and the addresses.
async fn overview(c: &Client) -> Result<()> {
    let mut f = Fetcher::new(c);
    let addrs = f.list("/ip/address").await;
    let bridges = f.list("/interface/bridge").await;
    let ports = f.list("/interface/bridge/port").await;
    let vlans = f.list("/interface/vlan").await;
    let bvlans = f.list("/interface/bridge/vlan").await;
    let pools = f.list("/ip/pool").await;
    let servers = f.list("/ip/dhcp-server").await;
    let routes = f.list("/ip/route").await;

    if render::is_json() {
        render::print_json(&json!({
            "addresses": addrs,
            "bridges": bridges,
            "bridgePorts": ports,
            "vlans": vlans,
            "bridgeVlans": bvlans,
            "pools": pools,
            "dhcpServers": servers,
            "routes": routes,
            "unreadable": f.unreadable,
        }));
        return Ok(());
    }

    f.report();
    render::heading("Network");
    render::pairs(&[
        ("addresses", addrs.len().to_string()),
        (
            "bridges",
            format!("{} ({} ports)", bridges.len(), ports.len()),
        ),
        (
            "vlans",
            format!(
                "{} interfaces, {} in bridge tables",
                vlans.len(),
                bvlans.len()
            ),
        ),
        (
            "dhcp",
            format!("{} servers, {} pools", servers.len(), pools.len()),
        ),
        (
            "routes",
            format!(
                "{} ({} active)",
                routes.len(),
                routes.iter().filter(|r| flag(r, "active")).count()
            ),
        ),
    ]);

    render::heading("Addresses");
    render::list(&address_rows(&addrs), render::ADDRESS_COLS);
    render::count(addrs.len(), "address");
    Ok(())
}

async fn addresses(c: &Client) -> Result<()> {
    let mut f = Fetcher::new(c);
    let addrs = f.list("/ip/address").await;
    let rows = address_rows(&addrs);

    if render::is_json() {
        render::print_json(&json!({ "addresses": rows, "unreadable": f.unreadable }));
        return Ok(());
    }
    f.report();
    render::heading("Addresses");
    render::list(&rows, render::ADDRESS_COLS);
    render::count(rows.len(), "address");
    Ok(())
}

fn address_rows(addrs: &[Value]) -> Vec<Value> {
    addrs
        .iter()
        .map(|a| {
            json!({
                "address": field(a, "address"),
                "network": field(a, "network"),
                // `actual-interface` is what a VLAN or a bridge resolves to;
                // `interface` is what was configured. Both matter, and they
                // differ often enough to be worth two columns.
                "interface": field(a, "interface"),
                "actual": field(a, "actual-interface"),
                "origin": origin(a),
            })
        })
        .collect()
}

async fn bridges(c: &Client) -> Result<()> {
    let mut f = Fetcher::new(c);
    let bridges = f.list("/interface/bridge").await;
    let ports = f.list("/interface/bridge/port").await;

    let brows: Vec<Value> = bridges
        .iter()
        .map(|b| {
            let name = field(b, "name");
            json!({
                "name": name,
                "state": crate::ros::state(b),
                "vlanFiltering": flag(b, "vlan-filtering"),
                "protocolMode": field(b, "protocol-mode"),
                "dhcpSnooping": flag(b, "dhcp-snooping"),
                "ports": ports.iter().filter(|p| field(p, "bridge") == name).count(),
            })
        })
        .collect();

    let prows: Vec<Value> = ports
        .iter()
        .map(|p| {
            json!({
                "bridge": field(p, "bridge"),
                "interface": field(p, "interface"),
                "pvid": field(p, "pvid"),
                "frameTypes": field(p, "frame-types"),
                "horizon": field(p, "horizon"),
                "state": field(p, "status"),
            })
        })
        .collect();

    if render::is_json() {
        render::print_json(&json!({
            "bridges": brows, "ports": prows, "unreadable": f.unreadable
        }));
        return Ok(());
    }
    f.report();
    render::heading("Bridges");
    render::list(&brows, render::BRIDGE_COLS);
    render::count(brows.len(), "bridge");
    render::heading("Ports");
    render::list(&prows, render::BRIDGE_PORT_COLS);
    render::count(prows.len(), "port");
    Ok(())
}

async fn vlans(c: &Client) -> Result<()> {
    let mut f = Fetcher::new(c);
    let vlans = f.list("/interface/vlan").await;
    let bvlans = f.list("/interface/bridge/vlan").await;
    let addrs = f.list("/ip/address").await;

    let rows: Vec<Value> = vlans
        .iter()
        .map(|v| {
            let name = field(v, "name");
            let addr: Vec<String> = addrs
                .iter()
                .filter(|a| field(a, "interface") == name || field(a, "actual-interface") == name)
                .map(|a| field(a, "address"))
                .collect();
            json!({
                "name": name,
                "vlanId": field(v, "vlan-id"),
                "on": field(v, "interface"),
                "state": crate::ros::state(v),
                "addresses": addr.join(" "),
                "mtu": first_field(v, &["l2mtu", "mtu"]),
            })
        })
        .collect();

    let btable: Vec<Value> = bvlans
        .iter()
        .map(|v| {
            json!({
                "bridge": field(v, "bridge"),
                "vlanIds": field(v, "vlan-ids"),
                "tagged": field(v, "tagged"),
                "untagged": field(v, "untagged"),
                "origin": origin(v),
            })
        })
        .collect();

    if render::is_json() {
        render::print_json(&json!({
            "vlans": rows, "bridgeVlans": btable, "unreadable": f.unreadable
        }));
        return Ok(());
    }
    f.report();
    render::heading("VLAN interfaces");
    render::list(&rows, render::VLAN_COLS);
    render::count(rows.len(), "vlan");

    render::heading("Bridge VLAN table");
    if btable.is_empty() {
        println!();
        println!("  empty — VLANs on this router are interfaces, not bridge tags");
    } else {
        render::list(&btable, render::BRIDGE_VLAN_COLS);
        render::count(btable.len(), "entry");
    }
    Ok(())
}

async fn dhcp(c: &Client) -> Result<()> {
    let mut f = Fetcher::new(c);
    let servers = f.list("/ip/dhcp-server").await;
    let pools = f.list("/ip/pool").await;
    let networks = f.list("/ip/dhcp-server/network").await;

    let srows: Vec<Value> = servers
        .iter()
        .map(|s| {
            json!({
                "name": field(s, "name"),
                "interface": field(s, "interface"),
                "pool": field(s, "address-pool"),
                "leaseTime": field(s, "lease-time"),
                "state": crate::ros::state(s),
            })
        })
        .collect();

    let prows: Vec<Value> = pools
        .iter()
        .map(|p| {
            json!({
                "name": field(p, "name"),
                "ranges": field(p, "ranges"),
                "used": field(p, "used"),
                "available": field(p, "available"),
                "total": field(p, "total"),
            })
        })
        .collect();

    if render::is_json() {
        render::print_json(&json!({
            "servers": srows, "pools": prows, "networks": networks, "unreadable": f.unreadable
        }));
        return Ok(());
    }
    f.report();
    render::heading("DHCP servers");
    if srows.is_empty() {
        println!();
        println!("  none — this router hands out no addresses");
    } else {
        render::list(&srows, render::DHCP_COLS);
        render::count(srows.len(), "server");
    }
    render::heading("Pools");
    render::list(&prows, render::POOL_COLS);
    render::count(prows.len(), "pool");
    Ok(())
}

async fn routes(c: &Client) -> Result<()> {
    let mut f = Fetcher::new(c);
    let routes = f.list("/ip/route").await;

    let rows: Vec<Value> = routes
        .iter()
        .map(|r| {
            json!({
                "dst": field(r, "dst-address"),
                "gateway": first_field(r, &["gateway", "immediate-gw"]),
                "distance": field(r, "distance"),
                "table": field(r, "routing-table"),
                "state": route_state(r),
                "origin": origin(r),
            })
        })
        .collect();

    if render::is_json() {
        render::print_json(&json!({ "routes": rows, "unreadable": f.unreadable }));
        return Ok(());
    }
    f.report();
    render::heading("Routes");
    render::list(&rows, render::ROUTE_COLS);
    render::count(rows.len(), "route");
    Ok(())
}

/// Where a row came from. RouterOS marks a row `dynamic` when something else
/// created it — DHCP, a routing protocol, a PPP session — and that is the
/// difference between a decision someone made and a consequence of one.
fn origin(v: &Value) -> String {
    if flag(v, "dynamic") {
        "dynamic".to_string()
    } else {
        "static".to_string()
    }
}

fn route_state(r: &Value) -> String {
    if flag(r, "disabled") {
        "disabled".to_string()
    } else if flag(r, "active") {
        "active".to_string()
    } else {
        "inactive".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_dynamic_row_is_a_consequence_not_a_decision() {
        assert_eq!(origin(&json!({"dynamic": "true"})), "dynamic");
        assert_eq!(origin(&json!({"dynamic": "false"})), "static");
        assert_eq!(origin(&json!({})), "static");
    }

    #[test]
    fn a_disabled_route_is_never_reported_active() {
        assert_eq!(
            route_state(&json!({"disabled": "true", "active": "true"})),
            "disabled"
        );
        assert_eq!(route_state(&json!({"active": "true"})), "active");
        assert_eq!(route_state(&json!({"active": "false"})), "inactive");
    }
}
