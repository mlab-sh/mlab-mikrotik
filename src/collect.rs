//! One pass over what the account can read.
//!
//! Two rules hold this module together. Nothing here judges: it fetches and
//! shapes, and the commands — later, the checks — decide what any of it means.
//! And nothing here fails a run: a menu the account is refused, or a menu this
//! router does not carry because the package is not installed, is recorded in
//! [`Fetcher::unreadable`] so a command can say "not readable" instead of
//! showing an empty table that reads as "nothing there".

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::checks::Input;
use crate::ros::{field, flag, mac, Client};
use crate::ui;

/// Why a menu produced nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Reason {
    /// The router has no such menu — almost always a package that is not
    /// installed. `/interface/wireless` on a device with only the `wifi`
    /// driver answers exactly this.
    Absent,
    /// The account's group does not carry the policy this menu needs.
    Refused,
    /// Anything else: a timeout, a transport failure, a body that would not
    /// parse.
    Failed,
}

impl Reason {
    pub fn label(self) -> &'static str {
        match self {
            Reason::Absent => "menu absent from this router",
            Reason::Refused => "refused to this account",
            Reason::Failed => "could not be read",
        }
    }
}

/// A menu that answered with something other than data.
///
/// Round-trips through a snapshot file: a comparison has to be able to say
/// that a menu readable last month is refused today, which is a change in the
/// account rather than in the router and is worth exactly as much.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Unreadable {
    pub path: String,
    pub reason: Reason,
    pub detail: String,
}

/// A client, plus the record of what it could not read.
pub struct Fetcher<'a> {
    c: &'a Client,
    pub unreadable: Vec<Unreadable>,
}

impl<'a> Fetcher<'a> {
    pub fn new(c: &'a Client) -> Self {
        Fetcher {
            c,
            unreadable: Vec::new(),
        }
    }

    /// One object, or `Null` with the failure recorded.
    pub async fn get(&mut self, path: &str) -> Value {
        match self.c.get_one(path).await {
            Ok(v) => v,
            Err(e) => {
                self.note(path, &e);
                Value::Null
            }
        }
    }

    /// One menu's rows, or an empty list with the failure recorded.
    pub async fn list(&mut self, path: &str) -> Vec<Value> {
        match self.c.list(path).await {
            Ok(v) => v,
            Err(e) => {
                self.note(path, &e);
                Vec::new()
            }
        }
    }

    /// The same, restricted to named properties.
    pub async fn list_props(&mut self, path: &str, props: &[&str]) -> Vec<Value> {
        match self.c.list_props(path, props).await {
            Ok(v) => v,
            Err(e) => {
                self.note(path, &e);
                Vec::new()
            }
        }
    }

    fn note(&mut self, path: &str, e: &anyhow::Error) {
        let detail = e.to_string().lines().next().unwrap_or("").to_string();
        self.unreadable.push(Unreadable {
            path: path.to_string(),
            reason: classify(&detail),
            detail,
        });
    }

    /// Say on stderr what could not be read, so an empty table is never taken
    /// for an empty router.
    pub fn report(&self) {
        for u in &self.unreadable {
            // A menu that simply is not on this hardware is expected, not a
            // problem: it is worth one quiet line, not a warning.
            let msg = format!("{} — {}", u.path, u.reason.label());
            match u.reason {
                Reason::Absent => ui::info(&msg),
                _ => ui::warning(&format!("{msg} ({})", u.detail)),
            }
        }
    }
}

/// Read the shape of a failure out of the error text.
///
/// RouterOS answers a missing package with `400 Bad Request` and the detail
/// `no such command or directory (wireless)`, which is a very different fact
/// from a refusal, and must not be reported as one.
fn classify(detail: &str) -> Reason {
    let d = detail.to_ascii_lowercase();
    if d.contains("no such command") || d.contains("no such item") {
        Reason::Absent
    } else if d.contains("api error 403")
        || d.contains("api error 401")
        || d.contains("not permitted")
    {
        Reason::Refused
    } else {
        Reason::Failed
    }
}

/// One machine seen on the network, however it was seen.
///
/// The MAC address is the join key because it is the only identifier every
/// source carries. A host that three menus name is one row, not three.
#[derive(Debug, Clone, Serialize)]
pub struct Host {
    pub mac: String,
    pub address: String,
    pub name: String,
    pub interface: String,
    /// Which menus named it: `lease`, `arp`, `bridge`, `neighbor`.
    pub seen_in: Vec<String>,
    pub status: String,
    pub last_seen: String,
    pub dynamic: bool,
    pub comment: String,
}

/// Everything the router knows about who is on the network.
///
/// Four menus, joined on the MAC address. None of them is authoritative on its
/// own: a lease says what was handed out, ARP says what answered, the bridge
/// table says which port it is behind, and a neighbour is a device that
/// announced itself.
pub async fn hosts(f: &mut Fetcher<'_>) -> Vec<Host> {
    let mut by_mac: BTreeMap<String, Host> = BTreeMap::new();

    let mut merge = |m: String, source: &str, fill: &dyn Fn(&mut Host)| {
        if m.is_empty() {
            return;
        }
        let h = by_mac.entry(m.clone()).or_insert_with(|| Host {
            mac: m,
            address: String::new(),
            name: String::new(),
            interface: String::new(),
            seen_in: Vec::new(),
            status: String::new(),
            last_seen: String::new(),
            dynamic: false,
            comment: String::new(),
        });
        fill(h);
        if !h.seen_in.iter().any(|s| s == source) {
            h.seen_in.push(source.to_string());
        }
    };

    for l in f.list("/ip/dhcp-server/lease").await {
        let (addr, name, status, last, dyn_, comment) = (
            field(&l, "address"),
            crate::ros::first_field(&l, &["host-name", "comment"]),
            field(&l, "status"),
            field(&l, "last-seen"),
            flag(&l, "dynamic"),
            field(&l, "comment"),
        );
        merge(mac(&l, "mac-address"), "lease", &|h: &mut Host| {
            set(&mut h.address, &addr);
            set(&mut h.name, &name);
            set(&mut h.status, &status);
            set(&mut h.last_seen, &last);
            set(&mut h.comment, &comment);
            h.dynamic = dyn_;
        });
    }

    for a in f.list("/ip/arp").await {
        let (addr, iface, status) = (
            field(&a, "address"),
            field(&a, "interface"),
            field(&a, "status"),
        );
        merge(mac(&a, "mac-address"), "arp", &|h: &mut Host| {
            set(&mut h.address, &addr);
            set(&mut h.interface, &iface);
            set(&mut h.status, &status);
        });
    }

    for b in f.list("/interface/bridge/host").await {
        // `on-interface` is the physical port; `interface` is what the bridge
        // calls it. The port is the useful one for finding the machine.
        let iface = crate::ros::first_field(&b, &["on-interface", "interface"]);
        merge(mac(&b, "mac-address"), "bridge", &|h: &mut Host| {
            set(&mut h.interface, &iface);
        });
    }

    for n in f.list("/ip/neighbor").await {
        let (addr, name, iface) = (
            crate::ros::first_field(&n, &["address4", "address"]),
            field(&n, "identity"),
            crate::ros::first_field(&n, &["interface", "interface-name"]),
        );
        merge(mac(&n, "mac-address"), "neighbor", &|h: &mut Host| {
            set(&mut h.address, &addr);
            set(&mut h.name, &name);
            set(&mut h.interface, &iface);
        });
    }

    by_mac.into_values().collect()
}

/// Fill a field only if it is still empty.
///
/// The merge order is deliberate — a lease's hostname beats a neighbour's
/// identity — so a later source must never overwrite what an earlier one
/// already established.
fn set(slot: &mut String, value: &str) {
    if slot.is_empty() && !value.is_empty() {
        *slot = value.to_string();
    }
}

/// Everything the graded checks read, in one pass.
///
/// Thirty-odd menus, fetched sequentially: RouterOS answers each in a few
/// milliseconds over a keep-alive connection, and a failure has to be recorded
/// against the menu that produced it rather than lost in a batch.
///
/// The two wireless stacks are both attempted on purpose. A router carries one
/// or the other, and the one it does not carry answers `400 no such command`,
/// which lands in `unreadable` as **absent** — which is exactly how the
/// wireless checks tell "no radios here" from "the menu was refused".
pub async fn security(f: &mut Fetcher<'_>) -> Input {
    Input {
        resource: f.get("/system/resource").await,
        routerboard: f.get("/system/routerboard").await,

        users: f.list("/user").await,
        groups: f.list("/user/group").await,

        services: f.list("/ip/service").await,
        filter: f.list("/ip/firewall/filter").await,
        nat: f.list("/ip/firewall/nat").await,
        ipv6_filter: f.list("/ipv6/firewall/filter").await,
        ipv6_addresses: f.list("/ipv6/address").await,

        bridges: f.list("/interface/bridge").await,
        bridge_ports: f.list("/interface/bridge/port").await,
        vlans: f.list("/interface/vlan").await,

        dns: f.get("/ip/dns").await,
        snmp: f.get("/snmp").await,
        snmp_communities: f.list("/snmp/community").await,
        socks: f.get("/ip/socks").await,
        proxy: f.get("/ip/proxy").await,
        upnp: f.get("/ip/upnp").await,
        cloud: f.get("/ip/cloud").await,
        ssh: f.get("/ip/ssh").await,

        romon: f.get("/tool/romon").await,
        mac_server: f.get("/tool/mac-server").await,
        mac_winbox: f.get("/tool/mac-server/mac-winbox").await,
        bandwidth_server: f.get("/tool/bandwidth-server").await,
        discovery: f.get("/ip/neighbor/discovery-settings").await,
        ntp: f.get("/system/ntp/client").await,

        logging: f.list("/system/logging").await,
        logging_actions: f.list("/system/logging/action").await,

        wifi: f.list("/interface/wifi").await,
        wifi_security: f.list("/interface/wifi/security").await,
        wireless: f.list("/interface/wireless").await,
        wireless_security: f.list("/interface/wireless/security-profiles").await,

        interfaces: f
            .list_props("/interface", &["name", "type", "disabled", "comment"])
            .await,
        scheduler: f.list("/system/scheduler").await,
        scripts: f.list("/system/script").await,
        netwatch: f.list("/tool/netwatch").await,
        // `/file` embeds each file's contents, and a binary one makes the
        // whole response invalid UTF-8 — RouterOS answers 200 with bytes that
        // are not JSON. Naming the properties is the only way to read it.
        files: f
            .list_props("/file", &[".id", "name", "type", "size", "creation-time"])
            .await,

        unreadable: f.unreadable.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_package_is_not_a_refusal() {
        assert_eq!(
            classify("API error 400: Bad Request (no such command or directory (wireless))"),
            Reason::Absent
        );
        assert_eq!(classify("API error 403: Forbidden"), Reason::Refused);
        assert_eq!(classify("API error 401: Unauthorized"), Reason::Refused);
        assert_eq!(classify("connection refused"), Reason::Failed);
    }

    #[test]
    fn the_first_source_to_name_a_field_keeps_it() {
        let mut s = String::new();
        set(&mut s, "imprimante");
        set(&mut s, "HP1234");
        assert_eq!(s, "imprimante", "a later source never overwrites");
        let mut empty = String::new();
        set(&mut empty, "");
        assert_eq!(empty, "");
    }
}
