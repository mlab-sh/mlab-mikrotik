//! The dated record, and the rules for comparing two of them.
//!
//! There is no event stream on a RouterOS device — nothing pushes, and the
//! only history the router keeps is a log that lives in memory until the next
//! reboot. Detection here is therefore **differential**: you do not read an
//! alarm, you compare two dated collections and qualify the difference. That
//! is slower, and it is harder to evade — an attacker can avoid tripping a
//! signature, but can hardly avoid existing in the inventory.
//!
//! `POST /rest/export` is not the base for any of this. It answers `200` with
//! an empty array: the configuration text never comes back over REST, and the
//! `file=` form writes to the router's own storage, which a read-only tool has
//! no business doing. So a snapshot is the REST menu catalogue, which diffs
//! field by field rather than line by line.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::collect::{Fetcher, Unreadable};
use crate::ros::{field, iso8601, now};
use crate::secrets;

/// Every menu a snapshot records.
///
/// Wider than what the checks read, on purpose: a snapshot is written once and
/// compared for years, and a menu left out today cannot be compared
/// retroactively. The integrity menus at the end carry nothing phase two
/// grades — they are here because arrivals in them are what phase five hunts.
pub const CATALOGUE: [&str; 48] = [
    // identity and hardware
    "/system/identity",
    "/system/resource",
    "/system/routerboard",
    "/system/license",
    "/system/package",
    "/system/clock",
    // who can log in
    "/user",
    "/user/group",
    "/user/ssh-keys",
    // what is listening and what it allows
    "/ip/service",
    "/ip/firewall/filter",
    "/ip/firewall/nat",
    "/ip/firewall/mangle",
    "/ip/firewall/raw",
    "/ip/firewall/address-list",
    "/ipv6/firewall/filter",
    "/ipv6/firewall/address-list",
    // the shape of the network
    "/interface",
    "/interface/list",
    "/interface/list/member",
    "/interface/bridge",
    "/interface/bridge/port",
    "/interface/bridge/vlan",
    "/interface/vlan",
    "/ip/address",
    "/ipv6/address",
    "/ip/route",
    "/ip/pool",
    "/ip/dhcp-server",
    "/ip/dhcp-server/network",
    "/ip/dhcp-server/lease",
    // settings that defend, or do not
    "/ip/dns",
    "/ip/dns/static",
    "/ip/ssh",
    "/ip/socks",
    "/ip/proxy",
    "/ip/upnp",
    "/ip/cloud",
    "/snmp",
    "/snmp/community",
    "/ip/neighbor/discovery-settings",
    "/tool/romon",
    // who may dial in, and with what
    "/ppp/secret",
    "/ppp/profile",
    "/ip/ipsec/peer",
    "/ip/ipsec/identity",
    "/radius",
    "/certificate",
];

/// Menus recorded on top of [`CATALOGUE`] when they exist on this router.
///
/// Split out because a device answers `400 no such command` for the wireless
/// stack it does not carry, and that is an expected absence rather than a
/// failure worth listing next to a refusal.
pub const OPTIONAL: [&str; 8] = [
    "/system/scheduler",
    "/system/script",
    "/tool/netwatch",
    "/tool/mac-server",
    "/tool/mac-server/mac-winbox",
    "/tool/bandwidth-server",
    "/interface/wifi",
    "/interface/wireless",
];

/// Fields that change on their own and mean nothing in a comparison.
///
/// Counters, clocks and identifiers. Leaving them in would make every diff
/// report every row as changed, which is the same as reporting nothing.
const VOLATILE: [&str; 32] = [
    ".id",
    ".nextid",
    "bytes",
    "packets",
    "uptime",
    "age",
    "last-seen",
    "last-logged-in",
    "last-link-up-time",
    "link-downs",
    "cache-used",
    "free-memory",
    "free-hdd-space",
    "cpu-load",
    "used",
    "available",
    "write-sect-since-reboot",
    "write-sect-total",
    "bad-blocks",
    "update-time",
    "rx-byte",
    "tx-byte",
    "rx-packet",
    "tx-packet",
    "rx-drop",
    "tx-drop",
    "rx-error",
    "tx-error",
    "tx-queue-drop",
    "status",
    "date",
    "time",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Router {
    #[serde(default)]
    pub identity: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub board: String,
    #[serde(default)]
    pub serial: String,
}

/// One dated collection.
///
/// Serialised in camelCase like every other JSON this tool emits, so a script
/// does not have to change convention between a command's output and the file
/// that command wrote.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    pub tool: String,
    /// UTC ISO 8601, so a directory listing sorts chronologically.
    pub taken: String,
    pub instance: String,
    pub router: Router,
    /// How many secrets were removed on the way to disk.
    #[serde(default)]
    pub secrets_redacted: usize,
    #[serde(default)]
    pub unreadable: Vec<Unreadable>,
    #[serde(default)]
    pub menus: BTreeMap<String, Value>,
}

impl Snapshot {
    /// Collect one, redacting on the way out.
    pub async fn take(f: &mut Fetcher<'_>, instance: &str) -> Snapshot {
        let mut menus: BTreeMap<String, Value> = BTreeMap::new();

        for path in CATALOGUE.iter().chain(OPTIONAL.iter()) {
            let v = f.list(path).await;
            // A single-object menu comes back as a one-row list; keep it as
            // the object so the diff compares fields rather than positions.
            let value = match v.len() {
                0 => Value::Array(vec![]),
                1 if !is_collection(path) => v[0].clone(),
                _ => Value::Array(v),
            };
            menus.insert(path.to_string(), value);
        }

        let mut all = Value::Object(
            menus
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect::<serde_json::Map<_, _>>(),
        );
        let redacted = secrets::redact(&mut all);
        if let Value::Object(map) = all {
            menus = map.into_iter().collect();
        }

        let identity = menus.get("/system/identity").cloned().unwrap_or_default();
        let resource = menus.get("/system/resource").cloned().unwrap_or_default();
        let board = menus
            .get("/system/routerboard")
            .cloned()
            .unwrap_or_default();

        Snapshot {
            tool: concat!("mlab-mikrotik/", env!("CARGO_PKG_VERSION")).to_string(),
            taken: iso8601(now()),
            instance: instance.to_string(),
            router: Router {
                identity: field(&identity, "name"),
                version: field(&resource, "version"),
                board: crate::ros::first_field(&board, &["model", "board-name"]),
                serial: field(&board, "serial-number"),
            },
            secrets_redacted: redacted,
            unreadable: f.unreadable.clone(),
            menus,
        }
    }

    /// How many rows the snapshot holds, across every menu.
    pub fn rows(&self) -> usize {
        self.menus
            .values()
            .map(|v| match v {
                Value::Array(a) => a.len(),
                Value::Null => 0,
                _ => 1,
            })
            .sum()
    }
}

/// Whether a field changes on its own.
///
/// The named list plus one prefix rule: RouterOS puts every fast-path counter
/// behind `fp-` (`fp-rx-byte`, `fp-tx-packet`, `fp-rps-drop`), and on a router
/// carrying traffic they move between any two snapshots taken seconds apart.
/// Without this, every interface reads as changed, which is the same as
/// reporting nothing at all.
fn is_volatile(name: &str) -> bool {
    VOLATILE.contains(&name) || name.starts_with("fp-")
}

/// Menus that are a list even when they hold one row.
///
/// `/ip/dns` is one object; `/user` with one account is still a list, and
/// storing it as an object would make the diff compare an account's fields
/// against a menu's.
fn is_collection(path: &str) -> bool {
    !matches!(
        path,
        "/system/identity"
            | "/system/resource"
            | "/system/routerboard"
            | "/system/license"
            | "/system/clock"
            | "/ip/dns"
            | "/ip/ssh"
            | "/ip/socks"
            | "/ip/proxy"
            | "/ip/upnp"
            | "/ip/cloud"
            | "/snmp"
            | "/ip/neighbor/discovery-settings"
            | "/tool/romon"
            | "/tool/mac-server"
            | "/tool/mac-server/mac-winbox"
            | "/tool/bandwidth-server"
    )
}

// ---- storage ----------------------------------------------------------------

/// `$MLAB_MIKROTIK_SNAPSHOTS`, else `$HOME/.mlab/mikrotik/snapshots`.
pub fn dir() -> PathBuf {
    if let Ok(p) = std::env::var("MLAB_MIKROTIK_SNAPSHOTS") {
        if !p.is_empty() {
            return PathBuf::from(p);
        }
    }
    let home = std::env::var("HOME").unwrap_or_default();
    PathBuf::from(home)
        .join(".mlab")
        .join("mikrotik")
        .join("snapshots")
}

/// Where one instance's snapshots live.
pub fn instance_dir(instance: &str) -> PathBuf {
    dir().join(sanitize(instance))
}

/// An instance name is user input and ends up in a path.
fn sanitize(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

pub fn save(s: &Snapshot) -> Result<PathBuf> {
    let dir = instance_dir(&s.instance);
    fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    set_mode(&dir, 0o700);

    // Colons are legal in a filename on Unix and a nuisance everywhere else.
    let name = format!("{}.json", s.taken.replace(':', ""));
    let path = dir.join(name);

    let mut data = serde_json::to_string_pretty(s)?;
    data.push('\n');
    fs::write(&path, data).with_context(|| format!("writing {}", path.display()))?;
    set_mode(&path, 0o600);
    Ok(path)
}

pub fn load(path: &Path) -> Result<Snapshot> {
    let raw = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_str(&raw).with_context(|| format!("parsing {}", path.display()))
}

/// Every snapshot of one instance, oldest first.
pub fn list(instance: &str) -> Vec<PathBuf> {
    let dir = instance_dir(instance);
    let Ok(entries) = fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut out: Vec<PathBuf> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .collect();
    // The filename is an ISO 8601 stamp, so lexicographic order is
    // chronological order.
    out.sort();
    out
}

fn set_mode(path: &Path, mode: u32) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(mode));
    }
    #[cfg(not(unix))]
    let _ = (path, mode);
}

// ---- comparison -------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Change {
    Appeared,
    Disappeared,
    Changed,
}

#[derive(Debug, Clone, Serialize)]
pub struct Difference {
    pub menu: String,
    pub key: String,
    pub change: Change,
    /// For a change, the fields that moved and what they moved between.
    pub fields: Vec<FieldChange>,
    /// Whether the row is one RouterOS created for itself.
    ///
    /// `/ip/service` grows and loses `dynamic` rows on its own — `detnet`,
    /// `route_BGP`, a `dhcp` entry that exists only while a lease renews — and
    /// so do routes and addresses. Their arrival is a consequence of something
    /// working, not a decision anyone made, which is exactly the distinction
    /// `shadow` is built on.
    pub dynamic: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct FieldChange {
    pub field: String,
    pub from: String,
    pub to: String,
}

/// Which fields identify a row across two collections.
///
/// Never `.id`: RouterOS reassigns it freely, so keying on it would report
/// every row as replaced after a reboot. Where a menu has no natural name, the
/// row's own content is the key — which means an edit reads as one row leaving
/// and another arriving, and that is the honest rendering of "a rule changed
/// and nothing names it".
fn keys_for(menu: &str) -> &'static [&'static str] {
    match menu {
        "/ip/address" | "/ipv6/address" => &["address"],
        "/ip/route" => &["dst-address", "gateway"],
        "/ip/arp" | "/ip/dhcp-server/lease" => &["mac-address"],
        "/interface/bridge/port" => &["bridge", "interface"],
        "/interface/bridge/vlan" => &["bridge", "vlan-ids"],
        "/interface/list/member" => &["list", "interface"],
        "/ip/firewall/address-list" | "/ipv6/firewall/address-list" => &["list", "address"],
        "/ip/service" => &["name", "vrf"],
        "/system/logging" => &["topics", "action"],
        "/ip/dns/static" => &["name", "address"],
        "/user/ssh-keys" => &["user", "key-owner"],
        "/ip/dhcp-server/network" => &["address"],
        _ => &["name"],
    }
}

/// The identity of one row, as a string.
fn key_of(menu: &str, row: &Value) -> String {
    let parts: Vec<String> = keys_for(menu)
        .iter()
        .map(|k| field(row, k))
        .filter(|v| !v.is_empty())
        .collect();
    if !parts.is_empty() {
        return parts.join(" ");
    }
    // Nothing names it — a firewall rule with no comment, say. Prefer the
    // comment, then fall back to the row's own stable content.
    let comment = field(row, "comment");
    if !comment.is_empty() {
        return comment;
    }
    signature(row)
}

/// A row reduced to the fields that are decisions, as a stable string.
fn signature(row: &Value) -> String {
    let Some(map) = row.as_object() else {
        return row.to_string();
    };
    let kept: BTreeMap<&String, &Value> = map.iter().filter(|(k, _)| !is_volatile(k)).collect();
    serde_json::to_string(&kept).unwrap_or_default()
}

/// Compare two dated collections.
///
/// Refuses what it cannot honestly compare: two snapshots of different routers
/// are not a diff, they are two snapshots.
pub fn compare(before: &Snapshot, after: &Snapshot) -> Result<Vec<Difference>> {
    if !before.router.serial.is_empty()
        && !after.router.serial.is_empty()
        && before.router.serial != after.router.serial
    {
        bail!(
            "these snapshots are of different routers ({} and {}); there is nothing honest to compare",
            before.router.serial,
            after.router.serial
        );
    }

    let mut out = Vec::new();
    let mut menus: Vec<&String> = before.menus.keys().chain(after.menus.keys()).collect();
    menus.sort();
    menus.dedup();

    for menu in menus {
        let a = before.menus.get(menu);
        let b = after.menus.get(menu);
        match (a, b) {
            (Some(Value::Array(a)), Some(Value::Array(b))) => out.extend(compare_rows(menu, a, b)),
            (Some(a), Some(b)) if !a.is_array() && !b.is_array() => {
                let fields = changed_fields(a, b);
                if !fields.is_empty() {
                    out.push(Difference {
                        menu: menu.clone(),
                        key: menu.clone(),
                        change: Change::Changed,
                        fields,
                        dynamic: false,
                    });
                }
            }
            // A menu present in one snapshot and not the other is a change in
            // what could be read, not in the router, and belongs to the
            // unreadable report rather than here.
            _ => {}
        }
    }
    Ok(out)
}

fn compare_rows(menu: &str, before: &[Value], after: &[Value]) -> Vec<Difference> {
    let index = |rows: &[Value]| -> BTreeMap<String, Value> {
        rows.iter().map(|r| (key_of(menu, r), r.clone())).collect()
    };
    let (a, b) = (index(before), index(after));
    let mut out = Vec::new();

    for (key, row) in &b {
        match a.get(key) {
            None => out.push(Difference {
                menu: menu.to_string(),
                key: key.clone(),
                change: Change::Appeared,
                fields: Vec::new(),
                dynamic: crate::ros::flag(row, "dynamic"),
            }),
            Some(old) => {
                let fields = changed_fields(old, row);
                if !fields.is_empty() {
                    out.push(Difference {
                        menu: menu.to_string(),
                        key: key.clone(),
                        change: Change::Changed,
                        fields,
                        dynamic: crate::ros::flag(row, "dynamic"),
                    });
                }
            }
        }
    }

    for (key, row) in &a {
        if !b.contains_key(key) {
            out.push(Difference {
                menu: menu.to_string(),
                key: key.clone(),
                change: Change::Disappeared,
                fields: Vec::new(),
                dynamic: crate::ros::flag(row, "dynamic"),
            });
        }
    }

    out
}

/// Which fields moved between two versions of the same row.
fn changed_fields(before: &Value, after: &Value) -> Vec<FieldChange> {
    let (Some(a), Some(b)) = (before.as_object(), after.as_object()) else {
        return Vec::new();
    };
    let mut names: Vec<&String> = a.keys().chain(b.keys()).collect();
    names.sort();
    names.dedup();

    names
        .into_iter()
        .filter(|k| !is_volatile(k))
        .filter_map(|k| {
            let (from, to) = (a.get(k), b.get(k));
            if from == to {
                return None;
            }
            Some(FieldChange {
                field: k.clone(),
                from: scalar(from),
                to: scalar(to),
            })
        })
        .collect()
}

fn scalar(v: Option<&Value>) -> String {
    match v {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(s)) => s.clone(),
        Some(other) => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn snap(menus: Vec<(&str, Value)>) -> Snapshot {
        Snapshot {
            tool: "test".into(),
            taken: "2026-09-05T00:00:00Z".into(),
            instance: "lab".into(),
            router: Router {
                identity: "gw".into(),
                version: "7.24.2".into(),
                board: "CCR2004".into(),
                serial: "ABC123".into(),
            },
            secrets_redacted: 0,
            unreadable: Vec::new(),
            menus: menus.into_iter().map(|(k, v)| (k.to_string(), v)).collect(),
        }
    }

    #[test]
    fn a_volatile_counter_is_not_a_change() {
        let a = snap(vec![(
            "/ip/firewall/filter",
            json!([{"comment": "drop the rest", "action": "drop", "packets": "10", ".id": "*1"}]),
        )]);
        let b = snap(vec![(
            "/ip/firewall/filter",
            json!([{"comment": "drop the rest", "action": "drop", "packets": "99999", ".id": "*7"}]),
        )]);
        assert!(
            compare(&a, &b).unwrap().is_empty(),
            "a counter moving and an id being reassigned are not changes"
        );
    }

    #[test]
    fn fast_path_counters_are_volatile_by_prefix() {
        // Taken from a live CCR2004: these five move on every interface that
        // carries traffic, and naming them one by one would miss the next one
        // RouterOS adds.
        for f in [
            "fp-rx-byte",
            "fp-tx-byte",
            "fp-rx-packet",
            "fp-tx-packet",
            "fp-rps-drop",
        ] {
            assert!(is_volatile(f), "{f} should be volatile");
        }
        assert!(
            !is_volatile("frame-types"),
            "not everything starting with f"
        );
        assert!(is_volatile("packets"));
        assert!(!is_volatile("name"));
    }

    #[test]
    fn an_idle_router_diffs_to_nothing() {
        // Two snapshots seconds apart, of an interface that moved traffic.
        let a = snap(vec![(
            "/interface",
            json!([{"name": "ether1", "mtu": "1500", "fp-rx-byte": "65365", "rx-byte": "65365"}]),
        )]);
        let b = snap(vec![(
            "/interface",
            json!([{"name": "ether1", "mtu": "1500", "fp-rx-byte": "65691", "rx-byte": "65691"}]),
        )]);
        assert!(compare(&a, &b).unwrap().is_empty());
    }

    #[test]
    fn a_real_edit_names_the_field_and_both_values() {
        let a = snap(vec![(
            "/ip/service",
            json!([{"name": "www", "port": "80"}]),
        )]);
        let b = snap(vec![(
            "/ip/service",
            json!([{"name": "www", "port": "8080"}]),
        )]);
        let d = compare(&a, &b).unwrap();
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].change, Change::Changed);
        assert_eq!(d[0].fields[0].field, "port");
        assert_eq!(d[0].fields[0].from, "80");
        assert_eq!(d[0].fields[0].to, "8080");
    }

    #[test]
    fn an_account_arriving_and_one_leaving_are_separate_facts() {
        let a = snap(vec![("/user", json!([{"name": "ops"}]))]);
        let b = snap(vec![("/user", json!([{"name": "ops"}, {"name": "ftu"}]))]);
        let d = compare(&a, &b).unwrap();
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].change, Change::Appeared);
        assert_eq!(d[0].key, "ftu");

        let back = compare(&b, &a).unwrap();
        assert_eq!(back[0].change, Change::Disappeared);
        assert_eq!(back[0].key, "ftu");
    }

    #[test]
    fn a_row_routeros_made_for_itself_is_marked_as_such() {
        // Seen live: /ip/service grows a `dhcp` row while a lease renews, and
        // every one of `detnet`, `route_BGP`, `discover` is dynamic too.
        let a = snap(vec![("/ip/service", json!([{"name": "winbox"}]))]);
        let b = snap(vec![(
            "/ip/service",
            json!([{"name": "winbox"}, {"name": "dhcp", "dynamic": "true"}]),
        )]);
        let d = compare(&a, &b).unwrap();
        assert_eq!(d.len(), 1);
        assert!(d[0].dynamic, "shadow filters this out; diff still shows it");
    }

    #[test]
    fn an_account_is_never_dynamic() {
        let a = snap(vec![("/user", json!([]))]);
        let b = snap(vec![("/user", json!([{"name": "ftu"}]))]);
        assert!(!compare(&a, &b).unwrap()[0].dynamic);
    }

    #[test]
    fn two_different_routers_are_refused_rather_than_diffed() {
        let a = snap(vec![]);
        let mut b = snap(vec![]);
        b.router.serial = "XYZ789".into();
        let err = compare(&a, &b).unwrap_err().to_string();
        assert!(err.contains("different routers"));
    }

    #[test]
    fn a_menu_with_no_natural_name_keys_on_its_comment() {
        // Firewall rules have no name; the comment is what an operator uses to
        // recognise one, so it is what the diff uses too.
        let rule = json!({"chain": "input", "action": "drop", "comment": "block the rest"});
        assert_eq!(key_of("/ip/firewall/filter", &rule), "block the rest");
    }

    #[test]
    fn a_row_with_neither_name_nor_comment_keys_on_its_content() {
        let a = json!({"chain": "input", "action": "accept", "dst-port": "22", "packets": "1"});
        let b = json!({"chain": "input", "action": "accept", "dst-port": "22", "packets": "9"});
        assert_eq!(
            key_of("/ip/firewall/filter", &a),
            key_of("/ip/firewall/filter", &b),
            "the same rule with a different counter is the same rule"
        );
    }

    #[test]
    fn service_rows_are_told_apart_by_their_vrf() {
        let main = json!({"name": "winbox", "vrf": "main"});
        let other = json!({"name": "winbox", "vrf": "customers"});
        assert_ne!(key_of("/ip/service", &main), key_of("/ip/service", &other));
    }

    #[test]
    fn an_upgrade_shows_up_and_the_uptime_it_reset_does_not() {
        let a = snap(vec![(
            "/system/resource",
            json!({"uptime": "6w2d", "version": "7.24.2", "cpu-load": "3"}),
        )]);
        let b = snap(vec![(
            "/system/resource",
            json!({"uptime": "4m", "version": "7.25.0", "cpu-load": "41"}),
        )]);
        let d = compare(&a, &b).unwrap();
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].fields.len(), 1, "only the version moved that matters");
        assert_eq!(d[0].fields[0].field, "version");
        assert_eq!(d[0].fields[0].to, "7.25.0");
    }

    #[test]
    fn an_instance_name_cannot_escape_the_snapshot_directory() {
        assert_eq!(sanitize("../../etc"), "______etc");
        assert_eq!(sanitize("lab-1_a"), "lab-1_a");
    }
}
