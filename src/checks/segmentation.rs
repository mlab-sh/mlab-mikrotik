//! Whether the firewall closes, whether IPv6 is treated like IPv4, and
//! whether the bridges separate what they look like they separate.

use serde_json::Value;

use super::{finding, Finding, Input, Outcome, Severity};
use crate::ros::{field, flag};

/// The properties that make a filter rule match less than everything.
///
/// A rule carrying none of them matches every packet in its chain. The list is
/// explicit rather than "any property at all", because `comment`, `log` and
/// the counters are on every rule and would make the test always true.
const MATCHERS: [&str; 16] = [
    "src-address",
    "dst-address",
    "src-address-list",
    "dst-address-list",
    "src-port",
    "dst-port",
    "port",
    "protocol",
    "in-interface",
    "out-interface",
    "in-interface-list",
    "out-interface-list",
    "connection-state",
    "connection-nat-state",
    "src-mac-address",
    "tls-host",
];

pub fn check(i: &Input, o: &mut Outcome) {
    o.guard(
        i,
        "default-policy",
        &["/ip/firewall/filter"],
        default_policy,
    );
    o.guard(
        i,
        "ipv6-firewall",
        &["/ipv6/address", "/ipv6/firewall/filter"],
        ipv6,
    );
    o.guard(
        i,
        "bridge-vlan-filtering",
        &["/interface/bridge", "/interface/vlan"],
        bridge_vlans,
    );
}

/// Does a chain end by refusing what nothing matched?
///
/// This is the one ordering question that can be answered without simulating
/// the whole rule set: a `drop` or `reject` with no matchers, in the chain,
/// with nothing after it. Everything more subtle than that needs per-packet
/// evaluation, which this tool deliberately does not claim to do.
fn closes(rules: &[Value], chain: &str) -> bool {
    let in_chain: Vec<&Value> = rules
        .iter()
        .filter(|r| !flag(r, "disabled") && field(r, "chain") == chain)
        .collect();

    match in_chain.last() {
        Some(last) => {
            let action = field(last, "action");
            (action == "drop" || action == "reject") && !matches_something(last)
        }
        None => false,
    }
}

fn matches_something(rule: &Value) -> bool {
    MATCHERS.iter().any(|m| !field(rule, m).trim().is_empty())
}

/// Whether a rule narrows nothing, and so applies to every packet in its
/// chain. The `firewall` command reports the same property, so both read it
/// from here rather than each deciding for itself what "catch-all" means.
pub fn is_catch_all(rule: &Value) -> bool {
    !matches_something(rule)
}

fn default_policy(i: &Input) -> Vec<Finding> {
    let mut out = Vec::new();

    if !closes(&i.filter, "input") {
        out.push(finding(
            Severity::High,
            "segmentation",
            "the input chain does not end in a refusal",
            "nothing matched by an earlier rule reaches the router's own services, and whether that is safe then depends entirely on each service's own `available-from`",
            "/ip firewall filter add chain=input action=drop comment=\"drop everything else\"",
        ));
    }

    if !closes(&i.filter, "forward") {
        out.push(finding(
            Severity::Medium,
            "segmentation",
            "the forward chain does not end in a refusal",
            "traffic between segments that no rule matched is allowed through; on a router that also carries a guest or customer network, that is the segmentation itself",
            "/ip firewall filter add chain=forward action=drop comment=\"drop everything else\"",
        ));
    }

    out
}

/// IPv6 configured and unfiltered, while IPv4 is filtered, is the asymmetry
/// worth reporting: the addresses are reachable and nothing is stopping
/// anything.
fn ipv6(i: &Input) -> Vec<Finding> {
    let addresses: Vec<&Value> = i
        .ipv6_addresses
        .iter()
        .filter(|a| !flag(a, "disabled"))
        // A link-local address is not reachable from anywhere that matters.
        .filter(|a| !field(a, "address").to_lowercase().starts_with("fe80"))
        .collect();

    if addresses.is_empty() {
        return Vec::new();
    }

    let active_rules = i
        .ipv6_filter
        .iter()
        .filter(|r| !flag(r, "disabled"))
        .count();

    if active_rules == 0 {
        return vec![finding(
            Severity::High,
            "segmentation",
            "IPv6 is configured and not filtered",
            format!(
                "{} routable IPv6 address(es) on this router, and /ipv6/firewall/filter has no active rule — every IPv4 control on this box has no IPv6 counterpart",
                addresses.len()
            ),
            "/ipv6 firewall filter add chain=input action=drop, then build up from there",
        )];
    }

    if !closes(&i.ipv6_filter, "input") {
        return vec![finding(
            Severity::Medium,
            "segmentation",
            "the IPv6 input chain does not end in a refusal",
            format!("{active_rules} active IPv6 rules, but nothing closes the chain"),
            "/ipv6 firewall filter add chain=input action=drop",
        )];
    }

    Vec::new()
}

/// A bridge carrying VLAN interfaces but not filtering VLANs is a bridge that
/// looks segmented and forwards every tag to every port.
fn bridge_vlans(i: &Input) -> Vec<Finding> {
    let mut out = Vec::new();

    for b in i.bridges.iter().filter(|b| !flag(b, "disabled")) {
        let name = field(b, "name");

        // VLAN interfaces sitting directly on this bridge.
        let riding: Vec<String> = i
            .vlans
            .iter()
            .filter(|v| field(v, "interface") == name)
            .map(|v| field(v, "name"))
            .collect();

        if riding.is_empty() {
            continue;
        }

        if !flag(b, "vlan-filtering") {
            out.push(finding(
                Severity::Medium,
                "segmentation",
                format!("bridge {name:?} carries VLANs without filtering them"),
                format!(
                    "{} VLAN interface(s) sit on it ({}), and vlan-filtering=no means the bridge forwards every tag to every port",
                    riding.len(),
                    riding.join(", ")
                ),
                format!("/interface bridge set {name} vlan-filtering=yes — after the VLAN table is complete, or the bridge stops forwarding"),
            ));
            continue;
        }

        // Filtering on, but every port admitting untagged traffic into VLAN 1
        // is the configuration that reads as segmented and is not.
        let admit_all: Vec<String> = i
            .bridge_ports
            .iter()
            .filter(|p| !flag(p, "disabled") && field(p, "bridge") == name)
            .filter(|p| field(p, "frame-types") == "admit-all" && field(p, "pvid") == "1")
            .map(|p| field(p, "interface"))
            .collect();

        if !admit_all.is_empty() {
            out.push(finding(
                Severity::Low,
                "segmentation",
                format!("bridge {name:?} filters VLANs, and its ports admit everything"),
                format!(
                    "{} port(s) are frame-types=admit-all with pvid=1 ({}) — untagged traffic on them lands in VLAN 1 rather than being refused",
                    admit_all.len(),
                    admit_all.join(", ")
                ),
                format!("/interface bridge port set [find bridge={name}] frame-types=admit-only-vlan-tagged"),
            ));
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn rule(chain: &str, action: &str) -> Value {
        json!({"chain": chain, "action": action, "disabled": "false"})
    }

    #[test]
    fn a_bare_drop_at_the_end_closes_the_chain() {
        let rules = vec![
            json!({"chain": "input", "action": "accept", "disabled": "false", "protocol": "icmp"}),
            rule("input", "drop"),
        ];
        assert!(closes(&rules, "input"));
    }

    #[test]
    fn a_drop_that_matches_something_does_not_close_anything() {
        let rules = vec![
            json!({"chain": "input", "action": "drop", "disabled": "false", "src-address": "10.0.0.0/8"}),
        ];
        assert!(
            !closes(&rules, "input"),
            "it drops one source, not everything else"
        );
    }

    #[test]
    fn a_disabled_final_drop_does_not_count() {
        let rules = vec![
            rule("input", "accept"),
            json!({"chain": "input", "action": "drop", "disabled": "true"}),
        ];
        assert!(!closes(&rules, "input"));
    }

    #[test]
    fn a_drop_that_is_not_last_does_not_close_the_chain() {
        let rules = vec![rule("input", "drop"), rule("input", "accept")];
        assert!(
            !closes(&rules, "input"),
            "the accept after it is what packets reach"
        );
    }

    #[test]
    fn an_empty_chain_is_open() {
        assert!(!closes(&[], "input"));
    }

    #[test]
    fn link_local_addresses_do_not_make_ipv6_reachable() {
        let i = Input {
            ipv6_addresses: vec![json!({"address": "fe80::1/64", "disabled": "false"})],
            ..Default::default()
        };
        assert!(ipv6(&i).is_empty());
    }

    #[test]
    fn routable_ipv6_with_no_rules_at_all_is_high() {
        let i = Input {
            ipv6_addresses: vec![json!({"address": "2001:db8::1/64", "disabled": "false"})],
            ipv6_filter: vec![],
            ..Default::default()
        };
        let f = ipv6(&i);
        assert_eq!(f[0].severity, Severity::High);
    }

    #[test]
    fn ipv6_with_rules_but_no_closing_drop_is_milder() {
        let i = Input {
            ipv6_addresses: vec![json!({"address": "2001:db8::1/64", "disabled": "false"})],
            ipv6_filter: vec![rule("input", "accept")],
            ..Default::default()
        };
        assert_eq!(ipv6(&i)[0].severity, Severity::Medium);
    }

    #[test]
    fn a_bridge_with_no_vlans_on_it_is_not_a_finding() {
        let i = Input {
            bridges: vec![json!({"name": "br0", "disabled": "false", "vlan-filtering": "false"})],
            vlans: vec![json!({"name": "v10", "interface": "ether2"})],
            ..Default::default()
        };
        assert!(bridge_vlans(&i).is_empty());
    }

    #[test]
    fn vlans_on_an_unfiltered_bridge_are_medium() {
        let i = Input {
            bridges: vec![json!({"name": "br0", "disabled": "false", "vlan-filtering": "false"})],
            vlans: vec![json!({"name": "v10", "interface": "br0"})],
            ..Default::default()
        };
        let f = bridge_vlans(&i);
        assert_eq!(f[0].severity, Severity::Medium);
        assert!(f[0].detail.contains("v10"));
    }
}
