//! What this router offers to anything that can reach it — including the two
//! features that are almost never a deliberate choice on a production router.

use serde_json::Value;

use super::{finding, Finding, Input, Outcome, Severity};
use crate::ros::{field, flag};

pub fn check(i: &Input, o: &mut Outcome) {
    o.guard(i, "socks", &["/ip/socks"], socks);
    o.guard(i, "web-proxy", &["/ip/proxy"], proxy);
    o.guard(i, "upnp", &["/ip/upnp"], upnp);
    o.guard(i, "open-resolver", &["/ip/dns"], resolver);
    o.guard(i, "snmp", &["/snmp"], snmp);
    o.guard(i, "cloud", &["/ip/cloud"], cloud);
    o.guard(i, "port-forwards", &["/ip/firewall/nat"], forwards);
}

/// SOCKS is the one setting on this list that is almost never turned on for a
/// reason. It is the relay every MikroTik botnet campaign since 2018 has left
/// behind, which is why it is graded on what its presence usually means rather
/// than on what the feature does.
fn socks(i: &Input) -> Vec<Finding> {
    if !flag(&i.socks, "enabled") {
        return Vec::new();
    }
    vec![finding(
        Severity::Critical,
        "exposure",
        "the SOCKS proxy is enabled",
        format!(
            "port {}, auth-method {} — if nobody turned this on deliberately, treat it as a compromise marker and check /system/scheduler and /system/script next",
            field(&i.socks, "port"),
            field(&i.socks, "auth-method")
        ),
        "/ip socks set enabled=no",
    )]
}

fn proxy(i: &Input) -> Vec<Finding> {
    if !flag(&i.proxy, "enabled") {
        return Vec::new();
    }
    vec![finding(
        Severity::High,
        "exposure",
        "the web proxy is enabled",
        format!(
            "port {} — an open proxy relays traffic on this router's address, and the cache is where the `error.html` campaigns put their payload",
            field(&i.proxy, "port")
        ),
        "/ip proxy set enabled=no",
    )]
}

fn upnp(i: &Input) -> Vec<Finding> {
    if !flag(&i.upnp, "enabled") {
        return Vec::new();
    }
    vec![finding(
        Severity::High,
        "exposure",
        "UPnP is enabled",
        "any host on the inside can open an inbound port through this router without asking anyone",
        "/ip upnp set enabled=no",
    )]
}

/// `allow-remote-requests` turns the router's cache into a resolver anything
/// can query — the classic amplification reflector.
fn resolver(i: &Input) -> Vec<Finding> {
    if !flag(&i.dns, "allow-remote-requests") {
        return Vec::new();
    }
    vec![finding(
        Severity::High,
        "exposure",
        "the DNS cache answers remote queries",
        "allow-remote-requests=yes: unless the input chain drops port 53 from outside, this router is an open resolver and can be used to amplify traffic at someone else",
        "/ip dns set allow-remote-requests=no, or restrict udp/tcp 53 in the input chain",
    )]
}

fn snmp(i: &Input) -> Vec<Finding> {
    if !flag(&i.snmp, "enabled") {
        return Vec::new();
    }
    let mut out = Vec::new();

    // v1 and v2c have no cryptography at all: the community string is a
    // password in plain text on the wire.
    let weak: Vec<String> = i
        .snmp_communities
        .iter()
        .filter(|c| !flag(c, "disabled"))
        .filter(|c| {
            let sec = field(c, "security");
            sec.is_empty() || sec == "none"
        })
        .map(|c| field(c, "name"))
        .collect();

    if !weak.is_empty() {
        let default = weak.iter().any(|n| n == "public" || n == "private");
        out.push(finding(
            if default {
                Severity::High
            } else {
                Severity::Medium
            },
            "exposure",
            "SNMP answers without cryptography",
            format!(
                "communit{} {} use v1/v2c, where the community string is a password sent in plain text{}",
                if weak.len() == 1 { "y" } else { "ies" },
                weak.join(", "),
                if default {
                    " — and one of them is a default name"
                } else {
                    ""
                }
            ),
            "/snmp community set <name> security=private authentication-protocol=SHA1 encryption-protocol=AES",
        ));
    }

    let unrestricted: Vec<String> = i
        .snmp_communities
        .iter()
        .filter(|c| !flag(c, "disabled"))
        .filter(|c| {
            let a = field(c, "addresses");
            a.is_empty() || a == "0.0.0.0/0" || a == "::/0"
        })
        .map(|c| field(c, "name"))
        .collect();

    if !unrestricted.is_empty() {
        out.push(finding(
            Severity::Medium,
            "exposure",
            "SNMP accepts queries from any address",
            format!(
                "communities with no address restriction: {}",
                unrestricted.join(", ")
            ),
            "/snmp community set <name> addresses=10.0.0.0/8",
        ));
    }

    out
}

fn cloud(i: &Input) -> Vec<Finding> {
    if !flag(&i.cloud, "ddns-enabled") {
        return Vec::new();
    }
    vec![finding(
        Severity::Low,
        "exposure",
        "MikroTik Cloud DDNS is enabled",
        format!(
            "this router publishes its public address to MikroTik and answers on a `<serial>.sn.mynetname.net` name; public address {}",
            match field(&i.cloud, "public-address").as_str() {
                "" => "not reported".to_string(),
                a => a.to_string(),
            }
        ),
        "/ip cloud set ddns-enabled=no",
    )]
}

/// Destination NAT is how anything inside becomes reachable from outside.
fn forwards(i: &Input) -> Vec<Finding> {
    let dst_nat: Vec<&Value> = i
        .nat
        .iter()
        .filter(|r| !flag(r, "disabled") && field(r, "action") == "dst-nat")
        .collect();

    if dst_nat.is_empty() {
        return Vec::new();
    }

    let open: Vec<String> = dst_nat
        .iter()
        .filter(|r| field(r, "src-address").is_empty() && field(r, "src-address-list").is_empty())
        .map(|r| {
            format!(
                "{}{} → {}{}",
                match field(r, "protocol").as_str() {
                    "" => String::new(),
                    p => format!("{p}/"),
                },
                match field(r, "dst-port").as_str() {
                    "" => "any".to_string(),
                    p => p.to_string(),
                },
                field(r, "to-addresses"),
                match field(r, "to-ports").as_str() {
                    "" => String::new(),
                    p => format!(":{p}"),
                }
            )
        })
        .collect();

    if open.is_empty() {
        return Vec::new();
    }

    vec![finding(
        Severity::Medium,
        "exposure",
        "port forwards accept connections from any source",
        format!(
            "{} of {} dst-nat rules restrict nothing on the source side: {}",
            open.len(),
            dst_nat.len(),
            open.join(", ")
        ),
        "/ip firewall nat set <n> src-address-list=<allowed>",
    )]
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn socks_off_is_silence_socks_on_is_critical() {
        let off = Input {
            socks: json!({"enabled": "false"}),
            ..Default::default()
        };
        assert!(socks(&off).is_empty());

        let on = Input {
            socks: json!({"enabled": "true", "port": "1080", "auth-method": "none"}),
            ..Default::default()
        };
        let f = socks(&on);
        assert_eq!(f[0].severity, Severity::Critical);
        assert!(
            f[0].detail.contains("scheduler"),
            "it points at the next step"
        );
    }

    #[test]
    fn a_default_community_name_raises_the_severity() {
        let public = Input {
            snmp: json!({"enabled": "true"}),
            snmp_communities: vec![json!({"name": "public", "security": "none", "addresses": ""})],
            ..Default::default()
        };
        let f = snmp(&public);
        assert_eq!(f[0].severity, Severity::High);
        assert!(f[0].detail.contains("default name"));

        let named = Input {
            snmp: json!({"enabled": "true"}),
            snmp_communities: vec![
                json!({"name": "mon1", "security": "none", "addresses": "10.0.0.0/8"}),
            ],
            ..Default::default()
        };
        assert_eq!(snmp(&named)[0].severity, Severity::Medium);
    }

    #[test]
    fn snmp_with_v3_and_a_restriction_says_nothing() {
        let i = Input {
            snmp: json!({"enabled": "true"}),
            snmp_communities: vec![
                json!({"name": "mon", "security": "private", "addresses": "10.0.0.0/8"}),
            ],
            ..Default::default()
        };
        assert!(snmp(&i).is_empty());
    }

    #[test]
    fn a_restricted_forward_is_not_reported() {
        let i = Input {
            nat: vec![
                json!({"action": "dst-nat", "disabled": "false", "src-address": "203.0.113.0/24", "dst-port": "443", "to-addresses": "10.0.0.5"}),
            ],
            ..Default::default()
        };
        assert!(forwards(&i).is_empty());
    }

    #[test]
    fn an_open_forward_is_described_by_what_it_publishes() {
        let i = Input {
            nat: vec![
                json!({"action": "dst-nat", "disabled": "false", "protocol": "tcp", "dst-port": "3389", "to-addresses": "10.0.0.5", "to-ports": "3389"}),
                json!({"action": "masquerade", "disabled": "false"}),
            ],
            ..Default::default()
        };
        let f = forwards(&i);
        assert_eq!(f.len(), 1);
        assert!(f[0].detail.contains("tcp/3389 → 10.0.0.5:3389"));
        assert!(
            f[0].detail.contains("1 of 1"),
            "masquerade is not a forward"
        );
    }
}
