//! What the router itself is listening on, and the side channels that are not
//! in `/ip/service` at all.

use serde_json::Value;

use super::{finding, Finding, Input, Outcome, Severity};
use crate::ros::{field, flag};

/// Services that carry credentials in the clear, whatever they are for.
const CLEARTEXT: [(&str, &str); 3] = [
    ("telnet", "the session and the password are in plain text"),
    ("ftp", "the session and the password are in plain text"),
    (
        "www",
        "WebFig and the REST API over HTTP: Basic auth sends the password in plain text",
    ),
];

pub fn check(i: &Input, o: &mut Outcome) {
    o.guard(i, "cleartext-services", &["/ip/service"], cleartext);
    o.guard(i, "service-reach", &["/ip/service"], unrestricted);
    o.guard(i, "bandwidth-server", &["/tool/bandwidth-server"], btest);
    o.guard(i, "mac-server", &["/tool/mac-server"], mac_server);
    o.guard(i, "romon", &["/tool/romon"], romon);
    o.guard(
        i,
        "discovery",
        &["/ip/neighbor/discovery-settings"],
        discovery,
    );
    o.guard(i, "ssh-crypto", &["/ip/ssh"], ssh);
    o.guard(i, "ntp", &["/system/ntp/client"], ntp);
}

fn enabled(services: &[Value]) -> Vec<&Value> {
    services.iter().filter(|s| !flag(s, "disabled")).collect()
}

/// How to name one service row.
///
/// RouterOS 7 lists a service once per VRF, so a router with a VRF answers
/// with two `winbox` rows on the same port. Naming them identically reads as a
/// bug in the report; the VRF is what tells them apart.
fn label(s: &Value) -> String {
    let base = format!("{}:{}", field(s, "name"), field(s, "port"));
    match field(s, "vrf").as_str() {
        // `main` is the default VRF and still distinguishes a row: a router
        // answers with one `winbox:8291` bound to `main` and another bound to
        // nothing, and collapsing them reads as a duplicated line.
        "" => base,
        vrf => format!("{base} (vrf {vrf})"),
    }
}

fn cleartext(i: &Input) -> Vec<Finding> {
    let mut out = Vec::new();
    for (name, why) in CLEARTEXT {
        let hits: Vec<String> = enabled(&i.services)
            .iter()
            .filter(|s| field(s, "name") == name)
            .map(|s| label(s))
            .collect();
        if !hits.is_empty() {
            out.push(finding(
                Severity::High,
                "services",
                format!("`{name}` is enabled"),
                format!("{} — {why}", hits.join(", ")),
                format!("/ip service disable {name}"),
            ));
        }
    }
    out
}

/// An enabled service with no source restriction.
///
/// RouterOS calls the field `available-from`. Empty means every address on
/// every interface the service is bound to, which on a router with a public
/// address means the internet.
fn unrestricted(i: &Input) -> Vec<Finding> {
    let open: Vec<String> = enabled(&i.services)
        .iter()
        .filter(|s| field(s, "available-from").trim().is_empty())
        .map(|s| label(s))
        .collect();

    if open.is_empty() {
        return Vec::new();
    }

    // Whether the firewall stops them is a separate question, answered by the
    // segmentation checks. This one is about the service's own control, which
    // is the layer that still applies when a firewall rule is edited by
    // mistake.
    vec![finding(
        Severity::High,
        "services",
        "enabled services accept connections from any address",
        format!(
            "{} service(s) have no `available-from`: {}",
            open.len(),
            open.join(", ")
        ),
        "/ip service set <name> available-from=203.0.113.0/24",
    )]
}

fn btest(i: &Input) -> Vec<Finding> {
    if !flag(&i.bandwidth_server, "enabled") {
        return Vec::new();
    }
    let auth = flag(&i.bandwidth_server, "authenticate");
    vec![finding(
        if auth { Severity::Low } else { Severity::Medium },
        "services",
        "the bandwidth test server is enabled",
        format!(
            "it answers throughput tests, which is a way to consume this router's CPU and uplink from outside; authentication is {}",
            if auth { "on" } else { "off" }
        ),
        "/tool bandwidth-server set enabled=no",
    )]
}

fn mac_server(i: &Input) -> Vec<Finding> {
    let mut out = Vec::new();
    for (menu, value, what) in [
        (
            "/tool/mac-server",
            field(&i.mac_server, "allowed-interface-list"),
            "MAC-telnet",
        ),
        (
            "/tool/mac-server/mac-winbox",
            field(&i.mac_winbox, "allowed-interface-list"),
            "MAC-Winbox",
        ),
    ] {
        // `none` is the hardened value; an empty string means the menu was not
        // read, and a named list is a deliberate restriction.
        if value == "all" {
            out.push(finding(
                Severity::Medium,
                "services",
                format!("{what} answers on every interface"),
                format!(
                    "{menu} allowed-interface-list=all — this reaches the router at layer 2, without an IP address and without passing the IP firewall"
                ),
                format!("{} set allowed-interface-list=none", menu.replace('/', " ").trim()),
            ));
        }
    }
    out
}

fn romon(i: &Input) -> Vec<Finding> {
    if !flag(&i.romon, "enabled") {
        return Vec::new();
    }
    let has_secret = !field(&i.romon, "secrets").trim().is_empty();
    vec![finding(
        if has_secret {
            Severity::Low
        } else {
            Severity::Medium
        },
        "services",
        "RoMON is enabled",
        format!(
            "this router can be reached, and can reach other routers, over layer 2 without an IP address; a shared secret is {}",
            if has_secret { "set" } else { "not set" }
        ),
        "/tool romon set enabled=no",
    )]
}

fn discovery(i: &Input) -> Vec<Finding> {
    let on = field(&i.discovery, "discover-interface-list");
    if on.is_empty() || on == "none" {
        return Vec::new();
    }
    // A named list is a decision about which links to announce on. `all`, or a
    // negated list that resolves to almost everything, is not.
    let severity = if on == "all" || on.starts_with('!') {
        Severity::Medium
    } else {
        Severity::Low
    };
    vec![finding(
        severity,
        "services",
        "the router announces itself to its neighbours",
        format!(
            "discover-interface-list={on}, protocols {} — every device on those links learns this router's identity, model and exact RouterOS version",
            field(&i.discovery, "protocol")
        ),
        "/ip neighbor discovery-settings set discover-interface-list=<management-list>",
    )]
}

fn ssh(i: &Input) -> Vec<Finding> {
    // Only worth saying when SSH is actually reachable.
    let ssh_on = enabled(&i.services)
        .iter()
        .any(|s| field(s, "name") == "ssh");
    if !ssh_on || i.ssh.is_null() {
        return Vec::new();
    }
    if flag(&i.ssh, "strong-crypto") {
        return Vec::new();
    }
    vec![finding(
        Severity::Medium,
        "services",
        "SSH accepts weak cryptography",
        "strong-crypto=no leaves the older ciphers, MACs and host key sizes enabled for compatibility",
        "/ip ssh set strong-crypto=yes",
    )]
}

fn ntp(i: &Input) -> Vec<Finding> {
    if i.ntp.is_null() || flag(&i.ntp, "enabled") {
        return Vec::new();
    }
    vec![finding(
        Severity::Low,
        "services",
        "the NTP client is off",
        "every timestamp this router writes — logs, leases, certificate validity — rests on its clock, and a clock nobody disciplines drifts",
        "/system ntp client set enabled=yes servers=...",
    )]
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn services(v: Vec<Value>) -> Input {
        Input {
            services: v,
            ..Default::default()
        }
    }

    #[test]
    fn a_disabled_cleartext_service_is_not_a_finding() {
        let i = services(vec![
            json!({"name": "telnet", "port": "23", "disabled": "true"}),
        ]);
        assert!(cleartext(&i).is_empty());
    }

    #[test]
    fn http_counts_as_cleartext_because_rest_uses_basic_auth() {
        let i = services(vec![
            json!({"name": "www", "port": "80", "disabled": "false"}),
        ]);
        let f = cleartext(&i);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::High);
        assert!(f[0].detail.contains("www:80"));
    }

    #[test]
    fn a_per_vrf_duplicate_is_told_apart_by_its_vrf() {
        // RouterOS lists a service once per VRF; two rows named `winbox:8291`
        // read as a bug in the report rather than as two real rows.
        let i = services(vec![
            json!({"name": "winbox", "port": "8291", "disabled": "false", "vrf": "main"}),
            json!({"name": "winbox", "port": "8291", "disabled": "false", "vrf": "customers"}),
            json!({"name": "winbox", "port": "8291", "disabled": "false"}),
        ]);
        let f = unrestricted(&i);
        assert!(f[0].detail.contains("winbox:8291 (vrf main)"));
        assert!(f[0].detail.contains("winbox:8291 (vrf customers)"));
    }

    #[test]
    fn a_restricted_service_is_not_reported_as_open() {
        let i = services(vec![
            json!({"name": "winbox", "port": "8291", "disabled": "false", "available-from": "10.0.0.0/8"}),
        ]);
        assert!(unrestricted(&i).is_empty());
    }

    #[test]
    fn every_open_service_lands_in_one_finding() {
        let i = services(vec![
            json!({"name": "winbox", "port": "8291", "disabled": "false", "available-from": ""}),
            json!({"name": "www", "port": "80", "disabled": "false"}),
            json!({"name": "ssh", "port": "22", "disabled": "true"}),
        ]);
        let f = unrestricted(&i);
        assert_eq!(f.len(), 1, "one finding listing them all, not one each");
        assert!(f[0].detail.contains("winbox:8291"));
        assert!(f[0].detail.contains("www:80"));
        assert!(!f[0].detail.contains("ssh"), "disabled services stay out");
    }

    #[test]
    fn an_authenticated_bandwidth_server_is_milder_than_an_open_one() {
        let open = Input {
            bandwidth_server: json!({"enabled": "true", "authenticate": "false"}),
            ..Default::default()
        };
        assert_eq!(btest(&open)[0].severity, Severity::Medium);

        let authed = Input {
            bandwidth_server: json!({"enabled": "true", "authenticate": "true"}),
            ..Default::default()
        };
        assert_eq!(btest(&authed)[0].severity, Severity::Low);

        let off = Input {
            bandwidth_server: json!({"enabled": "false"}),
            ..Default::default()
        };
        assert!(btest(&off).is_empty());
    }

    #[test]
    fn a_named_discovery_list_is_a_decision_a_negated_one_is_not() {
        let named = Input {
            discovery: json!({"discover-interface-list": "mgmt", "protocol": "lldp"}),
            ..Default::default()
        };
        assert_eq!(discovery(&named)[0].severity, Severity::Low);

        let negated = Input {
            discovery: json!({"discover-interface-list": "!dynamic", "protocol": "cdp,lldp,mndp"}),
            ..Default::default()
        };
        assert_eq!(discovery(&negated)[0].severity, Severity::Medium);

        let off = Input {
            discovery: json!({"discover-interface-list": "none"}),
            ..Default::default()
        };
        assert!(discovery(&off).is_empty());
    }

    #[test]
    fn ssh_crypto_is_only_reported_when_ssh_is_reachable() {
        let unreachable = Input {
            services: vec![json!({"name": "ssh", "disabled": "true"})],
            ssh: json!({"strong-crypto": "false"}),
            ..Default::default()
        };
        assert!(ssh(&unreachable).is_empty());

        let reachable = Input {
            services: vec![json!({"name": "ssh", "disabled": "false"})],
            ssh: json!({"strong-crypto": "false"}),
            ..Default::default()
        };
        assert_eq!(ssh(&reachable).len(), 1);
    }
}
