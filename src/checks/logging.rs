//! Whether anything survives the next reboot, and whether refusals are
//! recorded at all.

use serde_json::Value;

use super::{finding, Finding, Input, Outcome, Severity};
use crate::ros::{field, flag};

pub fn check(i: &Input, o: &mut Outcome) {
    o.guard(
        i,
        "log-durability",
        &["/system/logging", "/system/logging/action"],
        durability,
    );
    o.guard(i, "rule-logging", &["/ip/firewall/filter"], rule_logging);
}

/// Everything in `memory` is gone at the next reboot, and a reboot is the
/// first thing that happens after most incidents.
fn durability(i: &Input) -> Vec<Finding> {
    let used: Vec<String> = i
        .logging
        .iter()
        .filter(|l| !flag(l, "disabled"))
        .map(|l| field(l, "action"))
        .collect();

    if used.is_empty() {
        return Vec::new();
    }

    // An action's `target` says where it really goes: `memory`, `disk`,
    // `remote`, `echo`. The action's *name* is conventional, not binding.
    let target_of = |name: &str| -> String {
        i.logging_actions
            .iter()
            .find(|a| field(a, "name") == name)
            .map(|a| field(a, "target"))
            .unwrap_or_default()
    };

    let durable: Vec<String> = used
        .iter()
        .filter(|name| matches!(target_of(name).as_str(), "remote" | "disk"))
        .cloned()
        .collect();

    if !durable.is_empty() {
        return Vec::new();
    }

    let targets: Vec<String> = used
        .iter()
        .map(|n| {
            format!(
                "{n}→{}",
                match target_of(n).as_str() {
                    "" => "?".to_string(),
                    t => t.to_string(),
                }
            )
        })
        .collect();

    vec![finding(
        Severity::Medium,
        "logging",
        "nothing this router logs survives a reboot",
        format!(
            "every active logging rule writes to a volatile target ({}) — no remote and no disk action is in use",
            targets.join(", ")
        ),
        "/system logging action add name=remote target=remote remote=198.51.100.20, then /system logging add topics=info,error,warning,critical action=remote",
    )]
}

/// A refusal nobody wrote down did not happen, as far as anyone reviewing this
/// router later is concerned.
fn rule_logging(i: &Input) -> Vec<Finding> {
    let refusals: Vec<&Value> = i
        .filter
        .iter()
        .filter(|r| !flag(r, "disabled"))
        .filter(|r| matches!(field(r, "action").as_str(), "drop" | "reject"))
        .collect();

    if refusals.is_empty() {
        return Vec::new();
    }

    let silent = refusals.iter().filter(|r| !flag(r, "log")).count();

    // A catch-all drop at the end of a busy chain is *deliberately* silent on
    // most routers, and saying so every time would be noise. It is worth one
    // low finding only when every refusal is silent.
    if silent == refusals.len() {
        return vec![finding(
            Severity::Low,
            "logging",
            "no firewall refusal is logged",
            format!(
                "{silent} active drop/reject rule(s), none with log=yes — nothing records what this router turned away"
            ),
            "/ip firewall filter set <n> log=yes log-prefix=drop-input (on the rules worth watching, not all of them)",
        )];
    }

    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn memory_and_echo_are_not_durable() {
        // The shape seen on real hardware: three rules to `memory`, one to
        // `echo`, nothing remote.
        let i = Input {
            logging: vec![
                json!({"topics": "info", "action": "memory", "disabled": "false"}),
                json!({"topics": "critical", "action": "echo", "disabled": "false"}),
            ],
            logging_actions: vec![
                json!({"name": "memory", "target": "memory"}),
                json!({"name": "echo", "target": "echo"}),
            ],
            ..Default::default()
        };
        let f = durability(&i);
        assert_eq!(f[0].severity, Severity::Medium);
        assert!(f[0].detail.contains("memory→memory"));
    }

    #[test]
    fn one_remote_action_in_use_is_enough() {
        let i = Input {
            logging: vec![
                json!({"topics": "info", "action": "memory", "disabled": "false"}),
                json!({"topics": "critical", "action": "syslog", "disabled": "false"}),
            ],
            logging_actions: vec![
                json!({"name": "memory", "target": "memory"}),
                json!({"name": "syslog", "target": "remote"}),
            ],
            ..Default::default()
        };
        assert!(durability(&i).is_empty());
    }

    #[test]
    fn an_action_is_judged_by_its_target_not_its_name() {
        // An action *named* `remote` that writes to memory is the trap.
        let i = Input {
            logging: vec![json!({"topics": "info", "action": "remote", "disabled": "false"})],
            logging_actions: vec![json!({"name": "remote", "target": "memory"})],
            ..Default::default()
        };
        assert_eq!(durability(&i).len(), 1);
    }

    #[test]
    fn one_logged_refusal_is_enough_to_stay_quiet() {
        let i = Input {
            filter: vec![
                json!({"action": "drop", "disabled": "false", "log": "true"}),
                json!({"action": "drop", "disabled": "false", "log": "false"}),
            ],
            ..Default::default()
        };
        assert!(
            rule_logging(&i).is_empty(),
            "a silent catch-all next to a logged rule is a normal design"
        );
    }

    #[test]
    fn a_firewall_that_records_nothing_is_low() {
        let i = Input {
            filter: vec![
                json!({"action": "accept", "disabled": "false"}),
                json!({"action": "drop", "disabled": "false"}),
            ],
            ..Default::default()
        };
        assert_eq!(rule_logging(&i)[0].severity, Severity::Low);
    }

    #[test]
    fn a_firewall_with_no_refusals_says_nothing_here() {
        let i = Input {
            filter: vec![json!({"action": "accept", "disabled": "false"})],
            ..Default::default()
        };
        assert!(rule_logging(&i).is_empty());
    }
}
