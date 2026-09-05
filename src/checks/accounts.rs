//! Who can log in, from where, and with how much power.

use serde_json::Value;

use super::{finding, Finding, Input, Outcome, Severity};
use crate::ros::{field, flag};

/// Policies that make a group able to change the router or read its secrets.
const POWERFUL: [&str; 3] = ["write", "policy", "sensitive"];

pub fn check(i: &Input, o: &mut Outcome) {
    o.guard(i, "accounts", &["/user", "/user/group"], powerful_accounts);
    o.guard(i, "account-reach", &["/user"], unrestricted_accounts);
    o.guard(i, "default-admin", &["/user"], default_admin);
}

/// An account whose group can write or read secrets, and which may connect
/// from anywhere.
fn powerful_accounts(i: &Input) -> Vec<Finding> {
    let mut out = Vec::new();

    let powerful: Vec<String> = i
        .groups
        .iter()
        .filter(|g| {
            let granted = granted(&field(g, "policy"));
            POWERFUL.iter().any(|p| granted.iter().any(|x| x == p))
        })
        .map(|g| field(g, "name"))
        .collect();

    let exposed: Vec<String> = i
        .users
        .iter()
        .filter(|u| !flag(u, "disabled"))
        .filter(|u| powerful.contains(&field(u, "group")))
        .filter(|u| field(u, "address").trim().is_empty())
        .map(|u| format!("{} ({})", field(u, "name"), field(u, "group")))
        .collect();

    if !exposed.is_empty() {
        out.push(finding(
            Severity::High,
            "accounts",
            "powerful accounts can log in from anywhere",
            format!(
                "{} account(s) in a group carrying write, policy or sensitive have no address restriction: {}",
                exposed.len(),
                exposed.join(", ")
            ),
            "/user set <name> address=203.0.113.10/32",
        ));
    }

    // The built-in `read` group is the trap this whole tool keeps pointing at:
    // it is named for reading and grants rather more than that.
    for g in &i.groups {
        let name = field(g, "name");
        let granted = granted(&field(g, "policy"));
        let beyond: Vec<&str> = ["sensitive", "reboot", "sniff", "romon"]
            .iter()
            .copied()
            .filter(|p| granted.iter().any(|x| x == p))
            .collect();
        let used_by: Vec<String> = i
            .users
            .iter()
            .filter(|u| !flag(u, "disabled") && field(u, "group") == name)
            .map(|u| field(u, "name"))
            .collect();

        if !beyond.is_empty() && !used_by.is_empty() && !granted.iter().any(|p| p == "write") {
            out.push(finding(
                Severity::Medium,
                "accounts",
                format!("group {name:?} reads as read-only and is not"),
                format!(
                    "it grants {} — used by {}",
                    beyond.join(", "),
                    used_by.join(", ")
                ),
                format!("/user group set {name} policy=read,rest-api,api,!sensitive,!reboot,!sniff,!romon"),
            ));
        }
    }

    out
}

/// Every enabled account with no `address=`, powerful or not.
fn unrestricted_accounts(i: &Input) -> Vec<Finding> {
    let enabled: Vec<&Value> = i.users.iter().filter(|u| !flag(u, "disabled")).collect();
    let open = enabled
        .iter()
        .filter(|u| field(u, "address").trim().is_empty())
        .count();

    // Every account being unrestricted is a policy, not an oversight; some
    // accounts being restricted and others not is the shape worth reporting.
    if open > 0 && open < enabled.len() {
        return vec![finding(
            Severity::Low,
            "accounts",
            "address restrictions are applied inconsistently",
            format!(
                "{} of {} enabled accounts restrict where they may log in from; the other {} may log in from anywhere",
                enabled.len() - open,
                enabled.len(),
                open
            ),
            "/user set <name> address=<cidr>",
        )];
    }
    Vec::new()
}

/// The account RouterOS ships with.
fn default_admin(i: &Input) -> Vec<Finding> {
    i.users
        .iter()
        .find(|u| field(u, "name") == "admin" && !flag(u, "disabled"))
        .map(|_| {
            vec![finding(
                Severity::Medium,
                "accounts",
                "the default `admin` account is still enabled",
                "RouterOS ships this account and every attacker knows its name; a named account per operator is both safer and auditable",
                "/user disable admin",
            )]
        })
        .unwrap_or_default()
}

/// The policies a group actually holds — a leading `!` is a denial.
pub fn granted(policy: &str) -> Vec<String> {
    policy
        .split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty() && !p.starts_with('!'))
        .map(str::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn input(users: Vec<Value>, groups: Vec<Value>) -> Input {
        Input {
            users,
            groups,
            ..Default::default()
        }
    }

    #[test]
    fn a_restricted_powerful_account_is_not_a_finding() {
        let i = input(
            vec![
                json!({"name": "ops", "group": "full", "address": "203.0.113.0/24", "disabled": "false"}),
            ],
            vec![json!({"name": "full", "policy": "read,write,policy,sensitive"})],
        );
        assert!(powerful_accounts(&i).is_empty());
    }

    #[test]
    fn an_unrestricted_powerful_account_is_high() {
        let i = input(
            vec![json!({"name": "ops", "group": "full", "address": "", "disabled": "false"})],
            vec![json!({"name": "full", "policy": "read,write,policy,sensitive"})],
        );
        let f = powerful_accounts(&i);
        assert_eq!(f[0].severity, Severity::High);
        assert!(f[0].detail.contains("ops"));
    }

    #[test]
    fn a_disabled_account_is_not_a_way_in() {
        let i = input(
            vec![json!({"name": "ops", "group": "full", "address": "", "disabled": "true"})],
            vec![json!({"name": "full", "policy": "read,write"})],
        );
        assert!(powerful_accounts(&i).is_empty());
        assert!(default_admin(&input(
            vec![json!({"name": "admin", "disabled": "true"})],
            vec![]
        ))
        .is_empty());
    }

    #[test]
    fn the_builtin_read_group_is_reported_when_something_uses_it() {
        let policy = "local,telnet,ssh,reboot,read,test,winbox,password,web,sniff,sensitive,api,romon,rest-api,!ftp,!write,!policy";
        let i = input(
            vec![json!({"name": "mlab", "group": "read", "address": "", "disabled": "false"})],
            vec![json!({"name": "read", "policy": policy})],
        );
        let f = powerful_accounts(&i);
        let g = f.iter().find(|f| f.title.contains("read-only")).unwrap();
        assert_eq!(g.severity, Severity::Medium);
        assert!(g.detail.contains("sensitive"));
        assert!(g.detail.contains("reboot"));
        assert!(g.detail.contains("mlab"));
    }

    #[test]
    fn a_group_nobody_uses_is_not_a_finding() {
        let i = input(
            vec![],
            vec![json!({"name": "read", "policy": "read,sensitive,reboot"})],
        );
        assert!(powerful_accounts(&i).is_empty());
    }

    #[test]
    fn consistent_restrictions_are_not_reported_either_way() {
        // All open: a decision. All closed: correct. Neither is a finding here.
        let all_open = input(
            vec![
                json!({"name": "a", "address": "", "disabled": "false"}),
                json!({"name": "b", "address": "", "disabled": "false"}),
            ],
            vec![],
        );
        assert!(unrestricted_accounts(&all_open).is_empty());

        let mixed = input(
            vec![
                json!({"name": "a", "address": "", "disabled": "false"}),
                json!({"name": "b", "address": "10.0.0.1/32", "disabled": "false"}),
            ],
            vec![],
        );
        assert_eq!(unrestricted_accounts(&mixed).len(), 1);
    }
}
