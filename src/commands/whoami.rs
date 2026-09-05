//! `whoami` — what this account is, and everything it is allowed to read.
//!
//! Every other command's honesty rests on this one: a table that is empty
//! because the account cannot see the menu must never read as an empty router.
//!
//! It also answers a question specific to RouterOS. The built-in `read` group
//! is not a reader's group: it carries `sensitive`, so it returns pre-shared
//! keys, IPsec secrets and SNMP communities in clear text, and it carries
//! `reboot`, `sniff` and `password` besides. An account put in `read` because
//! the name sounded safe is more powerful than its owner thinks.

use anyhow::Result;
use serde_json::Value;

use crate::cli::Ctx;
use crate::ros::{field, flag, Client};
use crate::ui::{self, render};

/// The policies this CLI needs to do its work, and what each one buys.
const NEEDED: [(&str, &str); 2] = [
    ("read", "every menu this CLI reads"),
    (
        "rest-api",
        "the /rest transport itself — without it nothing answers",
    ),
];

/// Policies that are not about reading, and what they actually allow. A group
/// carrying one of these is not a read-only group, whatever it is called.
const BEYOND_READING: [(&str, &str); 8] = [
    ("write", "changes the configuration"),
    ("policy", "manages users and groups"),
    ("sensitive", "returns keys and passwords in clear text"),
    ("reboot", "restarts the router"),
    ("sniff", "captures traffic with the packet sniffer"),
    ("ftp", "reads and writes files over FTP"),
    ("password", "changes its own password"),
    ("romon", "reaches other routers over RoMON"),
];

pub async fn run(c: &Client, ctx: &Ctx) -> Result<()> {
    let users = ui::spin("Reading the account list", c.list("/user")).await?;
    let groups = ui::spin("Reading the groups", c.list("/user/group")).await?;
    let active = c.list("/user/active").await.unwrap_or_default();

    let me = ctx.profile.user.clone();
    let user = users.iter().find(|u| field(u, "name") == me);

    // A group named on the account but absent from /user/group would mean the
    // account cannot log in at all, so an empty policy string is reported as
    // unknown rather than as "no policies".
    let group_name = user.map(|u| field(u, "group")).unwrap_or_default();
    let group = groups.iter().find(|g| field(g, "name") == group_name);
    let policy = group.map(|g| field(g, "policy")).unwrap_or_default();

    let granted = granted_policies(&policy);
    let missing: Vec<&str> = NEEDED
        .iter()
        .map(|(p, _)| *p)
        .filter(|p| !granted.iter().any(|g| g == p))
        .collect();
    let extra: Vec<(&str, &str)> = BEYOND_READING
        .iter()
        .copied()
        .filter(|(p, _)| granted.iter().any(|g| g == p))
        .collect();

    if render::is_json() {
        render::print_json(&serde_json::json!({
            "instance": ctx.name,
            "user": me,
            "known": user.is_some(),
            "group": group_name,
            "policy": policy,
            "granted": granted,
            "denied": denied_policies(&policy),
            "missingForThisCli": missing,
            "beyondReading": extra.iter().map(|(p, w)| serde_json::json!({"policy": p, "allows": w})).collect::<Vec<_>>(),
            "allowedAddress": user.map(|u| field(u, "address")).unwrap_or_default(),
            "lastLoggedIn": user.map(|u| field(u, "last-logged-in")).unwrap_or_default(),
            "disabled": user.map(|u| flag(u, "disabled")).unwrap_or(false),
            "activeSessions": active,
        }));
        return Ok(());
    }

    render::heading(&format!("Account {me}"));
    render::pairs(&[
        ("instance", ctx.name.clone()),
        (
            "group",
            if group_name.is_empty() {
                "unknown".into()
            } else {
                group_name.clone()
            },
        ),
        (
            "allowed from",
            match user.map(|u| field(u, "address")).unwrap_or_default() {
                s if s.is_empty() => "anywhere".to_string(),
                s => s,
            },
        ),
        (
            "last logged in",
            user.map(|u| field(u, "last-logged-in")).unwrap_or_default(),
        ),
        ("policies", granted.join(", ")),
    ]);

    if user.is_none() {
        ui::warning(&format!(
            "no account named {me:?} in /user — the login works, so the name is probably cased differently"
        ));
    }

    for p in &missing {
        ui::warning(&format!(
            "the group is missing the {p:?} policy; some commands will report menus as refused"
        ));
    }

    if !extra.is_empty() {
        render::heading("Beyond reading");
        let rows: Vec<Value> = extra
            .iter()
            .map(|(p, w)| serde_json::json!({ "policy": p, "allows": w }))
            .collect();
        render::list(&rows, render::POLICY_COLS);
        println!();
        println!("  a group carrying these is not a read-only group, whatever it is named");
    }

    if granted.iter().any(|p| p == "sensitive") {
        ui::warning(
            "this account reads secrets in clear text (`sensitive`); a snapshot must redact before writing",
        );
    }

    if !active.is_empty() {
        render::heading("Sessions open right now");
        render::list(&active, render::SESSION_COLS);
        render::count(active.len(), "session");
    }
    Ok(())
}

/// The policies a group actually holds.
///
/// RouterOS writes a group's policy as one comma-separated string in which a
/// leading `!` means denied — `read,write,!ftp`. Splitting on the comma alone
/// would report `ftp` as granted, which is the wrong way round.
fn granted_policies(policy: &str) -> Vec<String> {
    policy
        .split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty() && !p.starts_with('!'))
        .map(str::to_string)
        .collect()
}

fn denied_policies(policy: &str) -> Vec<String> {
    policy
        .split(',')
        .map(str::trim)
        .filter_map(|p| p.strip_prefix('!'))
        .filter(|p| !p.is_empty())
        .map(str::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_denied_policy_is_not_a_granted_one() {
        let p = "local,ssh,read,test,winbox,sensitive,api,rest-api,!ftp,!write,!policy";
        let g = granted_policies(p);
        assert!(g.contains(&"read".to_string()));
        assert!(g.contains(&"sensitive".to_string()));
        assert!(
            !g.contains(&"write".to_string()),
            "!write is a denial, not a grant"
        );
        assert_eq!(denied_policies(p), vec!["ftp", "write", "policy"]);
    }

    #[test]
    fn an_empty_policy_grants_nothing() {
        assert!(granted_policies("").is_empty());
        assert!(denied_policies("").is_empty());
    }

    #[test]
    fn the_builtin_read_group_is_not_a_reading_group() {
        // Taken verbatim from a RouterOS 7.24 device: this is what `read`
        // actually carries, and the reason this command exists.
        let p = "local,telnet,ssh,reboot,read,test,winbox,password,web,sniff,sensitive,api,romon,rest-api,!ftp,!write,!policy";
        let g = granted_policies(p);
        let beyond: Vec<&str> = BEYOND_READING
            .iter()
            .map(|(p, _)| *p)
            .filter(|p| g.iter().any(|x| x == p))
            .collect();
        assert!(beyond.contains(&"sensitive"));
        assert!(beyond.contains(&"reboot"));
        assert!(beyond.contains(&"sniff"));
    }
}
