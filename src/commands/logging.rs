//! `logging` — where this router's log goes, and what never reaches it.
//!
//! Two questions, and the second is the one people forget. Whether anything
//! survives a reboot — everything in `memory` does not, and a reboot is the
//! first thing that happens after most incidents. And whether the topics that
//! matter for an investigation are recorded at all: a login, a configuration
//! change, a refusal.

use anyhow::Result;
use serde_json::{json, Value};

use crate::collect::Fetcher;
use crate::ros::{field, flag, Client};
use crate::ui::render;

/// The topics worth having, and what each one answers afterwards.
///
/// RouterOS ships with `info`, `error`, `warning` and `critical` to memory and
/// nothing else, so every one of these is a decision somebody has to make.
const WANTED: [(&str, &str); 5] = [
    ("account", "who logged in, from where, and who failed to"),
    ("system", "what changed in the configuration, and by whom"),
    ("critical", "what the router considers an emergency"),
    ("error", "what failed"),
    ("firewall", "what the rules that log actually caught"),
];

/// Targets whose contents outlive a reboot.
const DURABLE: [&str; 2] = ["remote", "disk"];

pub async fn run(c: &Client) -> Result<()> {
    let mut f = Fetcher::new(c);
    let rules = f.list("/system/logging").await;
    let actions = f.list("/system/logging/action").await;
    let filter = f.list("/ip/firewall/filter").await;

    let target_of = |name: &str| -> String {
        actions
            .iter()
            .find(|a| field(a, "name") == name)
            .map(|a| field(a, "target"))
            .unwrap_or_default()
    };

    let active: Vec<&Value> = rules.iter().filter(|r| !flag(r, "disabled")).collect();

    let rows: Vec<Value> = active
        .iter()
        .map(|r| {
            let action = field(r, "action");
            let target = target_of(&action);
            json!({
                "topics": field(r, "topics"),
                "action": action,
                "target": if target.is_empty() { "?".to_string() } else { target.clone() },
                "durable": DURABLE.contains(&target.as_str()),
                "prefix": field(r, "prefix"),
            })
        })
        .collect();

    // A topic is covered when some active rule names it. RouterOS matches on
    // prefixes — a rule for `system` catches `system,info` — so the comparison
    // is on the first component of each term.
    let covered = |topic: &str| -> Option<String> {
        active
            .iter()
            .find(|r| {
                field(r, "topics")
                    .split(',')
                    .any(|t| t.trim() == topic || t.trim().starts_with(&format!("{topic},")))
            })
            .map(|r| field(r, "action"))
    };

    let coverage: Vec<Value> = WANTED
        .iter()
        .map(|(topic, why)| {
            let action = covered(topic);
            let target = action.as_deref().map(target_of).unwrap_or_default();
            json!({
                "topic": topic,
                "answers": why,
                "action": action.clone().unwrap_or_else(|| "—".to_string()),
                "durable": DURABLE.contains(&target.as_str()),
            })
        })
        .collect();

    let refusals: Vec<&Value> = filter
        .iter()
        .filter(|r| !flag(r, "disabled"))
        .filter(|r| matches!(field(r, "action").as_str(), "drop" | "reject"))
        .collect();
    let logged = refusals.iter().filter(|r| flag(r, "log")).count();

    let durable_rules = rows.iter().filter(|r| r["durable"] == json!(true)).count();

    if render::is_json() {
        render::print_json(&json!({
            "rules": rows,
            "actions": actions,
            "coverage": coverage,
            "refusals": { "total": refusals.len(), "logged": logged },
            "durableRules": durable_rules,
            "unreadable": f.unreadable,
        }));
        return Ok(());
    }

    f.report();

    render::heading("Where it goes");
    render::list(&rows, render::LOG_RULE_COLS);
    render::count(rows.len(), "rule");
    println!();
    if durable_rules == 0 {
        println!("  every active rule writes somewhere volatile — the whole log is gone at the");
        println!("  next reboot, and a reboot is the first thing that happens after an incident");
    } else {
        println!("  {durable_rules} rule(s) write somewhere that survives a reboot");
    }
    println!("  a rule is judged by its action's target, not by the action's name");

    render::heading("What is recorded");
    render::list(&coverage, render::LOG_COVERAGE_COLS);
    let missing: Vec<&str> = WANTED
        .iter()
        .map(|(t, _)| *t)
        .filter(|t| covered(t).is_none())
        .collect();
    println!();
    if missing.is_empty() {
        println!("  every topic worth having is recorded somewhere");
    } else {
        println!(
            "  not recorded: {} — these are the questions that cannot be answered afterwards",
            missing.join(", ")
        );
    }

    render::heading("Firewall refusals");
    render::pairs(&[
        ("drop or reject rules", refusals.len().to_string()),
        ("with log=yes", format!("{logged} of {}", refusals.len())),
    ]);
    if refusals.is_empty() {
        println!("  nothing refuses anything, so there is nothing to log");
    } else if logged == 0 {
        println!("  nothing records what this router turned away");
    } else {
        println!("  logging every refusal is usually a mistake — a busy catch-all drop will");
        println!("  fill the log on its own. The rules worth watching are the narrow ones.");
    }

    Ok(())
}
