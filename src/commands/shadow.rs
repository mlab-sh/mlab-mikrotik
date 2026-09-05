//! `shadow` — what turned up on this router that nobody announced.
//!
//! The live configuration against the last snapshot, filtered down to
//! **arrivals** in the menus where an arrival is a decision somebody made: an
//! account, a service, a firewall rule, a scheduled task. A departure is
//! rarely a surprise and a counter moving is never one; both are `diff`'s job.
//!
//! This is the shape detection takes on a platform with no event stream. It is
//! slower than an alert and it is harder to evade: an intruder can avoid
//! tripping a signature, but can hardly avoid existing in the inventory.

use std::path::PathBuf;

use anyhow::{bail, Result};
use clap::Args;
use colored::Colorize;
use serde_json::json;

use crate::cli::Ctx;
use crate::collect::Fetcher;
use crate::ros::Client;
use crate::snapshot::{self, Change, Snapshot};
use crate::ui::{self, render};

/// Menus where something appearing is worth a look, and what it would mean.
///
/// Ordered by how much an arrival costs, because that is the order a reader
/// wants them in.
const WATCHED: [(&str, &str); 12] = [
    ("/system/scheduler", "a task that runs on its own schedule"),
    ("/system/script", "a script the router can run"),
    ("/user", "an account that can log in"),
    ("/user/group", "a set of permissions"),
    ("/user/ssh-keys", "a key that logs in without a password"),
    ("/tool/netwatch", "a probe that can trigger a script"),
    ("/ip/service", "a service listening on the router"),
    (
        "/ip/firewall/filter",
        "a rule that admits or refuses traffic",
    ),
    (
        "/ip/firewall/nat",
        "a rule that publishes or rewrites traffic",
    ),
    ("/ip/dns/static", "a name this router answers for"),
    ("/interface", "an interface, including a tunnel"),
    ("/ip/address", "an address on this router"),
];

#[derive(Args, Debug)]
pub struct ShadowArgs {
    /// Compare against this snapshot instead of the most recent one
    #[arg(long, value_name = "PATH")]
    pub since: Option<PathBuf>,
    /// Every menu in the catalogue, not just the ones worth watching
    #[arg(long)]
    pub all: bool,
    /// Also report what disappeared
    #[arg(long)]
    pub departures: bool,
    /// Include rows RouterOS created for itself
    #[arg(long)]
    pub dynamic: bool,
}

pub async fn run(c: &Client, ctx: &Ctx, args: &ShadowArgs) -> Result<()> {
    let baseline_path = match &args.since {
        Some(p) => p.clone(),
        None => {
            let saved = snapshot::list(&ctx.name);
            let Some(newest) = saved.last() else {
                bail!(
                    "instance {:?} has no snapshot to compare against; run `mlab-mikrotik snapshot` first",
                    ctx.name
                );
            };
            newest.clone()
        }
    };
    let baseline = snapshot::load(&baseline_path)?;

    let mut f = Fetcher::new(c);
    let live = ui::spin("Reading the router now", Snapshot::take(&mut f, &ctx.name)).await;

    let all = snapshot::compare(&baseline, &live)?;

    let watched: Vec<&str> = WATCHED.iter().map(|(m, _)| *m).collect();
    // A dynamic row is one the router created for itself. Its arrival is a
    // consequence of something working — a lease renewing, a routing protocol
    // converging — and reporting it as something that "turned up" buries the
    // one line that matters under a dozen that do not.
    let arrivals: Vec<_> = all
        .iter()
        .filter(|d| d.change == Change::Appeared)
        .filter(|d| args.dynamic || !d.dynamic)
        .filter(|d| args.all || watched.contains(&d.menu.as_str()))
        .collect();
    let departures: Vec<_> = all
        .iter()
        .filter(|d| d.change == Change::Disappeared)
        .filter(|d| args.dynamic || !d.dynamic)
        .filter(|d| args.all || watched.contains(&d.menu.as_str()))
        .collect();
    let hidden = all
        .iter()
        .filter(|d| d.dynamic && d.change != Change::Changed)
        .count();

    if render::is_json() {
        render::print_json(&json!({
            "since": { "taken": baseline.taken, "file": baseline_path },
            "now": live.taken,
            "arrivals": arrivals,
            "departures": departures,
            "otherChanges": all.iter().filter(|d| d.change == Change::Changed).count(),
            "dynamicHidden": if args.dynamic { 0 } else { hidden },
            "unreadable": live.unreadable,
        }));
        return Ok(());
    }

    f.report();
    render::heading(&format!("Since {}", baseline.taken));

    if arrivals.is_empty() {
        println!();
        println!("  {}", "nothing new".dimmed());
    } else {
        let mut menu = String::new();
        for d in &arrivals {
            if d.menu != menu {
                menu = d.menu.clone();
                let why = WATCHED
                    .iter()
                    .find(|(m, _)| *m == menu)
                    .map(|(_, w)| *w)
                    .unwrap_or("");
                println!();
                println!("  {}  {}", menu.bold(), why.dimmed());
            }
            println!("    {} {}", "+".green().bold(), d.key);
        }
    }

    if args.departures && !departures.is_empty() {
        render::heading("Gone");
        for d in &departures {
            println!("    {} {}  {}", "-".red().bold(), d.key, d.menu.dimmed());
        }
    }

    println!();
    let edits = all.iter().filter(|d| d.change == Change::Changed).count();
    println!(
        "  {}",
        format!(
            "{} arrival(s), {} departure(s), {} edit(s) — `diff` shows the edits",
            arrivals.len(),
            departures.len(),
            edits
        )
        .dimmed()
    );

    if hidden > 0 && !args.dynamic {
        println!(
            "  {}",
            format!("{hidden} row(s) RouterOS created for itself are not shown — add --dynamic")
                .dimmed()
        );
    }

    // An arrival is a fact about the configuration, never a verdict about who
    // put it there. Saying so once is cheaper than a reader assuming it.
    if !arrivals.is_empty() {
        println!();
        println!("  these are things that were not here at the last snapshot, not accusations —");
        println!("  a change window explains most of them, and the ones it does not are the point");
    }

    Ok(())
}
