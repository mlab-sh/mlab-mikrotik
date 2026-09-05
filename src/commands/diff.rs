//! `diff` — what changed between two snapshots.

use std::path::PathBuf;

use anyhow::{bail, Result};
use clap::Args;
use colored::Colorize;
use serde_json::json;

use crate::cli::Ctx;
use crate::snapshot::{self, Change, Difference};
use crate::ui::render;

#[derive(Args, Debug)]
pub struct DiffArgs {
    /// The older snapshot. With neither argument, the last two of this instance.
    pub before: Option<PathBuf>,
    /// The newer snapshot. With only `before` given, compares it to the newest.
    pub after: Option<PathBuf>,
    /// Only this menu, e.g. /user or /ip/firewall/filter
    #[arg(long, value_name = "MENU")]
    pub menu: Option<String>,
    /// Only arrivals and departures; hide field-level edits
    #[arg(long)]
    pub presence: bool,
}

pub async fn run(ctx: &Ctx, args: &DiffArgs) -> Result<()> {
    let (before_path, after_path) = resolve(ctx, args)?;
    let before = snapshot::load(&before_path)?;
    let after = snapshot::load(&after_path)?;

    let mut diffs = snapshot::compare(&before, &after)?;
    if let Some(menu) = &args.menu {
        diffs.retain(|d| d.menu == *menu);
    }
    if args.presence {
        diffs.retain(|d| d.change != Change::Changed);
    }

    // A menu that stopped being readable is a change in what the account may
    // see, not in the router, and it belongs in its own line rather than
    // silently emptying a table.
    let lost: Vec<&str> = after
        .unreadable
        .iter()
        .map(|u| u.path.as_str())
        .filter(|p| !before.unreadable.iter().any(|u| u.path == *p))
        .collect();

    if render::is_json() {
        render::print_json(&json!({
            "before": { "taken": before.taken, "file": before_path },
            "after": { "taken": after.taken, "file": after_path },
            "differences": diffs,
            "newlyUnreadable": lost,
        }));
        return Ok(());
    }

    render::heading(&format!("{} → {}", before.taken, after.taken));

    if before.router.version != after.router.version {
        println!();
        println!(
            "  RouterOS {} → {}",
            before.router.version, after.router.version
        );
    }

    if diffs.is_empty() {
        println!();
        println!("  {}", "nothing changed".dimmed());
    } else {
        let mut menu = String::new();
        for d in &diffs {
            if d.menu != menu {
                menu = d.menu.clone();
                println!();
                println!("  {}", menu.bold());
            }
            println!("    {} {}", marker(d.change), d.key);
            for f in &d.fields {
                println!(
                    "        {}  {} → {}",
                    f.field.dimmed(),
                    show(&f.from),
                    show(&f.to)
                );
            }
        }
    }

    println!();
    println!(
        "  {}",
        format!(
            "{} appeared, {} disappeared, {} changed",
            count(&diffs, Change::Appeared),
            count(&diffs, Change::Disappeared),
            count(&diffs, Change::Changed),
        )
        .dimmed()
    );

    if !lost.is_empty() {
        println!();
        println!(
            "  {} {} menu(s) readable in the older snapshot and not in the newer: {}",
            "!".yellow().bold(),
            lost.len(),
            lost.join(", ")
        );
        println!(
            "  a menu that went quiet is a change in the account, and its rows are not compared"
        );
    }

    Ok(())
}

/// Which two files to compare.
fn resolve(ctx: &Ctx, args: &DiffArgs) -> Result<(PathBuf, PathBuf)> {
    match (&args.before, &args.after) {
        (Some(a), Some(b)) => Ok((a.clone(), b.clone())),
        (Some(a), None) => {
            let saved = snapshot::list(&ctx.name);
            let Some(newest) = saved.last() else {
                bail!(
                    "no saved snapshot for instance {:?} to compare against",
                    ctx.name
                );
            };
            Ok((a.clone(), newest.clone()))
        }
        (None, _) => {
            let saved = snapshot::list(&ctx.name);
            if saved.len() < 2 {
                bail!(
                    "instance {:?} has {} snapshot(s); a diff needs two — run `mlab-mikrotik snapshot` again later",
                    ctx.name,
                    saved.len()
                );
            }
            Ok((
                saved[saved.len() - 2].clone(),
                saved[saved.len() - 1].clone(),
            ))
        }
    }
}

fn count(diffs: &[Difference], c: Change) -> usize {
    diffs.iter().filter(|d| d.change == c).count()
}

fn marker(c: Change) -> colored::ColoredString {
    match c {
        Change::Appeared => "+".green().bold(),
        Change::Disappeared => "-".red().bold(),
        Change::Changed => "~".cyan().bold(),
    }
}

/// An empty value reads as a gap, not as an empty string.
fn show(v: &str) -> String {
    if v.is_empty() {
        "(none)".to_string()
    } else {
        v.to_string()
    }
}
