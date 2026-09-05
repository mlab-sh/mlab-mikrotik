//! `audit` — every graded check in one report.
//!
//! The report is only as honest as its footer. A check that could not run
//! produces nothing and is counted as skipped, never as a pass, and the count
//! is printed whether or not anything was found — so a clean run on a router
//! that refused half its menus cannot read as a clean router.

use anyhow::Result;
use clap::Args;
use colored::Colorize;
use serde_json::json;

use crate::checks::{self, Severity};
use crate::collect::{self, Fetcher};
use crate::ros::Client;
use crate::ui::{self, render};

#[derive(Args, Debug)]
pub struct AuditArgs {
    /// Only findings at this severity or worse: low, medium, high, critical
    #[arg(long, value_name = "LEVEL", value_parser = ["low", "medium", "high", "critical"])]
    pub min_severity: Option<String>,
    /// Only this area: accounts, services, exposure, segmentation, wireless, patch, logging
    #[arg(long, value_name = "AREA")]
    pub area: Option<String>,
    /// Exit 1 when anything at this severity or worse was found
    #[arg(long, value_name = "LEVEL", value_parser = ["low", "medium", "high", "critical"])]
    pub fail_on: Option<String>,
}

pub async fn run(c: &Client, args: &AuditArgs) -> Result<()> {
    let mut f = Fetcher::new(c);
    let input = ui::spin("Collecting", collect::security(&mut f)).await;
    let mut outcome = checks::run(&input);

    // The counts are taken before any filter is applied. A footer that said
    // "0 medium" because `--min-severity high` hid nine of them would be the
    // exact kind of quiet lie the rest of this tool is built to avoid.
    let total = outcome.findings.len();
    let counts = json!({
        "critical": outcome.count(Severity::Critical),
        "high": outcome.count(Severity::High),
        "medium": outcome.count(Severity::Medium),
        "low": outcome.count(Severity::Low),
    });

    let floor = args
        .min_severity
        .as_deref()
        .map(parse)
        .unwrap_or(Severity::Low);
    outcome.findings.retain(|f| f.severity >= floor);
    if let Some(area) = &args.area {
        outcome
            .findings
            .retain(|f| f.area.eq_ignore_ascii_case(area));
    }
    let filtered = total != outcome.findings.len();

    if render::is_json() {
        render::print_json(&json!({
            "findings": outcome.findings,
            "skipped": outcome.skipped,
            // `counts` is the whole router; `shown` is what survived the
            // filters on this run.
            "counts": counts,
            "shown": outcome.findings.len(),
            "unreadable": input.unreadable,
        }));
        return exit_code(args, &outcome);
    }

    f.report();

    if outcome.findings.is_empty() {
        render::heading("Audit");
        println!();
        println!("  {}", "nothing found at this severity".dimmed());
    } else {
        render::heading("Audit");
        for finding in &outcome.findings {
            println!();
            println!("  {}  {}", badge(finding.severity), finding.title.bold());
            println!("  {:>8}  {}", "".dimmed(), finding.detail);
            if !finding.fix.is_empty() {
                println!("  {:>8}  {}", "".dimmed(), finding.fix.dimmed());
            }
        }
    }

    // The footer is the part that makes the rest trustworthy, so it prints
    // even when nothing was found.
    println!();
    println!(
        "  {}",
        format!(
            "{} critical, {} high, {} medium, {} low",
            counts["critical"], counts["high"], counts["medium"], counts["low"],
        )
        .dimmed()
    );
    if filtered {
        println!(
            "  {}",
            format!(
                "{} of {} shown — the counts above are the whole router",
                outcome.findings.len(),
                total
            )
            .dimmed()
        );
    }

    if !outcome.skipped.is_empty() {
        println!();
        println!(
            "  {} not run:",
            format!("{} check(s)", outcome.skipped.len()).yellow()
        );
        for s in &outcome.skipped {
            println!("    {}  {}", s.check.dimmed(), s.because);
        }
        println!();
        println!("  {}", "a check that could not run is not a pass".dimmed());
    }

    exit_code(args, &outcome)
}

/// `--fail-on` turns the report into a gate, for CI.
fn exit_code(args: &AuditArgs, outcome: &checks::Outcome) -> Result<()> {
    let Some(level) = args.fail_on.as_deref().map(parse) else {
        return Ok(());
    };
    let hits = outcome
        .findings
        .iter()
        .filter(|f| f.severity >= level)
        .count();
    if hits > 0 {
        anyhow::bail!(
            "{hits} finding(s) at {} or worse (--fail-on {})",
            level.label(),
            level.label()
        );
    }
    Ok(())
}

fn parse(s: &str) -> Severity {
    match s {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        _ => Severity::Low,
    }
}

fn badge(s: Severity) -> colored::ColoredString {
    let text = format!("{:>8}", s.label());
    match s {
        Severity::Critical => text.red().bold(),
        Severity::High => text.red(),
        Severity::Medium => text.yellow(),
        Severity::Low => text.dimmed(),
    }
}
