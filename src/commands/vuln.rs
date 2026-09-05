//! `vuln` — the published advisories that cover *this* version.
//!
//! Not a reading list. NVD carries version ranges for most of the RouterOS
//! corpus and applies them itself when asked with a versioned CPE, so this
//! command can say "these three cover you" rather than "here are eighty-six
//! advisories that mention RouterOS".
//!
//! Two things it will not do. It will not treat a bound that is not a version
//! number as one — there is at least one such record — and it will not report
//! an advisory written for another release branch against this one. Both come
//! back as their own category rather than being quietly dropped or quietly
//! believed.

use anyhow::Result;
use clap::Args;
use colored::Colorize;
use serde_json::json;

use crate::collect::Fetcher;
use crate::enrich::advisories::{self, Verdict};
use crate::ros::version::{Channel, Version};
use crate::ros::{field, Client};
use crate::ui::{self, render};

#[derive(Args, Debug)]
pub struct VulnArgs {
    /// Ask vuln.mlab.sh which advisories cover this version
    #[arg(long)]
    pub allow_web: bool,
    /// Ignore a fresh cache entry and ask again
    #[arg(long)]
    pub refresh: bool,

    /// Also list the advisories the local pass excluded or could not check
    #[arg(long)]
    pub all: bool,
    /// Check this version instead of the one the router reports
    #[arg(long, value_name = "VERSION")]
    pub version: Option<String>,
    /// Judge against this release channel instead of the router's own —
    /// answers "would moving to long-term help", and nothing is changed
    #[arg(long, value_name = "CHANNEL", value_parser = ["stable", "long-term", "testing"])]
    pub channel: Option<String>,
}

pub async fn run(c: &Client, args: &VulnArgs) -> Result<()> {
    let mut f = Fetcher::new(c);
    let resource = f.get("/system/resource").await;
    let update = f.get("/system/package/update").await;

    let text = args
        .version
        .clone()
        .unwrap_or_else(|| field(&resource, "version"));
    let Some(version) = Version::parse(&text) else {
        anyhow::bail!(
            "{text:?} is not a version number, so there is nothing to look up — pass --version"
        );
    };
    let channel = args
        .channel
        .as_deref()
        .or(Some(&field(&update, "channel")))
        .and_then(Channel::parse)
        .unwrap_or(Channel::Stable);

    let found = advisories::for_version(&version, args.allow_web, args.refresh).await;
    let assessed: Vec<_> = found
        .items
        .iter()
        .map(|a| advisories::assess(a, &version, channel))
        .collect();

    let pick = |v: Verdict| -> Vec<&advisories::Assessment> {
        assessed.iter().filter(|a| a.verdict == v).collect()
    };
    let (applies, unclear, excluded) = (
        pick(Verdict::Applies),
        pick(Verdict::Unclear),
        pick(Verdict::Excluded),
    );

    if render::is_json() {
        render::print_json(&json!({
            "version": version.to_string(),
            "channel": channel.label(),
            "cpe": format!("cpe:2.3:o:mikrotik:routeros:{version}"),
            "assessed": assessed,
            "counts": {
                "applies": applies.len(),
                "unclear": unclear.len(),
                "excluded": excluded.len(),
            },
            "lookupSkipped": found.skipped,
            "lookupProvenance": found.provenance(),
            "lookupError": found.error,
        }));
        return Ok(());
    }

    f.report();

    if found.skipped {
        render::heading(&format!("RouterOS {version} ({})", channel.label()));
        ui::info("no advisory was looked up — add --allow-web");
        println!("  what leaves this machine is the version string and nothing else");
        return Ok(());
    }
    if let Some(e) = &found.error {
        ui::warning(&format!("the advisory lookup failed: {e}"));
        println!("  a failed lookup is not a clean result — nothing is claimed below");
        return Ok(());
    }

    render::heading(&format!("RouterOS {version} ({})", channel.label()));

    if applies.is_empty() {
        println!();
        println!("  {}", "no advisory covers this version".dimmed());
    } else {
        for a in &applies {
            println!();
            println!(
                "  {}  {}  {}",
                badge(&a.advisory),
                a.advisory.id.bold(),
                marks(&a.advisory)
            );
            println!("            {}", clip(&a.advisory.description));
            println!("            {}", a.why.dimmed());
        }
    }

    println!();
    println!(
        "  {}",
        format!(
            "{} cover this version, {} could not be checked, {} name another branch or version",
            applies.len(),
            unclear.len(),
            excluded.len()
        )
        .dimmed()
    );

    // The unclear pile is the honest part of the answer and is never folded
    // into either of the other two.
    if !unclear.is_empty() {
        render::heading("Could not be checked");
        for a in &unclear {
            println!("    {}  {}", a.advisory.id, a.why.dimmed());
        }
        println!();
        println!("  these are advisories NVD returned for this version whose own bounds do not");
        println!("  settle it. Read them; do not count them either way.");
    }

    if args.all && !excluded.is_empty() {
        render::heading("Named another branch or version");
        for a in &excluded {
            println!("    {}  {}", a.advisory.id, a.why.dimmed());
        }
    } else if !excluded.is_empty() {
        println!("  {} excluded — add --all to see why", excluded.len());
    }

    println!();
    // A cached answer is served with or without --allow-web — the flag gates
    // the network, not data already on this disk — so where it came from has
    // to be on screen, or two consecutive runs differ for no visible reason.
    println!(
        "  {}",
        format!("{} — add --refresh to ask again", found.provenance()).dimmed()
    );
    println!(
        "  {}",
        "an advisory that names no version at all cannot be ruled out by this method".dimmed()
    );

    Ok(())
}

fn badge(a: &advisories::Advisory) -> colored::ColoredString {
    let label = a
        .cvss_severity
        .clone()
        .unwrap_or_else(|| "unrated".to_string())
        .to_lowercase();
    let text = format!("{label:>8}");
    match label.as_str() {
        "critical" => text.red().bold(),
        "high" => text.red(),
        "medium" => text.yellow(),
        "low" => text.dimmed(),
        _ => text.normal(),
    }
}

/// The two facts that change what you do about an advisory today.
fn marks(a: &advisories::Advisory) -> String {
    let mut out = Vec::new();
    if let Some(s) = a.cvss_score {
        out.push(format!("CVSS {s}"));
    }
    if let Some(e) = a.epss_score {
        out.push(format!("EPSS {:.1}%", e * 100.0));
    }
    if a.in_kev {
        out.push(format!(
            "in CISA KEV{}",
            a.kev_date_added
                .as_deref()
                .map(|d| format!(" since {d}"))
                .unwrap_or_default()
        ));
    }
    out.join("  ")
}

fn clip(s: &str) -> String {
    const MAX: usize = 150;
    let one_line = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if one_line.chars().count() <= MAX {
        return one_line;
    }
    format!("{}…", one_line.chars().take(MAX - 1).collect::<String>())
}
