//! `hunt` — the markers a compromised MikroTik router leaves behind.
//!
//! Everything here is an **observation**, never a verdict about who put it
//! there. A backup script that uploads and a persistence script that downloads
//! use the same two commands; the difference is whether you wrote it, and
//! nothing in the configuration knows that.
//!
//! The list is not invented. It is what the public post-mortems of the
//! MikroTik campaigns since 2018 describe: a scheduled task that fetches and
//! imports, SOCKS turned on, a web proxy whose cache holds an injected page,
//! an account nobody recognises, an L2TP client to somewhere unexpected.

use anyhow::Result;
use clap::Args;
use colored::Colorize;
use serde_json::{json, Value};

use crate::collect::Fetcher;
use crate::ros::{field, first_field, flag, Client};
use crate::ui::render;

/// The properties of `/file` worth asking for.
///
/// Never the whole menu: RouterOS embeds each file's **contents**, and one
/// binary file makes the entire response invalid UTF-8 — the request answers
/// `200` with bytes that are not JSON.
const FILE_PROPS: [&str; 5] = [".id", "name", "type", "size", "creation-time"];

#[derive(Args, Debug)]
pub struct HuntArgs {
    /// Show every marker checked, including the ones that found nothing
    #[arg(long)]
    pub all: bool,
}

/// One thing looked for, and what was there.
struct Marker {
    name: &'static str,
    /// What it would mean if it were found.
    means: &'static str,
    hits: Vec<String>,
}

pub async fn run(c: &Client, args: &HuntArgs) -> Result<()> {
    let mut f = Fetcher::new(c);

    let scheduler = f.list("/system/scheduler").await;
    let scripts = f.list("/system/script").await;
    let netwatch = f.list("/tool/netwatch").await;
    let files = f.list_props("/file", &FILE_PROPS).await;
    let interfaces = f
        .list_props("/interface", &["name", "type", "disabled", "comment"])
        .await;
    let users = f.list("/user").await;
    let socks = f.get("/ip/socks").await;
    let proxy = f.get("/ip/proxy").await;
    let dns_static = f.list("/ip/dns/static").await;
    let certificates = f.list("/certificate").await;

    let source_of = |name: &str| -> String {
        scripts
            .iter()
            .find(|s| field(s, "name") == name.trim())
            .map(|s| field(s, "source"))
            .unwrap_or_default()
    };

    let markers = vec![
        Marker {
            name: "scheduled tasks",
            means: "the persistence mechanism seen most often on RouterOS",
            hits: scheduler
                .iter()
                .map(|e| {
                    let ev = field(e, "on-event");
                    format!(
                        "{} — {} — {}",
                        field(e, "name"),
                        match field(e, "interval").as_str() {
                            "" => format!("at {}", field(e, "start-time")),
                            iv => format!("every {iv}"),
                        },
                        one_line(&format!("{ev} {}", source_of(&ev)))
                    )
                })
                .collect(),
        },
        Marker {
            name: "scripts",
            means: "what a scheduled task, a netwatch probe or a login can run",
            hits: scripts
                .iter()
                .map(|s| format!("{} — {}", field(s, "name"), one_line(&field(s, "source"))))
                .collect(),
        },
        Marker {
            name: "netwatch probes with a script",
            means: "a second persistence path, forgotten after /system/scheduler is cleaned",
            hits: netwatch
                .iter()
                .filter(|n| {
                    !field(n, "up-script").is_empty() || !field(n, "down-script").is_empty()
                })
                .map(|n| {
                    format!(
                        "{} — up:{} down:{}",
                        field(n, "host"),
                        field(n, "up-script"),
                        field(n, "down-script")
                    )
                })
                .collect(),
        },
        Marker {
            name: "SOCKS proxy",
            means: "the relay every MikroTik botnet campaign since 2018 has left behind",
            hits: if flag(&socks, "enabled") {
                vec![format!("enabled on port {}", field(&socks, "port"))]
            } else {
                Vec::new()
            },
        },
        Marker {
            name: "web proxy",
            means: "where the error.html injection campaigns put their payload",
            hits: if flag(&proxy, "enabled") {
                vec![format!("enabled on port {}", field(&proxy, "port"))]
            } else {
                Vec::new()
            },
        },
        Marker {
            name: "outbound tunnels",
            means: "a path back into this network for whoever terminates it",
            hits: interfaces
                .iter()
                .filter(|i| field(i, "type").ends_with("-out") || field(i, "type") == "wireguard")
                .map(|i| format!("{} ({})", field(i, "name"), field(i, "type")))
                .collect(),
        },
        Marker {
            name: "accounts",
            means: "a login left behind is the cheapest persistence there is",
            hits: users
                .iter()
                .filter(|u| !flag(u, "disabled"))
                .map(|u| {
                    format!(
                        "{} — group {} — last login {}",
                        field(u, "name"),
                        field(u, "group"),
                        match field(u, "last-logged-in").as_str() {
                            "" => "never".to_string(),
                            t => t.to_string(),
                        }
                    )
                })
                .collect(),
        },
        Marker {
            name: "files on the router's storage",
            means: "captures, backups and support dumps hold more than they look like they do",
            hits: files
                .iter()
                .filter(|f| field(f, "type") != "directory")
                .map(|f| {
                    format!(
                        "{} ({}{})",
                        field(f, "name"),
                        crate::ros::num(f, "size")
                            .map(crate::ros::bytes)
                            .unwrap_or_else(|| "?".into()),
                        match field(f, "creation-time").as_str() {
                            "" => String::new(),
                            t => format!(", {t}"),
                        }
                    )
                })
                .collect(),
        },
        Marker {
            name: "static DNS entries",
            means: "a name this router answers for, whatever the real one resolves to",
            hits: dns_static
                .iter()
                .filter(|d| !flag(d, "disabled"))
                .map(|d| {
                    format!(
                        "{} → {}",
                        first_field(d, &["name", "regexp"]),
                        first_field(d, &["address", "cname", "text"])
                    )
                })
                .collect(),
        },
        Marker {
            name: "certificates",
            means: "one this router did not need is one somebody else installed",
            hits: certificates
                .iter()
                .map(|c| {
                    format!(
                        "{} — {}",
                        field(c, "name"),
                        first_field(c, &["common-name", "issuer"])
                    )
                })
                .collect(),
        },
    ];

    if render::is_json() {
        let rows: Vec<Value> = markers
            .iter()
            .map(|m| json!({ "marker": m.name, "means": m.means, "found": m.hits }))
            .collect();
        render::print_json(&json!({
            "markers": rows,
            "found": markers.iter().filter(|m| !m.hits.is_empty()).count(),
            "unreadable": f.unreadable,
        }));
        return Ok(());
    }

    f.report();
    render::heading("Hunt");

    let found: Vec<&Marker> = markers.iter().filter(|m| !m.hits.is_empty()).collect();

    for m in &markers {
        if m.hits.is_empty() && !args.all {
            continue;
        }
        println!();
        if m.hits.is_empty() {
            println!("  {}  {}", m.name.bold(), "nothing".dimmed());
            continue;
        }
        println!("  {}  {}", m.name.bold(), m.means.dimmed());
        for h in &m.hits {
            println!("    {} {h}", "·".dimmed());
        }
    }

    println!();
    println!(
        "  {}",
        format!(
            "{} of {} markers found something",
            found.len(),
            markers.len()
        )
        .dimmed()
    );

    if !args.all {
        println!(
            "  {}",
            "add --all to see the ones that found nothing".dimmed()
        );
    }

    // The sentence this whole command hangs on.
    println!();
    println!("  none of this is evidence of anything on its own. A scheduled task that fetches");
    println!("  is a backup job on most routers and persistence on a few, and only you know");
    println!("  which. What `hunt` gives you is the list to go through, not a verdict.");

    Ok(())
}

/// A script source on one line, clipped — sources run to dozens of lines and
/// the point here is to recognise one, not to read it.
fn one_line(s: &str) -> String {
    const MAX: usize = 90;
    let joined = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if joined.is_empty() {
        return "(empty)".to_string();
    }
    if joined.chars().count() <= MAX {
        return joined;
    }
    format!("{}…", joined.chars().take(MAX - 1).collect::<String>())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_script_source_is_reduced_to_something_recognisable() {
        assert_eq!(one_line("/tool fetch\n  url=x"), "/tool fetch url=x");
        assert_eq!(one_line("   "), "(empty)");
        let long = "a ".repeat(100);
        assert_eq!(one_line(&long).chars().count(), 90);
        assert!(one_line(&long).ends_with('…'));
    }
}
