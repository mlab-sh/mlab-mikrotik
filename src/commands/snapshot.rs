//! `snapshot` — one dated, secret-free record of everything this account can
//! read.

use std::path::PathBuf;

use anyhow::Result;
use clap::{Args, Subcommand};
use serde_json::json;

use crate::cli::Ctx;
use crate::collect::Fetcher;
use crate::ros::Client;
use crate::snapshot::{self, Snapshot};
use crate::ui::{self, render};

#[derive(Subcommand, Debug)]
pub enum SnapshotCmd {
    /// Every snapshot saved for this instance, oldest first
    #[command(alias = "ls")]
    List,
}

#[derive(Args, Debug)]
pub struct SnapshotArgs {
    #[command(subcommand)]
    pub cmd: Option<SnapshotCmd>,
    /// Write to this file instead of the snapshot directory
    #[arg(long, short = 'f', value_name = "PATH")]
    pub out: Option<PathBuf>,
    /// Print the snapshot on stdout and save nothing
    #[arg(long)]
    pub stdout: bool,
}

pub async fn run(c: &Client, ctx: &Ctx, args: &SnapshotArgs) -> Result<()> {
    if let Some(SnapshotCmd::List) = args.cmd {
        return list(&ctx.name);
    }

    let mut f = Fetcher::new(c);
    let snap = ui::spin(
        "Collecting the whole catalogue",
        Snapshot::take(&mut f, &ctx.name),
    )
    .await;

    if args.stdout {
        render::print_json(&serde_json::to_value(&snap)?);
        return Ok(());
    }

    let path = match &args.out {
        Some(p) => {
            let mut data = serde_json::to_string_pretty(&snap)?;
            data.push('\n');
            std::fs::write(p, data)?;
            p.clone()
        }
        None => snapshot::save(&snap)?,
    };

    if render::is_json() {
        render::print_json(&json!({
            "path": path,
            "taken": snap.taken,
            "menus": snap.menus.len(),
            "rows": snap.rows(),
            "secretsRedacted": snap.secrets_redacted,
            "unreadable": snap.unreadable,
        }));
        return Ok(());
    }

    f.report();
    ui::success(&format!("saved {}", path.display()));
    render::pairs(&[
        ("taken", snap.taken.clone()),
        (
            "router",
            format!("{} ({})", snap.router.identity, snap.router.board),
        ),
        ("routeros", snap.router.version.clone()),
        (
            "menus",
            format!("{} ({} rows)", snap.menus.len(), snap.rows()),
        ),
        ("secrets removed", snap.secrets_redacted.to_string()),
        ("unreadable", snap.unreadable.len().to_string()),
    ]);

    // The two numbers that say what this file is worth: what was taken out of
    // it, and what never made it in.
    if snap.secrets_redacted > 0 {
        println!(
            "  {} secret(s) were replaced by their length before this file was written",
            snap.secrets_redacted
        );
    }
    let previous = snapshot::list(&ctx.name);
    if previous.len() > 1 {
        println!(
            "  {} snapshots for this instance — `diff` compares the last two",
            previous.len()
        );
    }
    Ok(())
}

fn list(instance: &str) -> Result<()> {
    let paths = snapshot::list(instance);

    if render::is_json() {
        render::print_json(&json!(paths));
        return Ok(());
    }

    if paths.is_empty() {
        ui::warning(&format!(
            "no snapshot for instance {instance:?} yet; run `mlab-mikrotik snapshot`"
        ));
        return Ok(());
    }

    render::heading(&format!("Snapshots of {instance}"));
    let rows: Vec<serde_json::Value> = paths
        .iter()
        .map(|p| {
            // A file that will not parse is still worth listing: it is the one
            // the reader is looking for when something has gone wrong.
            let (taken, rows, secrets) = match snapshot::load(p) {
                Ok(s) => (
                    s.taken.clone(),
                    s.rows().to_string(),
                    s.secrets_redacted.to_string(),
                ),
                Err(_) => ("unreadable".to_string(), String::new(), String::new()),
            };
            json!({
                "taken": taken,
                "rows": rows,
                "secretsRemoved": secrets,
                "file": p.file_name().and_then(|n| n.to_str()).unwrap_or_default(),
            })
        })
        .collect();
    render::list(&rows, render::SNAPSHOT_COLS);
    render::count(rows.len(), "snapshot");
    println!("  {}", snapshot::instance_dir(instance).display());
    Ok(())
}
