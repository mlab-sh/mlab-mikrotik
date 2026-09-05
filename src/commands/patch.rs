//! `patch` — how far behind this router is.
//!
//! Two gaps, and they move independently: RouterOS against its own release
//! channel, and the RouterBOARD bootloader against the RouterOS already
//! installed. The second is the one everybody misses, because a RouterOS
//! upgrade never moves it.
//!
//! The router is never asked to check. `/system/package/update/
//! check-for-updates` would have it contact MikroTik, and a passive audit does
//! not change what a production router does on the wire; the question goes to
//! MikroTik from this machine instead, behind `--allow-web`.

use anyhow::Result;
use clap::Args;
use serde_json::json;

use crate::collect::Fetcher;
use crate::enrich::release;
use crate::ros::version::{Channel, Version};
use crate::ros::{field, Client};
use crate::ui::{self, render};

#[derive(Args, Debug)]
pub struct PatchArgs {
    /// Ask MikroTik which version this channel is on (from this machine, not
    /// from the router)
    #[arg(long)]
    pub allow_web: bool,
    /// Ignore a fresh cache entry and ask again
    #[arg(long)]
    pub refresh: bool,
}

pub async fn run(c: &Client, args: &PatchArgs) -> Result<()> {
    let mut f = Fetcher::new(c);
    let resource = f.get("/system/resource").await;
    let board = f.get("/system/routerboard").await;
    let update = f.get("/system/package/update").await;
    let packages = f.list("/system/package").await;

    let installed_text = crate::ros::first_field(&update, &["installed-version"]);
    let installed_text = if installed_text.is_empty() {
        field(&resource, "version")
    } else {
        installed_text
    };
    let installed = Version::parse(&installed_text);

    let channel_text = field(&update, "channel");
    let channel = Channel::parse(&channel_text);

    // What the router already knows, if a check has ever been run on it. Never
    // triggered from here.
    let cached_latest = field(&update, "latest-version");

    let current = match channel {
        Some(ch) => release::current(ch, args.allow_web, args.refresh).await,
        None => Default::default(),
    };

    let latest = current
        .items
        .as_ref()
        .map(|r| r.version.clone())
        .filter(|v| !v.is_empty())
        .or_else(|| (!cached_latest.is_empty()).then(|| cached_latest.clone()));

    let behind = match (&installed, latest.as_deref().and_then(Version::parse)) {
        (Some(i), Some(l)) => Some(*i < l),
        _ => None,
    };

    let (fw_current, fw_available) = (
        field(&board, "current-firmware"),
        field(&board, "upgrade-firmware"),
    );
    let bootloader_behind = !fw_current.is_empty()
        && !fw_available.is_empty()
        && match (Version::parse(&fw_current), Version::parse(&fw_available)) {
            (Some(a), Some(b)) => a < b,
            _ => fw_current != fw_available,
        };

    if render::is_json() {
        render::print_json(&json!({
            "installed": installed_text,
            "channel": channel_text,
            "latest": latest,
            "behind": behind,
            "latestFrom": if current.items.is_some() { "upgrade.mikrotik.com" } else if !cached_latest.is_empty() { "the router's own last check" } else { "" },
            "lookupProvenance": current.provenance(),
            "routerboard": {
                "firmware": fw_current,
                "available": fw_available,
                "behind": bootloader_behind,
            },
            "packages": packages,
            "lookupSkipped": current.skipped,
            "lookupError": current.error,
            "unreadable": f.unreadable,
        }));
        return Ok(());
    }

    f.report();
    render::heading("RouterOS");
    render::pairs(&[
        ("installed", installed_text.clone()),
        (
            "channel",
            match channel {
                Some(ch) => ch.label().to_string(),
                None if channel_text.is_empty() => "unknown".to_string(),
                None => format!("{channel_text} (unrecognised)"),
            },
        ),
        (
            "current on that channel",
            match (&latest, current.skipped) {
                (Some(v), _) => format!("{v}  ({})", current.provenance()),
                (None, true) => "not looked up".to_string(),
                (None, false) => "unknown".to_string(),
            },
        ),
        (
            "verdict",
            match behind {
                Some(true) => "behind".to_string(),
                Some(false) => "up to date".to_string(),
                None => "cannot say".to_string(),
            },
        ),
    ]);

    if current.skipped {
        ui::info(
            "the current version was not looked up — add --allow-web to ask MikroTik from this machine",
        );
        println!(
            "  the router itself is never asked to check; that would make it contact MikroTik"
        );
    }
    if let Some(e) = &current.error {
        ui::warning(&format!("the version lookup failed: {e}"));
        println!(
            "  a failed lookup is not an up-to-date router — the verdict above says `cannot say`"
        );
    }
    if behind == Some(true) {
        println!();
        println!("  what changed between the two is in MikroTik's changelog, not here");
    }

    if !fw_current.is_empty() {
        render::heading("RouterBOARD bootloader");
        render::pairs(&[
            ("installed", fw_current.clone()),
            (
                "shipped with this RouterOS",
                if fw_available.is_empty() {
                    "unknown".to_string()
                } else {
                    fw_available.clone()
                },
            ),
            (
                "verdict",
                if bootloader_behind {
                    "behind".to_string()
                } else {
                    "up to date".to_string()
                },
            ),
        ]);
        if bootloader_behind {
            println!(
                "  /system routerboard upgrade, then a reboot — a RouterOS upgrade never moves it"
            );
        }
    }

    if !packages.is_empty() {
        render::heading("Packages");
        render::list(&packages, render::PACKAGE_COLS);
        render::count(packages.len(), "package");
    }

    Ok(())
}
