//! `info` — what this router is: software, hardware, licence, health.

use anyhow::Result;
use serde_json::Value;

use crate::collect::Fetcher;
use crate::ros::{bytes, field, num, Client};
use crate::ui::render;

pub async fn run(c: &Client) -> Result<()> {
    let mut f = Fetcher::new(c);

    let identity = f.get("/system/identity").await;
    let resource = f.get("/system/resource").await;
    let board = f.get("/system/routerboard").await;
    let license = f.get("/system/license").await;
    let clock = f.get("/system/clock").await;
    let health = f.list("/system/health").await;
    let packages = f.list("/system/package").await;

    if render::is_json() {
        render::print_json(&serde_json::json!({
            "identity": identity,
            "resource": resource,
            "routerboard": board,
            "license": license,
            "clock": clock,
            "health": health,
            "packages": packages,
            "unreadable": f.unreadable,
        }));
        return Ok(());
    }

    f.report();

    render::heading(&format!(
        "{} — RouterOS {}",
        match field(&identity, "name").as_str() {
            "" => "this router".to_string(),
            n => n.to_string(),
        },
        field(&resource, "version")
    ));

    render::pairs(&[
        (
            "model",
            crate::ros::first_field(&board, &["model", "board-name"]),
        ),
        ("architecture", field(&resource, "architecture-name")),
        ("cpu", cpu(&resource)),
        ("memory", memory(&resource)),
        ("storage", storage(&resource)),
        ("uptime", field(&resource, "uptime")),
        ("built", field(&resource, "build-time")),
        (
            "clock",
            format!(
                "{} {} ({})",
                field(&clock, "date"),
                field(&clock, "time"),
                field(&clock, "time-zone-name")
            ),
        ),
        ("licence", licence(&license)),
    ]);

    // The bootloader is versioned separately from RouterOS and does not move
    // with it: on the hardware tested, an up-to-date 7.24 was still running a
    // 7.12 bootloader. Two fields, side by side, so the gap is visible.
    let (current, upgrade) = (
        field(&board, "current-firmware"),
        field(&board, "upgrade-firmware"),
    );
    if !current.is_empty() {
        render::heading("RouterBOARD");
        render::pairs(&[
            ("serial", field(&board, "serial-number")),
            ("revision", field(&board, "revision")),
            ("firmware", current.clone()),
            (
                "firmware available",
                if upgrade.is_empty() || upgrade == current {
                    "up to date".to_string()
                } else {
                    upgrade
                },
            ),
        ]);
    }

    let installed: Vec<&Value> = packages
        .iter()
        .filter(|p| !crate::ros::flag(p, "disabled"))
        .collect();
    if !installed.is_empty() {
        render::heading("Packages");
        let rows: Vec<Value> = installed.iter().map(|p| (*p).clone()).collect();
        render::list(&rows, render::PACKAGE_COLS);
        render::count(rows.len(), "package");
    }

    let measured: Vec<Value> = health
        .iter()
        .filter(|h| !field(h, "value").is_empty())
        .cloned()
        .collect();
    if !measured.is_empty() {
        render::heading("Health");
        render::list(&measured, render::HEALTH_COLS);
    }

    Ok(())
}

fn cpu(r: &Value) -> String {
    let count = field(r, "cpu-count");
    let mhz = field(r, "cpu-frequency");
    let load = num(r, "cpu-load")
        .map(|l| format!(", {l:.0}% load"))
        .unwrap_or_default();
    let mut s = field(r, "cpu");
    if !count.is_empty() {
        s.push_str(&format!(" ×{count}"));
    }
    if !mhz.is_empty() {
        s.push_str(&format!(" @ {mhz} MHz"));
    }
    s.push_str(&load);
    s.trim().to_string()
}

fn memory(r: &Value) -> String {
    match (num(r, "free-memory"), num(r, "total-memory")) {
        (Some(free), Some(total)) if total > 0.0 => format!(
            "{} free of {} ({:.0}% used)",
            bytes(free),
            bytes(total),
            (total - free) / total * 100.0
        ),
        _ => String::new(),
    }
}

fn storage(r: &Value) -> String {
    match (num(r, "free-hdd-space"), num(r, "total-hdd-space")) {
        (Some(free), Some(total)) if total > 0.0 => {
            format!("{} free of {}", bytes(free), bytes(total))
        }
        _ => String::new(),
    }
}

/// The licence line. `nlevel` is the number every MikroTik document calls
/// "level"; a CHR or an x86 install has a `software-id` and no level at all.
fn licence(l: &Value) -> String {
    let level = crate::ros::first_field(l, &["nlevel", "level"]);
    let id = field(l, "software-id");
    match (level.is_empty(), id.is_empty()) {
        (true, true) => String::new(),
        (false, true) => format!("level {level}"),
        (true, false) => id,
        (false, false) => format!("level {level} ({id})"),
    }
}
