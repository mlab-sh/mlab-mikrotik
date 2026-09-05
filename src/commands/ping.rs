//! `ping` — can this instance reach its router, and what is on the other end.

use anyhow::Result;

use crate::cli::Ctx;
use crate::ros::{field, Client, Scheme};
use crate::ui::{self, render};

pub async fn run(c: &Client, ctx: &Ctx) -> Result<()> {
    let started = std::time::Instant::now();
    let resource = ui::spin("Reaching the router", c.get_one("/system/resource")).await?;
    let identity = ui::spin("Reading the identity", c.get_one("/system/identity")).await?;
    let took = ui::elapsed(started.elapsed());

    let tls_verified = !ctx.profile.insecure() && ctx.profile.scheme == Scheme::Https;

    if render::is_json() {
        render::print_json(&serde_json::json!({
            "instance": ctx.name,
            "endpoint": c.base(),
            "identity": field(&identity, "name"),
            "version": field(&resource, "version"),
            "boardName": field(&resource, "board-name"),
            "uptime": field(&resource, "uptime"),
            "tlsVerified": tls_verified,
            "elapsed": took,
        }));
        return Ok(());
    }

    ui::success(&format!("answered in {took}"));
    render::pairs(&[
        ("instance", ctx.name.clone()),
        ("endpoint", c.base().to_string()),
        ("identity", field(&identity, "name")),
        (
            "routeros",
            format!(
                "{} on {}",
                field(&resource, "version"),
                field(&resource, "board-name")
            ),
        ),
        ("uptime", field(&resource, "uptime")),
        (
            "tls",
            match ctx.profile.scheme {
                Scheme::Http => "none (plain http)".to_string(),
                Scheme::Https if tls_verified => "verified".to_string(),
                Scheme::Https => "not verified".to_string(),
            },
        ),
    ]);
    Ok(())
}
