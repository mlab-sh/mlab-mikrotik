//! `login` — create or update an instance, prove it works, save it.

use std::io::IsTerminal;
use std::time::Duration;

use anyhow::{bail, Result};
use clap::Args;

use crate::cli::Overrides;
use crate::commands::prompt::{ask, ask_secret};
use crate::ros::{config, field, Client, Profile, Scheme};
use crate::ui::{self, render};

#[derive(Args, Debug)]
pub struct LoginArgs {
    /// Instance name to create or update
    #[arg(long, short = 'n', default_value = "default", value_name = "NAME")]
    pub name: String,

    /// Make this instance the default one
    #[arg(long)]
    pub set_default: bool,

    /// Save without checking that the credentials work
    #[arg(long)]
    pub no_test: bool,

    /// Never prompt; fail when something is missing
    #[arg(long)]
    pub non_interactive: bool,
}

pub async fn run(ov: &Overrides, args: &LoginArgs) -> Result<()> {
    let mut cfg = config::load()?;
    let existing = cfg.profiles.get(&args.name).cloned();
    let base = existing.clone().unwrap_or_default();
    let interactive = !args.non_interactive && std::io::stdin().is_terminal();

    let scheme: Scheme = match ov.scheme.clone().or_else(|| config::env("SCHEME")) {
        Some(s) => s.parse()?,
        None if existing.is_some() => base.scheme,
        None => Scheme::Https,
    };

    let mut host = ov
        .host
        .clone()
        .or_else(|| config::env("HOST"))
        .unwrap_or_else(|| base.host.clone());
    if host.is_empty() {
        if !interactive {
            bail!("--host is required");
        }
        host = ask("router host (e.g. 192.168.88.1 or gw.lan)", "")?;
    }
    host = config::normalize_host(&host)?;

    let mut user = ov
        .user
        .clone()
        .or_else(|| config::env("USER"))
        .unwrap_or_else(|| base.user.clone());
    if user.is_empty() {
        if !interactive {
            bail!("--user or MIKROTIK_USER is required");
        }
        user = ask("RouterOS user", "admin")?;
    }

    let password = password(ov, &base, interactive)?;

    let p = Profile {
        host,
        user,
        password,
        scheme,
        insecure: ov.insecure.or(base.insecure),
        output: ov.output.clone().or(base.output.clone()),
    };
    p.validate()?;

    if args.no_test {
        ui::warning("skipping the connection test (--no-test)");
    } else {
        verify(&p).await?;
    }

    let first = cfg.profiles.is_empty();
    cfg.profiles.insert(args.name.clone(), p.clone());
    if args.set_default || first || cfg.default_profile.is_none() {
        cfg.default_profile = Some(args.name.clone());
    }
    config::save(&cfg)?;

    ui::success(&format!(
        "saved instance {:?} to {}",
        args.name,
        config::path().display()
    ));
    render::one(&serde_json::to_value(p.redacted())?);
    Ok(())
}

/// A password from the flags, the environment, the stored instance, or the
/// terminal. An empty one is a real RouterOS login, so it is allowed through
/// with a warning rather than refused.
fn password(ov: &Overrides, base: &Profile, interactive: bool) -> Result<String> {
    let mut pass = ov
        .password
        .clone()
        .or_else(|| config::env("PASSWORD"))
        .unwrap_or_default();

    if pass.is_empty() {
        if !base.password.is_empty() {
            ui::info("keeping the stored password");
            pass = base.password.clone();
        } else if interactive {
            pass = ask_secret("password (empty for a router with none)")?;
        }
    }

    if pass.is_empty() {
        ui::warning("this login has no password");
    }
    Ok(pass)
}

/// Prove the instance works before it is written.
async fn verify(p: &Profile) -> Result<()> {
    let c = Client::new(p, Duration::from_secs(30))?;

    let resource = ui::spin(
        &format!("Testing {}", c.base()),
        c.get_one("/system/resource"),
    )
    .await?;
    let identity = ui::spin("Reading the identity", c.get_one("/system/identity")).await?;

    ui::success(&format!(
        "connected to {} — RouterOS {} on {}",
        match field(&identity, "name").as_str() {
            "" => "the router".to_string(),
            n => n.to_string(),
        },
        field(&resource, "version"),
        field(&resource, "board-name"),
    ));

    if p.insecure() {
        ui::warning("TLS certificate verification is off for this instance");
    }
    if p.scheme == Scheme::Http {
        ui::warning("plain http: the password crosses the network in the clear");
    }
    Ok(())
}
