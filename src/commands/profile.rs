//! `profile` — list, inspect, select and delete saved instances.

use anyhow::{bail, Result};
use clap::Subcommand;
use serde_json::Value;

use crate::ros::{config, Scheme};
use crate::ui::{self, render};

#[derive(Subcommand, Debug)]
pub enum ProfileCmd {
    /// List saved instances
    #[command(alias = "ls")]
    List,
    /// Show one instance, with the password masked
    Show {
        /// Instance name (default: the default one)
        name: Option<String>,
    },
    /// Set the default instance
    Use { name: String },
    /// Delete an instance
    #[command(alias = "rm", alias = "delete")]
    Remove { name: String },
}

pub fn run(cmd: &ProfileCmd) -> Result<()> {
    let mut cfg = config::load()?;

    match cmd {
        ProfileCmd::List => list(&cfg),
        ProfileCmd::Show { name } => {
            let (name, p) = cfg.profile(name.as_deref())?;
            render::heading(&format!("Instance {name}"));
            render::one(&serde_json::to_value(p.redacted())?);
            Ok(())
        }
        ProfileCmd::Use { name } => {
            if !cfg.profiles.contains_key(name) {
                bail!("instance {name:?} does not exist");
            }
            cfg.default_profile = Some(name.clone());
            config::save(&cfg)?;
            ui::success(&format!("default instance is now {name:?}"));
            Ok(())
        }
        ProfileCmd::Remove { name } => {
            if cfg.profiles.remove(name).is_none() {
                bail!("instance {name:?} does not exist");
            }
            // Leaving a dangling default would make every later command fail
            // with "not found" rather than fall back to what is left.
            if cfg.default_profile.as_deref() == Some(name.as_str()) {
                cfg.default_profile = cfg.profiles.keys().next().cloned();
            }
            config::save(&cfg)?;
            ui::success(&format!("removed instance {name:?}"));
            Ok(())
        }
    }
}

fn list(cfg: &config::ConfigFile) -> Result<()> {
    if cfg.profiles.is_empty() {
        if render::is_json() {
            render::print_json(&serde_json::json!([]));
        } else {
            ui::warning("no instance yet; run `mlab-mikrotik login`");
        }
        return Ok(());
    }

    let rows: Vec<Value> = cfg
        .profiles
        .iter()
        .map(|(name, p)| {
            serde_json::json!({
                "name": name,
                "default": cfg.default_profile.as_deref() == Some(name),
                "target": format!("{}://{}", p.scheme, p.host),
                "user": p.user,
                "tls": match p.scheme {
                    Scheme::Http => "none",
                    Scheme::Https if p.insecure() => "not verified",
                    Scheme::Https => "verified",
                },
            })
        })
        .collect();

    render::list(&rows, render::PROFILE_COLS);
    render::count(rows.len(), "instance");
    Ok(())
}
