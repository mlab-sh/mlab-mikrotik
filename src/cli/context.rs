//! Turning flags, environment and config file into one resolved connection.

use std::time::Duration;

use anyhow::Result;

use crate::cli::Cli;
use crate::ros::{config, Profile};
use crate::ui::render;

/// Settings a flag may override on top of a stored instance. Kept apart from
/// [`Cli`] so the login wizard can take the same shape without clap in scope.
#[derive(Debug, Default)]
pub struct Overrides {
    pub host: Option<String>,
    pub user: Option<String>,
    pub password: Option<String>,
    pub scheme: Option<String>,
    pub output: Option<String>,
    pub insecure: Option<bool>,
}

impl From<&Cli> for Overrides {
    fn from(cli: &Cli) -> Self {
        Overrides {
            host: cli.host.clone(),
            user: cli.user.clone(),
            password: cli.password.clone(),
            scheme: cli.scheme.clone(),
            output: cli.output.clone(),
            // Two flags for one tri-state, so an instance's `insecure: true`
            // can be turned off from the command line.
            insecure: if cli.insecure {
                Some(true)
            } else if cli.secure {
                Some(false)
            } else {
                None
            },
        }
    }
}

/// The resolved connection settings for this invocation.
pub struct Ctx {
    pub name: String,
    pub profile: Profile,
    pub timeout: Duration,
}

impl Ctx {
    /// Resolve the instance for this run: file, then environment, then flags.
    pub fn build(cli: &Cli) -> Result<Ctx> {
        let cfg = config::load()?;
        let ov = Overrides::from(cli);

        let (name, mut p) = match cfg.profile(cli.profile.as_deref()) {
            Ok(found) => found,
            Err(e) => {
                // Usable with no config file at all when everything is given.
                let has_host = ov.host.is_some() || config::env("HOST").is_some();
                if cli.profile.is_none() && has_host {
                    ("(flags)".to_string(), Profile::default())
                } else {
                    return Err(e);
                }
            }
        };

        if let Some(v) = config::env("SCHEME") {
            p.scheme = v.parse()?;
        }
        if let Some(v) = config::env("HOST") {
            p.host = v;
        }
        if let Some(v) = config::env("USER") {
            p.user = v;
        }
        if let Some(v) = config::env("PASSWORD") {
            p.password = v;
        }
        if let Some(v) = config::env_bool("INSECURE") {
            p.insecure = Some(v);
        }

        if let Some(v) = &ov.scheme {
            p.scheme = v.parse()?;
        }
        if let Some(v) = &ov.host {
            p.host = v.clone();
        }
        if let Some(v) = &ov.user {
            p.user = v.clone();
        }
        if let Some(v) = &ov.password {
            p.password = v.clone();
        }
        if let Some(v) = ov.insecure {
            p.insecure = Some(v);
        }

        // The flag and the environment were applied at startup; an instance's
        // own preference only speaks when neither of them did.
        if ov.output.is_none() && config::env("OUTPUT").is_none() {
            render::init(p.output.as_deref());
        }

        Ok(Ctx {
            name,
            profile: p,
            timeout: Duration::from_secs(cli.timeout.max(1)),
        })
    }
}
