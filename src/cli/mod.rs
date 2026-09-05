//! The command line surface, and the dispatch behind it.
//!
//! Adding a command means: a module under [`crate::commands`], a variant in
//! [`Cmd`], and one arm in [`run`].

mod context;

pub use context::{Ctx, Overrides};

use anyhow::{Context as _, Result};
use clap::{Parser, Subcommand};

use crate::commands;
use crate::ros::{config, Client};
use crate::ui::{self, render};

#[derive(Parser, Debug)]
#[command(
    name = "mlab-mikrotik",
    version,
    about = "Talk to a MikroTik router over the RouterOS REST API",
    long_about = "Talk to a MikroTik router over the RouterOS REST API.\n\n\
                  Connection settings live as named instances in \
                  $HOME/.mlab/mikrotik.conf; run `mlab-mikrotik login` once to create \
                  one. Flags override environment variables (MLAB_MIKROTIK_* then \
                  MIKROTIK_*), which override the stored instance.",
    after_help = "The REST API needs RouterOS 7.1 or later with the www-ssl service on:\n  \
                  /ip service enable www-ssl\n\n\
                  Give the login its own user, in a group holding the `rest-api`,\n\
                  `api` and `read` policies rather than `full`."
)]
pub struct Cli {
    /// Instance to use (default: the one marked default in the config)
    #[arg(long, short = 'p', global = true, value_name = "NAME")]
    pub profile: Option<String>,

    /// Router hostname or host:port
    #[arg(long, global = true, value_name = "HOST")]
    pub host: Option<String>,

    /// RouterOS user
    #[arg(long, short = 'u', global = true, value_name = "USER")]
    pub user: Option<String>,

    /// Password; prefer MIKROTIK_PASSWORD, a command line is visible to other users
    #[arg(long, global = true, value_name = "PASSWORD")]
    pub password: Option<String>,

    /// Which REST service to reach
    #[arg(long, global = true, value_parser = ["https", "http"], value_name = "SCHEME")]
    pub scheme: Option<String>,

    /// Output format: a terminal render, or raw JSON for scripting
    #[arg(long, short = 'o', global = true, value_parser = ["human", "json"], value_name = "FORMAT")]
    pub output: Option<String>,

    /// Silence progress and status lines on stderr
    #[arg(long, short = 'q', global = true)]
    pub quiet: bool,

    /// Per-request timeout, in seconds
    #[arg(long, global = true, default_value_t = 30, value_name = "SECS")]
    pub timeout: u64,

    /// Skip TLS certificate verification (the default over https)
    #[arg(long, global = true, conflicts_with = "secure")]
    pub insecure: bool,

    /// Verify the router's TLS certificate
    #[arg(long, global = true)]
    pub secure: bool,

    #[command(subcommand)]
    pub command: Cmd,
}

#[derive(Subcommand, Debug)]
pub enum Cmd {
    /// Create or update an instance, test it, and save it to the config file
    #[command(alias = "configure", alias = "setup", alias = "add")]
    Login(commands::login::LoginArgs),

    /// Manage saved instances
    #[command(alias = "instance", alias = "instances")]
    Profile {
        #[command(subcommand)]
        cmd: commands::profile::ProfileCmd,
    },

    /// Inspect the config file
    Config {
        #[command(subcommand)]
        cmd: commands::settings::ConfigCmd,
    },

    /// Check that the current instance can reach its router
    Ping,

    /// What this account is, and everything it is allowed to read
    Whoami,

    /// What this router is: software, hardware, licence, health
    Info,

    /// The ports: state, addresses, and what is dropping packets
    #[command(alias = "interface", alias = "ports")]
    Interfaces(commands::interfaces::InterfaceArgs),

    /// What the router knows about who is on the network
    #[command(alias = "hosts")]
    Clients(commands::clients::ClientArgs),

    /// Addresses, bridges, VLANs, DHCP and routes
    #[command(alias = "net")]
    Network {
        #[command(subcommand)]
        cmd: Option<commands::network::NetworkCmd>,
    },

    /// The neighbours this router can hear, and what it announces itself
    #[command(alias = "neighbors", alias = "neighbours")]
    Topology,

    /// The firewall rules, and whether each chain closes
    #[command(alias = "fw")]
    Firewall(commands::firewall::FirewallArgs),

    /// What this router offers to anything that can reach it
    #[command(alias = "exposed")]
    Exposure,

    /// The radios, their security, and who is associated
    #[command(alias = "wireless")]
    Wifi,

    /// The settings that claim to defend something
    Posture,

    /// Every graded check in one report
    Audit(commands::audit::AuditArgs),

    /// One dated, secret-free record of everything this account can read
    Snapshot(commands::snapshot::SnapshotArgs),

    /// What changed between two snapshots
    Diff(commands::diff::DiffArgs),

    /// What turned up on this router that nobody announced
    Shadow(commands::shadow::ShadowArgs),

    /// How far behind this router is, in RouterOS and in its bootloader
    Patch(commands::patch::PatchArgs),

    /// The published advisories that cover this exact version
    #[command(alias = "cve")]
    Vuln(commands::vuln::VulnArgs),

    /// What this router looks like from outside
    Footprint(commands::footprint::FootprintArgs),

    /// The markers a compromised MikroTik router leaves behind
    Hunt(commands::hunt::HuntArgs),

    /// Where the log goes, and what never reaches it
    #[command(alias = "logs")]
    Logging,

    /// What a compromised host on one segment reaches
    Blast(commands::blast::BlastArgs),

    /// Raw request against any menu, for what is not wrapped yet
    #[command(after_help = "PATH is a RouterOS menu, relative to /rest.\n\n\
                      Examples:\n  \
                      mlab-mikrotik api GET /system/resource\n  \
                      mlab-mikrotik api GET /ip/address --list\n  \
                      mlab-mikrotik api GET /interface --list --props name,type,running\n  \
                      mlab-mikrotik api GET /ip/firewall/filter --list --limit 20")]
    Api(commands::api::ApiArgs),
}

/// Parse, set up output, then hand over to a command.
pub async fn run() -> Result<()> {
    let cli = Cli::parse();
    ui::init(cli.quiet);
    // Resolved again from the instance in `Ctx::build` when neither the flag
    // nor the environment picked a format.
    render::init(cli.output.as_deref().or(config::env("OUTPUT").as_deref()));

    // Commands that only touch the config file need no connection.
    match &cli.command {
        Cmd::Login(args) => return commands::login::run(&Overrides::from(&cli), args).await,
        Cmd::Profile { cmd } => return commands::profile::run(cmd),
        Cmd::Config { cmd } => return commands::settings::run(cmd),
        _ => {}
    }

    if let Some(w) = config::perms_warning() {
        ui::warning(&w);
    }

    let ctx = Ctx::build(&cli)?;
    let c = Client::new(&ctx.profile, ctx.timeout)
        .with_context(|| format!("instance {:?}", ctx.name))?;

    match cli.command {
        Cmd::Login(_) | Cmd::Profile { .. } | Cmd::Config { .. } => unreachable!(),
        Cmd::Ping => commands::ping::run(&c, &ctx).await,
        Cmd::Whoami => commands::whoami::run(&c, &ctx).await,
        Cmd::Info => commands::info::run(&c).await,
        Cmd::Interfaces(a) => commands::interfaces::run(&c, &a).await,
        Cmd::Clients(a) => commands::clients::run(&c, &a).await,
        Cmd::Network { cmd } => commands::network::run(&c, cmd).await,
        Cmd::Topology => commands::topology::run(&c).await,
        Cmd::Firewall(a) => commands::firewall::run(&c, &a).await,
        Cmd::Exposure => commands::exposure::run(&c).await,
        Cmd::Wifi => commands::wifi::run(&c).await,
        Cmd::Posture => commands::posture::run(&c).await,
        Cmd::Audit(a) => commands::audit::run(&c, &a).await,
        Cmd::Snapshot(a) => commands::snapshot::run(&c, &ctx, &a).await,
        Cmd::Diff(a) => commands::diff::run(&ctx, &a).await,
        Cmd::Shadow(a) => commands::shadow::run(&c, &ctx, &a).await,
        Cmd::Patch(a) => commands::patch::run(&c, &a).await,
        Cmd::Vuln(a) => commands::vuln::run(&c, &a).await,
        Cmd::Footprint(a) => commands::footprint::run(&c, &a).await,
        Cmd::Hunt(a) => commands::hunt::run(&c, &a).await,
        Cmd::Logging => commands::logging::run(&c).await,
        Cmd::Blast(a) => commands::blast::run(&c, &a).await,
        Cmd::Api(a) => commands::api::run(&c, a).await,
    }
}
