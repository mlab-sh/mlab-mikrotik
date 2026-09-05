//! One module per command.
//!
//! Each exposes a `run` taking whatever it needs — a [`Client`](crate::ros::Client)
//! and, when the command depends on the resolved connection, the
//! [`Ctx`](crate::cli::Ctx); nothing but its own arguments for the ones that
//! only touch the config file.

pub mod api;
pub mod audit;
pub mod blast;
pub mod clients;
pub mod diff;
pub mod exposure;
pub mod firewall;
pub mod footprint;
pub mod hunt;
pub mod info;
pub mod interfaces;
pub mod logging;
pub mod login;
pub mod network;
pub mod patch;
pub mod ping;
pub mod posture;
pub mod profile;
pub mod prompt;
pub mod settings;
pub mod shadow;
pub mod snapshot;
pub mod topology;
pub mod vuln;
pub mod whoami;
pub mod wifi;
