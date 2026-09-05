//! `api` — the raw handler, for every menu the CLI does not wrap.
//!
//! This is the lab bench: try a menu here, and once it earns its place, give
//! it a module of its own next to this one.
//!
//! It is also the only command that can send anything but a GET. That is
//! deliberate and it is guarded: RouterOS maps `PATCH` to `set`, `PUT` to
//! `add` and `DELETE` to `remove`, so anything other than GET changes a live
//! router and has to be asked for twice.

use anyhow::{bail, Context, Result};
use clap::Args;
use reqwest::Method;
use serde_json::Value;

use crate::ros::Client;
use crate::ui::{self, render};

#[derive(Args, Debug)]
pub struct ApiArgs {
    /// HTTP method: GET, POST, PATCH, PUT, DELETE
    pub method: String,
    /// Menu path relative to /rest, e.g. /ip/address
    pub path: String,
    /// JSON body: inline, @file, or - for stdin
    #[arg(long, short = 'd', value_name = "JSON")]
    pub data: Option<String>,
    /// Extra query parameter, repeatable: --query key=value
    // No short form: `-q` is the global --quiet, and clap refuses the clash.
    #[arg(long, value_name = "K=V")]
    pub query: Vec<String>,
    /// Only these properties, comma-separated — RouterOS `.proplist`
    #[arg(long, value_name = "A,B,C")]
    pub props: Option<String>,
    /// Render an array response as a table instead of a block
    #[arg(long)]
    pub list: bool,
    /// With --list, stop after this many rows
    #[arg(long, value_name = "N")]
    pub limit: Option<u32>,
    /// Required for any method that is not GET
    #[arg(long)]
    pub write: bool,
}

pub async fn run(c: &Client, a: ApiArgs) -> Result<()> {
    let method = Method::from_bytes(a.method.to_ascii_uppercase().as_bytes())
        .with_context(|| format!("{:?} is not an HTTP method", a.method))?;

    if method != Method::GET && !a.write {
        bail!(
            "{method} changes the router; pass --write to allow it\n\
             hint: on RouterOS, PATCH is `set`, PUT is `add`, DELETE is `remove`, \
             and POST runs an arbitrary console command"
        );
    }

    let mut path = a.path.clone();
    if !path.starts_with('/') {
        path.insert(0, '/');
    }
    // A path pasted from the documentation, or from a terminal session, tends
    // to carry the prefix already.
    if let Some(rest) = path.strip_prefix("/rest") {
        path = rest.to_string();
    }

    let mut query = Vec::new();
    for kv in &a.query {
        let (k, v) = kv
            .split_once('=')
            .with_context(|| format!("--query expects key=value, got {kv:?}"))?;
        query.push((k.to_string(), v.to_string()));
    }
    if let Some(props) = &a.props {
        query.push((".proplist".to_string(), props.clone()));
    }

    let body = match &a.data {
        None => None,
        Some(d) => Some(read_json(d)?),
    };

    let label = format!("{method} {path}");
    if method != Method::GET {
        ui::warning(&format!("{label} — this changes the router"));
    }
    let v = ui::spin(&label, c.request(method, &path, &query, body.as_ref())).await?;

    if a.list {
        let Value::Array(mut rows) = v else {
            bail!("--list needs an array response; this menu answered with a single object");
        };
        if let Some(n) = a.limit {
            rows.truncate(n as usize);
        }
        render::heading(&label);
        render::list_auto(&rows);
        render::count(rows.len(), "row");
        return Ok(());
    }

    render::one(&v);
    Ok(())
}

/// Read a JSON body from an inline string, `@file`, or `-` (stdin).
fn read_json(spec: &str) -> Result<Value> {
    let raw = if spec == "-" {
        use std::io::Read;
        let mut s = String::new();
        std::io::stdin()
            .read_to_string(&mut s)
            .context("reading the body from stdin")?;
        s
    } else if let Some(file) = spec.strip_prefix('@') {
        std::fs::read_to_string(file).with_context(|| format!("reading {file}"))?
    } else {
        spec.to_string()
    };
    serde_json::from_str(&raw).context("the request body is not valid JSON")
}
