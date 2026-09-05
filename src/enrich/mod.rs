//! Everything that leaves this machine.
//!
//! Three lookups, each behind `--allow-web`, each cached on disk so a repeated
//! run costs nothing:
//!
//! * [`release`] asks MikroTik which version its channels are on. The call is
//!   made **from this machine**, never from the router — `/system/package/
//!   update/check-for-updates` would make the router itself phone home, and a
//!   passive audit does not change what a production router does on the wire.
//! * [`advisories`] asks vuln.mlab.sh which CVEs cover a version.
//! * [`netinfo`] asks mlab.sh what a public address looks like from outside.
//!
//! **What is sent:** a version string, a CPE, a public IP address. Never an
//! inventory, never a hostname, never anything from the configuration.

pub mod advisories;
pub mod netinfo;
pub mod release;

use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};

/// Where the caches live: `$HOME/.mlab/mikrotik/cache`.
pub fn cache_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_default();
    PathBuf::from(home)
        .join(".mlab")
        .join("mikrotik")
        .join("cache")
}

/// Read a cache file, or `None` when it is absent or unreadable. A corrupt
/// cache is never fatal: the caller refetches.
pub fn read_cache<T: serde::de::DeserializeOwned>(path: &PathBuf) -> Option<T> {
    serde_json::from_str(&fs::read_to_string(path).ok()?).ok()
}

/// Write a cache file, creating the directory at 0700 if needed.
pub fn write_cache<T: serde::Serialize>(path: &PathBuf, value: &T) -> Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        set_mode(dir, 0o700);
    }
    fs::write(path, serde_json::to_string(value)?)
        .with_context(|| format!("writing {}", path.display()))?;
    set_mode(path, 0o600);
    Ok(())
}

fn set_mode(path: &std::path::Path, mode: u32) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(mode));
    }
    #[cfg(not(unix))]
    let _ = (path, mode);
}

/// The mlab.sh API key, if this machine has one.
///
/// Read from `$HOME/.mlab/conf.yml`, which is where `mlab-cli` puts it, so the
/// suite shares one credential rather than each tool asking for its own. The
/// file has two keys and is parsed as such rather than by pulling in a YAML
/// crate for it. `MLAB_API_KEY` overrides.
pub fn mlab_key() -> Option<String> {
    if let Ok(k) = std::env::var("MLAB_API_KEY") {
        if !k.trim().is_empty() {
            return Some(k.trim().to_string());
        }
    }
    let home = std::env::var("HOME").ok()?;
    let raw = fs::read_to_string(PathBuf::from(home).join(".mlab").join("conf.yml")).ok()?;
    parse_conf(&raw, "api_key")
}

/// One `key: value` out of a two-key configuration file.
fn parse_conf(raw: &str, want: &str) -> Option<String> {
    for line in raw.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        let (k, v) = line.split_once(':')?;
        if k.trim() == want {
            let v = v.trim().trim_matches(['"', '\'']).to_string();
            return (!v.is_empty()).then_some(v);
        }
    }
    None
}

/// Seconds since the Unix epoch.
pub fn now() -> i64 {
    crate::ros::now()
}

/// One HTTP client for every outbound lookup, so the timeout and the
/// user agent are set once.
pub fn http() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .user_agent(concat!("mlab-mikrotik/", env!("CARGO_PKG_VERSION")))
        .build()
        .context("building the HTTP client for outbound lookups")
}

/// What a lookup produced, so the caller can be precise about it.
///
/// Four states, and a command that cannot tell them apart ends up printing
/// "no advisories" for a run that never left the machine — or, worse, showing
/// a cached answer as though it had just been fetched. Whichever one happened
/// is printed on screen; see [`Outcome::provenance`].
#[derive(Debug, Default)]
pub struct Outcome<T> {
    pub items: T,
    /// The answer came from the network, just now.
    pub fetched: bool,
    /// The answer came from a file this machine wrote earlier.
    pub cached: bool,
    /// Nothing was attempted, because `--allow-web` was not given and the
    /// cache had nothing fresh.
    pub skipped: bool,
    /// How old the cached answer is, in seconds.
    pub age: Option<i64>,
    pub error: Option<String>,
}

impl<T> Outcome<T> {
    /// Where this answer came from, in words, for the reader.
    ///
    /// A cached answer is served whether or not `--allow-web` was passed —
    /// the flag gates the *network*, not data already on this disk — so it
    /// has to be labelled, or the same command appears to behave differently
    /// on two consecutive runs for no visible reason.
    pub fn provenance(&self) -> String {
        let age = self.age;
        if self.error.is_some() {
            return "the lookup failed".to_string();
        }
        if self.fetched {
            return "looked up just now".to_string();
        }
        if self.cached {
            return match age {
                Some(a) => format!("from cache, {}", ago(a)),
                None => "from cache".to_string(),
            };
        }
        "not looked up".to_string()
    }
}

/// How long ago, in the roughest useful terms.
pub fn ago(seconds: i64) -> String {
    match seconds {
        s if s < 90 => "just now".to_string(),
        s if s < 5400 => format!("{} minutes old", s / 60),
        s if s < 172_800 => format!("{} hours old", s / 3600),
        s => format!("{} days old", s / 86_400),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_cached_answer_says_so_rather_than_passing_for_a_fresh_one() {
        let cached = Outcome::<()> {
            cached: true,
            age: Some(300),
            ..Default::default()
        };
        assert_eq!(cached.provenance(), "from cache, 5 minutes old");

        let fresh = Outcome::<()> {
            fetched: true,
            ..Default::default()
        };
        assert_eq!(fresh.provenance(), "looked up just now");

        let nothing = Outcome::<()> {
            skipped: true,
            ..Default::default()
        };
        assert_eq!(nothing.provenance(), "not looked up");

        let broken = Outcome::<()> {
            error: Some("boom".into()),
            ..Default::default()
        };
        assert_eq!(broken.provenance(), "the lookup failed");
    }

    #[test]
    fn an_age_reads_at_the_scale_that_matters() {
        assert_eq!(ago(5), "just now");
        assert_eq!(ago(300), "5 minutes old");
        assert_eq!(ago(7200), "2 hours old");
        assert_eq!(ago(200_000), "2 days old");
    }

    #[test]
    fn the_two_key_config_file_parses() {
        let raw = "hostname: mlab.sh\napi_key: abc123\n";
        assert_eq!(parse_conf(raw, "api_key").as_deref(), Some("abc123"));
        assert_eq!(parse_conf(raw, "hostname").as_deref(), Some("mlab.sh"));
        assert_eq!(parse_conf(raw, "nope"), None);
    }

    #[test]
    fn quotes_and_blank_values_are_handled() {
        assert_eq!(
            parse_conf("api_key: \"quoted\"", "api_key").as_deref(),
            Some("quoted")
        );
        assert_eq!(parse_conf("api_key:", "api_key"), None);
        assert_eq!(parse_conf("api_key:   ", "api_key"), None);
    }
}
