//! Config storage for the `mlab-mikrotik` CLI.
//!
//! One file, `$HOME/.mlab/mikrotik.conf` (JSON), holding any number of named
//! instances plus the name of the default one. Written 0600 inside a 0700 dir:
//! RouterOS has no API token, so what is stored is a real login password.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

/// How the REST service is reached.
///
/// RouterOS serves `/rest` from two separate services: `www-ssl` on 443 with a
/// certificate the router generated for itself, and `www` on 80 with no
/// transport security at all. Which one is on is a per-device decision, so it
/// belongs in the profile rather than being guessed per request.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum Scheme {
    #[default]
    Https,
    Http,
}

impl std::fmt::Display for Scheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Scheme::Https => "https",
            Scheme::Http => "http",
        })
    }
}

impl std::str::FromStr for Scheme {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "https" | "ssl" | "www-ssl" | "tls" => Ok(Scheme::Https),
            "http" | "www" | "plain" => Ok(Scheme::Http),
            other => bail!("unknown scheme {other:?} (expected \"https\" or \"http\")"),
        }
    }
}

/// Connection parameters for one RouterOS instance.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Profile {
    /// Hostname or `host:port` of the router.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub host: String,
    /// RouterOS user. Give it a group with `api`, `rest-api` and `read`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub user: String,
    /// That user's password. Stored as typed: RouterOS Basic auth sends the
    /// password itself on every request, so nothing weaker would work.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub password: String,
    #[serde(default)]
    pub scheme: Scheme,
    /// Tri-state: `None` means "use the scheme default" (see [`Profile::insecure`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub insecure: Option<bool>,
    /// `json`; `None` means the global default (a terminal render).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output: Option<String>,
}

impl Profile {
    /// Effective TLS behaviour. A router's REST certificate is the one it
    /// generated for itself, so verification is off by default; over plain
    /// HTTP the question does not arise.
    pub fn insecure(&self) -> bool {
        match self.scheme {
            Scheme::Https => self.insecure.unwrap_or(true),
            Scheme::Http => false,
        }
    }

    /// `https://host`, the root `/rest` hangs off.
    pub fn root(&self) -> Result<String> {
        Ok(format!("{}://{}", self.scheme, normalize_host(&self.host)?))
    }

    /// Reject a profile that cannot produce a request.
    pub fn validate(&self) -> Result<()> {
        if self.host.is_empty() {
            bail!("host is missing (set --host, MIKROTIK_HOST, or run `mlab-mikrotik login`)");
        }
        normalize_host(&self.host)?;
        if self.user.is_empty() {
            bail!("user is missing (set --user, MIKROTIK_USER, or run `mlab-mikrotik login`)");
        }
        Ok(())
    }

    /// A copy with the password masked, for printing.
    pub fn redacted(&self) -> Profile {
        let mut p = self.clone();
        p.password = redact(&self.password);
        p
    }
}

/// Mask a password.
///
/// Unlike an API key, a password is short and human-chosen, so no part of it
/// is safe to echo: even its length narrows a guess. Either it is set or it
/// is not, and that is all this says.
pub fn redact(password: &str) -> String {
    if password.is_empty() {
        String::new()
    } else {
        "********".to_string()
    }
}

/// Canonicalize a router host: strip any scheme and trailing slashes, reject a
/// value carrying a path, query, fragment, or whitespace.
pub fn normalize_host(h: &str) -> Result<String> {
    let mut s = h.trim();
    if let Some(i) = s.find("://") {
        s = &s[i + 3..];
    }
    let s = s.trim_end_matches('/');
    if s.is_empty() {
        bail!("host is empty");
    }
    if s.contains(['/', '?', '#', ' ', '\t', '\r', '\n']) {
        bail!("host {h:?} must be a hostname or host:port, without a path");
    }
    Ok(s.to_string())
}

/// The whole config file.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct ConfigFile {
    /// Name of the instance used when `--profile` is not given.
    #[serde(rename = "default", default, skip_serializing_if = "Option::is_none")]
    pub default_profile: Option<String>,
    #[serde(default)]
    pub profiles: BTreeMap<String, Profile>,
}

impl ConfigFile {
    /// Resolve `name` (or the default instance when `None`).
    pub fn profile(&self, name: Option<&str>) -> Result<(String, Profile)> {
        let wanted = match name {
            Some(n) => n.to_string(),
            None => match &self.default_profile {
                Some(d) => d.clone(),
                None if self.profiles.len() == 1 => self.profiles.keys().next().unwrap().clone(),
                _ => bail!("no instance selected and no default set; run `mlab-mikrotik login`"),
            },
        };
        match self.profiles.get(&wanted) {
            Some(p) => Ok((wanted, p.clone())),
            None => bail!(
                "instance {wanted:?} not found in {} (known: {})",
                path().display(),
                if self.profiles.is_empty() {
                    "none".to_string()
                } else {
                    self.profiles.keys().cloned().collect::<Vec<_>>().join(", ")
                }
            ),
        }
    }
}

/// `$MLAB_MIKROTIK_CONFIG`, else `$HOME/.mlab/mikrotik.conf`.
pub fn path() -> PathBuf {
    if let Ok(p) = std::env::var("MLAB_MIKROTIK_CONFIG") {
        if !p.is_empty() {
            return PathBuf::from(p);
        }
    }
    let home = std::env::var("HOME").unwrap_or_default();
    PathBuf::from(home).join(".mlab").join("mikrotik.conf")
}

/// Read the config file. A missing file is an empty config, not an error.
pub fn load() -> Result<ConfigFile> {
    let p = path();
    let data = match fs::read_to_string(&p) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(ConfigFile::default()),
        Err(e) => return Err(e).with_context(|| format!("reading {}", p.display())),
    };
    if data.trim().is_empty() {
        return Ok(ConfigFile::default());
    }
    serde_json::from_str(&data).with_context(|| format!("parsing {}", p.display()))
}

/// Write the config file, 0600 in a 0700 directory.
pub fn save(cfg: &ConfigFile) -> Result<()> {
    let p = path();
    if let Some(dir) = p.parent() {
        fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        set_mode(dir, 0o700)?;
    }
    let mut data = serde_json::to_string_pretty(cfg)?;
    data.push('\n');
    fs::write(&p, data).with_context(|| format!("writing {}", p.display()))?;
    set_mode(&p, 0o600)?;
    Ok(())
}

/// Non-empty when the config file is readable or writable by group/others.
pub fn perms_warning() -> Option<String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let p = path();
        let meta = fs::metadata(&p).ok()?;
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Some(format!(
                "config {} has mode {mode:04o}; it holds passwords, 0600 is recommended",
                p.display()
            ));
        }
    }
    None
}

fn set_mode(path: &std::path::Path, mode: u32) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .with_context(|| format!("chmod {mode:o} {}", path.display()))?;
    }
    #[cfg(not(unix))]
    let _ = (path, mode);
    Ok(())
}

/// First non-empty of `MLAB_MIKROTIK_<name>` then `MIKROTIK_<name>`.
pub fn env(name: &str) -> Option<String> {
    for key in [format!("MLAB_MIKROTIK_{name}"), format!("MIKROTIK_{name}")] {
        if let Ok(v) = std::env::var(&key) {
            if !v.is_empty() {
                return Some(v);
            }
        }
    }
    None
}

/// Same as [`env`] but for a boolean, so an explicit `false` can override a file.
pub fn env_bool(name: &str) -> Option<bool> {
    env(name).map(|v| {
        matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_host_strips_scheme_and_slashes() {
        assert_eq!(normalize_host("https://10.0.0.1/").unwrap(), "10.0.0.1");
        assert_eq!(normalize_host(" rb.lan:8729 ").unwrap(), "rb.lan:8729");
        assert!(normalize_host("10.0.0.1/rest").is_err());
        assert!(normalize_host("  ").is_err());
    }

    #[test]
    fn tls_defaults_per_scheme() {
        let https = Profile::default();
        assert!(
            https.insecure(),
            "a router serves the certificate it made for itself"
        );

        let strict = Profile {
            insecure: Some(false),
            ..https.clone()
        };
        assert!(!strict.insecure());

        let plain = Profile {
            scheme: Scheme::Http,
            insecure: Some(true),
            ..Default::default()
        };
        assert!(!plain.insecure(), "there is no certificate to skip on http");
    }

    #[test]
    fn validate_requires_host_and_user() {
        let mut p = Profile::default();
        assert!(p.validate().is_err());
        p.host = "10.0.0.1".into();
        assert!(p.validate().is_err(), "a router login needs a user");
        p.user = "mlab".into();
        assert!(
            p.validate().is_ok(),
            "an empty password is a real RouterOS login"
        );
    }

    #[test]
    fn root_is_the_scheme_and_the_normalized_host() {
        let p = Profile {
            host: "https://10.0.0.1/".into(),
            scheme: Scheme::Http,
            ..Default::default()
        };
        assert_eq!(p.root().unwrap(), "http://10.0.0.1");
    }

    #[test]
    fn redact_keeps_nothing_of_a_password() {
        assert_eq!(redact("hunter2"), "********");
        assert_eq!(redact(""), "");
    }

    #[test]
    fn scheme_parses_aliases() {
        assert_eq!("WWW-SSL".parse::<Scheme>().unwrap(), Scheme::Https);
        assert_eq!("plain".parse::<Scheme>().unwrap(), Scheme::Http);
        assert!("ftp".parse::<Scheme>().is_err());
    }

    #[test]
    fn profile_falls_back_to_the_only_one() {
        let mut cfg = ConfigFile::default();
        cfg.profiles.insert("only".into(), Profile::default());
        assert_eq!(cfg.profile(None).unwrap().0, "only");
        assert!(cfg.profile(Some("other")).is_err());
    }
}
