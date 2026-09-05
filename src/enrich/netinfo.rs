//! What a public address looks like from outside, through mlab.sh.
//!
//! One address goes out and nothing else: no hostname, no inventory, nothing
//! from the configuration. The address is already public by definition — it is
//! the one every packet this router sends carries in its source field.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::enrich::{cache_dir, http, mlab_key, now, read_cache, write_cache, Outcome};

const ENDPOINT: &str = "https://mlab.sh/api/v1/scan/ip";

/// An allocation's operator does not change hourly.
const TTL_SECONDS: i64 = 24 * 3600;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NetInfo {
    #[serde(default)]
    pub ip: String,
    /// `AS210732 Some Operator`, as the service reports it.
    #[serde(default)]
    pub as_: String,
    #[serde(default)]
    pub isp: String,
    #[serde(default)]
    pub country: String,
    #[serde(default)]
    pub city: String,
    /// Whether the allocation is a hosting or datacentre range.
    #[serde(default)]
    pub hosting: bool,
    #[serde(default)]
    pub mobile: bool,
    #[serde(default)]
    pub proxy: bool,
}

#[derive(Serialize, Deserialize, Default)]
struct Cache {
    fetched: i64,
    info: Option<NetInfo>,
}

fn cache_path(ip: &str) -> PathBuf {
    let safe: String = ip
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    cache_dir().join(format!("netinfo-{safe}.json"))
}

pub async fn lookup(ip: &str, allow_web: bool, refresh: bool) -> Outcome<Option<NetInfo>> {
    let mut out = Outcome::<Option<NetInfo>>::default();
    if ip.is_empty() {
        return out;
    }

    if let Some(c) = read_cache::<Cache>(&cache_path(ip)) {
        let age = now() - c.fetched;
        if c.info.is_some() && !refresh && age < TTL_SECONDS {
            out.cached = true;
            out.age = Some(age);
            out.items = c.info;
            return out;
        }
    }

    if !allow_web {
        out.skipped = true;
        return out;
    }

    let client = match http() {
        Ok(c) => c,
        Err(e) => {
            out.error = Some(e.to_string());
            return out;
        }
    };

    let mut req = client.get(ENDPOINT).query(&[("ip", ip)]);
    if let Some(key) = mlab_key() {
        req = req.header("Authorization", format!("token {key}"));
    }

    match req.send().await {
        Ok(resp) if resp.status().is_success() => match resp.json::<serde_json::Value>().await {
            Ok(body) => {
                let info = from_body(&body, ip);
                out.fetched = true;
                let _ = write_cache(
                    &cache_path(ip),
                    &Cache {
                        fetched: now(),
                        info: Some(info.clone()),
                    },
                );
                out.items = Some(info);
            }
            Err(e) => out.error = Some(e.to_string()),
        },
        Ok(resp) => out.error = Some(format!("mlab.sh answered {}", resp.status().as_u16())),
        Err(e) => out.error = Some(e.to_string()),
    }
    out
}

/// The service's field names differ from ours in one place — `as` is a Rust
/// keyword — so the mapping is written out rather than derived.
fn from_body(v: &serde_json::Value, ip: &str) -> NetInfo {
    let s = |k: &str| {
        v.get(k)
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string()
    };
    let b = |k: &str| {
        v.get(k)
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
    };
    NetInfo {
        ip: match s("ip").as_str() {
            "" => ip.to_string(),
            got => got.to_string(),
        },
        as_: s("as"),
        isp: s("isp"),
        country: s("country"),
        city: s("city"),
        hosting: b("hosting"),
        mobile: b("mobile"),
        proxy: b("proxy"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_service_shape_maps_onto_ours() {
        // The keys the live endpoint returns.
        let body = json!({
            "ip": "198.51.100.1", "as": "AS64500 Example Transit", "isp": "Example",
            "country": "France", "city": "Strasbourg", "hosting": false, "mobile": false
        });
        let i = from_body(&body, "198.51.100.1");
        assert_eq!(i.as_, "AS64500 Example Transit");
        assert_eq!(i.city, "Strasbourg");
        assert!(!i.hosting);
    }

    #[test]
    fn a_thin_answer_still_names_the_address_we_asked_about() {
        let i = from_body(&json!({}), "198.51.100.1");
        assert_eq!(i.ip, "198.51.100.1");
        assert_eq!(i.as_, "");
    }
}
