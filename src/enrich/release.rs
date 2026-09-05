//! Which version each RouterOS channel is on, asked of MikroTik **from this
//! machine**.
//!
//! `/system/package/update/check-for-updates` would answer the same question,
//! but it is the *router* that would make the call. A passive audit does not
//! change what a production router does on the wire, so the question is asked
//! here instead and the router is never told about it.
//!
//! The feed is a plain-text file holding `<version> <unix timestamp>`:
//!
//! ```text
//! https://upgrade.mikrotik.com/routeros/NEWESTa7.stable  →  7.24.2 1788429434
//! ```

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::enrich::{cache_dir, http, now, read_cache, write_cache, Outcome};
use crate::ros::version::{Channel, Version};

const BASE: &str = "https://upgrade.mikrotik.com/routeros";

/// A release moves every few weeks; an hour is plenty and keeps a scripted run
/// from asking on every invocation.
const TTL_SECONDS: i64 = 3600;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Release {
    pub channel: String,
    pub version: String,
    /// When MikroTik published it, as reported by the feed.
    pub released: i64,
}

#[derive(Serialize, Deserialize, Default)]
struct Cache {
    fetched: i64,
    release: Option<Release>,
}

fn cache_path(channel: Channel) -> PathBuf {
    cache_dir().join(format!("release-{}.json", channel.label()))
}

/// The current version of one channel.
pub async fn current(channel: Channel, allow_web: bool, refresh: bool) -> Outcome<Option<Release>> {
    let mut out = Outcome::<Option<Release>>::default();

    if let Some(c) = read_cache::<Cache>(&cache_path(channel)) {
        let age = now() - c.fetched;
        if c.release.is_some() && !refresh && age < TTL_SECONDS {
            out.cached = true;
            out.age = Some(age);
            out.items = c.release;
            return out;
        }
    }

    if !allow_web {
        out.skipped = true;
        return out;
    }

    // MikroTik publishes no feed for the development channel, so there is
    // nothing to ask and nothing to report — which is different from asking
    // and getting no answer.
    let Some(feed) = channel.feed() else {
        out.error = Some(format!(
            "MikroTik publishes no version feed for the {} channel",
            channel.label()
        ));
        return out;
    };

    let client = match http() {
        Ok(c) => c,
        Err(e) => {
            out.error = Some(e.to_string());
            return out;
        }
    };

    let url = format!("{BASE}/{feed}");
    match fetch(&client, &url).await {
        Ok(text) => match parse(&text, channel) {
            Some(r) => {
                out.fetched = true;
                let _ = write_cache(
                    &cache_path(channel),
                    &Cache {
                        fetched: now(),
                        release: Some(r.clone()),
                    },
                );
                out.items = Some(r);
            }
            None => {
                out.error = Some(format!(
                    "{url} answered something that is not a version: {text:?}"
                ))
            }
        },
        Err(e) => out.error = Some(e),
    }
    out
}

async fn fetch(client: &reqwest::Client, url: &str) -> Result<String, String> {
    let resp = client.get(url).send().await.map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("{url} answered {}", resp.status().as_u16()));
    }
    resp.text().await.map_err(|e| e.to_string())
}

/// `7.24.2 1788429434` → a release, or `None` when it is not one.
fn parse(text: &str, channel: Channel) -> Option<Release> {
    let mut parts = text.split_whitespace();
    let version = Version::parse(parts.next()?)?;
    Some(Release {
        channel: channel.label().to_string(),
        version: version.to_string(),
        released: parts.next().and_then(|t| t.parse().ok()).unwrap_or(0),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_feed_line_parses() {
        // Copied verbatim from the live feed.
        let r = parse("7.24.2 1788429434\n", Channel::Stable).unwrap();
        assert_eq!(r.version, "7.24.2");
        assert_eq!(r.released, 1788429434);
        assert_eq!(r.channel, "stable");
    }

    #[test]
    fn a_missing_timestamp_is_not_fatal() {
        let r = parse("7.23.5", Channel::LongTerm).unwrap();
        assert_eq!(r.version, "7.23.5");
        assert_eq!(r.released, 0);
    }

    /// If MikroTik ever serves an error page at that path, it must not be read
    /// as a version number.
    #[test]
    fn anything_that_is_not_a_version_is_refused() {
        assert!(parse("", Channel::Stable).is_none());
        assert!(parse("<html>404</html>", Channel::Stable).is_none());
        assert!(parse("not-a-version 123", Channel::Stable).is_none());
    }
}
