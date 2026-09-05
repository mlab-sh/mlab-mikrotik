//! Published advisories covering a RouterOS version, through vuln.mlab.sh.
//!
//! Unlike the UniFi corpus, this one supports a **verdict** rather than a
//! reading list. NVD carries version *ranges* for most RouterOS entries — 53
//! of the 82 under `cpe:2.3:o:mikrotik:routeros` — and applies them itself
//! when the query carries a version, so there is no range arithmetic on this
//! side of the wire.
//!
//! What is on this side is the honesty pass. Two things NVD's match does not
//! do, and both change the answer:
//!
//! * **The edition.** A query for `…routeros:7.24.2` matches advisories
//!   written for the long-term branch as readily as for stable, because the
//!   edition field is a wildcard. An advisory that only names `ltr` does not
//!   cover a stable router.
//! * **Bounds that are not versions.** `CVE-2021-3014` carries
//!   `version_end_including: "2021-01-04"` — a date. NVD's comparator sorts it
//!   before `7.24.2` and returns the CVE for every modern router. A bound that
//!   will not parse as a version proves nothing, and is reported as such
//!   rather than believed.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::enrich::{cache_dir, http, now, read_cache, write_cache, Outcome};
use crate::ros::version::{Channel, Version};

const ENDPOINT: &str = "https://vuln.mlab.sh/api/v1/cve";

/// The corpus for one version moves when NVD publishes, not faster.
const TTL_SECONDS: i64 = 6 * 3600;

/// One page covers every advisory that has ever named a RouterOS version.
const PAGE: u32 = 100;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Advisory {
    pub id: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub published: String,
    #[serde(default)]
    pub cvss_score: Option<f64>,
    #[serde(default)]
    pub cvss_severity: Option<String>,
    #[serde(default)]
    pub epss_score: Option<f64>,
    #[serde(default)]
    pub in_kev: bool,
    #[serde(default)]
    pub kev_date_added: Option<String>,
    #[serde(default)]
    pub risk_score: Option<f64>,
    #[serde(default)]
    pub affected_products: Vec<String>,
    /// NVD's configuration tree, bounds intact. Empty when the record came
    /// from a fallback source rather than NVD, which is not the same fact as
    /// "this CVE has no version bounds".
    #[serde(default)]
    pub cpe_matches: Vec<CpeMatch>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CpeMatch {
    pub criteria: String,
    #[serde(default)]
    pub vulnerable: bool,
    pub version_start_including: Option<String>,
    pub version_start_excluding: Option<String>,
    pub version_end_including: Option<String>,
    pub version_end_excluding: Option<String>,
}

impl CpeMatch {
    /// The edition field of the CPE, which is what separates the branches.
    pub fn edition(&self) -> &str {
        self.criteria.split(':').nth(9).unwrap_or("*")
    }

    /// The version field, `*` when the match is a range rather than a pin.
    pub fn pinned(&self) -> Option<Version> {
        let v = self.criteria.split(':').nth(5)?;
        if v == "*" || v == "-" {
            return None;
        }
        Version::parse(v)
    }

    /// Every bound this match carries, as `(label, text)`.
    fn bounds(&self) -> Vec<(&'static str, &String)> {
        [
            ("≥", &self.version_start_including),
            (">", &self.version_start_excluding),
            ("≤", &self.version_end_including),
            ("<", &self.version_end_excluding),
        ]
        .into_iter()
        .filter_map(|(l, v)| v.as_ref().map(|v| (l, v)))
        .collect()
    }

    /// How this match reads, for a reader who wants to see why.
    pub fn range(&self) -> String {
        if let Some(p) = self.pinned() {
            return format!("= {p}");
        }
        let b = self.bounds();
        if b.is_empty() {
            return "any version".to_string();
        }
        b.iter()
            .map(|(l, v)| format!("{l} {v}"))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// What the local pass concluded about one advisory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    /// A match covers this exact version and channel.
    Applies,
    /// Every match that could apply carries a bound that is not a version, or
    /// the record carries no CPE data at all. Nothing can be concluded.
    Unclear,
    /// Every match names another branch, or another version. NVD returned it
    /// because the query's edition field is a wildcard.
    Excluded,
}

#[derive(Debug, Clone, Serialize)]
pub struct Assessment {
    pub advisory: Advisory,
    pub verdict: Verdict,
    /// The match that decided it, in words.
    pub why: String,
}

/// Judge one advisory against a version and a channel.
pub fn assess(a: &Advisory, version: &Version, channel: Channel) -> Assessment {
    let mine: Vec<&CpeMatch> = a
        .cpe_matches
        .iter()
        .filter(|m| m.criteria.contains(":mikrotik:routeros:"))
        .filter(|m| m.vulnerable)
        .collect();

    if mine.is_empty() {
        return Assessment {
            advisory: a.clone(),
            verdict: Verdict::Unclear,
            why: "the record carries no CPE data for RouterOS, so nothing local can confirm it"
                .to_string(),
        };
    }

    let mut unclear: Option<String> = None;

    for m in &mine {
        if !channel.covered_by(m.edition()) {
            continue;
        }

        if let Some(p) = m.pinned() {
            if p == *version {
                return Assessment {
                    advisory: a.clone(),
                    verdict: Verdict::Applies,
                    why: format!("names {p} exactly"),
                };
            }
            continue;
        }

        // A range. Every bound has to parse, or the match proves nothing.
        let bounds = m.bounds();
        let mut ok = true;
        let mut inside = true;
        for (label, text) in &bounds {
            let Some(b) = Version::parse(text) else {
                ok = false;
                unclear = Some(format!(
                    "its bound {label} {text:?} is not a version number, so it cannot be checked"
                ));
                break;
            };
            let holds = match *label {
                "≥" => *version >= b,
                ">" => *version > b,
                "≤" => *version <= b,
                "<" => *version < b,
                _ => true,
            };
            if !holds {
                inside = false;
            }
        }
        if !ok {
            continue;
        }
        if inside {
            return Assessment {
                advisory: a.clone(),
                verdict: Verdict::Applies,
                why: format!(
                    "{} {}",
                    m.range(),
                    match m.edition() {
                        "*" | "" => "on any branch".to_string(),
                        e => format!("on the {e} branch"),
                    }
                ),
            };
        }
    }

    match unclear {
        Some(why) => Assessment {
            advisory: a.clone(),
            verdict: Verdict::Unclear,
            why,
        },
        None => Assessment {
            advisory: a.clone(),
            verdict: Verdict::Excluded,
            why: format!(
                "every match names another branch or another version ({})",
                mine.iter()
                    .map(|m| format!("{} {}", m.edition(), m.range()))
                    .collect::<Vec<_>>()
                    .join("; ")
            ),
        },
    }
}

#[derive(Serialize, Deserialize, Default)]
struct Cache {
    fetched: i64,
    items: Vec<Advisory>,
}

fn cache_path(cpe: &str) -> PathBuf {
    // One file per queried CPE; the version is part of the question.
    let safe: String = cpe
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect();
    cache_dir().join(format!("advisories-{safe}.json"))
}

/// The advisories covering one version, from cache when fresh.
pub async fn for_version(
    version: &Version,
    allow_web: bool,
    refresh: bool,
) -> Outcome<Vec<Advisory>> {
    let cpe = format!("cpe:2.3:o:mikrotik:routeros:{version}");
    let mut out = Outcome::<Vec<Advisory>>::default();

    if let Some(c) = read_cache::<Cache>(&cache_path(&cpe)) {
        let age = now() - c.fetched;
        if !refresh && age < TTL_SECONDS {
            out.cached = true;
            out.age = Some(age);
            out.items = c.items;
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

    let mut req = client
        .get(ENDPOINT)
        .query(&[("cpe", cpe.as_str()), ("limit", &PAGE.to_string())]);
    // The key is optional: the endpoint answers without one, and having it
    // only lifts the rate limit.
    if let Some(key) = crate::enrich::mlab_key() {
        req = req.header("Authorization", format!("token {key}"));
    }

    match req.send().await {
        Ok(resp) if resp.status().is_success() => match resp.json::<serde_json::Value>().await {
            Ok(body) => {
                let list = body.get("cves").cloned().unwrap_or(serde_json::Value::Null);
                match serde_json::from_value::<Vec<Advisory>>(list) {
                    Ok(items) => {
                        out.fetched = true;
                        let _ = write_cache(
                            &cache_path(&cpe),
                            &Cache {
                                fetched: now(),
                                items: items.clone(),
                            },
                        );
                        out.items = items;
                    }
                    Err(e) => {
                        out.error = Some(format!(
                            "vuln.mlab.sh answered a shape this version does not know: {e}"
                        ))
                    }
                }
            }
            Err(e) => out.error = Some(e.to_string()),
        },
        Ok(resp) => out.error = Some(format!("vuln.mlab.sh answered {}", resp.status().as_u16())),
        Err(e) => out.error = Some(e.to_string()),
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(criteria: &str, bounds: &[(&str, &str)]) -> CpeMatch {
        let mut m = CpeMatch {
            criteria: criteria.to_string(),
            vulnerable: true,
            ..Default::default()
        };
        for (k, v) in bounds {
            let v = Some(v.to_string());
            match *k {
                "starti" => m.version_start_including = v,
                "starte" => m.version_start_excluding = v,
                "endi" => m.version_end_including = v,
                _ => m.version_end_excluding = v,
            }
        }
        m
    }

    fn advisory(matches: Vec<CpeMatch>) -> Advisory {
        Advisory {
            id: "CVE-TEST".into(),
            cpe_matches: matches,
            ..Default::default()
        }
    }

    fn v(s: &str) -> Version {
        Version::parse(s).unwrap()
    }

    /// CVE-2024-54772, verbatim from NVD: three matches, two branches.
    #[test]
    fn a_range_that_covers_the_version_applies() {
        let a = advisory(vec![
            m(
                "cpe:2.3:o:mikrotik:routeros:*:*:*:*:-:*:*:*",
                &[("starti", "6.43"), ("ende", "6.49.18")],
            ),
            m(
                "cpe:2.3:o:mikrotik:routeros:*:*:*:*:ltr:*:*:*",
                &[("starti", "6.43.13"), ("endi", "6.49.13")],
            ),
            m(
                "cpe:2.3:o:mikrotik:routeros:*:*:*:*:-:*:*:*",
                &[("starti", "7.1"), ("ende", "7.18")],
            ),
        ]);
        let r = assess(&a, &v("7.15.3"), Channel::Stable);
        assert_eq!(r.verdict, Verdict::Applies);
        assert!(
            r.why.contains("7.1"),
            "it says which range matched: {}",
            r.why
        );
    }

    /// The same advisory against a version past every range.
    #[test]
    fn a_version_past_the_range_is_excluded() {
        let a = advisory(vec![m(
            "cpe:2.3:o:mikrotik:routeros:*:*:*:*:-:*:*:*",
            &[("ende", "7.20")],
        )]);
        assert_eq!(
            assess(&a, &v("7.24.2"), Channel::Stable).verdict,
            Verdict::Excluded
        );
        assert_eq!(
            assess(&a, &v("7.19"), Channel::Stable).verdict,
            Verdict::Applies
        );
    }

    /// The edition filter earning its place: an advisory written only for the
    /// long-term branch must not be reported against a stable router, even
    /// though NVD returned it.
    #[test]
    fn an_advisory_for_another_branch_is_excluded() {
        let a = advisory(vec![m(
            "cpe:2.3:o:mikrotik:routeros:*:*:*:*:ltr:*:*:*",
            &[("endi", "6.48.7")],
        )]);
        assert_eq!(
            assess(&a, &v("6.48.0"), Channel::Stable).verdict,
            Verdict::Excluded
        );
        assert_eq!(
            assess(&a, &v("6.48.0"), Channel::LongTerm).verdict,
            Verdict::Applies
        );
    }

    /// CVE-2021-3014, verbatim: the bound is a date. This is the case the
    /// whole honesty pass exists for.
    #[test]
    fn a_bound_that_is_a_date_is_unclear_never_applies() {
        let a = advisory(vec![m(
            "cpe:2.3:o:mikrotik:routeros:*:*:*:*:*:*:*:*",
            &[("endi", "2021-01-04")],
        )]);
        let r = assess(&a, &v("7.24.2"), Channel::Stable);
        assert_eq!(r.verdict, Verdict::Unclear);
        assert!(r.why.contains("2021-01-04"));
        assert!(r.why.contains("not a version"));
    }

    #[test]
    fn a_pinned_version_matches_only_itself() {
        let a = advisory(vec![m(
            "cpe:2.3:o:mikrotik:routeros:6.44.6:*:*:*:*:*:*:*",
            &[],
        )]);
        assert_eq!(
            assess(&a, &v("6.44.6"), Channel::Stable).verdict,
            Verdict::Applies
        );
        assert_eq!(
            assess(&a, &v("6.44.7"), Channel::Stable).verdict,
            Verdict::Excluded
        );
    }

    /// A record from a fallback source has no CPE tree. That is not the same
    /// fact as "this CVE does not apply", and must not be reported as one.
    #[test]
    fn a_record_with_no_cpe_data_is_unclear() {
        let r = assess(&advisory(vec![]), &v("7.24.2"), Channel::Stable);
        assert_eq!(r.verdict, Verdict::Unclear);
        assert!(r.why.contains("no CPE data"));
    }

    #[test]
    fn a_match_nvd_marks_as_not_vulnerable_is_ignored() {
        let mut nv = m(
            "cpe:2.3:o:mikrotik:routeros:*:*:*:*:-:*:*:*",
            &[("ende", "9.0")],
        );
        nv.vulnerable = false;
        assert_eq!(
            assess(&advisory(vec![nv]), &v("7.1"), Channel::Stable).verdict,
            Verdict::Unclear
        );
    }

    #[test]
    fn the_range_reads_as_a_range() {
        let m = m(
            "cpe:2.3:o:mikrotik:routeros:*:*:*:*:-:*:*:*",
            &[("starti", "6.34"), ("ende", "6.49.7")],
        );
        assert_eq!(m.range(), "≥ 6.34, < 6.49.7");
        assert_eq!(m.edition(), "-");
    }
}
