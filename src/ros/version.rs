//! RouterOS version numbers, and the release channel they belong to.
//!
//! Small on purpose. Everything downstream — is this router behind, does this
//! advisory's range cover it — rests on being able to say *no* when a string
//! is not a version, and NVD's corpus contains at least one CPE whose version
//! bound is a **date** (`versionEndIncluding: "2021-01-04"`). A comparator
//! that shrugs and guesses turns that into a confident false positive.

use std::cmp::Ordering;
use std::fmt;

/// A RouterOS version: up to four dot-separated numbers.
#[derive(Debug, Clone, Eq)]
pub struct Version(Vec<u32>);

impl Version {
    /// Parse a version, or `None` when the string is not one.
    ///
    /// Accepts what RouterOS actually reports — `7.24.2`, `6.49.7`,
    /// `7.24.2 (stable)`, `7.1` — and rejects everything else, dates
    /// included.
    pub fn parse(s: &str) -> Option<Version> {
        // `/system/resource` reports `7.24.2 (stable)`; the channel travels
        // separately and is not part of the number.
        let head = s.split_whitespace().next()?.trim();
        if head.is_empty() {
            return None;
        }
        let parts: Vec<&str> = head.split('.').collect();
        if parts.is_empty() || parts.len() > 4 {
            return None;
        }
        let mut out = Vec::with_capacity(parts.len());
        for p in parts {
            // A leading zero is fine (`7.01`); anything non-numeric is not.
            if p.is_empty() || !p.chars().all(|c| c.is_ascii_digit()) {
                return None;
            }
            out.push(p.parse::<u32>().ok()?);
        }
        Some(Version(out))
    }

    /// The major number, for the "still on 6.x" question.
    pub fn major(&self) -> u32 {
        self.0.first().copied().unwrap_or(0)
    }
}

/// Equality is defined by the ordering rather than derived, because the two
/// have to agree: `Ord` treats a missing component as zero, so `7.24` and
/// `7.24.0` compare equal, and a derived `PartialEq` comparing the vectors
/// would call them different. `Ord`'s contract requires `a == b` exactly when
/// `a.cmp(b)` is `Equal`, and a type that breaks it misbehaves in every sorted
/// collection it is put into.
impl PartialEq for Version {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Version {
    /// Compare component by component, treating a missing component as zero,
    /// so `7.24` and `7.24.0` are the same version.
    fn cmp(&self, other: &Self) -> Ordering {
        let n = self.0.len().max(other.0.len());
        for i in 0..n {
            let (a, b) = (
                self.0.get(i).copied().unwrap_or(0),
                other.0.get(i).copied().unwrap_or(0),
            );
            match a.cmp(&b) {
                Ordering::Equal => continue,
                other => return other,
            }
        }
        Ordering::Equal
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let parts: Vec<String> = self.0.iter().map(|n| n.to_string()).collect();
        f.write_str(&parts.join("."))
    }
}

/// Which release channel a router follows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Channel {
    Stable,
    LongTerm,
    Testing,
    Development,
}

impl Channel {
    /// What `/system/package/update` calls it.
    pub fn parse(s: &str) -> Option<Channel> {
        match s.trim().to_ascii_lowercase().as_str() {
            "stable" => Some(Channel::Stable),
            "long-term" | "longterm" | "ltr" => Some(Channel::LongTerm),
            "testing" => Some(Channel::Testing),
            "development" | "devel" => Some(Channel::Development),
            _ => None,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Channel::Stable => "stable",
            Channel::LongTerm => "long-term",
            Channel::Testing => "testing",
            Channel::Development => "development",
        }
    }

    /// The path MikroTik publishes the current version of this channel at.
    ///
    /// A plain-text file holding `<version> <unix timestamp>`. There is no
    /// feed for the development channel.
    pub fn feed(self) -> Option<&'static str> {
        match self {
            Channel::Stable => Some("NEWESTa7.stable"),
            Channel::LongTerm => Some("NEWESTa7.long-term"),
            Channel::Testing => Some("NEWESTa7.testing"),
            Channel::Development => None,
        }
    }

    /// The CPE 2.3 edition field NVD uses for this channel.
    ///
    /// This is the difference between "your long-term release is affected" and
    /// "it is not": NVD writes `ltr` for long-term and `-` for stable, and an
    /// advisory that only names one of them does not cover the other.
    pub fn cpe_edition(self) -> &'static str {
        match self {
            Channel::Stable => "-",
            Channel::LongTerm => "ltr",
            Channel::Testing => "testing",
            Channel::Development => "-",
        }
    }

    /// Whether an advisory written for `edition` covers this channel.
    ///
    /// `*` is NVD's "any edition" and covers everything; an empty field means
    /// the CPE was too short to carry one, which is treated the same way.
    pub fn covered_by(self, edition: &str) -> bool {
        matches!(edition, "*" | "" | "-*") || edition == self.cpe_edition()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_versions_routeros_actually_reports_all_parse() {
        for s in ["7.24.2", "6.49.7", "7.1", "6.48.7", "7.12.2"] {
            assert!(Version::parse(s).is_some(), "{s} should parse");
        }
        assert_eq!(
            Version::parse("7.24.2 (stable)").unwrap(),
            Version::parse("7.24.2").unwrap(),
            "the channel travels separately and is not part of the number"
        );
    }

    /// The reason this module exists. NVD carries at least one RouterOS CPE
    /// whose version bound is a date, and a comparator that accepts it reports
    /// every modern router as vulnerable to CVE-2021-3014.
    #[test]
    fn a_date_is_not_a_version() {
        assert_eq!(Version::parse("2021-01-04"), None);
        assert_eq!(Version::parse("2021-01-04T00:00:00Z"), None);
    }

    #[test]
    fn nothing_else_sneaks_through_either() {
        for s in ["", "  ", "-", "7.x", "v7.24.2", "7..2", "1.2.3.4.5", "*"] {
            assert_eq!(Version::parse(s), None, "{s:?} should not parse");
        }
    }

    #[test]
    fn ordering_is_component_wise_not_lexical() {
        let v = |s: &str| Version::parse(s).unwrap();
        assert!(v("7.10.0") > v("7.9.9"), "10 is after 9, not before it");
        assert!(v("6.49.7") < v("7.1"));
        assert!(v("7.24.2") > v("7.24.1"));
    }

    #[test]
    fn a_missing_component_counts_as_zero() {
        let v = |s: &str| Version::parse(s).unwrap();
        assert_eq!(v("7.24"), v("7.24.0"));
        assert!(v("7.24.1") > v("7.24"));
    }

    /// `Ord` and `Eq` have to tell the same story, or every sorted collection
    /// this type is put into misbehaves.
    #[test]
    fn equality_and_ordering_agree() {
        let v = |s: &str| Version::parse(s).unwrap();
        for (a, b) in [("7.24", "7.24.0"), ("7.24.2", "7.24.2"), ("7", "7.0.0.0")] {
            assert_eq!(v(a), v(b));
            assert_eq!(v(a).cmp(&v(b)), std::cmp::Ordering::Equal);
        }
        for (a, b) in [("7.24", "7.24.1"), ("6.49.7", "7.1")] {
            assert_ne!(v(a), v(b));
            assert_ne!(v(a).cmp(&v(b)), std::cmp::Ordering::Equal);
        }
    }

    #[test]
    fn the_channel_decides_which_advisories_apply() {
        assert!(Channel::Stable.covered_by("-"));
        assert!(Channel::Stable.covered_by("*"));
        assert!(
            !Channel::Stable.covered_by("ltr"),
            "an advisory naming only the long-term branch does not cover stable"
        );
        assert!(Channel::LongTerm.covered_by("ltr"));
        assert!(!Channel::LongTerm.covered_by("-"));
    }

    #[test]
    fn channel_names_come_from_the_router_and_from_nvd() {
        assert_eq!(Channel::parse("stable"), Some(Channel::Stable));
        assert_eq!(Channel::parse("long-term"), Some(Channel::LongTerm));
        assert_eq!(Channel::parse("nonsense"), None);
        assert_eq!(Channel::LongTerm.cpe_edition(), "ltr");
        assert_eq!(
            Channel::Development.feed(),
            None,
            "MikroTik publishes no feed for it"
        );
    }
}
