//! The graded checks, as pure functions over already-fetched data.
//!
//! Kept apart from the collection that feeds them so every rule here is
//! testable against a fixture with no router in the loop, which is the only
//! way a security check earns any trust.
//!
//! Two rules govern what may appear:
//!
//! * **A severity is about what it costs, not how it looks.** A control that
//!   is simply switched off is usually a decision and stays out; a control
//!   that reads as protection without being one belongs here.
//! * **A check that could not run produces nothing.** Never a pass. The
//!   command reports how many were skipped, so an incomplete audit cannot pass
//!   for a clean one.

pub mod accounts;
pub mod exposure;
pub mod integrity;
pub mod logging;
pub mod patch;
pub mod segmentation;
pub mod services;
pub mod wireless;

use serde::Serialize;
use serde_json::Value;

use crate::collect::Unreadable;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub severity: Severity,
    pub area: &'static str,
    pub title: String,
    /// What was actually observed, with the values that led to it.
    pub detail: String,
    /// The RouterOS command that changes it, where there is one.
    pub fix: String,
}

pub fn finding(
    severity: Severity,
    area: &'static str,
    title: impl Into<String>,
    detail: impl Into<String>,
    fix: impl Into<String>,
) -> Finding {
    Finding {
        severity,
        area,
        title: title.into(),
        detail: detail.into(),
        fix: fix.into(),
    }
}

/// Everything the checks read.
///
/// A menu that could not be read arrives as an empty list or a `Null`, and the
/// path is in `unreadable`; that is what lets a check say "not readable"
/// rather than "clean".
#[derive(Debug, Default, Clone, Serialize)]
pub struct Input {
    pub resource: Value,
    pub routerboard: Value,
    pub users: Vec<Value>,
    pub groups: Vec<Value>,
    pub services: Vec<Value>,
    pub filter: Vec<Value>,
    pub nat: Vec<Value>,
    pub ipv6_filter: Vec<Value>,
    pub ipv6_addresses: Vec<Value>,
    pub bridges: Vec<Value>,
    pub bridge_ports: Vec<Value>,
    pub vlans: Vec<Value>,
    pub dns: Value,
    pub snmp: Value,
    pub snmp_communities: Vec<Value>,
    pub socks: Value,
    pub proxy: Value,
    pub upnp: Value,
    pub cloud: Value,
    pub ssh: Value,
    pub romon: Value,
    pub mac_server: Value,
    pub mac_winbox: Value,
    pub bandwidth_server: Value,
    pub discovery: Value,
    pub ntp: Value,
    pub logging: Vec<Value>,
    pub logging_actions: Vec<Value>,
    /// The `wifi` stack (RouterOS 7.13+, ex-wifiwave2).
    pub wifi: Vec<Value>,
    pub wifi_security: Vec<Value>,
    /// The legacy `wireless` stack. A router carries one or the other, never
    /// both, and a router with no radios carries neither.
    pub wireless: Vec<Value>,
    pub wireless_security: Vec<Value>,
    /// The integrity menus: what runs on its own, and what is on the disk.
    pub interfaces: Vec<Value>,
    pub scheduler: Vec<Value>,
    pub scripts: Vec<Value>,
    pub netwatch: Vec<Value>,
    pub files: Vec<Value>,
    pub unreadable: Vec<Unreadable>,
}

impl Input {
    /// Whether a menu answered at all.
    pub fn readable(&self, path: &str) -> bool {
        !self.unreadable.iter().any(|u| u.path == path)
    }
}

/// What one pass of the checks produced.
#[derive(Debug, Default, Serialize)]
pub struct Outcome {
    pub findings: Vec<Finding>,
    /// Checks that could not run, by name. Never counted as passes.
    pub skipped: Vec<Skipped>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Skipped {
    pub check: &'static str,
    pub because: String,
}

impl Outcome {
    /// Run `body` only when every menu it needs was readable; otherwise record
    /// the check as skipped and move on.
    ///
    /// This is the mechanism the second rule at the top of this file rests on:
    /// there is no path by which a check produces a pass without its data.
    pub fn guard(
        &mut self,
        i: &Input,
        check: &'static str,
        needs: &[&str],
        body: impl FnOnce(&Input) -> Vec<Finding>,
    ) {
        let missing: Vec<&str> = needs.iter().copied().filter(|p| !i.readable(p)).collect();
        if missing.is_empty() {
            self.findings.extend(body(i));
        } else {
            self.skipped.push(Skipped {
                check,
                because: format!("could not read {}", missing.join(", ")),
            });
        }
    }

    /// Record a check that has nothing to work on — no radios, no IPv6 — which
    /// is different from one whose data was refused.
    pub fn not_applicable(&mut self, check: &'static str, because: impl Into<String>) {
        self.skipped.push(Skipped {
            check,
            because: because.into(),
        });
    }

    pub fn worst_first(&mut self) {
        self.findings
            .sort_by(|a, b| b.severity.cmp(&a.severity).then(a.area.cmp(b.area)));
    }

    pub fn count(&self, s: Severity) -> usize {
        self.findings.iter().filter(|f| f.severity == s).count()
    }
}

/// Every check, worst first.
pub fn run(i: &Input) -> Outcome {
    let mut o = Outcome::default();
    accounts::check(i, &mut o);
    services::check(i, &mut o);
    exposure::check(i, &mut o);
    segmentation::check(i, &mut o);
    wireless::check(i, &mut o);
    integrity::check(i, &mut o);
    patch::check(i, &mut o);
    logging::check(i, &mut o);
    o.worst_first();
    o
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collect::Reason;

    fn unreadable(path: &str) -> Unreadable {
        Unreadable {
            path: path.to_string(),
            reason: Reason::Refused,
            detail: "API error 403".into(),
        }
    }

    #[test]
    fn a_check_without_its_data_is_skipped_never_passed() {
        let i = Input {
            unreadable: vec![unreadable("/ip/service")],
            ..Default::default()
        };
        let mut o = Outcome::default();
        o.guard(&i, "services", &["/ip/service"], |_| {
            panic!("the body must not run")
        });
        assert!(o.findings.is_empty());
        assert_eq!(o.skipped.len(), 1);
        assert_eq!(o.skipped[0].check, "services");
        assert!(o.skipped[0].because.contains("/ip/service"));
    }

    #[test]
    fn a_check_with_its_data_runs() {
        let i = Input::default();
        let mut o = Outcome::default();
        o.guard(&i, "services", &["/ip/service"], |_| {
            vec![finding(Severity::Low, "services", "t", "d", "f")]
        });
        assert_eq!(o.findings.len(), 1);
        assert!(o.skipped.is_empty());
    }

    #[test]
    fn findings_sort_worst_first() {
        let mut o = Outcome {
            findings: vec![
                finding(Severity::Low, "a", "low", "", ""),
                finding(Severity::Critical, "b", "critical", "", ""),
                finding(Severity::Medium, "c", "medium", "", ""),
            ],
            ..Default::default()
        };
        o.worst_first();
        let order: Vec<&str> = o.findings.iter().map(|f| f.title.as_str()).collect();
        assert_eq!(order, vec!["critical", "medium", "low"]);
        assert_eq!(o.count(Severity::Critical), 1);
    }
}
