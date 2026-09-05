//! How far behind this router is, using only what it already knows.
//!
//! Nothing here asks MikroTik anything. `/system/package/update` would, and it
//! is the router itself that would make the call, so it stays out of a passive
//! audit — it belongs to phase four, behind an explicit flag.

use super::{finding, Finding, Input, Outcome, Severity};
use crate::ros::field;
use crate::ros::version::Version;

pub fn check(i: &Input, o: &mut Outcome) {
    o.guard(i, "bootloader", &["/system/routerboard"], bootloader);
    o.guard(i, "routeros-branch", &["/system/resource"], branch);
}

/// The RouterBOARD bootloader is versioned separately and a RouterOS upgrade
/// does not move it. It is the single most common gap on an otherwise
/// up-to-date router.
fn bootloader(i: &Input) -> Vec<Finding> {
    let current = field(&i.routerboard, "current-firmware");
    let available = field(&i.routerboard, "upgrade-firmware");

    if current.is_empty() || available.is_empty() || current == available {
        return Vec::new();
    }

    // Compare as versions where both parse, so `7.9` is not reported as ahead
    // of `7.12` the way a string comparison would have it.
    if let (Some(a), Some(b)) = (Version::parse(&current), Version::parse(&available)) {
        if a >= b {
            return Vec::new();
        }
    }

    vec![finding(
        Severity::Medium,
        "patch",
        "the RouterBOARD bootloader is behind the installed RouterOS",
        format!(
            "firmware {current}, and {available} ships with the RouterOS already installed — a RouterOS upgrade never moves the bootloader on its own"
        ),
        "/system routerboard upgrade, then /system reboot",
    )]
}

/// RouterOS 6 reached the end of its life; 7.x is where fixes land.
fn branch(i: &Input) -> Vec<Finding> {
    let version = field(&i.resource, "version");
    // A string that is not a version number says nothing, and must not be
    // coerced into one — `/system/resource` on a damaged install can report
    // anything at all.
    let Some(parsed) = Version::parse(&version) else {
        return Vec::new();
    };

    if parsed.major() < 7 {
        return vec![finding(
            Severity::High,
            "patch",
            "this router runs RouterOS 6",
            format!(
                "version {version} — the 6.x branch is long-term maintenance at best, it has no /rest at all, and the published vulnerabilities that name RouterOS cluster there"
            ),
            "plan a 6.49.x → 7.x upgrade; read the release notes first, the migration is not transparent",
        )];
    }

    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_matching_bootloader_is_silence() {
        let i = Input {
            routerboard: json!({"current-firmware": "7.24.2", "upgrade-firmware": "7.24.2"}),
            ..Default::default()
        };
        assert!(bootloader(&i).is_empty());
    }

    #[test]
    fn a_lagging_bootloader_names_both_versions() {
        // The real shape seen on hardware: RouterOS current, bootloader years
        // behind, because nobody ran the second command.
        let i = Input {
            routerboard: json!({"current-firmware": "7.12.2", "upgrade-firmware": "7.24.2"}),
            ..Default::default()
        };
        let f = bootloader(&i);
        assert_eq!(f[0].severity, Severity::Medium);
        assert!(f[0].detail.contains("7.12.2"));
        assert!(f[0].detail.contains("7.24.2"));
    }

    #[test]
    fn a_router_that_reports_no_bootloader_is_not_a_finding() {
        // CHR and x86 have no RouterBOARD at all.
        assert!(bootloader(&Input::default()).is_empty());
    }

    #[test]
    fn the_major_version_is_read_out_of_the_version_string() {
        let six = Input {
            resource: json!({"version": "6.49.7 (long-term)"}),
            ..Default::default()
        };
        assert_eq!(branch(&six)[0].severity, Severity::High);

        let seven = Input {
            resource: json!({"version": "7.24.2 (stable)"}),
            ..Default::default()
        };
        assert!(branch(&seven).is_empty());

        let nonsense = Input {
            resource: json!({"version": "unknown"}),
            ..Default::default()
        };
        assert!(
            branch(&nonsense).is_empty(),
            "a version that will not parse says nothing"
        );
    }

    #[test]
    fn a_bootloader_ahead_of_the_routeros_is_not_a_finding() {
        // Happens after a downgrade: the firmware stays where it was.
        let i = Input {
            routerboard: json!({"current-firmware": "7.24.2", "upgrade-firmware": "7.12.2"}),
            ..Default::default()
        };
        assert!(bootloader(&i).is_empty());
    }

    #[test]
    fn versions_are_compared_numerically_not_lexically() {
        let i = Input {
            routerboard: json!({"current-firmware": "7.9.0", "upgrade-firmware": "7.12.2"}),
            ..Default::default()
        };
        assert_eq!(
            bootloader(&i).len(),
            1,
            "7.9 is behind 7.12, not ahead of it"
        );
    }
}
