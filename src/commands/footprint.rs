//! `footprint` — what this router looks like from outside.
//!
//! The addresses it answers on that are reachable from the internet, and who
//! the operator of each one is. Nothing is probed: the public address comes
//! from the router's own `/ip/cloud`, the rest from `/ip/address`, and the
//! only thing that ever leaves this machine is an address that is public by
//! definition — it is the one every packet this router sends already carries.

use anyhow::Result;
use clap::Args;
use serde_json::{json, Value};

use crate::collect::Fetcher;
use crate::enrich::netinfo;
use crate::ros::{field, first_field, flag, Client};
use crate::ui::{self, render};

#[derive(Args, Debug)]
pub struct FootprintArgs {
    /// Ask mlab.sh who operates each public address
    #[arg(long)]
    pub allow_web: bool,
    /// Ignore a fresh cache entry and ask again
    #[arg(long)]
    pub refresh: bool,
}

pub async fn run(c: &Client, args: &FootprintArgs) -> Result<()> {
    let mut f = Fetcher::new(c);
    let cloud = f.get("/ip/cloud").await;
    let addresses = f.list("/ip/address").await;
    let v6 = f.list("/ipv6/address").await;
    let services = f.list("/ip/service").await;
    let nat = f.list("/ip/firewall/nat").await;

    // What the router itself believes its public address to be. RouterOS keeps
    // this current even with DDNS off, which makes it free.
    let cloud_address = field(&cloud, "public-address");

    let mut public: Vec<Value> = addresses
        .iter()
        .chain(v6.iter())
        .filter(|a| !flag(a, "disabled") && !flag(a, "invalid"))
        .filter(|a| is_public(&field(a, "address")))
        .map(|a| {
            json!({
                "address": field(a, "address"),
                "interface": first_field(a, &["actual-interface", "interface"]),
                "origin": if flag(a, "dynamic") { "dynamic" } else { "static" },
            })
        })
        .collect();

    // The cloud address may not be configured on any interface — behind a
    // provider's NAT it will not be — and it is still the address the world
    // sees, so it earns its own row.
    if !cloud_address.is_empty()
        && !public.iter().any(|p| {
            p["address"]
                .as_str()
                .unwrap_or("")
                .starts_with(&cloud_address)
        })
    {
        public.insert(
            0,
            json!({
                "address": cloud_address.clone(),
                "interface": "(reported by /ip/cloud)",
                "origin": "observed",
            }),
        );
    }

    // One lookup per distinct address, not per row.
    let mut lookups: Vec<Value> = Vec::new();
    let mut skipped = false;
    let mut failed: Option<String> = None;
    let mut provenance = String::new();
    for a in &public {
        let bare = bare_address(a["address"].as_str().unwrap_or(""));
        let out = netinfo::lookup(&bare, args.allow_web, args.refresh).await;
        skipped |= out.skipped;
        if provenance.is_empty() || out.fetched {
            provenance = out.provenance();
        }
        if out.error.is_some() && failed.is_none() {
            failed = out.error.clone();
        }
        if let Some(i) = out.items {
            let place: Vec<String> = [i.city.clone(), i.country.clone()]
                .into_iter()
                .filter(|s| !s.is_empty())
                .collect();
            lookups.push(json!({
                "address": bare,
                "as": i.as_,
                "isp": i.isp,
                "where": place.join(", "),
                "hosting": i.hosting,
            }));
        }
    }

    let listening = services
        .iter()
        .filter(|s| !flag(s, "disabled") && field(s, "available-from").trim().is_empty())
        .count();
    let forwards = nat
        .iter()
        .filter(|r| !flag(r, "disabled") && field(r, "action") == "dst-nat")
        .count();

    if render::is_json() {
        render::print_json(&json!({
            "cloudAddress": cloud_address,
            "publicAddresses": public,
            "operators": lookups,
            "unrestrictedServices": listening,
            "portForwards": forwards,
            "lookupSkipped": skipped,
            "lookupProvenance": provenance,
            "lookupError": failed,
            "unreadable": f.unreadable,
        }));
        return Ok(());
    }

    f.report();
    render::heading("Reachable from outside");

    if public.is_empty() {
        println!();
        println!("  no public address on this router — everything it holds is RFC 1918 or");
        println!("  link-local, and whatever reaches it is forwarded by something upstream");
    } else {
        render::list(&public, render::PUBLIC_ADDRESS_COLS);
        render::count(public.len(), "public address");
    }

    if !lookups.is_empty() {
        render::heading("Who operates them");
        render::list(&lookups, render::OPERATOR_COLS);
        // Where these rows came from, because a cached answer is served with
        // or without --allow-web and would otherwise be indistinguishable
        // from one fetched a second ago.
        println!();
        println!("  {provenance} — add --refresh to ask again");
    } else if skipped && !public.is_empty() {
        ui::info("the operator of each address was not looked up — add --allow-web");
        println!("  the address is all that would be sent, and it is public by definition");
    }
    if let Some(e) = &failed {
        ui::warning(&format!("the operator lookup failed: {e}"));
    }

    // What an address is worth knowing depends on what answers on it, and that
    // number belongs to `exposure`. Naming it here saves a reader the guess.
    render::heading("What answers there");
    render::pairs(&[
        (
            "services with no address restriction",
            listening.to_string(),
        ),
        ("port forwards", forwards.to_string()),
    ]);
    println!("  `exposure` lists them; `firewall` says whether a chain stops them");

    Ok(())
}

/// The address without its prefix length.
fn bare_address(cidr: &str) -> String {
    cidr.split('/').next().unwrap_or(cidr).trim().to_string()
}

/// Whether an address is one the internet can route to.
///
/// Everything RFC 1918, RFC 6598 (carrier-grade NAT), loopback, link-local and
/// the IPv6 unique-local range is excluded. A router behind a provider's NAT
/// therefore reports no public address of its own, which is the truth.
fn is_public(cidr: &str) -> bool {
    let a = bare_address(cidr);
    if a.is_empty() {
        return false;
    }

    if a.contains(':') {
        let lower = a.to_ascii_lowercase();
        // fe80::/10 link-local, fc00::/7 unique-local, ::1 loopback.
        return !(lower.starts_with("fe8")
            || lower.starts_with("fe9")
            || lower.starts_with("fea")
            || lower.starts_with("feb")
            || lower.starts_with("fc")
            || lower.starts_with("fd")
            || lower == "::1");
    }

    let o: Vec<u32> = a.split('.').filter_map(|p| p.parse().ok()).collect();
    if o.len() != 4 {
        return false;
    }
    // Written as "everything that is not routable", because that is the list
    // an operator recognises: RFC 1918, loopback, link-local, RFC 6598
    // carrier-grade NAT, "this network", and multicast upwards.
    let reserved = matches!((o[0], o[1]), (10, _) | (127, _) | (169, 254) | (192, 168))
        || o[0] == 0
        || o[0] >= 224
        || (o[0] == 172 && (16..=31).contains(&o[1]))
        || (o[0] == 100 && (64..=127).contains(&o[1]));
    !reserved
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_ranges_are_not_public() {
        for a in [
            "10.0.0.1/8",
            "192.168.1.1/24",
            "172.17.2.6/30",
            "172.31.255.1/16",
            "127.0.0.1/8",
            "169.254.1.1/16",
            "100.64.0.1/10",
        ] {
            assert!(!is_public(a), "{a} should not count as public");
        }
    }

    #[test]
    fn a_routable_address_is_public() {
        for a in [
            "45.8.205.249/32",
            "198.51.100.1/24",
            "172.15.0.1/16",
            "172.32.0.1/16",
        ] {
            assert!(is_public(a), "{a} should count as public");
        }
    }

    #[test]
    fn multicast_and_nonsense_are_not_public() {
        assert!(!is_public("224.0.0.1/4"));
        assert!(!is_public("0.0.0.0/0"));
        assert!(!is_public(""));
        assert!(!is_public("not an address"));
    }

    #[test]
    fn ipv6_link_local_and_unique_local_are_not_public() {
        assert!(!is_public("fe80::1/64"));
        assert!(!is_public("fd00::1/8"));
        assert!(!is_public("::1/128"));
        assert!(is_public("2001:db8::1/64"));
    }

    #[test]
    fn the_prefix_length_is_stripped_for_a_lookup() {
        assert_eq!(bare_address("45.8.205.249/32"), "45.8.205.249");
        assert_eq!(bare_address("2001:db8::1/64"), "2001:db8::1");
        assert_eq!(bare_address("45.8.205.249"), "45.8.205.249");
    }
}
