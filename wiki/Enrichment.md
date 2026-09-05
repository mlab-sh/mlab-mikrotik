# Enrichment

Everything that leaves this machine, and the rule that governs all of it.

## The rule

**Nothing leaves without `--allow-web`.** Three commands can make an outbound
call, each says so when it did not, and each names what would have been sent.
Without the flag they still run — from cache, or with the verdict left open —
rather than failing.

**Nothing is sent that identifies the network.** A version string, a CPE, a
public IP address. Never an inventory, never a hostname, never a MAC, never
anything out of the configuration.

**The router never makes the call.** This is the part worth being precise
about. `/system/package/update/check-for-updates` would answer the version
question, but it is the *router* that would contact MikroTik. A passive audit
does not change what a production router does on the wire, so the question is
asked from the machine running the CLI and the router is never told.

## The three lookups

| Command | Service | What is sent | What comes back |
| --- | --- | --- | --- |
| [`patch`](Patch) | `upgrade.mikrotik.com` | nothing but the request itself | `7.24.2 1788429434` — the current version of one channel |
| [`vuln`](Vuln) | `vuln.mlab.sh` | `cpe:2.3:o:mikrotik:routeros:7.24.2` | the advisories NVD says cover that version |
| [`footprint`](Footprint) | `mlab.sh` | one public IP address | its ASN, operator, country and whether the range is hosting |

The MikroTik feed is a plain text file with no authentication. The two mlab.sh
endpoints answer without a key too; when `$HOME/.mlab/conf.yml` holds one —
the file `mlab-cli` writes — it is sent, which only lifts the rate limit.
`MLAB_API_KEY` overrides it.

## Caching

Every answer is cached in `$HOME/.mlab/mikrotik/cache`, `0600` in a `0700`
directory, so a repeated run and a scripted one cost nothing:

| Lookup | Kept for | Because |
| --- | --- | --- |
| release feed | 1 hour | a release moves every few weeks |
| advisories | 6 hours | the corpus moves when NVD publishes |
| address operator | 24 hours | an allocation's operator does not change hourly |

A cached answer is used **before** the `--allow-web` check. The flag gates the
*network*, not data already on this disk, so a run without it still reports
what a previous run learned — which is why every command that uses a lookup
prints where its answer came from:

```
  from cache, 6 minutes old — add --refresh to ask again
  looked up just now — add --refresh to ask again
```

Without that line the same command appears to behave differently on two
consecutive runs for no visible reason. `--refresh` ignores a fresh entry and
asks again; it needs `--allow-web` like any other network call.

A corrupt cache file is never fatal: it is ignored and refetched.

## Four states, not two

Every lookup reports which of these happened, because a command that cannot
tell them apart ends up printing "no advisories" for a run that never left the
machine — or showing a week-old answer as though it were current:

| State | On screen |
| --- | --- |
| fetched | `looked up just now` |
| cached | `from cache, 6 minutes old` |
| skipped | `not looked up` — `--allow-web` was not given and the cache had nothing fresh |
| failed | `the lookup failed`, with the reason |

**A failed lookup is never a clean result.** `patch` says `cannot say` rather
than `up to date`; `vuln` claims nothing at all.
