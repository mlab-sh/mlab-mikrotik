# Roadmap

Six phases. The order is deliberate: each step is usable on its own, and each
one makes the next cheaper.

## Done — phase 1, *reading*

**The core CLI.** Instances with precedence between file, environment and
flags; the HTTP handler with typed RouterOS errors and the hints that go with
them; the human render and the JSON passthrough; progress that never pollutes a
pipe.

**The collection layer.** `src/collect.rs` fetches and shapes and never
judges, and records every menu that produced nothing — separating *absent from
this router* (a package that is not installed, which RouterOS reports as a
`400`) from *refused to this account*. Nothing downstream can mistake an empty
table for a clean one.

**`whoami`.** What the account is allowed to do, with the policies that are
not about reading called out by name. This is the command the rest of the
tool's honesty rests on.

**`info`, `interfaces`, `clients`, `network`, `topology`.** The five reading
commands, each joining the two or three menus that have to be read together —
addresses onto interfaces, four host sources onto one MAC, three VLAN menus
side by side.

**`api`.** Raw access to every menu, with `.proplist` and a guard on anything
that is not a GET.

## Done — phase 2, *hardening*

**The checks.** `src/checks/` — twenty-six graded rules across seven areas,
every one a pure function over an `Input` the collection layer filled, tested
against fixtures with no router in the loop. `Outcome::guard` is the mechanism
behind the second rule: a check whose menus were refused is recorded as skipped
and can never produce a pass. See [Checks](Checks).

**`audit`.** All of it in one report, worst first, with `--min-severity`,
`--area` and a `--fail-on` gate for CI. The footer prints the skipped count
whether or not anything was found.

**`firewall`.** Every chain, with the one ordering question that can be
answered honestly — whether a chain ends in a refusal that narrows nothing —
and an explicit refusal to guess at rule shadowing.

**`exposure`.** What the router listens on with each service's own
`available-from`, what NAT publishes, and the five relay features that make a
router useful to somebody else.

**`posture`.** Accounts resolved against their groups, the four ways in that
bypass the IP firewall, cryptography and time, and logging judged by target
rather than by action name.

**`wifi`.** Both wireless stacks normalised into one shape, and a router with
no radios saying so rather than showing an empty table.

## Done — phase 3, *recording*

**`snapshot`.** Fifty-six menus into one dated file, `0600` in a `0700`
directory, with every secret replaced by its length on the way out and the
count printed. Not built on `POST /rest/export`, which answers `200` with an
empty array — the configuration text never comes back over REST. See
[Snapshot](Snapshot) and [Secrets](Secrets).

**`diff`.** Two snapshots compared field by field, keyed per menu on something
stable rather than on `.id`, with counters and clocks excluded — including
every `fp-*` fast-path counter, without which two snapshots of a live router
taken thirty seconds apart report every interface as changed. It refuses two
snapshots of different routers, and reports a menu that stopped being readable
as a change in the account rather than in the router.

**`shadow`.** The live configuration against the last snapshot, filtered to
arrivals in the twelve menus where an arrival is a decision somebody made.
Rows RouterOS created for itself are counted and hidden, because `/ip/service`
grows dynamic entries on its own and they would bury the one line that matters.

## Done — phase 4, *correlating*

**`patch`.** RouterOS against its own release channel, and the RouterBOARD
bootloader against the RouterOS installed. The current version is fetched from
`upgrade.mikrotik.com` **by this machine**, never by the router: asking the
router to check would change what a production box does on the wire. A failed
lookup produces `cannot say`, never `up to date`.

**`vuln`.** A real verdict rather than a reading list, which RouterOS makes
possible and UniFi does not: NVD carries version ranges for most of the corpus
and applies them itself. On top of that, two local passes NVD's match does not
do — the release branch, which turns 11 hits into 9 when the same version is
judged as long-term, and bounds that are not version numbers, of which the
corpus contains at least one. Three verdicts, never two. See [Vuln](Vuln).

**`footprint`.** The public addresses this router answers on, v4 and v6, with
the operator of each. `/ip/cloud` reports the public address even with DDNS
off, so the address list itself costs no outbound call at all.

**The enrichment layer.** `src/enrich/` — three lookups, all behind
`--allow-web`, all cached on disk at 0600, each reporting whether it fetched,
reused, skipped or failed. What is sent is a version string, a CPE, or a
public IP; never an inventory, a hostname or a line of configuration. See
[Enrichment](Enrichment).

**And the API it rests on.** `vuln.mlab.sh` gained a `?cpe=` parameter for
this: it forwards to NVD's `virtualMatchString`, and the CVE records now carry
`cpe_matches` with their version bounds intact rather than flattened to a
product name.

## Done — phase 5, *hunting*

**`hunt`.** Ten markers, drawn from the public post-mortems of the MikroTik
campaigns since 2018 — the one platform in this suite with a corpus that
specific. Every line is an observation and the command says on every run that
none of it is evidence on its own. See [Hunt](Hunt).

**The integrity checks.** The graded half: a scheduled task that fetches is
**high** and says *confirm you wrote it*; it becomes **critical** only when the
same script also changes accounts, SOCKS, the proxy or NAT — the combination
the campaigns left and no backup job needs. Plus netwatch scripts, files left
on the router's storage, and outbound tunnels.

**`logging`.** Where the log goes, judged by each action's target rather than
its name, and which topics are recorded at all — `account`, `system` and
`firewall` are the three that answer the questions asked after an incident, and
RouterOS records none of them by default.

**`blast`.** The segment matrix, with three states of which the middle one is
openly undecided. Host routes are excluded — a `/32` is the router talking to
itself — and a matrix where every pair says the same thing is printed as one
fact rather than a hundred rows.

## Then

**Phase 6, listening.** The binary API on 8728/8729 and its `/listen`
subscription — the real-time half of the tool, and the largest piece of pure
engineering. It unlocks nothing else, so it goes last.

## Also wanted

- Shell completions and a man page.
- A CI workflow on every push. Today the test gate only runs as part of a
  release, so a pull request gets no checks at all.
- Signed packages. Nothing signs these builds; `SHA256SUMS` stands in for it.
- A `--dry-run` on anything that ever gains the ability to write.
