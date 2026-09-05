# mlab-mikrotik

**A CLI over the MikroTik RouterOS REST API, built as a base for passive
network security work.**

It talks to one router over `<scheme>://<host>/rest`, authenticating with a
RouterOS user and password, and an *instance* in `$HOME/.mlab/mikrotik.conf`
says which router to reach and how.

It reads. Every wrapped command issues nothing but GET requests, and the one
command that can send anything else refuses to until you pass `--write`.

Requires RouterOS 7.1 or later. Tested against 7.24.2 on a CCR2004.

---

## The commands

| Command | What it does |
| --- | --- |
| [`login`](Login) | Create or update an instance, prove the credentials work, save them. |
| [`ping`](Ping) | Check that the current instance reaches its router, and report what answered. |
| [`whoami`](Whoami) | What this account is, and everything it is allowed to read. **Start here.** |
| [`info`](Info) | What this router is: software, hardware, licence, health. |
| [`interfaces`](Interfaces) | The ports: state, addresses, and what is dropping packets. |
| [`clients`](Clients) | What the router knows about who is on the network. |
| [`network`](Network) | Addresses, bridges, VLANs, DHCP and routes. |
| [`topology`](Topology) | The neighbours this router hears, and what it announces itself. |
| [`audit`](Audit) | Every graded check in one report. |
| [`firewall`](Firewall) | The rules, and whether each chain closes. |
| [`exposure`](Exposure) | What this router offers to anything that can reach it. |
| [`posture`](Posture) | The settings that claim to defend something. |
| [`wifi`](Wifi) | The radios, their security, and who is associated. |
| [`snapshot`](Snapshot) | One dated, secret-free record of everything this account can read. |
| [`diff`](Diff) | What changed between two snapshots. |
| [`shadow`](Shadow) | What turned up that nobody announced. |
| [`patch`](Patch) | How far behind this router is, in RouterOS and in its bootloader. |
| [`vuln`](Vuln) | The published advisories that cover this exact version. |
| [`footprint`](Footprint) | What this router looks like from outside. |
| [`hunt`](Hunt) | The markers a compromised MikroTik router leaves behind. |
| [`logging`](Logging) | Where the log goes, and what never reaches it. |
| [`blast`](Blast) | What a compromised host on one segment reaches. |
| [`api`](Api) | Raw request against any menu, for everything not wrapped yet. |
| [`profile`](Configuration) | List, show, select and delete saved instances. |
| [`config`](Configuration) | Where the config file is, and what is in it. |

## Key concepts

- **[Account](Account)** — the RouterOS user this CLI logs in as, and why the
  built-in `read` group is not a reader's group.
- **[Surfaces](Surfaces)** — the one API a router answers on, what a read
  account actually reaches, and the six quirks that shape every command.
- **[Checks](Checks)** — the catalogue of graded findings, what each one means,
  and the two rules that decide whether something may appear at all.
- **[Secrets](Secrets)** — what never reaches the disk, and why the field list
  is explicit rather than a substring rule.
- **[Enrichment](Enrichment)** — everything that leaves this machine, all of it
  behind `--allow-web`, and why the router itself never makes the call.
- **[Configuration](Configuration)** — instances, and the precedence between
  flags, environment and file.
- **[Output](Output)** — a terminal render by default, raw JSON with
  `-o json`, and the rules that keep the two from mixing.
- **[Roadmap](Roadmap)** — what is built, what is next, in order.
- **[Releasing](Releasing)** — how a version becomes a Homebrew formula, a
  `.deb` and an `.rpm`, and how this wiki is mirrored.

## Getting started

```bash
cargo build --release
mlab-mikrotik login --name lab --host 192.0.2.1 --user mlab
mlab-mikrotik whoami
mlab-mikrotik audit
```

## Scope

Phases one to five: **reading**, **hardening**, **recording**,
**correlating**, **hunting**.

Everything is passive. Three commands can reach the network, each behind
`--allow-web`, each sending a version string or a public address and nothing
else — and none of them ever asks the *router* to contact anyone. See
[Enrichment](Enrichment).

There is no event stream on a RouterOS device, so detection is differential:
you do not read an alarm, you compare two dated collections. That is what
[`snapshot`](Snapshot), [`diff`](Diff) and [`shadow`](Shadow) are for.
