# Surfaces

The one API a RouterOS device answers on, what a read account actually
reaches, and the quirks that shape every command in this CLI.

## The REST API

One base URL, `<scheme>://<host>/rest`, and HTTP Basic authentication on every
request. A console menu maps straight onto a path: `/ip/address/print` becomes
`GET /rest/ip/address`.

RouterOS serves it from two separate services, and which one is on is a
per-device decision:

| Service | Port | Scheme |
| --- | --- | --- |
| `www-ssl` | 443 | `https`, with the certificate the router generated for itself |
| `www` | 80 | `http`, no transport security at all — Basic auth sends the password in the clear |

```
/ip service enable www-ssl
```

`--scheme http` exists for a lab. On anything reachable from outside, it means
the RouterOS password crosses the network in plain text on every request.

## What a read account reaches

Probed on RouterOS 7.24.2 with an account in the built-in `read` group. Every
menu below answered `200`:

| Menu | Rows | Used by |
| --- | --- | --- |
| `/system/resource`, `/routerboard`, `/license`, `/health`, `/clock`, `/package` | 1–10 | [`info`](Info) |
| `/user`, `/user/group`, `/user/active` | 7, 3, 4 | [`whoami`](Whoami) |
| `/interface`, `/ip/address` | 36, 21 | [`interfaces`](Interfaces) |
| `/ip/arp`, `/interface/bridge/host`, `/ip/dhcp-server/lease` | 6, 2, 0 | [`clients`](Clients) |
| `/ip/neighbor`, `/ip/neighbor/discovery-settings` | 3, 1 | [`topology`](Topology) |
| `/interface/bridge`, `/bridge/port`, `/bridge/vlan`, `/interface/vlan` | 3, 4, 0, 14 | [`network`](Network) |
| `/ip/pool`, `/ip/dhcp-server`, `/ip/route` | 5, 0, 24 | [`network`](Network) |
| `/ip/firewall/{filter,nat,mangle,raw,address-list}` | 16, 7, 0, 0, 6 | phase 2 |
| `/ipv6/firewall/filter`, `/ipv6/address` | 0, 12 | phase 2 |
| `/ip/{service,dns,cloud,upnp,socks,proxy,ssh}`, `/snmp` | 1 each | phase 2 |
| `/tool/{romon,mac-server,bandwidth-server}` | 1 each | phase 2 |

Nothing was refused. The `read` group reaches every configuration menu this
CLI is built on — which is precisely the point [Account](Account) makes.

## The eight quirks

**Every value is a string.** `"cpu-load": "3"`, `"disabled": "false"`. There is
no number and no boolean anywhere in a REST reply. The CLI funnels all of it
through one set of coercions in `src/ros/mod.rs`, and nothing calls
`as_u64()` on a router response directly.

**A missing package answers `400`, not `404`.** Asking a router that has only
the `wifi` driver for `/interface/wireless` gets:

```json
{"error":400,"message":"Bad Request","detail":"no such command or directory (wireless)"}
```

That is "this menu does not exist here", not "you may not". The CLI classifies
it as **absent** and reports it as one quiet line, where a refusal gets a
warning. See `src/collect.rs`.

**There is no pagination.** A menu answers with its whole collection in one
array. `/ip/firewall/connection` on a busy router is tens of thousands of rows,
which is why every wide collection goes through `.proplist`:

```bash
mlab-mikrotik api GET /interface --list --props name,type,running
```

**`.id` is volatile.** Row identifiers look like `*1` or `*4A` and are
reassigned freely. They are fine for addressing a row inside one run and
useless as a key for comparing two dated collections — which is why the
`diff` of a later phase will key on names and comments instead.

**Commands can time out at 60 seconds.** Anything that would run indefinitely
(`/ping`, `/tool/bandwidth-test`) has to be given a bounding parameter. No
phase-one command goes near them.

**`/file` can answer with something that is not JSON.** The menu embeds each
file's *contents*, so one binary file on the router's storage — an
`autosupout.rif`, a `.pcap` — makes the whole response invalid UTF-8. It comes
back as `200` with bytes that will not parse. Every read of `/file` in this
tool names its properties explicitly:

```bash
mlab-mikrotik api GET /file --list --props name,type,size,creation-time
```

**Some rows are created by the router, not by a person.** `/ip/service` grows
and loses `dynamic` rows on its own — `detnet`, `route_BGP`, `discover`, and a
`dhcp` entry that exists only while a lease renews. [`shadow`](Shadow) filters
them out of its arrivals for that reason, and counts what it hid.

**RouterOS 6 has no `/rest` at all.** It answers a REST call with its own web
page. The client reduces that page to one line and attaches the version hint,
rather than echoing a stylesheet into your terminal.

## What is not here yet

**The binary API** on TCP 8728/8729, and its `/listen` command — a documented
subscription to changes on almost any menu (`/ip/arp/listen`, `/log/listen`).
It is the real-time half of this tool and it is a protocol of its own, with
length-prefixed words. It is deliberately last on the [roadmap](Roadmap): it
unlocks nothing else.

**Nothing else.** `POST /rest/export` looked like the natural base for a
snapshot and is not: over REST it answers `200` with an **empty array**. The
configuration text never comes back, and the `file=` form writes to the
router's own storage, which a read-only tool has no business doing. Tested on
7.24.2 with `{}`, `{"compact":""}` and on a sub-menu; all three answer `[]`.

So [`snapshot`](Snapshot) records the REST menu catalogue instead — which is
the better shape anyway, because JSON diffs field by field where `.rsc` diffs
line by line.
