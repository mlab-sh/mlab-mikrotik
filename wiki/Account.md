# Account

The RouterOS user this CLI logs in as, and why choosing it carelessly gives a
"read-only" tool more power than anyone intended.

## The short version

```
/user group add name=mlab-audit policy=read,rest-api,api,!sensitive,!write,!policy,!reboot,!sniff,!romon,!ftp,!password
/user add name=mlab group=mlab-audit password=... address=203.0.113.10/32
```

Then `mlab-mikrotik whoami` says exactly what that account can do.

## Why not the built-in `read` group

Because it is not a reading group. This is its policy string, read verbatim off
a RouterOS 7.24 device:

```
local,telnet,ssh,reboot,read,test,winbox,password,web,sniff,sensitive,api,romon,rest-api,!ftp,!write,!policy
```

Four of those are not about reading:

| Policy | What it actually allows |
| --- | --- |
| `sensitive` | Returns pre-shared keys, IPsec secrets, SNMP communities and VPN passwords **in clear text** |
| `reboot` | Restarts the router |
| `sniff` | Captures traffic with the packet sniffer |
| `romon` | Reaches *other* routers over RoMON, from this one |

A group named `read` that can reboot the router and capture traffic is a
reasonable thing to hand an operator and a poor thing to hand an audit tool.
`whoami` reports every one of these under **Beyond reading**, so the gap
between the name and the grant is visible on the first run.

## What the CLI actually needs

| Policy | Why |
| --- | --- |
| `read` | Every menu this CLI reads |
| `rest-api` | The `/rest` transport itself — without it, nothing answers at all |
| `api` | Kept for the binary API and its `/listen` stream, which a later phase uses |

Everything else can be denied. `!sensitive` in particular costs almost nothing
today: no phase-one command reads a secret, and denying it means the tool
cannot leak one even by accident.

## `sensitive`, and what it means for a snapshot

If you do grant `sensitive` — and you will, the day a check needs to measure
pre-shared key strength — then everything the CLI writes to disk has to be
redacted on the way out, the way `mlab-unifi` does it: an explicit list of
field names, each replaced by its length rather than its value. A length is
not a secret and it is what a strength check needs.

Until then, `whoami` warns when the account carries `sensitive`, because a
tool that *could* have written a key to disk deserves the same scrutiny as one
that did.

## Restricting where the account can log in from

`address=` on the user is the cheapest control there is, and RouterOS accepts a
list:

```
/user set mlab address=203.0.113.10/32,198.51.100.0/24
```

`whoami` prints `allowed from anywhere` when it is empty, which on a router
with a public address is worth reading twice.

## Checking it worked

```bash
mlab-mikrotik whoami
```

```
  Account mlab

  instance        lab
  group           mlab-audit
  allowed from    203.0.113.10/32
  last logged in  2026-09-03 22:45:51
  policies        read, api, rest-api

  4 sessions
```

No **Beyond reading** section means the group grants nothing but reading. That
is the state to aim for.
