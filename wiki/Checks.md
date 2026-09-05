# Checks

The catalogue of graded findings, what each one means, and the two rules that
decide whether something is allowed to appear at all.

## The two rules

**A severity is about what it costs, not how it looks.** A control that is
simply switched off is usually a decision, and stays out. A control that *reads
as* protection without being one belongs here. That is why a bridge with
`vlan-filtering=yes` whose ports admit everything is a finding, and a router
with no DHCP server is not.

**A check that could not run produces nothing.** Never a pass. Every check
declares the menus it needs; if one of them was refused or is absent, the check
is recorded as skipped and the count is printed in the footer of every report —
including a report with no findings. There is no code path by which a check
produces a pass without its data. See `Outcome::guard` in
`src/checks/mod.rs`.

## The catalogue

### accounts

| Check | Severity | Reads |
| --- | --- | --- |
| Accounts in a group carrying `write`, `policy` or `sensitive`, with no `address=` restriction | high | `/user`, `/user/group` |
| A group that reads as read-only and is not — grants `sensitive`, `reboot`, `sniff` or `romon` without `write`, and something uses it | medium | `/user/group`, `/user` |
| The default `admin` account is still enabled | medium | `/user` |
| Address restrictions applied to some accounts and not others | low | `/user` |

The third rule is deliberately mild: `admin` being enabled is not an
exploit, it is a name every attacker already knows. The fourth fires only on
*inconsistency* — every account being unrestricted is a policy, and reporting
it as an oversight would be wrong.

### services

| Check | Severity | Reads |
| --- | --- | --- |
| `telnet`, `ftp` or `www` enabled | high | `/ip/service` |
| Enabled services with no `available-from` | high | `/ip/service` |
| MAC-telnet or MAC-Winbox answering on every interface | medium | `/tool/mac-server`, `…/mac-winbox` |
| The router announces itself to its neighbours | medium / low | `/ip/neighbor/discovery-settings` |
| RoMON enabled | medium / low | `/tool/romon` |
| SSH accepts weak cryptography | medium | `/ip/ssh`, `/ip/service` |
| The bandwidth test server is enabled | medium / low | `/tool/bandwidth-server` |
| The NTP client is off | low | `/system/ntp/client` |

Three of these are graded on a condition rather than fixed. Discovery on a
**named** interface list is a decision and scores low; `all`, or a negated list
that resolves to nearly everything, scores medium. RoMON and the bandwidth
server drop to low when a secret or authentication is set.

`www` counts as cleartext because the REST API rides on it, and Basic auth
sends the password on every request.

### exposure

| Check | Severity | Reads |
| --- | --- | --- |
| The SOCKS proxy is enabled | **critical** | `/ip/socks` |
| The web proxy is enabled | high | `/ip/proxy` |
| UPnP is enabled | high | `/ip/upnp` |
| The DNS cache answers remote queries | high | `/ip/dns` |
| SNMP answers without cryptography | high / medium | `/snmp`, `/snmp/community` |
| SNMP accepts queries from any address | medium | `/snmp/community` |
| Port forwards with no source restriction | medium | `/ip/firewall/nat` |
| MikroTik Cloud DDNS is enabled | low | `/ip/cloud` |

SOCKS is the only critical in the catalogue, and it is graded on what its
presence usually *means* rather than on what the feature does: it is the relay
every MikroTik botnet campaign since 2018 has left behind. The finding says so,
and points at `/system/scheduler` and `/system/script` as the next place to
look.

SNMP rises to high when a community is named `public` or `private`.

### segmentation

| Check | Severity | Reads |
| --- | --- | --- |
| The `input` chain does not end in a refusal | high | `/ip/firewall/filter` |
| IPv6 configured and not filtered at all | high | `/ipv6/address`, `/ipv6/firewall/filter` |
| The `forward` chain does not end in a refusal | medium | `/ip/firewall/filter` |
| The IPv6 `input` chain does not close | medium | `/ipv6/firewall/filter` |
| A bridge carries VLANs without filtering them | medium | `/interface/bridge`, `/interface/vlan` |
| A bridge filters VLANs and its ports admit everything | low | `/interface/bridge/port` |

**What "closes" means, precisely.** A chain closes when its last *active* rule
is a `drop` or `reject` that narrows nothing — no address, port, protocol,
interface or connection state. That is the one ordering question answerable
without simulating a packet, and it is the only one this tool answers. A final
drop restricted to one destination address does **not** close the chain, and is
reported as such.

Link-local IPv6 addresses do not count as reachable, so a router that only has
`fe80::` produces nothing here.

### wireless

| Check | Severity |
| --- | --- |
| Profiles with no authentication | high |
| TKIP still allowed | high |
| WPA1 accepted without WPA2 | high |
| WPS enabled | high |
| Short pre-shared key (< 12 characters) | high |
| WPA2 only, no WPA3 transition | low |
| Management frame protection off | low |

RouterOS 7 ships two wireless stacks and a device carries one or the other;
both are normalised into one shape before anything is graded. A router with no
radios reports **wireless: not applicable**, which is a different fact from a
refused menu and is printed as one.

WPA2-PSK is graded low on purpose. It is not broken, and calling it a failure
is the kind of noise that gets a whole report ignored — but it leaves a
captured handshake open to offline attack, which is the one thing WPA3's SAE
removes.

**A masked key is never measured.** Without the `sensitive` policy the
pre-shared key comes back as `***`, and a length taken from that would be a
measurement of the mask. Those profiles are skipped rather than guessed at.

### patch

| Check | Severity | Reads |
| --- | --- | --- |
| RouterOS 6.x | high | `/system/resource` |
| The RouterBOARD bootloader is behind the installed RouterOS | medium | `/system/routerboard` |

Nothing here asks MikroTik anything. `/system/package/update` would, and it is
the *router* that makes the call, so it stays out of a passive audit — it
belongs to phase four, behind an explicit flag.

The bootloader check is the most common real finding on an otherwise current
router: RouterOS upgrades never move the RouterBOARD firmware, and nobody
remembers `/system routerboard upgrade`.

### logging

| Check | Severity | Reads |
| --- | --- | --- |
| Nothing this router logs survives a reboot | medium | `/system/logging`, `…/action` |
| No firewall refusal is logged | low | `/ip/firewall/filter` |

An action is judged by its **target**, not its name: an action called `remote`
that writes to memory is exactly the trap worth catching.

The second fires only when *every* refusal is silent. A quiet catch-all drop
next to a logged rule is a normal design, and saying so every time would be
noise.

## What is not checked

**Rule shadowing and dead rules.** Deciding that rule 12 can never match needs
per-packet evaluation of the whole ordered set. A tool that guesses at it
produces confident nonsense, so this one says nothing and prints why.

**Whether the firewall actually protects a given service.** `exposure` reports
what each service allows on its own; `firewall` reports whether each chain
closes. Joining the two into "port 8291 is reachable from the internet" would
need to know which interfaces face outward, and nothing in the configuration
says so reliably.

**Anything requiring a second point in time.** Accounts created since the last
review, scheduler entries that appeared, configuration that drifted: all of it
needs two dated collections, which is phase three.
