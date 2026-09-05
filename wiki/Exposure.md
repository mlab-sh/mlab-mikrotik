# exposure

What this router offers to anything that can reach it.

Two layers, reported separately because they fail independently: the services
the router itself listens on, and the forwards that publish something behind
it.

```bash
mlab-mikrotik exposure
```

```
  Listening

  SERVICE     PORT   AVAILABLE FROM   VRF
  www         80     anywhere         main
  ntp         123    anywhere
  snmp        161    203.0.113.0/24
  winbox      8291   anywhere         main
  winbox      8291   anywhere

  5 services
  4 of them accept connections from any address — whether the firewall stops them
  is a separate question, see `firewall`

  Published from outside

  PROTO  PORT  FROM      TO
  tcp    3389  anywhere  10.0.0.5:3389

  1 forward

  Relays and reflectors

  FEATURE                     STATE  DETAIL
  SOCKS proxy                 off
  web proxy                   off
  UPnP                        on
  DNS answers remote queries  off
  MikroTik Cloud DDNS         off

  these are the features that make a router useful to somebody else
```

## AVAILABLE FROM is the service's own control

RouterOS calls it `available-from`, and it is a separate layer from the
firewall. `anywhere` means the service accepts a connection from any address
that reaches it — which still matters when a firewall rule is edited by
mistake, because it is the control that keeps applying.

The command deliberately does **not** claim a service is reachable from the
internet. That would need to know which interfaces face outward, and nothing in
the configuration says so reliably. It reports the service's own restriction
and points at [`firewall`](Firewall) for the other half.

## Why a service can appear twice

RouterOS 7 lists a service once per VRF. Two rows named `winbox` on port 8291,
one bound to `main` and one bound to nothing, are two real rows — not a
duplicated line. `audit` names them apart as `winbox:8291 (vrf main)`.

## Relays and reflectors

The five features that make a router useful to somebody else:

| Feature | Why it is on this list |
| --- | --- |
| SOCKS proxy | The relay every MikroTik botnet campaign since 2018 has left behind |
| Web proxy | Relays traffic on this router's address; its cache is where the `error.html` campaigns put their payload |
| UPnP | Any host on the inside can open an inbound port without asking anyone |
| DNS answering remote queries | An open resolver, usable to amplify traffic at a third party |
| Cloud DDNS | Publishes this router's public address to MikroTik, reachable at a `<serial>.sn.mynetname.net` name |

`audit` grades SOCKS **critical** — not for what the feature does, but for what
its presence usually means. See [Checks](Checks).

## JSON

```bash
mlab-mikrotik exposure -o json | jq '.listening[] | select(.availableFrom=="anywhere")'
```

Carries `listening`, `forwards`, `relays` and `unreadable`.
