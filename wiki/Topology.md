# topology

The neighbours this router can hear, and what it announces about itself.

```bash
mlab-mikrotik topology
```

```
  Neighbours

  IDENTITY     ADDRESS      INTERFACE  VIA            PLATFORM                         MAC                AGE
  fw-edge-01   192.0.2.1    ether1     lldp           FortiGate-100F v7.2.11,build17…  00:00:5E:00:53:24  11s
  sw-core-02   10.0.69.5    tun-a      cdp,lldp,mndp  MikroTik RouterOS 7.23.3 (stab…  00:00:5E:00:53:25  12s
  rtr-partner  198.51.100.5 tun-a      cdp,mndp       MikroTik x86 7.23.2 (stable) 2…  00:00:5E:00:53:26  3s

  3 neighbours

  announcing on  !dynamic
  protocols      cdp,lldp,mndp
  lldp med       disabled

  › this router announces itself on "!dynamic" — every device on those links
    learns its identity, model and RouterOS version
```

## What this actually is

`/ip/neighbor` is filled by three protocols at once: MikroTik's own MNDP, plus
CDP and LLDP. Every row is a device that **announced itself** on a link. That
makes it the cheapest map of the adjacent network there is — no probe, no
scan, no packet sent at anything.

It also cuts both ways, which is why the second block exists.

## PLATFORM

MNDP fills `platform`, `board` and `version`. LLDP fills `system-description`
instead, and it is usually more precise — it carries the firmware build. The
column prefers the LLDP description when there is one, so a mixed-vendor link
reads consistently. A cross-vendor neighbour is the normal case here: LLDP is
how a MikroTik learns it is plugged into a Fortinet.

## What the router announces

`/ip/neighbor/discovery-settings` is the other half of the picture, and the
half that is a decision rather than an observation.

| Value | Means |
| --- | --- |
| `none` | The router announces itself nowhere |
| `all` | Every interface, including whatever faces the internet |
| `!dynamic` | Every interface except dynamically created ones |
| a list name | Only the interfaces in that interface list |

Anything other than `none` means the devices on those links learn this
router's identity, model and exact RouterOS version — which is a version
number handed to whoever is listening. MikroTik's own hardening guidance is to
set it to a named list covering management links only.

Phase two grades this. Phase one states it.

## JSON

```bash
mlab-mikrotik topology -o json | jq '.neighbours[] | {identity, via, platform}'
```

Carries `neighbours`, the full `discoverySettings` object, and `unreadable`.
