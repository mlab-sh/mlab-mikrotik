# network

Addresses, bridges, VLANs, DHCP and routes — the five menus that define a
segment, side by side.

On RouterOS a VLAN is described in three menus at once, and reading any one of
them alone gives the wrong answer. Nothing here grades anything; that is phase
two's job.

```bash
mlab-mikrotik network
```

```
  Network

  addresses  21
  bridges    3 (4 ports)
  vlans      14 interfaces, 0 in bridge tables
  dhcp       0 servers, 5 pools
  routes     24 (18 active)

  Addresses

  ADDRESS        NETWORK      INTERFACE     RESOLVES TO    ORIGIN
  10.0.2.2/24    10.0.2.0     sfp-sfpplus3  sfp-sfpplus3   static
  192.0.2.5/24   192.0.2.0    ether1        ether1         static
  10.0.21.1/24   10.0.21.0    br-access     br-access      static
```

## Subcommands

| Command | Menus |
| --- | --- |
| `network` | The counts above, then the address table |
| `network addresses` | `/ip/address` |
| `network bridges` | `/interface/bridge` + `/interface/bridge/port` |
| `network vlans` | `/interface/vlan` + `/interface/bridge/vlan` |
| `network dhcp` | `/ip/dhcp-server` + `/ip/pool` + `/ip/dhcp-server/network` |
| `network routes` | `/ip/route` |

`addr`, `bridge`, `vlan` and `route` are accepted as aliases.

## bridges

```
  Bridges

  NAME        STATE     PORTS  VLAN FILTERING  STP   DHCP SNOOPING
  br-access   running   2      true            rstp  false
  br-guest    running   1      false           rstp  false
  br-spare    disabled  0      false           rstp  false

  Ports

  BRIDGE     INTERFACE      PVID  FRAME TYPES  HORIZON  STATE
  br-access  VLAN-300-A     1     admit-all    none     forwarding
  br-access  VLAN-100-B     1     admit-all    none     inactive
```

`VLAN FILTERING` on with every port at `pvid 1` and `admit-all` is the shape
worth noticing: the bridge is filtering, and the ports let everything in
untagged anyway. Phase two grades that; this command shows it.

## vlans

Two tables, because RouterOS has two ways of doing VLANs and they are not the
same thing. **VLAN interfaces** (`/interface/vlan`) are routed sub-interfaces
with addresses. The **bridge VLAN table** (`/interface/bridge/vlan`) is
switched tagging inside a bridge. When the second is empty, the page says so:

```
  Bridge VLAN table

  empty — VLANs on this router are interfaces, not bridge tags
```

## dhcp

Pools are reported with their occupancy, which is the number worth watching:

```
  Pools

  NAME         RANGES                    USED  AVAILABLE  TOTAL
  pool-access  10.0.21.2-10.0.21.254     31    223        253
```

A router that serves no DHCP says so plainly rather than showing an empty
table.

## routes

```
  Routes

  DESTINATION     GATEWAY      DISTANCE  TABLE  STATE     ORIGIN
  0.0.0.0/0       192.0.2.254  1         main   active    static
  10.0.21.0/24    br-access    0         main   active    dynamic
```

**ORIGIN** separates a decision someone made from a consequence of one:
RouterOS marks a row `dynamic` when something else created it — DHCP, a routing
protocol, a PPP session. **STATE** never reports a disabled route as active.
