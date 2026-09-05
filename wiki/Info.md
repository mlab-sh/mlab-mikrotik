# info

What this router is: software, hardware, licence, health.

```bash
mlab-mikrotik info
```

```
  gw-edge-01 — RouterOS 7.24.2 (stable)

  model         CCR2004-1G-12S+2XS
  architecture  arm64
  cpu           ARM64 ×4 @ 1700 MHz, 0% load
  memory        3.7 GB free of 4.3 GB (14% used)
  storage       108.9 MB free of 134.2 MB
  uptime        6w2d11h04m
  built         2026-09-03 09:57:14
  clock         2026-09-03 23:20:43 (Europe/Paris)
  licence       level 6 (XXXX-XXXX)


  RouterBOARD

  serial              XXXXXXXXXXX
  revision            r2
  firmware            7.12.2
  firmware available  7.24.2


  Packages

  PACKAGE   VERSION  BUILT
  routeros  7.24.2   2026-09-03 09:57:14

  1 package

  Health

  SENSOR              VALUE  TYPE
  cpu-temperature     41     C
  fan-state           ok
  fan1-speed          1500   RPM
  psu1-state          ok
  psu2-state          ok
```

Seven menus: `/system/identity`, `/resource`, `/routerboard`, `/license`,
`/clock`, `/health` and `/package`.

## The two firmware lines

`firmware` and `firmware available` come from `/system/routerboard`, and they
are the bootloader — versioned separately from RouterOS and **not moved by a
RouterOS upgrade**. The example above is real behaviour: a router running a
fully current 7.24.2 was still booting a 7.12.2 bootloader, because nobody ran
`/system/routerboard/upgrade` after the last update.

The line says `up to date` when the two agree. When they do not, that gap is a
finding the graded checks will pick up in phase two.

## Health

`/system/health` is whatever the hardware exposes: temperatures, fan speeds,
PSU state, voltages. A CHR or an x86 install reports nothing at all, and the
section is then omitted rather than shown empty.

## Licence

`level` is what every MikroTik document calls the licence level. A CHR or x86
install has a `software-id` and no level; the line adapts.

## JSON

```bash
mlab-mikrotik info -o json | jq '{version: .resource.version, firmware: .routerboard."current-firmware"}'
```

The JSON is the raw menu content, unflattened — `resource`, `routerboard`,
`license`, `clock`, `health`, `packages` — plus `unreadable`.
