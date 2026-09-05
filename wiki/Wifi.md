# wifi

The radios, their security, and who is associated.

```bash
mlab-mikrotik wifi
```

```
  Radios (wifi stack)

  NAME   SSID   BAND     STATE    SECURITY  MAC
  wifi1  corp   5ghz-ax  running  corp      00:00:5E:00:53:30
  wifi2  guest  2ghz-ax  running  guest     00:00:5E:00:53:31

  2 radios

  Security profiles

  PROFILE  AUTH                 CIPHERS  PMF       WPS      KEY
  corp     wpa2-psk,wpa3-psk    ccmp     required  disable  24 characters
  guest    wpa2-psk             ccmp     allowed   disable  masked

  the key column says whether this account may read the pre-shared key at all —
  without the `sensitive` policy it comes back masked, and a length taken from a mask means nothing

  Associated

  MAC                INTERFACE  SIGNAL  UPTIME    RX      TX
  00:00:5E:00:53:40  wifi1      -54     2h11m03s  866Mbps 866Mbps

  1 client
```

## Two stacks

RouterOS 7 ships two wireless drivers and a device carries one or the other:

| Stack | Menu | Notes |
| --- | --- | --- |
| `wifi` | `/interface/wifi` | The current driver; called `wifiwave2` before RouterOS 7.13 |
| `wireless` | `/interface/wireless` | The legacy one, with `/interface/wireless/security-profiles` |

They name their properties differently — `passphrase` against
`wpa2-pre-shared-key`, `wps` against `wps-mode` — and both are normalised into
one shape before anything is shown or graded. The heading says which stack the
router is running.

## A router with no radios

```
  Wireless

  no radios on this router — neither /interface/wifi nor /interface/wireless
  carries an interface, which is what a wired-only device looks like
```

That is a statement, not an empty table. The menu the router does not carry
answers `400 no such command or directory`, which the collection layer records
as **absent** rather than as a refusal — and `audit` reports `wireless` as
*not applicable* rather than passing it.

## The KEY column

| Value | Means |
| --- | --- |
| `24 characters` | The account may read the key, and it is that long |
| `masked` | The router returned `***`: this account has no `sensitive` policy |
| `not set` | The profile carries no pre-shared key |

A length taken from a mask would be a measurement of the mask, so those
profiles are reported as masked and left alone — by this command and by the
check behind it. See [Account](Account) for what `sensitive` costs.

## What audit grades

Open networks, TKIP, WPA1, WPS and short keys are high; WPA2-without-WPA3 and
management frame protection off are low. The reasoning for each is in
[Checks](Checks).
