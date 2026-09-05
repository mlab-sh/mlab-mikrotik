# ping

Check that the current instance reaches its router, and report what answered.

```bash
mlab-mikrotik ping
```

```
  ✔ answered in 41ms

  instance  lab
  endpoint  https://192.0.2.1/rest
  identity  gw-edge-01
  routeros  7.24.2 (stable) on CCR2004-1G-12S+2XS
  uptime    6w2d11h04m
  tls       not verified
```

Two menus, `/system/resource` and `/system/identity`, which is the cheapest
pair that proves both the transport and the credentials.

## What the `tls` line means

| Value | What it is |
| --- | --- |
| `verified` | HTTPS, certificate checked against the system trust store |
| `not verified` | HTTPS against the router's self-signed certificate — the default |
| `none (plain http)` | The `www` service on port 80: no transport security at all |

## In a script

```bash
mlab-mikrotik ping -o json | jq -r .version
```

```json
{
  "instance": "lab",
  "endpoint": "https://192.0.2.1/rest",
  "identity": "gw-edge-01",
  "version": "7.24.2 (stable)",
  "boardName": "CCR2004-1G-12S+2XS",
  "uptime": "6w2d11h04m",
  "tlsVerified": false,
  "elapsed": "41ms"
}
```

Exit code 1 on any failure, with the reason and a hint:

```
  ✖ API error 401: Unauthorized (invalid user name or password)
hint: check the user and password, and that the user's group has the `rest-api` policy
```
