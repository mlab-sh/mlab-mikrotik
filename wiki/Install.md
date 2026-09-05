# Install

A recent Rust toolchain:

```bash
git clone https://github.com/mlab-sh/mlab-mikrotik.git
cd mlab-mikrotik && cargo build --release
```

The binary lands in `target/release/mlab-mikrotik`. Copy it onto your path, or
run it from the repository with `cargo run --`.

Or take a prebuilt one from the [releases
page](https://github.com/mlab-sh/mlab-mikrotik/releases): tarballs for macOS
and Linux on both architectures, a `.deb`, and an `.rpm`.

```bash
brew tap mlab-sh/mlab-mikrotik https://github.com/mlab-sh/mlab-mikrotik.git
brew install mlab-mikrotik
```

The Linux builds are linked against glibc 2.35, so Debian 12 and Ubuntu 22.04
and newer. Nothing signs these assets, so every release carries a `SHA256SUMS`
covering all of them:

```bash
sha256sum -c --ignore-missing SHA256SUMS
```

See [Releasing](Releasing) for how they are built.

## On the router

REST is served by the web services, which are off on a hardened device:

```
/ip service enable www-ssl
```

Then create an account for the CLI rather than reusing `admin`. The group
matters more than it looks — see [Account](Account):

```
/user group add name=mlab-audit policy=read,rest-api,api,!sensitive,!write,!policy,!reboot,!sniff,!romon,!ftp,!password
/user add name=mlab group=mlab-audit password=... address=203.0.113.10/32
```

## First run

```bash
mlab-mikrotik login --name lab --host 192.0.2.1 --user mlab
mlab-mikrotik whoami
mlab-mikrotik info
```

## Requirements

RouterOS **7.1 or later**: `/rest` does not exist before that. A version 6
router answers a REST call with its own web page, and the CLI says so:

```
  ✖ API error 404: RouterOS 404 Not Found
hint: /rest needs RouterOS 7.1+ with the www-ssl (or www) service enabled
```
