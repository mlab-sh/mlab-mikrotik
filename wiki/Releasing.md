# Releasing

How a version becomes a Homebrew formula, a `.deb`, an `.rpm` and four
tarballs.

## The whole procedure

1. Bump `version` in `Cargo.toml`.
2. Commit and push to `main`.
3. Run the **Release** workflow from the Actions tab.

That is the entire release process. The version is whatever `Cargo.toml` says —
there is no tag to create by hand, no changelog to assemble, and nothing to
upload. The workflow tags `v<version>` itself.

## What the workflow does

**A test gate first.** `cargo fmt --check`, `cargo clippy --all-targets
--locked -- -D warnings` and `cargo test --all --locked`. Nothing is built
until all three pass, so a release cannot ship code that would not have merged.

**Four targets**, built in parallel:

| Target | Runner |
| --- | --- |
| `x86_64-apple-darwin` | `macos-latest` |
| `aarch64-apple-darwin` | `macos-latest` |
| `x86_64-unknown-linux-gnu` | `ubuntu-22.04` |
| `aarch64-unknown-linux-gnu` | `ubuntu-22.04` |

Ubuntu is **pinned to 22.04 on purpose**. A glibc binary never runs against a
glibc older than the one it was linked with, and `ubuntu-latest` (24.04,
glibc 2.39) produces binaries that refuse to start on Debian 12 and Ubuntu
22.04. Pinning lowers the floor to glibc 2.35.

The ARM64 Linux build needs a C cross-compiler: `ring`, underneath rustls,
compiles C, so a linker alone is not enough — the workflow installs
`gcc-aarch64-linux-gnu` and `binutils-aarch64-linux-gnu`.

**Packages** for the two Linux targets only, from the metadata in
`Cargo.toml`:

- `.deb` via `cargo-deb`, with `--no-strip` because the release profile already
  strips. Letting cargo-deb strip again would run the *host* strip against the
  aarch64 binary and fail the cross build.
- `.rpm` via `cargo-generate-rpm`, with the binary staged at `pkg/` first: the
  rpm asset paths are taken literally, so pointing them at `target/release`
  would package the host build — the wrong architecture entirely on a cross
  run. Compressed with gzip rather than the zstd default, so rpm 4.14 (RHEL 8
  and its rebuilds) can still read the payload.

**A Homebrew formula**, generated from the checksums just computed and
committed back to the repository. It is generated rather than hand-edited
precisely because it carries hashes.

**`SHA256SUMS`**, covering every asset. Nothing signs these builds, so the
checksums are the only way a manual download can be checked.

## The wiki mirror

A second workflow, `wiki-sync.yml`, pushes `wiki/` to the GitHub wiki on every
push to `main` that touches it.

**The repository is the source of truth.** Pages edited in the wiki web UI are
overwritten on the next sync — edit the files in `wiki/` instead.

The wiki repository only exists once a first page has been created in the UI.
Until then the workflow fails with a message saying exactly that.

## What is not automated

**Tests do not run on every push**, only as the release gate. A pull request
gets no CI. Adding a third workflow would fix it, and it is not there yet.

**Nothing is signed.** No GPG on the packages, no notarization on the macOS
binaries — a first run on macOS needs Gatekeeper to be told to allow it. The
`SHA256SUMS` file is what stands in for signatures.
