# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

`nxthdr` is the command-line client for the nxthdr platform, published to crates.io as the `nxthdr` binary. It is an async Rust (tokio) CLI built with `clap` (derive API) that talks to the platform's HTTP APIs and to public BGP data sources.

## Commands

```bash
cargo build                       # build (CI runs `cargo build --verbose`)
cargo test                        # run tests (CI runs `cargo test --verbose`)
cargo test <name>                 # run a single test by name substring
cargo run -- <args>               # run locally, e.g. `cargo run -- peering route list`
cargo run -- -o json <args>       # force JSON output
cargo fmt && cargo clippy         # format + lint (not enforced in CI, but expected)
```

CI (`.github/workflows/cicd.yml`) only builds and tests. Publishing to crates.io happens on a git tag; multi-arch Docker images are built on every push.

### Endpoint overrides (for local/staging testing)

All service endpoints fall back to production but can be overridden via env vars — use these to point the CLI at a local backend instead of editing code:

- `NXTHDR_API_URL` — PeerLab API (default `https://peerlab.nxthdr.dev`)
- `NXTHDR_SAIMIRIS_API_URL` — Saimiris/probing API (default `https://saimiris.nxthdr.dev`)
- `NXTHDR_RIS_URL` — RIPEstat (default `https://stat.ripe.net`)
- `NXTHDR_CLIENT_ID` — Auth0 client id

## Releasing

Publishing to crates.io is **git-tag-driven**: the `publish` job in `cicd.yml` runs `cargo publish` only on a `refs/tags/` push (after `tests` pass). Auth is **crates.io Trusted Publishing (OIDC)** — `rust-lang/crates-io-auth-action` mints a short-lived token at run time (auto-revoked when the job ends), so there is **no `CARGO_REGISTRY_TOKEN` secret**. The trust is configured on crates.io (crate Settings → Trusted Publishing → GitHub: owner `nxthdr`, repo `cli`, workflow `cicd.yml`, no environment); the job needs `id-token: write`. To cut a release:

1. Bump `version` in `Cargo.toml` (semver — breaking command changes warrant a minor bump pre-1.0) and land it on `main` **via a PR** — either its own `chore: Release nxthdr version X.Y.Z` PR or folded into the feature PR that motivates the release. `main` is ruleset-protected (review required) and you can't approve your own PR, so a solo maintainer bypasses the review gate with an admin merge: `gh pr merge <n> --squash --admin`.
2. Tag the merged commit on `main` and push the tag — tags are **not** ruleset-protected, so this is a direct push (no PR):
   ```bash
   git tag vX.Y.Z && git push origin vX.Y.Z
   ```
   The bump must already be on `main` first: the `publish` job **verifies the tag matches `Cargo.toml`** (stripping the leading `v`) and fails fast on a mismatch.
3. The tag push runs CI; on success it publishes `nxthdr` X.Y.Z to crates.io (via OIDC) and pushes docker images tagged `X.Y.Z` / `X.Y`. Confirm the `publish` job is green and crates.io shows the new version.
4. **Create the GitHub Release** — CI does *not* do this, but every prior version has one. Match the repo's auto-generated-notes style:
   ```bash
   gh release create vX.Y.Z --generate-notes --latest --verify-tag
   ```

Gotchas: the `Cargo.toml` version must be a not-yet-published version — `cargo publish` hard-fails on a duplicate, and crates.io is publish-once (you can only *yank*, never unpublish). `Cargo.lock` is gitignored (nothing to bump). To re-publish an already-pushed tag after changing the workflow itself, delete and re-push the tag (`git push origin :vX.Y.Z`, then re-tag `origin/main` and push) — `gh run rerun` would reuse the workflow from the tag's *old* commit, not the new one.

## Architecture

The CLI is organized as thin layers; command modules call a shared HTTP client and route all user-facing output through one module.

- **`main.rs`** — the entire CLI surface (clap `Cli`/`Commands` enums), command dispatch, and the auth lifecycle handlers (`login`/`logout`/`status`). Two global flags apply everywhere: `-o/--output text|json` and `clap-verbosity-flag` verbosity (wired into `tracing_subscriber`). Adding a command means adding a variant here (keeping the `<group> <resource> <verb>` structure — see Conventions) and a handler in the relevant feature module.
- **`api.rs`** — `ApiClient`, a small `reqwest` wrapper with `get`/`get_public`/`post`/`put`/`delete`. There are **two backends**: `ApiClient::new()` (PeerLab API) and `ApiClient::new_saimiris()` (probing API) — pick by which platform the command targets. Authed methods inject the bearer token and validate expiry first (deleting tokens and erroring if expired); `get_public` skips auth.
- **`auth.rs`** — Auth0 **OAuth2 Device Authorization flow**: `start_device_flow` → `poll_for_token` (handles `authorization_pending`/`slow_down`) → tokens. `refresh_access_token` renews using the stored refresh token. Returns `(access_token, refresh_token, expires_at_unix_secs)`.
- **`config.rs`** — token persistence to `tokens.json` in the OS config dir (`directories::ProjectDirs::from("dev", "nxthdr", "nxthdr")`). Expiry is enforced client-side from `expires_at`.
- **`output.rs`** — the single output abstraction. A thread-local `OutputFormat` (set once in `main`) makes every helper format-aware across three formats (`text`/`json`/`csv`): `section`/`info`/`success`/`warn`/`hint` render only in text mode (gate any text-only decoration or truncation on `output::is_text()`), while `kv` and `table` emit aligned text, structured JSON, **or** RFC-4180 CSV (a `kv` block becomes a single-row CSV; `table` is header + rows). Auto-sizes column widths in text mode.
- **`peering.rs`** — peering commands against the PeerLab API (`/api/user/info`, `/api/user/prefix`, …), plus `routes`/`lookup` which layer on `ris.rs` for BGP visibility.
- **`probing.rs`** — probing commands against the Saimiris API, plus `results` which queries ClickHouse directly.
- **`ris.rs`** — RIPEstat looking-glass client (15s timeout since it's an external public service). Aggregates RIS data into `Visibility` (peer/collector counts, origins, AS paths) and computes propagation % against the full-feed peer count.

## Conventions specific to this repo

- **Command structure is `<group> <resource> <verb>`** (gh/docker style). Top-level groups are `auth`, `peering`, `probing`. Under each, every resource is a **singular-noun subcommand group** (`agent`, `measurement`, `reply`, `asn`, `credits`, `prefix`, `route`) whose leaves are **verbs**: listing is `<resource> list`, a single-value read is `<resource> get` (e.g. `asn get`, `credits get`), other actions are explicit verbs (`send`, `cancel`, `request`, `revoke`, `lookup`, `enable`/`disable`). When adding a command, fit it into an existing resource group or add a new singular-noun group — **never a bare top-level verb or a noun-ending leaf**. Deliberate exceptions are `peering peerlab env` (a codegen utility with no natural verb) and the top-level `completions <shell>` (a meta-command in the same class as the built-in `help`/`--version`, not a platform resource — it generates clap completion scripts via `clap_complete` and writes them to stdout).
- **Request/response types are declared inline inside each command function**, not in a shared models module (e.g. a local `#[derive(Deserialize)] struct UserInfo` scoped to `asn()`). Follow this — only hoist a type when genuinely shared. Each function deserializes just the fields it needs.
- **Never `println!` user-facing data directly** — route everything through `output.rs` so `-o json`/`-o csv` keep working. The deliberate exception is output that is machine-data-by-design: `peering peerlab env` writes a dotenv file to stdout. Every command must handle its empty/“nothing found” case via `output::empty(headers)`, which prints `[]` (JSON) or a header-only row (CSV) and returns `true`, or returns `false` in text mode so the caller can emit a friendly note + hint.
- **Errors use `anyhow`** end to end (`.context(...)`, `anyhow::bail!`, `anyhow::ensure!`); they bubble up to `main`. Attach user-actionable context (e.g. suggest the `nxthdr` command to run next via `output::hint`).
- **`tracing::debug!`** is the channel for diagnostic detail (URLs, derived values); surface it with `-v`.

## Domain notes

- **Peering / RIS:** leased prefixes are announced via PeerLab's export ASN **AS215011** — a user's private ASN is stripped on export, so `peering route list` reports AS215011 as origin. Visibility/propagation come from public RIPE RIS collectors and lag announcements by a few minutes.
- **Probing source IPs:** `probing measurement send` derives each agent's IPv6 source address by overwriting the host bits of the agent's allocated prefix with a **single shared random 48-bit value** (`random_host_48`), so all replies from one measurement share an identifier and can be queried together without server-side state. `--src-ip` overrides this.
- **Probe input format:** `probing measurement send` reads CSV lines `dst_addr,src_port,dst_port,ttl,protocol` (protocol `icmpv6`|`udp`) from a file or stdin; `#` comments and blank lines are skipped.
- **Replies:** `probing reply list` queries the public read-only ClickHouse endpoint (table `saimiris.replies`) directly over HTTP, bypassing the platform API.
