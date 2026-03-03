# node-onboarding

The onboarding and management server that ships inside every Holo Sovereign Node ISO.

It is a single Rust binary with zero external dependencies — no Tokio, no Axum, no serde. It serves a browser UI over plain TCP on port 8080 and handles the full lifecycle of a node: first-time setup, SSH key management, AI agent configuration, hardware mode switching, and binary self-updates pulled from this repository's GitHub Releases.

---

## Table of contents

1. [How it fits into the system](#how-it-fits-into-the-system)
2. [What it does](#what-it-does)
3. [Building locally](#building-locally)
4. [Repository structure](#repository-structure)
5. [Shipping a release](#shipping-a-release)
6. [Self-update mechanism](#self-update-mechanism)
7. [Routes reference](#routes-reference)
8. [File paths on the node](#file-paths-on-the-node)
9. [Security model](#security-model)
10. [Adding a new chat channel](#adding-a-new-chat-channel)
11. [Contributing](#contributing)

---

## How it fits into the system

```
holo-host/holo-node-iso          holo-host/node-onboarding
        │                                  │
        │  bakes the binary into           │  source + release pipeline
        │  the FCOS image at               │
        │  build time                      │  GitHub Actions builds two
        │                                  │  musl-static binaries on
        ▼                                  │  every version tag
┌─────────────────────┐                    ▼
│   Holo Node ISO     │       node-onboarding-x86_64
│                     │       node-onboarding-aarch64
│  /usr/local/bin/    │
│  node-onboarding ◄──┼── baked in at ISO build time
│                     │
│  node-onboarding    │   After first boot, the binary
│  .service (systemd) │   checks GitHub Releases hourly
│                     │   and replaces itself in-place
└─────────────────────┘   without needing a new ISO.
```

The ISO build repo (`holo-host/holo-node-iso`) downloads the binary from the latest GitHub Release here and bakes it into the FCOS image. Once a node is running, subsequent updates to this binary are delivered automatically — no new ISO required.

---

## What it does

### First boot

On first boot the binary generates a random 12-character password, writes its SHA-256 hash to `/etc/node-onboarding/auth`, and displays the password and the node's local IP address on the HDMI-connected screen (`/dev/tty1`) in large coloured text. The node operator uses that information to open the setup UI in a browser.

### Onboarding wizard

A four-step browser UI walks the operator through:

1. **Node identity & SSH** — node name (used as hostname slug) and optional SSH public key for the `holo` user
2. **AI agent** — opt-in toggle (default off); if enabled, choose a chat platform and credentials
3. **AI engine & hardware mode** — provider/model selection (if agent enabled), autonomy level, and initial container mode (EdgeNode or Wind Tunnel)
4. **Review & initialize** — summary before committing

After the operator submits, the server configures everything, starts the appropriate container service, sends a welcome message through the chosen chat platform (if agent enabled), and redirects the browser to the management panel. The server **does not shut down** — it stays running permanently.

### Management panel (`/manage`)

After onboarding, `GET /` redirects to `/manage`. The panel (password-protected) lets the operator:

- Add and remove SSH public keys for the `holo` user without physical access
- Enable or disable the ZeroClaw AI agent at any time
- Hot-swap the AI provider, model, and API key without re-onboarding
- Switch hardware mode between Standard EdgeNode and Wind Tunnel
- Change the node password
- Trigger an immediate software update check

### Self-update

A background thread wakes every hour, queries the GitHub Releases API for this repository, and compares the latest tag against the compiled-in `VERSION` constant. If a newer version exists it downloads the architecture-matched binary, atomically replaces the running binary on disk, and calls `systemctl restart node-onboarding.service`. The update check can also be triggered manually from the `/manage` panel.

---

## Building locally

### Prerequisites

- Rust stable (1.75 or newer)
- For the static musl builds that ship in the ISO: `musl-tools` (`apt install musl-tools`) and the musl targets added to your toolchain

```bash
# Add musl targets (first time only)
rustup target add x86_64-unknown-linux-musl
rustup target add aarch64-unknown-linux-musl
```

### Development build (dynamic, your host OS)

```bash
cargo build
./target/debug/node-onboarding
# Open http://localhost:8080
```

### Production build (static musl — what goes in the ISO)

```bash
# x86_64
cargo build --release --target x86_64-unknown-linux-musl

# aarch64 (requires aarch64-linux-gnu-gcc cross-compiler)
sudo apt install gcc-aarch64-linux-gnu
CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=aarch64-linux-gnu-gcc \
  cargo build --release --target aarch64-unknown-linux-musl
```

The resulting binaries are fully static — no glibc, no external libraries. They run on any FCOS image regardless of what userland packages are present.

### Testing the UI locally

```bash
cargo run
# Visit http://localhost:8080
# On first run it will print the generated password to stderr since /dev/tty1
# won't exist on a dev machine.
```

To simulate an already-onboarded node (skip to /manage):

```bash
mkdir -p /etc/node-onboarding
echo "onboarded=true\nnode_name=test\nhw_mode=STANDARD\nagent_enabled=false" \
  > /etc/node-onboarding/state
cargo run
# GET / will redirect to /manage
```

---

## Repository structure

```
node-onboarding/
├── main.rs                  ← entire server (single file, std-only)
├── holo-node.md             ← ZeroClaw skill file, embedded via include_str!
├── Cargo.toml
├── Cargo.lock
├── .github/
│   └── workflows/
│       └── release.yml      ← builds + publishes binaries on version tag
└── README.md
```

The server is intentionally a single file with no dependencies so it can be audited easily and compiled without a network connection.

---

## Shipping a release

Every release publishes two binary assets:

| Asset name                    | Architecture          |
|-------------------------------|-----------------------|
| `node-onboarding-x86_64`      | x86-64 (most hardware)|
| `node-onboarding-aarch64`     | ARM64 (Raspberry Pi, Apple Silicon VMs) |

**These asset names are load-bearing.** The self-update code in `find_asset_download_url()` searches for them by exact name. Do not rename them.

### Step-by-step release process

1. Make your changes to `main.rs` (and/or `holo-node.md`).

2. Update the version in **two places** — they must match exactly:
   - `const VERSION: &str = "5.1.0";` in `main.rs`
   - `version = "5.1.0"` in `Cargo.toml`

3. Commit:
   ```bash
   git add main.rs Cargo.toml
   git commit -m "release: v5.1.0 — <one line summary of changes>"
   ```

4. Tag and push:
   ```bash
   git tag v5.1.0
   git push origin main
   git push origin v5.1.0
   ```

5. GitHub Actions (`.github/workflows/release.yml`) picks up the tag, builds both binaries using musl static linking, creates a GitHub Release, and attaches both binary assets automatically. No manual upload needed.

6. Running nodes pick up the update within 60 minutes. Operators can trigger it immediately from the `/manage` panel's "Software Update" section.

### What the release workflow does

```yaml
on:
  push:
    tags:
      - 'v*'
```

It runs a matrix build for both targets, cross-compiles using `musl-tools` and `gcc-aarch64-linux-gnu`, and uses `softprops/action-gh-release` to create the release and attach the assets. See `.github/workflows/release.yml` for the full workflow.

---

## Self-update mechanism

The update logic lives in `check_and_apply_update()` and `spawn_update_checker()`.

**Flow:**
1. Background thread sleeps 90 seconds after startup (gives the server time to fully come up), then checks every `UPDATE_INTERVAL_SECS` (3600 = 1 hour).
2. Hits `https://api.github.com/repos/{UPDATE_REPO}/releases/latest` using `curl` (the server itself doesn't use curl/wget for agent commands but the binary itself can invoke system curl for update checks).
3. Parses `tag_name` from the response and compares `tag_name.trim_start_matches('v')` against the compiled-in `VERSION` const.
4. If newer: downloads the arch-matched asset (`node-onboarding-x86_64` or `node-onboarding-aarch64`) to `/tmp/node-onboarding-update`.
5. `chmod +x`, then `fs::rename()` to replace the running binary atomically.
6. `systemctl restart node-onboarding.service` — systemd restarts the process, which picks up the new binary.

**Environment variable:**
```
UPDATE_REPO=holo-host/node-onboarding   # default; override for forks/testing
```

**Rollback:** There is no automatic rollback. If a bad binary is released, publish a new release with a higher version number. The broken binary will attempt to restart, fail (if it panics on startup), and systemd's `Restart=always` will keep retrying — meaning the node will retry the update check as soon as a good release is available, because each restart re-runs the update checker.

---

## Routes reference

### Public (no authentication required)

| Method | Path       | Description |
|--------|------------|-------------|
| GET    | `/`        | Onboarding wizard (pre-onboard) or redirect to `/manage` (post-onboard) |
| GET    | `/login`   | Login page |
| POST   | `/login`   | Authenticate; sets `session` cookie; redirects to `/manage` |
| POST   | `/logout`  | Clears session cookie; redirects to `/login` |
| POST   | `/submit`  | Runs onboarding; expects JSON body |

### Authenticated (require valid `session` cookie)

| Method | Path                    | Description |
|--------|-------------------------|-------------|
| GET    | `/manage`               | Management panel HTML |
| GET    | `/manage/status`        | Current node state as JSON |
| POST   | `/manage/ssh/add`       | Add SSH public key `{"key":"ssh-ed25519 ..."}` |
| POST   | `/manage/ssh/remove`    | Remove SSH key by index `{"index":0}` |
| POST   | `/manage/agent`         | Enable/disable agent `{"enabled":true}` |
| POST   | `/manage/provider`      | Hot-swap provider `{"provider":"anthropic","model":"...","apiKey":"..."}` |
| POST   | `/manage/hardware`      | Switch mode `{"mode":"WIND_TUNNEL"}` |
| POST   | `/manage/password`      | Change password `{"current":"...","newPassword":"..."}` |
| POST   | `/manage/update`        | Trigger immediate update check |

Sessions last 24 hours. Session tokens are stored in-memory and cleared on restart — operators will need to log in again after an update.

---

## File paths on the node

| Path | Contents | Permissions |
|------|----------|-------------|
| `/etc/node-onboarding/state` | Key-value store of node state (node_name, hw_mode, agent_enabled, channel, provider, model) | 600 |
| `/etc/node-onboarding/auth` | Password hash: `sha256:<salt>:<hash>` | 600 |
| `/etc/node-onboarding/provider` | Provider credentials for agent re-enable | 600 |
| `/etc/zeroclaw/config.toml` | ZeroClaw agent configuration (if agent enabled) | 600 |
| `/etc/zeroclaw/skills/holo-node.md` | Embedded ZeroClaw skill | 644 |
| `/etc/containers/systemd/edgenode.container` | Podman Quadlet for the EdgeNode container | 644 |
| `/etc/containers/systemd/wind-tunnel.container` | Podman Quadlet for Wind Tunnel | 644 |
| `/home/holo/.ssh/authorized_keys` | SSH public keys for the holo user | 600 |
| `/var/lib/zeroclaw/workspace/mode_switch.txt` | Current hardware mode (STANDARD or WIND_TUNNEL) | 644 |
| `/var/lib/edgenode/` | EdgeNode persistent data volume | — |

---

## Security model

### Authentication

The server is protected by a single password (the "node password"). On first run a random 12-character password is generated (charset excludes ambiguous characters: `0`, `O`, `1`, `l`, `I`), hashed as `sha256:<8-hex-salt>:<sha256(salt:password)>`, and the hash is stored at `/etc/node-onboarding/auth` (chmod 600). The cleartext password is never stored — it is only displayed once on the HDMI screen and logged to the systemd journal.

Sessions are 24-hour cookie-based tokens stored in-memory. They are cleared on server restart. All `/manage/*` routes require an active session; unauthenticated requests are redirected to `/login`.

### SSH access

SSH access is provided only for the `holo` system user. Root login is disabled via `/etc/ssh/sshd_config.d/90-holo.conf`. Password authentication is disabled — SSH keys only. SSH is intended as a "break glass" access path, not the primary management interface. The `/manage` panel is the primary interface.

### AI agent command allowlist

The ZeroClaw AI agent operates against a strict allowlist. `curl` and `wget` are intentionally excluded to prevent the agent from making arbitrary outbound HTTP requests. The full list:

```
ls, cat, grep, find, head, tail, wc, echo, pwd, date, git,
podman, docker, systemctl, journalctl,
chmod, chown, mkdir, rm, cp, mv, touch,
df, du, ps, free, uname, env, which
```

The agent also cannot write outside `/var/lib/zeroclaw/workspace` (enforced by `allowed_roots` in the ZeroClaw config) and cannot modify system files (enforced by `forbidden_paths`).

### Network exposure

The server binds to `0.0.0.0:8080`. It is intended to be reachable only on the local network — the FCOS firewall configuration in `holo-node-iso` should not expose port 8080 to the internet. The UI has no HTTPS; TLS termination (if desired) should be handled at the network edge.

---

## Adding a new chat channel

1. Add a credentials block to the HTML in `build_onboarding_html()` (copy the pattern from the `cr-telegram` div).
2. Add a case to `build_channel_toml()` that serialises the credentials to TOML.
3. Add a case to `send_welcome_message()` that posts the welcome message via the channel's API.
4. Add the channel to the `extract_channel_config()` regex-free parser if the section header differs from the `[channels_config.<name>]` pattern.
5. Test locally; submit a PR.

---

## Contributing

This repository is intentionally kept simple. Before contributing, please read the design constraints:

- **No async runtime.** The server uses `std::thread` for concurrency. Each connection spawns a thread. This is appropriate for a UI that handles at most a handful of simultaneous requests.
- **No third-party crates.** `std` only. This keeps the binary small, the build reproducible, and the audit surface minimal.
- **Single file.** `main.rs` contains the entire server. This is a deliberate choice for auditability — an operator should be able to read the entire source in one sitting.

Pull requests that introduce dependencies or split the code across multiple files will not be accepted unless there is a very strong reason.

For bug reports or feature requests, open an issue. For security issues, contact security@holo.host directly.
