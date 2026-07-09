# node-manager

The onboarding and management server that ships inside every Holo Node.

It is a single Rust binary with one external dependency (`bip39` for recovery seed phrases). It serves a browser UI over plain TCP on port 80 and handles the full lifecycle of a node: first-time setup, SSH key management, Unyt Agent ID linking for HoloFuel compensation, hardware mode switching, and binary self-updates pulled from this repository's GitHub Releases.

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
10. [Contributing](#contributing)

---

## How it fits into the system

```
holo-host/holo-node-iso          holo-host/node-manager
        │                                  │
        │  Butane YAML + build scripts     │  source + release pipeline
        │                                  │
        │  ISO contains node-setup.sh,     │  GitHub Actions builds two
        │  a first-boot shell script       │  musl-static binaries on
        │                                  │  every version tag
        ▼                                  │
┌─────────────────────┐                    ▼
│   Holo Node ISO     │       node-manager-x86_64
│                     │       node-manager-aarch64
│  node-setup.sh ─────┼──────────────────────────────►  downloaded at first boot
│  (inlined script)   │
│                     │
│  node-manager       │   After first boot, the binary
│  .service (systemd) │   checks GitHub Releases hourly
│                     │   and replaces itself in-place
└─────────────────────┘   without needing a new ISO.
```

The binary is **not baked into the ISO**. Instead, the ISO contains `node-setup.sh` — a small bash script that runs once on first boot, downloads the appropriate binary from the latest GitHub Release here, and exits. From that point on, the binary self-updates hourly. No new ISO is required to deliver updates to running nodes.

---

## What it does

### First boot

On first boot `node-setup.sh` (part of the ISO) downloads this binary from the latest GitHub Release and installs it to `/usr/local/bin/node-manager`. Once installed, `node-manager.service` starts and listens on port 80.

The operator opens `http://holo.local` (or `http://<node-ip>`) in a browser to complete setup. No password is pre-generated — the operator chooses one during onboarding.

### Onboarding wizard

A two-step browser UI walks the operator through:

1. **Node identity & access** — node name (used as hostname slug), hardware mode, optional SSH public key, optional Unyt Agent ID, and a user-defined password (minimum 8 characters)
2. **Review & initialize** — summary before committing

When Wind Tunnel mode is selected, the Nomad client hostname is `nomad-client-{node_name}` (must fit within 63 characters total, so the node name can be at most 50 characters). The optional Unyt Agent ID is stored separately in `client-meta.json` for HoloFuel compensation and is independent of hostname length.

On successful initialization, the server:

- Hashes and stores the chosen password at `/etc/node-manager/auth`
- Generates a 12-word BIP39 recovery seed phrase, hashes it, and stores the hash in `/etc/node-manager/state` as `seed_hash`
- Returns the plain-text seed phrase once in the JSON response

The UI displays the seed phrase prominently and requires the operator to confirm they have saved it before proceeding to the management panel.

### Password recovery

If an operator forgets their password, they can use the **Forgot Password?** link on the login page. Recovery requires the 12-word seed phrase and a new password. The seed phrase is validated as BIP39 and checked against the stored hash.

### Legacy node migration

Nodes that were onboarded before the seed-phrase system was introduced do not have a `seed_hash` in state. After upgrading, authenticated operators see an **Upgrade Security: Generate Recovery Seed Phrase** banner on the `/manage` dashboard. Clicking it generates a new seed phrase (one-time display) and stores its hash — the same flow as onboarding, without re-running setup.

### Management panel (`/manage`)

After onboarding, `GET /` redirects to `/manage`. The panel (password-protected) lets the operator:

- Generate a recovery seed phrase (legacy nodes only, via the security upgrade banner)
- Add and remove SSH public keys for the `holo` user without physical access
- Link or update a Unyt Agent ID for HoloFuel compensation
- Configure the Log Collector URL for Unyt resource accounting
- Join and manage Moss groups on the EdgeNode
- Switch hardware mode between Standard EdgeNode and Wind Tunnel
- Change the node password
- Trigger an immediate software update check

### Self-update

A background thread wakes every hour, queries the GitHub Releases API for this repository, and compares the latest tag against the compiled-in `VERSION` constant. If a newer version exists it downloads the architecture-matched binary, atomically replaces the running binary on disk, and calls `systemctl restart node-manager.service`. The update check can also be triggered manually from the `/manage` panel.

---

## Building locally

### Branch workflow

| Branch | Purpose |
|--------|---------|
| `main` | Production-ready releases. Tag pushes trigger GitHub Actions release builds. |
| `develop` | Integration branch for in-progress features. Merge to `main` when ready to release. |
| `feature/*` | Short-lived branches off `develop`. |

### Prerequisites

- Rust stable (1.75 or newer)
- For the static musl builds that ship in releases: `musl-tools` (`apt install musl-tools`) and the musl targets added to your toolchain

```bash
# Add musl targets (first time only)
rustup target add x86_64-unknown-linux-musl
rustup target add aarch64-unknown-linux-musl
```

### Development build (dynamic, your host OS)

Binding to port 80 requires root on Linux:

```bash
cargo build
sudo ./target/debug/node-manager
# Open http://localhost
```

For local development without root, you can temporarily change the bind port in `main.rs`.

### Production build (static musl — what goes into GitHub Releases)

```bash
# x86_64
cargo build --release --target x86_64-unknown-linux-musl

# aarch64 (requires aarch64-linux-gnu-gcc cross-compiler)
sudo apt install gcc-aarch64-linux-gnu
CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=aarch64-linux-gnu-gcc \
  cargo build --release --target aarch64-unknown-linux-musl
```

The resulting binaries are fully static — no glibc, no external libraries beyond what is linked from `bip39`. They run on any FCOS image regardless of what userland packages are present.

### Testing the UI locally

```bash
sudo cargo run
# Visit http://localhost
# Complete onboarding to set a password and receive a seed phrase.
```

To simulate an already-onboarded legacy node (no seed phrase):

```bash
sudo mkdir -p /etc/node-manager
echo -e "onboarded=true\nnode_name=test\nhw_mode=STANDARD\nunyt_agent_id=" \
  | sudo tee /etc/node-manager/state
echo 'sha256:deadbeef:placeholder' | sudo tee /etc/node-manager/auth
sudo cargo run
# GET / will redirect to /manage; log in, then use the security upgrade banner.
```

---

## Repository structure

```
node-manager/
├── src/
│   └── main.rs              ← entire server (single file)
├── Cargo.toml
├── Cargo.lock
├── .github/
│   └── workflows/
│       └── release.yml      ← builds + publishes binaries on version tag
└── README.md
```

The server is intentionally a single file so it can be audited easily.

---

## Shipping a release

Every release publishes two binary assets:

| Asset name                | Architecture           |
|---------------------------|------------------------|
| `node-manager-x86_64`     | x86-64 (most hardware) |
| `node-manager-aarch64`    | ARM64 (Raspberry Pi, Apple Silicon VMs) |

**These asset names are load-bearing.** Both the self-update code in `find_asset_download_url()` and the first-boot `node-setup.sh` in `holo-node-iso` search for them by exact name. Do not rename them.

### Step-by-step release process

1. Make your changes on a `feature/*` branch off `develop`, then merge into `develop`.

2. When ready to release, merge `develop` into `main` and update the version in **two places** — they must match exactly:
   - `const VERSION: &str = "6.1.0";` in `src/main.rs`
   - `version = "6.1.0"` in `Cargo.toml`

3. Commit:
   ```bash
   git add src/main.rs Cargo.toml
   git commit -m "release: v6.1.0 — <one line summary of changes>"
   ```

4. Tag and push:
   ```bash
   git tag v6.1.0
   git push origin main
   git push origin v6.1.0
   ```

5. GitHub Actions (`.github/workflows/release.yml`) picks up the tag, builds both binaries using musl static linking, creates a GitHub Release, and attaches both binary assets automatically. No manual upload needed.

6. Running nodes pick up the update within 60 minutes. Operators can trigger it immediately from the `/manage` panel's "Software Update" section.

### Delivery to nodes

Once a release is published, updates reach nodes in two ways:

- **Running nodes** — the hourly self-update check downloads the new binary and restarts the service automatically, within 60 minutes of the release being published.
- **Freshly provisioned nodes** — `node-setup.sh` always downloads the latest release at first boot, so new nodes get the current version immediately with no ISO rebuild required.

---

## Self-update mechanism

The update logic lives in `check_and_apply_update()` and `spawn_update_checker()`.

**Flow:**

1. Thread sleeps 90 seconds after startup (lets the server stabilise)
2. Queries `https://api.github.com/repos/{UPDATE_REPO}/releases/latest`
3. Parses `tag_name`, strips the leading `v`, compares to `VERSION`
4. If newer: finds the asset named `node-manager-{uname -m}` in the release JSON
5. Downloads to `/usr/local/bin/node-manager-update`
6. `chmod +x`, then `fs::rename` (atomic on Linux)
7. `systemctl restart node-manager.service`
8. Sleeps 1 hour, repeats

The `UPDATE_REPO` environment variable overrides the default (`holo-host/node-manager`). This is used in staging environments.

---

## Routes reference

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/` | — | Onboarding wizard (pre-onboard) or redirect to `/manage` |
| `POST` | `/submit` | — | Run onboarding; returns JSON with `seed_phrase` |
| `GET` | `/login` | — | Login page (includes password recovery flow) |
| `POST` | `/login` | — | Authenticate; sets session cookie |
| `POST` | `/logout` | session | Clear session cookie |
| `POST` | `/manage/auth/recover` | — | Reset password using seed phrase + new password |
| `GET` | `/manage` | session | Management panel HTML |
| `GET` | `/manage/status` | session | JSON node state snapshot (includes `has_seed_phrase`) |
| `POST` | `/manage/auth/generate_seed` | session | Generate recovery seed for legacy nodes (one-time) |
| `POST` | `/manage/ssh/add` | session | Add SSH public key |
| `POST` | `/manage/ssh/remove` | session | Remove SSH key by index |
| `POST` | `/manage/nodename` | session | Change node name and system hostname |
| `POST` | `/manage/unyt` | session | Save or update Unyt Agent ID |
| `POST` | `/manage/log-sender` | session | Save Log Collector URL (`LOG_SENDER_ENDPOINT`) |
| `POST` | `/manage/moss/join` | session | Join a Moss group |
| `POST` | `/manage/moss/start` | session | Start EdgeNode Moss node |
| `GET` | `/manage/moss/list` | session | List Moss groups |
| `GET` | `/manage/moss/info` | session | Moss node info |
| `GET` | `/manage/moss/apps` | session | List installed Moss apps |
| `POST` | `/manage/hardware` | session | Switch STANDARD ↔ WIND_TUNNEL |
| `POST` | `/manage/wind-tunnel` | session | Apply Wind Tunnel image/entrypoint config |
| `POST` | `/manage/password` | session | Change node password |
| `POST` | `/manage/update` | session | Trigger immediate update check |

Session tokens are stored in-memory and cleared on restart — operators will need to log in again after an update.

---

## File paths on the node

| Path | Contents | Permissions |
|------|----------|-------------|
| `/etc/node-manager/state` | Key-value store of node state (`onboarded`, `node_name`, `hw_mode`, `unyt_agent_id`, `log_sender_endpoint`, `seed_hash`) | 600 |
| `/etc/node-manager/auth` | Password hash: `sha256:<salt>:<hash>` | 600 |
| `/etc/node-manager/sessions` | Persisted session tokens | 600 |
| `/etc/node-manager/client-meta.json` | Nomad client meta drop-in for Wind Tunnel (`unyt_agent_id`); bind-mounted read-only into the container at `/etc/nomad.d/client-meta.json` | 600 |
| `/etc/containers/systemd/edgenode.container` | Podman Quadlet for the EdgeNode container | 644 |
| `/etc/containers/systemd/wind-tunnel.container` | Podman Quadlet for Wind Tunnel | 644 |
| `/home/holo/.ssh/authorized_keys` | SSH public keys for the holo user | 600 |
| `/var/lib/edgenode/` | EdgeNode persistent data volume | — |

The `seed_hash` field stores a salted SHA-256 hash of the normalized BIP39 seed phrase. The plain-text seed phrase is never written to disk.

---

## Security model

### Authentication

The server is protected by a user-defined password (the "node password") set during onboarding. Passwords are hashed as `sha256:<8-hex-salt>:<sha256(salt:password)>` and stored at `/etc/node-manager/auth` (chmod 600). The cleartext password is never stored.

During onboarding, a 12-word BIP39 seed phrase is generated. Its hash is stored in state as `seed_hash`. The plain-text seed phrase is returned once in the API response and shown in the UI — it is never persisted on disk.

**Password recovery:** Operators who forget their password can reset it via `POST /manage/auth/recover` using their seed phrase and a new password.

**Legacy migration:** Nodes upgraded from older versions without a seed hash can generate one from the `/manage` dashboard while authenticated (`POST /manage/auth/generate_seed`). This is a one-time operation.

Sessions are 24-hour cookie-based tokens stored in-memory (persisted to `/etc/node-manager/sessions`). They are cleared on server restart. All `/manage/*` routes require an active session except where noted; unauthenticated HTML requests redirect to `/login`.

### SSH access

SSH access is provided only for the `holo` system user. Root login is disabled via `/etc/ssh/sshd_config.d/90-holo.conf`. Password authentication is disabled — SSH keys only. SSH is intended as a "break glass" access path, not the primary management interface. The `/manage` panel is the primary interface.

### Network exposure

The server binds to `0.0.0.0:80`. It is intended to be reachable only on the local network — the FCOS firewall configuration in `holo-node-iso` should not expose port 80 to the internet. The UI has no HTTPS; TLS termination (if desired) should be handled at the network edge.

On production nodes, `node-manager.service` runs as root (no `User=` in the unit file), which is required for binding to port 80 and for managing systemd/Podman resources.

---

## Contributing

This repository is intentionally kept simple. Before contributing, please read the design constraints:

- **No async runtime.** The server uses `std::thread` for concurrency. Each connection spawns a thread. This is appropriate for a UI that handles at most a handful of simultaneous requests.
- **Minimal dependencies.** The only external crate is `bip39` (for recovery seed generation and validation). Everything else uses `std` to keep the binary small and the audit surface minimal.
- **Single file.** `src/main.rs` contains the entire server. This is a deliberate choice for auditability — an operator should be able to read the entire source in one sitting.

Pull requests that introduce unnecessary dependencies or split the code across multiple files will not be accepted unless there is a very strong reason.

For bug reports or feature requests, open an issue. For security issues, contact security@holo.host directly.
