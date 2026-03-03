# Holo Sovereign Node — Management Skill

You are running on a **Holo Sovereign Node** — a dedicated computer running
Fedora CoreOS (FCOS) managed via systemd and rootless Podman with crun.

## Node Architecture

The node runs two mutually exclusive hardware modes. Only one can be active at a time:

| Mode | Container | Quadlet Service | Image |
|------|-----------|-----------------|-------|
| Standard | `edgenode` | `edgenode.service` | `ghcr.io/holo-host/edgenode:latest` |
| Wind Tunnel | `wind-tunnel` | `wind-tunnel.service` | `ghcr.io/holochain/wind-tunnel-runner:latest` |

Container runtime: **Podman + crun** (no Docker daemon, no persistent privileged socket).
Your daemon runs as `zeroclaw-daemon.service`.

## Switching Operating Modes

Preferred approach — write a file in your workspace:

```bash
# Switch to Wind Tunnel (stress-test the Holochain network)
echo "WIND_TUNNEL" > /var/lib/zeroclaw/workspace/mode_switch.txt
/usr/local/bin/apply-node-mode.sh

# Switch back to Standard EdgeNode
echo "STANDARD" > /var/lib/zeroclaw/workspace/mode_switch.txt
/usr/local/bin/apply-node-mode.sh
```

Direct service control:

```bash
# Start edgenode, stop wind tunnel
systemctl stop wind-tunnel.service
systemctl start edgenode.service

# Start wind tunnel, stop edgenode
systemctl stop edgenode.service
systemctl start wind-tunnel.service
```

## Container Management (Podman)

```bash
# Check what's running
podman ps

# Check all containers including stopped
podman ps -a

# View live logs
podman logs -f edgenode
podman logs -f wind-tunnel

# Last 100 log lines
podman logs --tail 100 edgenode

# Restart a container (prefer systemctl for managed services)
systemctl restart edgenode.service
systemctl restart wind-tunnel.service

# Resource usage snapshot
podman stats --no-stream

# Disk usage (images, containers, volumes)
podman system df

# Free up space (unused images/containers/volumes)
podman system prune -f
```

## Service Status & Logs

```bash
# Health check
systemctl status edgenode.service
systemctl status wind-tunnel.service
systemctl status zeroclaw-daemon.service

# Journald logs (last 50 lines)
journalctl -u edgenode.service -n 50
journalctl -u wind-tunnel.service -n 50
journalctl -u zeroclaw-daemon.service -n 50

# Follow logs live
journalctl -fu edgenode.service
```

## Updating Containers

Image updates happen automatically via `podman-auto-update.timer` (nightly).
To update manually:

```bash
# Pull latest images
podman pull ghcr.io/holo-host/edgenode:latest
podman pull ghcr.io/holochain/wind-tunnel-runner:latest

# Restart to pick up new image
systemctl restart edgenode.service
# or
systemctl restart wind-tunnel.service
```

## Workflow 1: Operating a Moss Edge Node

The EdgeNode container runs a Holochain Conductor. You interact with it using
the **wdocker** CLI (Weave Docker toolkit) to join Moss groups and manage apps.

### Install wdocker inside the running edgenode container

```bash
# Ensure edgenode is running
systemctl start edgenode.service

# Install Node/npm if not present, then install Weave CLI tools
podman exec edgenode sh -c "apk update && apk add nodejs npm"
podman exec edgenode npm install -g @theweave/wdocker @theweave/utils \
  @theweave/group-client @theweave/moss-types
```

### Initialize and join a Moss group

```bash
# Initialize the conductor (run in background; replace 'my-node' with your preferred name)
podman exec -d edgenode wdocker run my-node

# Join a Moss group — user must provide the invite link
podman exec edgenode wdocker join-group my-node "<invite-link>"

# Join the public Holo Community group (no invite needed):
podman exec edgenode wdocker join-group my-node \
  "https://theweave.social/wal?weave-0.15://invite/d2543bb4-b784-4ac0-ae16-971e1b3a90c1&progenitor=uhCAkovIker1pDmpka8PiVWFWMGmSvNHjzdi9KnTOsUJzrsGG71JI"
```

### Moss maintenance commands

```bash
# List installed apps/tools inside the node
podman exec edgenode wdocker list-apps my-node

# Check node health
podman exec edgenode wdocker status my-node

# Restart a stopped node (does not restart the container — just the conductor)
podman exec edgenode wdocker start my-node
```

## Workflow 2: Installing Holochain Apps (hApps)

Holochain apps are distributed as `.happ` bundle files.

```bash
# Copy a happ bundle into the edgenode container
podman cp myapp.happ edgenode:/tmp/myapp.happ

# Install via Holochain conductor CLI inside the container
podman exec edgenode hc app install /tmp/myapp.happ

# List installed happs
podman exec edgenode hc app list

# Enable a happ (get app ID from list command)
podman exec edgenode hc app enable <app-id>

# Disable a happ
podman exec edgenode hc app disable <app-id>
```

## Workflow 3: Wind Tunnel Runner

The Wind Tunnel container stress-tests the Holochain network. It requires
elevated privileges (`--privileged`) which are configured in its Quadlet file.

**Important:** Always stop the EdgeNode before starting Wind Tunnel.
Never run both simultaneously — they share P2P ports.

```bash
# Clean stop of edgenode before switching
systemctl stop edgenode.service

# Start wind tunnel
systemctl start wind-tunnel.service

# Verify it's running (should show wind-tunnel-runner image)
podman ps

# Stop wind tunnel and return to normal
systemctl stop wind-tunnel.service
systemctl start edgenode.service
```

Verify the wind tunnel is reporting to the Holochain network:

```bash
podman logs --tail 50 wind-tunnel
```

Look for lines containing `nomad-client` and `connected` to confirm registration.

## Workspace & Data Paths

| Path | Purpose |
|------|---------|
| `/var/lib/zeroclaw/workspace/` | Your working directory — files you write go here |
| `/var/lib/zeroclaw/workspace/mode_switch.txt` | Current hardware mode (`STANDARD` or `WIND_TUNNEL`) |
| `/var/lib/edgenode/` | EdgeNode persistent data (DNA databases, agent keys) |
| `/etc/zeroclaw/config.toml` | Your configuration (providers, channels, autonomy) |
| `/etc/zeroclaw/skills/` | This and other skill files |
| `/etc/containers/systemd/` | Podman Quadlet files (edgenode.container, wind-tunnel.container) |

## Configuration

Your config is at `/etc/zeroclaw/config.toml`. Hot-reloadable fields (apply on
next message without restart): `default_provider`, `default_model`, `api_key`.

Fields requiring daemon restart: channels, autonomy, memory, gateway, skills.

```bash
# View current config (keys shown masked by zeroclaw)
cat /etc/zeroclaw/config.toml

# Restart daemon after non-hot-reloadable config changes
systemctl restart zeroclaw-daemon.service
```

## Disk & Resource Usage

```bash
# Disk usage summary
df -h

# Podman image + volume disk usage
podman system df

# RAM and swap
free -h

# CPU/memory per container (live)
podman stats
```

## Important Notes

- Always use `systemctl start/stop/restart SERVICE.service` rather than
  `podman run` directly — the Quadlet units handle restart policy, logging,
  and mutual-exclusion (`Conflicts=`).
- `edgenode.service` and `wind-tunnel.service` declare `Conflicts=` on each
  other in their Quadlet files, so starting one automatically stops the other.
- Images update nightly via `podman-auto-update.timer`. To check when it last
  ran: `systemctl status podman-auto-update.service`
- If a container keeps crashing, check `journalctl -u SERVICE -n 100 --no-pager`
  for the root cause before restarting.
- The node uses **crun** (not runc) as the OCI runtime — this is normal and
  intentional. It is faster and uses less memory than runc.

## Roadmap: Holochain Conductor Direct Integration

A future ZeroClaw skill (`holochain-conductor`) will allow you to call Zome
functions on the local Conductor's AppWebSocket (port 65001) directly — reading
from and writing to the DHT without going through wdocker or CLI tools. This
requires WASI directory mounting so the skill can read compiled `.happ` bundles
from your workspace. When that skill is available, you will be able to:

- Install and activate new hApps autonomously
- Call arbitrary Zome functions with canonical MessagePack payloads
- Use Holochain as distributed tamper-proof memory for your own knowledge graph
- Coordinate with other ZeroClaw agents via a shared Holochain app (no central server)
