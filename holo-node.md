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
Your daemon runs as `openclaw-daemon.service`.

## Switching Operating Modes

Preferred approach — write a file in your workspace:

```bash
# Switch to Wind Tunnel (stress-test the Holochain network)
echo "WIND_TUNNEL" > /var/lib/openclaw/workspace/mode_switch.txt
/usr/local/bin/apply-node-mode.sh

# Switch back to Standard EdgeNode
echo "STANDARD" > /var/lib/openclaw/workspace/mode_switch.txt
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
systemctl status openclaw-daemon.service

# Journald logs (last 50 lines)
journalctl -u edgenode.service -n 50
journalctl -u wind-tunnel.service -n 50
journalctl -u openclaw-daemon.service -n 50

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

```bash
# Check the EdgeNode is running and healthy
systemctl status edgenode.service
podman logs --tail 20 edgenode

# List joined Moss groups (run inside the container)
podman exec edgenode wdocker group list

# Join a new Moss group (replace GROUP_URL with the invite URL)
podman exec edgenode wdocker group join GROUP_URL

# Show running hApps
podman exec edgenode wdocker happs list
```

## Workflow 2: Running Wind Tunnel

The Wind Tunnel mode runs the Holochain network stress-tester. The container
registers as a `nomad-client-{node_name}` peer with the Holochain test network.
It requires elevated privileges (`--privileged`) which are configured in its
Quadlet file.

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
| `/var/lib/openclaw/workspace/` | Your working directory — files you write go here |
| `/var/lib/openclaw/workspace/mode_switch.txt` | Current hardware mode (`STANDARD` or `WIND_TUNNEL`) |
| `/var/lib/edgenode/` | EdgeNode persistent data (DNA databases, agent keys) |
| `/etc/openclaw/config.toml` | Your configuration (providers, channels, autonomy) |
| `/etc/openclaw/skills/` | This and other skill files |
| `/etc/containers/systemd/` | Podman Quadlet files (edgenode.container, wind-tunnel.container) |

## Configuration

Your config is at `/etc/openclaw/config.toml`. Hot-reloadable fields (apply on
next message without restart): `default_provider`, `default_model`, `api_key`.

Fields requiring daemon restart: channels, autonomy, memory, gateway, skills.

```bash
# View current config (keys shown masked by openclaw)
cat /etc/openclaw/config.toml

# Restart daemon after non-hot-reloadable config changes
systemctl restart openclaw-daemon.service
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

A future OpenClaw skill (`holochain-conductor`) will allow you to call Zome
functions on the local Conductor's AppWebSocket (port 65001) directly — reading
from and writing to the DHT without going through wdocker or CLI tools. This
requires WASI directory mounting so the skill can read compiled `.happ` bundles
from your workspace. When that skill is available, you will be able to:

- Install and activate new hApps autonomously
- Call arbitrary Zome functions with canonical MessagePack payloads
- Use Holochain as distributed tamper-proof memory for your own knowledge graph
- Coordinate with other OpenClaw agents via a shared Holochain app (no central server)
