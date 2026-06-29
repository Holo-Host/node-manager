use std::{
    collections::HashMap,
    env, fs,
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    process::Command,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, SystemTime},
};

// ── Version & path constants ───────────────────────────────────────────────────

const VERSION: &str = "6.2.1";
const WT_HOSTNAME_MAX: usize = 63;
const WT_RANDOM_SUFFIX_LEN: usize = 16;
const STATE_FILE: &str = "/etc/node-manager/state";
const AUTH_FILE: &str = "/etc/node-manager/auth";
const SESSIONS_FILE: &str = "/etc/node-manager/sessions";
const WIND_TUNNEL_CLIENT_META: &str = "/etc/node-manager/client-meta.json";
const WIND_TUNNEL_LEGACY_ENV: &str = "/etc/node-manager/wind-tunnel.env";
const QUADLET_DIR: &str = "/etc/containers/systemd";
const AUTHORIZED_KEYS: &str = "/home/holo/.ssh/authorized_keys";
const UPDATE_REPO_ENV: &str = "UPDATE_REPO";
const UPDATE_REPO_DEFAULT: &str = "holo-host/node-manager";
const WT_IMAGE_ENV: &str = "WIND_TUNNEL_IMAGE";
const WT_ENTRYPOINT_ENV: &str = "WIND_TUNNEL_ENTRYPOINT_BIND";
const SESSION_TTL_SECS: u64 = 86400;
const UPDATE_INTERVAL_SECS: u64 = 3600;
const DEPLOYMENTS_FILE: &str = "/etc/node-manager/deployments.json";
const HAPP_LOGS_DIR: &str = "/etc/node-manager/happ-logs";
const HAPP_MANIFESTS_DIR: &str = "/var/lib/edgenode/manifests";
const EDGENODE_CONTAINER: &str = "edgenode";

// ── Shared application state ───────────────────────────────────────────────────

struct AppState {
    ap_mode:        bool,
    start_time:     SystemTime,
    sessions:       Mutex<HashMap<String, SystemTime>>,
    onboarded:      AtomicBool,
    node_name:      Mutex<String>,
    hw_mode:        Mutex<String>,
    unyt_agent_id:       Mutex<String>,
    log_sender_endpoint: Mutex<String>,
    wt_suffix:           Mutex<String>,
    wt_image_override:   Mutex<String>,
    wt_entrypoint_bind:  Mutex<String>,
}

impl AppState {
    fn new(ap_mode: bool) -> Self {
        let kv = read_state_file();
        AppState {
            ap_mode,
            start_time: SystemTime::now(),
            sessions:   Mutex::new(load_sessions()),
            onboarded:  AtomicBool::new(kv.get("onboarded").map(|v| v == "true").unwrap_or(false)),
            node_name:     Mutex::new(kv.get("node_name").cloned().unwrap_or_default()),
            hw_mode:       Mutex::new(kv.get("hw_mode").cloned().unwrap_or_else(|| "STANDARD".into())),
            unyt_agent_id:      Mutex::new(kv.get("unyt_agent_id").cloned().unwrap_or_default()),
            log_sender_endpoint: Mutex::new(kv.get("log_sender_endpoint").cloned().unwrap_or_default()),
            wt_suffix:          Mutex::new(kv.get("wt_suffix").cloned().unwrap_or_default()),
            wt_image_override:  Mutex::new(kv.get("wt_image_override").cloned().unwrap_or_default()),
            wt_entrypoint_bind: Mutex::new(kv.get("wt_entrypoint_bind").cloned().unwrap_or_default()),
        }
    }
}

// ── State file helpers ─────────────────────────────────────────────────────────

fn read_state_file() -> HashMap<String, String> {
    let mut map = HashMap::new();
    for line in fs::read_to_string(STATE_FILE).unwrap_or_default().lines() {
        if let Some(eq) = line.find('=') {
            map.insert(line[..eq].trim().to_string(), line[eq + 1..].to_string());
        }
    }
    map
}

fn write_state_file(kv: &HashMap<String, String>) {
    let _ = fs::create_dir_all("/etc/node-manager");
    let content: String = kv.iter().map(|(k, v)| format!("{}={}\n", k, v)).collect();
    let _ = fs::write(STATE_FILE, content);
    let _ = Command::new("chmod").args(["600", STATE_FILE]).output();
}

fn update_state_key(key: &str, value: &str) {
    let mut kv = read_state_file();
    kv.insert(key.to_string(), value.to_string());
    write_state_file(&kv);
}

// ── Crypto / auth helpers ──────────────────────────────────────────────────────

fn random_bytes(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    if let Ok(mut f) = fs::File::open("/dev/urandom") { let _ = f.read_exact(&mut buf); }
    buf
}

fn random_hex(n: usize) -> String {
    random_bytes(n).iter().map(|b| format!("{:02x}", b)).collect()
}

fn generate_password() -> String {
    let alpha: &[u8] = b"abcdefghjkmnpqrstuvwxyz23456789";
    random_bytes(12).iter().map(|&b| alpha[(b as usize) % alpha.len()] as char).collect()
}

fn sha256_of(input: &str) -> String {
    let mut child = match Command::new("sha256sum")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
    { Ok(c) => c, Err(_) => return String::new() };
    if let Some(mut s) = child.stdin.take() { let _ = s.write_all(input.as_bytes()); }
    let out = child.wait_with_output().map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string()).unwrap_or_default();
    out.split_whitespace().next().unwrap_or("").to_string()
}

fn hash_password(password: &str) -> String {
    let salt = random_hex(8);
    let hash = sha256_of(&format!("{}:{}", salt, password));
    format!("sha256:{}:{}", salt, hash)
}

fn verify_password(input: &str, stored: &str) -> bool {
    let parts: Vec<&str> = stored.trim().splitn(3, ':').collect();
    if parts.len() != 3 || parts[0] != "sha256" { return false; }
    let actual = sha256_of(&format!("{}:{}", parts[1], input));
    !actual.is_empty() && actual == parts[2].trim()
}

fn load_or_create_auth() -> String {
    if let Ok(h) = fs::read_to_string(AUTH_FILE) {
        let h = h.trim().to_string();
        if !h.is_empty() { return h; }
    }
    let password = generate_password();
    let hash = hash_password(&password);
    let _ = fs::create_dir_all("/etc/node-manager");
    let _ = fs::write(AUTH_FILE, &hash);
    let _ = Command::new("chmod").args(["600", AUTH_FILE]).output();
    display_password_on_tty(&password);
    hash
}

fn get_local_ip() -> String {
    Command::new("sh")
        .args(["-c", "ip -4 addr show scope global | grep -oP '(?<=inet )\\d+\\.\\d+\\.\\d+\\.\\d+' | head -1"])
        .output().ok()
        .and_then(|o| { let s = String::from_utf8_lossy(&o.stdout).trim().to_string(); if s.is_empty() { None } else { Some(s) } })
        .unwrap_or_else(|| "<node-ip>".to_string())
}

fn display_password_on_tty(password: &str) {
    let ip = get_local_ip();
    let msg = format!(
        "\x1b[2J\x1b[H\n\
         \x1b[1;36m  ╔══════════════════════════════════════════╗\n\
         \x1b[1;36m  ║      🜲  HOLO NODE SETUP                 ║\n\
         \x1b[1;36m  ╚══════════════════════════════════════════╝\x1b[0m\n\n\
         \x1b[1m  Open a browser on your local network and visit:\x1b[0m\n\
         \x1b[1;33m  http://{}:8080\x1b[0m\n\n\
         \x1b[1m  One-time setup password:\x1b[0m\n\
         \x1b[1;32m  {}\x1b[0m\n\n\
         \x1b[31m  ⚠  Write this password down. It will NOT show again.\x1b[0m\n\n",
        ip, password
    );
    if let Ok(mut tty) = fs::OpenOptions::new().write(true).open("/dev/tty1") { let _ = tty.write_all(msg.as_bytes()); }
    let issue = format!("\n\x1b[1;36m╔═══════════════════════════════╗\x1b[0m\n\x1b[1;36m║  HOLO NODE SETUP              ║\x1b[0m\n\x1b[1;36m╚═══════════════════════════════╝\x1b[0m\n\x1b[1mURL:\x1b[0m      http://{}:8080\n\x1b[1mPassword:\x1b[0m \x1b[1;32m{}\x1b[0m\n\n", ip, password);
    let _ = fs::create_dir_all("/run/issue.d");
    let _ = fs::write("/run/issue.d/51-node-manager.issue", issue.as_bytes());
    eprintln!("[onboard] *** SETUP PASSWORD: {} | URL: http://{}:8080 ***", password, ip);
}

// ── Session management ─────────────────────────────────────────────────────────

fn load_sessions() -> HashMap<String, SystemTime> {
    let mut sessions = HashMap::new();
    let now = SystemTime::now();
    for line in fs::read_to_string(SESSIONS_FILE).unwrap_or_default().lines() {
        if let Some(eq) = line.find('=') {
            let token = line[..eq].trim().to_string();
            if let Ok(secs) = line[eq + 1..].trim().parse::<u64>() {
                if let Some(exp) = SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(secs)) {
                    if now < exp {
                        sessions.insert(token, exp);
                    }
                }
            }
        }
    }
    sessions
}

fn save_sessions(sessions: &HashMap<String, SystemTime>) {
    let _ = fs::create_dir_all("/etc/node-manager");
    let content: String = sessions.iter()
        .filter_map(|(token, exp)| {
            exp.duration_since(SystemTime::UNIX_EPOCH).ok()
                .map(|d| format!("{}={}\n", token, d.as_secs()))
        })
        .collect();
    let _ = fs::write(SESSIONS_FILE, content);
    let _ = Command::new("chmod").args(["600", SESSIONS_FILE]).output();
}

fn create_session(state: &AppState) -> String {
    let token = random_hex(32);
    let exp = SystemTime::now() + Duration::from_secs(SESSION_TTL_SECS);
    let mut sessions = state.sessions.lock().unwrap();
    sessions.retain(|_, &mut e| SystemTime::now() < e);
    sessions.insert(token.clone(), exp);
    save_sessions(&sessions);
    token
}

fn is_authenticated(req: &Req, state: &AppState) -> bool {
    let token = match get_cookie(&req.headers, "session") { Some(t) => t, None => return false };
    let mut sessions = state.sessions.lock().unwrap();
    let ok = match sessions.get(&token) {
        Some(&exp) if SystemTime::now() < exp => true,
        Some(_) => { sessions.remove(&token); false }
        None => false,
    };
    if !ok { save_sessions(&sessions); }
    ok
}

fn session_cookie(token: &str) -> String { format!("session={}; HttpOnly; SameSite=Strict; Path=/", token) }
fn clear_cookie() -> String { "session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0".to_string() }

// ── SSH key management ─────────────────────────────────────────────────────────

fn read_ssh_keys() -> Vec<String> {
    fs::read_to_string(AUTHORIZED_KEYS).unwrap_or_default()
        .lines().map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty() && !l.starts_with('#')).collect()
}

fn write_ssh_keys(keys: &[String]) -> Result<(), String> {
    let _ = fs::create_dir_all("/home/holo/.ssh");
    fs::write(AUTHORIZED_KEYS, keys.join("\n") + "\n").map_err(|e| e.to_string())?;
    let _ = Command::new("chown").args(["-R", "holo:holo", "/home/holo/.ssh"]).output();
    let _ = Command::new("chmod").args(["700", "/home/holo/.ssh"]).output();
    let _ = Command::new("chmod").args(["600", AUTHORIZED_KEYS]).output();
    Ok(())
}

fn is_valid_ssh_pubkey(key: &str) -> bool {
    let k = key.trim();
    k.starts_with("ssh-ed25519 ") || k.starts_with("ssh-rsa ") || k.starts_with("ecdsa-sha2-") || k.starts_with("sk-ssh-")
}

// ── Image resolvers ────────────────────────────────────────────────────────────

fn detect_arch() -> String {
    Command::new("uname").arg("-m").output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|_| "x86_64".to_string())
}

fn resolve_image(image_ref: &str, arm64_prefix: &str) -> String {
    let arch = detect_arch();
    if arch != "aarch64" { return format!("{}:latest", image_ref); }
    let manifest = Command::new("skopeo")
        .args(["inspect", "--raw", &format!("docker://{}:latest", image_ref)])
        .output().ok().filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string()).unwrap_or_default();
    if manifest.contains("arm64") || manifest.contains("aarch64") { return format!("{}:latest", image_ref); }
    let repo_path = image_ref.trim_start_matches("ghcr.io/");
    let token_json = Command::new("curl")
        .args(["-sf", &format!("https://ghcr.io/token?scope=repository:{}:pull&service=ghcr.io", repo_path)])
        .output().ok().map(|o| String::from_utf8_lossy(&o.stdout).to_string()).unwrap_or_default();
    let token = extract_json_str(&token_json, "token");
    if token.is_empty() { return format!("{}:latest", image_ref); }
    let tags_json = Command::new("curl")
        .args(["-sf", "-H", &format!("Authorization: Bearer {}", token),
            &format!("https://ghcr.io/v2/{}/tags/list", repo_path)])
        .output().ok().map(|o| String::from_utf8_lossy(&o.stdout).to_string()).unwrap_or_default();
    match pick_arm64_tag(&tags_json, arm64_prefix) {
        Some(tag) => format!("{}:{}", image_ref, tag),
        None => format!("{}:latest", image_ref),
    }
}

fn resolve_edgenode_image() -> String { resolve_image("ghcr.io/holo-host/edgenode", "latest-hc") }
fn resolve_wind_tunnel_image() -> String { resolve_image("ghcr.io/holochain/wind-tunnel-runner", "latest-") }

fn extract_json_str<'a>(json: &'a str, key: &str) -> &'a str {
    let needle = format!("\"{}\":", key);
    let pos = match json.find(&needle) { Some(p) => p, None => return "" };
    let after = json[pos + needle.len()..].trim_start();
    if after.starts_with('"') { let inner = &after[1..]; &inner[..inner.find('"').unwrap_or(0)] } else { "" }
}

fn pick_arm64_tag(tags_json: &str, prefix: &str) -> Option<String> {
    let start = tags_json.find('[')?; let end = tags_json.rfind(']')?;
    let array = &tags_json[start + 1..end];
    let mut candidates = Vec::new();
    let mut rest = array;
    while let Some(q1) = rest.find('"') {
        let after = &rest[q1 + 1..];
        if let Some(q2) = after.find('"') {
            let tag = &after[..q2];
            if tag.starts_with(prefix) && tag != "latest" { candidates.push(tag.to_string()); }
            rest = &after[q2 + 1..];
        } else { break; }
    }
    candidates.sort_by(|a, b| b.cmp(a));
    candidates.into_iter().next()
}

// ── Quadlet builders ───────────────────────────────────────────────────────────

fn build_edgenode_quadlet(image: &str, log_sender_endpoint: &str, unyt_agent_id: &str) -> String {
    let mut env_lines = String::new();
    let endpoint = log_sender_endpoint.trim();
    let unyt = unyt_agent_id.trim();
    if !endpoint.is_empty() {
        env_lines.push_str(&format!("Environment=LOG_SENDER_ENDPOINT={}\n", endpoint));
    }
    if !unyt.is_empty() {
        env_lines.push_str(&format!("Environment=LOG_SENDER_UNYT_PUB_KEY={}\n", unyt));
    }
    format!(
        "[Unit]\nDescription=Holo EdgeNode\nAfter=network-online.target\nConflicts=wind-tunnel.service\n\n[Container]\nImage={image}\nContainerName=edgenode\nVolume=/var/lib/edgenode:/data:Z\n{env_lines}Label=io.containers.autoupdate=registry\n\n[Service]\nRestart=always\nRestartSec=5\n\n[Install]\nWantedBy=multi-user.target\n",
        image = image,
        env_lines = env_lines,
    )
}

fn build_wind_tunnel_quadlet(hostname: &str, image: &str, entrypoint_bind: Option<&str>) -> String {
    let entrypoint_volume = entrypoint_bind
        .map(|p| format!("Volume={}:/entrypoint.sh:ro,Z\n", p))
        .unwrap_or_default();
    format!(
        "[Unit]\n\
         Description=Holochain Wind Tunnel Runner\n\
         After=network-online.target\n\
         Conflicts=edgenode.service\n\n\
         [Container]\n\
         Image={image}\n\
         ContainerName=wind-tunnel\n\
         HostName={hostname}\n\
         Network=host\n\
         Volume={client_meta}:/etc/nomad.d/client-meta.json:ro,Z\n\
         {entrypoint_volume}\
         PodmanArgs=--cgroupns=host --privileged\n\
         Label=io.containers.autoupdate=registry\n\n\
         [Service]\n\
         Restart=always\n\
         RestartSec=5\n\n\
         [Install]\n\
         WantedBy=multi-user.target\n",
        hostname = hostname,
        image = image,
        client_meta = WIND_TUNNEL_CLIENT_META,
        entrypoint_volume = entrypoint_volume,
    )
}

fn generate_wt_suffix() -> String {
    random_hex(8)
}

fn ensure_wt_suffix(state: &AppState) -> String {
    let existing = state.wt_suffix.lock().unwrap().clone();
    if !existing.is_empty() { return existing; }
    let suffix = generate_wt_suffix();
    update_state_key("wt_suffix", &suffix);
    *state.wt_suffix.lock().unwrap() = suffix.clone();
    suffix
}

fn validate_unyt_agent_id(agent_id: &str) -> Option<String> {
    let id = agent_id.trim();
    if id.is_empty() { return None; }
    if id.starts_with('-') || id.ends_with('-') {
        return Some("Unyt Agent ID cannot start or end with a hyphen.".into());
    }
    if !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return Some("Unyt Agent ID may only contain letters, numbers, and hyphens.".into());
    }
    None
}

fn build_wt_hostname(node_name: &str) -> String {
    format!("nomad-client-{}", node_name)
}

fn build_wt_client_name(node_name: &str, unyt_agent_id: &str, wt_suffix: &str) -> String {
    let agent = unyt_agent_id.trim();
    if agent.is_empty() {
        format!("{}-{}", node_name, wt_suffix)
    } else {
        format!("{}-{}", node_name, agent)
    }
}

fn wt_client_name_error(node_name: &str, unyt_agent_id: &str) -> Option<String> {
    if let Some(msg) = validate_unyt_agent_id(unyt_agent_id) { return Some(msg); }
    let agent = unyt_agent_id.trim();
    let overhead = if agent.is_empty() {
        1 + WT_RANDOM_SUFFIX_LEN
    } else {
        1 + agent.len()
    };
    if node_name.len() + overhead <= WT_HOSTNAME_MAX { return None; }
    let max_name = WT_HOSTNAME_MAX.saturating_sub(overhead);
    let detail = if agent.is_empty() {
        "random tracking suffix"
    } else {
        "full Agent ID"
    };
    Some(format!(
        "Wind Tunnel client name would exceed {} characters (node name + {}). Shorten node name to at most {} characters.",
        WT_HOSTNAME_MAX, detail, max_name
    ))
}

fn json_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn write_wind_tunnel_client_meta(unyt_agent_id: &str) {
    let id = json_escape(unyt_agent_id.trim());
    let json = format!(
        "{{\n  \"client\": {{\n    \"meta\": {{\n      \"unyt_agent_id\": \"{}\"\n    }}\n  }}\n}}\n",
        id
    );
    let _ = fs::create_dir_all("/etc/node-manager");
    let _ = fs::write(WIND_TUNNEL_CLIENT_META, json);
    let _ = Command::new("chmod").args(["600", WIND_TUNNEL_CLIENT_META]).output();
    let _ = fs::remove_file(WIND_TUNNEL_LEGACY_ENV);
}

fn validate_node_name(node_name: &str) -> Option<String> {
    if node_name.is_empty() {
        return Some("Node name is required.".into());
    }
    if !node_name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-') {
        return Some("Node name must be lowercase letters, numbers and hyphens only.".into());
    }
    None
}

struct WindTunnelConfig {
    hostname: String,
    image: String,
    entrypoint_bind: Option<String>,
}

fn validate_wt_image_override(image: &str) -> Option<String> {
    let image = image.trim();
    if image.is_empty() { return None; }
    if image.chars().any(|c| c == ';' || c == '|' || c == '`' || c == '$' || c == '\n' || c == ' ') {
        return Some("Image override contains invalid characters.".into());
    }
    if !image.contains(':') {
        return Some("Image override must include a tag (e.g. registry/image:tag).".into());
    }
    if !image.chars().all(|c| c.is_ascii_alphanumeric() || "/:._-@".contains(c)) {
        return Some("Image override has invalid characters.".into());
    }
    None
}

fn validate_wt_entrypoint_bind(path: &str) -> Option<String> {
    let path = path.trim();
    if path.is_empty() { return None; }
    if !path.starts_with("/home/holo/") {
        return Some("Entrypoint bind must be under /home/holo/.".into());
    }
    let meta = match fs::metadata(path) {
        Ok(m) => m,
        Err(_) => return Some(format!("Entrypoint file not found: {}", path)),
    };
    if !meta.is_file() {
        return Some("Entrypoint bind must point to a regular file.".into());
    }
    None
}

fn resolve_wt_image_override(state: &AppState) -> Option<String> {
    let from_state = state.wt_image_override.lock().unwrap().trim().to_string();
    if !from_state.is_empty() { return Some(from_state); }
    env::var(WT_IMAGE_ENV).ok().filter(|s| !s.trim().is_empty()).map(|s| s.trim().to_string())
}

fn resolve_wt_entrypoint_bind(state: &AppState) -> Option<String> {
    let from_state = state.wt_entrypoint_bind.lock().unwrap().trim().to_string();
    if !from_state.is_empty() { return Some(from_state); }
    env::var(WT_ENTRYPOINT_ENV).ok().filter(|s| !s.trim().is_empty()).map(|s| s.trim().to_string())
}

fn resolve_wind_tunnel_config(state: &AppState) -> WindTunnelConfig {
    let node_name = state.node_name.lock().unwrap().clone();
    let hostname = build_wt_hostname(&node_name);
    let image = match resolve_wt_image_override(state) {
        Some(override_img) => override_img,
        None => resolve_wind_tunnel_image(),
    };
    let entrypoint_bind = resolve_wt_entrypoint_bind(state);
    WindTunnelConfig { hostname, image, entrypoint_bind }
}

fn write_quadlets_from_state(state: &AppState) {
    let cfg = resolve_wind_tunnel_config(state);
    let unyt = state.unyt_agent_id.lock().unwrap().clone();
    write_wind_tunnel_client_meta(&unyt);
    let edgenode_image = resolve_edgenode_image();
    let wt_quadlet = build_wind_tunnel_quadlet(
        &cfg.hostname,
        &cfg.image,
        cfg.entrypoint_bind.as_deref(),
    );
    let log_sender = state.log_sender_endpoint.lock().unwrap().clone();
    let _ = fs::write(
        format!("{}/edgenode.container", QUADLET_DIR),
        build_edgenode_quadlet(&edgenode_image, &log_sender, &unyt),
    );
    let _ = fs::write(format!("{}/wind-tunnel.container", QUADLET_DIR), wt_quadlet);
    let _ = Command::new("systemctl").args(["daemon-reload"]).output();
    eprintln!("[quadlet] WT hostname={} image={}", cfg.hostname, cfg.image);
    if let Some(ep) = cfg.entrypoint_bind.as_deref() {
        eprintln!("[quadlet] entrypoint bind={}", ep);
    }
}

fn apply_wind_tunnel_config(state: &AppState) {
    write_quadlets_from_state(state);
    if state.hw_mode.lock().unwrap().as_str() == "WIND_TUNNEL" {
        restart_wind_tunnel_if_running();
    }
}

fn restart_wind_tunnel_if_running() {
    let status = Command::new("systemctl")
        .args(["is-active", "wind-tunnel.service"])
        .output();
    if status.map(|o| o.status.success()).unwrap_or(false) {
        let _ = Command::new("systemctl").args(["restart", "wind-tunnel.service"]).output();
        eprintln!("[quadlet] wind-tunnel.service restarted");
    }
}

fn restart_edgenode_if_running() {
    let status = Command::new("systemctl")
        .args(["is-active", "edgenode.service"])
        .output();
    if status.map(|o| o.status.success()).unwrap_or(false) {
        let _ = Command::new("systemctl").args(["restart", "edgenode.service"]).output();
        eprintln!("[quadlet] edgenode.service restarted");
    }
}

fn apply_edgenode_config(state: &AppState) {
    write_quadlets_from_state(state);
    if state.hw_mode.lock().unwrap().as_str() != "WIND_TUNNEL" {
        restart_edgenode_if_running();
    }
}

fn validate_log_sender_endpoint(url: &str) -> Option<String> {
    let url = url.trim();
    if url.is_empty() { return None; }
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return Some("Log Collector URL must start with http:// or https://".into());
    }
    if url.chars().any(|c| c == ' ' || c == '\n' || c == '"' || c == '\'') {
        return Some("Log Collector URL contains invalid characters.".into());
    }
    None
}

// ── hApp / EdgeNode bridge ─────────────────────────────────────────────────────

#[derive(Clone)]
struct Deployment {
    id: String,
    app_name: String,
    app_version: String,
    app_id: String,
    status: String,
    deployed_at: String,
    last_error: String,
    manifest: String,
}

fn edgenode_running() -> bool {
    Command::new("systemctl")
        .args(["is-active", "edgenode.service"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn shell_single_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

fn podman_exec_nonroot(cmd: &str) -> (i32, String, String) {
    let quoted = shell_single_quote(cmd);
    let script = format!("podman exec {} su - nonroot -c {}", EDGENODE_CONTAINER, quoted);
    match Command::new("sh").args(["-c", &script]).output() {
        Ok(o) => {
            let code = o.status.code().unwrap_or(1);
            (
                code,
                String::from_utf8_lossy(&o.stdout).to_string(),
                String::from_utf8_lossy(&o.stderr).to_string(),
            )
        }
        Err(e) => (1, String::new(), e.to_string()),
    }
}

fn json_block<'a>(json: &'a str, key: &str) -> &'a str {
    let needle = format!("\"{}\":", key);
    let pos = match json.find(&needle) { Some(p) => p, None => return "" };
    let after = json[pos + needle.len()..].trim_start();
    if !after.starts_with('{') { return ""; }
    let mut depth = 0i32;
    for (i, ch) in after.char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 { return &after[..=i]; }
            }
            _ => {}
        }
    }
    ""
}

fn json_nested_str<'a>(json: &'a str, outer: &str, inner: &str) -> &'a str {
    let block = json_block(json, outer);
    if block.is_empty() { return ""; }
    json_str(block, inner)
}

fn manifest_app_name(manifest: &str) -> String {
    json_nested_str(manifest, "app", "name").to_string()
}

fn manifest_app_version(manifest: &str) -> String {
    json_nested_str(manifest, "app", "version").to_string()
}

fn manifest_has_economics_agreement(manifest: &str) -> bool {
    let econ = json_block(manifest, "economics");
    !econ.is_empty() && !json_str(econ, "agreementHash").is_empty()
}

fn deployment_to_json(d: &Deployment) -> String {
    format!(
        r#"{{"id":"{}","app_name":"{}","app_version":"{}","app_id":"{}","status":"{}","deployed_at":"{}","last_error":"{}","manifest":{}}}"#,
        json_escape(&d.id),
        json_escape(&d.app_name),
        json_escape(&d.app_version),
        json_escape(&d.app_id),
        json_escape(&d.status),
        json_escape(&d.deployed_at),
        json_escape(&d.last_error),
        d.manifest,
    )
}

fn read_deployments() -> Vec<Deployment> {
    let content = fs::read_to_string(DEPLOYMENTS_FILE).unwrap_or_default();
    let trimmed = content.trim();
    if trimmed.is_empty() || trimmed == "[]" { return Vec::new(); }
    let inner = trimmed.strip_prefix('[').and_then(|s| s.strip_suffix(']')).unwrap_or(trimmed);
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut start = 0usize;
    for (i, ch) in inner.char_indices() {
        match ch {
            '{' => {
                if depth == 0 { start = i; }
                depth += 1;
            }
            '}' => {
                depth -= 1;
                if depth == 0 {
                    let obj = &inner[start..=i];
                    out.push(Deployment {
                        id: json_str(obj, "id").to_string(),
                        app_name: json_str(obj, "app_name").to_string(),
                        app_version: json_str(obj, "app_version").to_string(),
                        app_id: json_str(obj, "app_id").to_string(),
                        status: json_str(obj, "status").to_string(),
                        deployed_at: json_str(obj, "deployed_at").to_string(),
                        last_error: json_str(obj, "last_error").to_string(),
                        manifest: extract_manifest_field(obj),
                    });
                }
            }
            _ => {}
        }
    }
    out
}

fn extract_manifest_field(obj: &str) -> String {
    let needle = "\"manifest\":";
    let pos = match obj.find(needle) { Some(p) => p, None => return "{}".into() };
    let after = obj[pos + needle.len()..].trim_start();
    if after.starts_with('{') {
        let mut depth = 0i32;
        for (i, ch) in after.char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 { return after[..=i].to_string(); }
                }
                _ => {}
            }
        }
    }
    "{}".into()
}

fn write_deployments(deployments: &[Deployment]) {
    let _ = fs::create_dir_all("/etc/node-manager");
    let body: String = deployments.iter().map(deployment_to_json).collect::<Vec<_>>().join(",");
    let content = format!("[{}]", body);
    let _ = fs::write(DEPLOYMENTS_FILE, content);
    let _ = Command::new("chmod").args(["600", DEPLOYMENTS_FILE]).output();
}

fn upsert_deployment(deployments: &mut Vec<Deployment>, d: Deployment) {
    if let Some(pos) = deployments.iter().position(|x| x.id == d.id) {
        deployments[pos] = d;
    } else {
        deployments.push(d);
    }
    write_deployments(deployments);
}

fn remove_deployment(deployments: &mut Vec<Deployment>, id: &str) {
    deployments.retain(|d| d.id != id);
    write_deployments(deployments);
}

fn generate_deployment_id() -> String {
    random_hex(16)
}

fn utc_now_iso() -> String {
    let secs = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format_unix_iso(secs)
}

fn format_unix_iso(secs: u64) -> String {
    let days = secs / 86400;
    let rem = secs % 86400;
    let h = rem / 3600;
    let m = (rem % 3600) / 60;
    let s = rem % 60;
    let (y, mo, d) = days_to_ymd(days);
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, mo, d, h, m, s)
}

fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    let mut y = 1970u64;
    let mut remaining = days;
    loop {
        let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
        let year_days = if leap { 366 } else { 365 };
        if remaining < year_days { break; }
        remaining -= year_days;
        y += 1;
    }
    let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
    let month_days = [31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut mo = 1u64;
    for &md in &month_days {
        if remaining < md { break; }
        remaining -= md;
        mo += 1;
    }
    (y, mo, remaining + 1)
}

fn parse_iso_to_secs(iso: &str) -> Option<u64> {
    if iso.len() < 19 { return None; }
    let y: u64 = iso[0..4].parse().ok()?;
    let mo: u64 = iso[5..7].parse().ok()?;
    let d: u64 = iso[8..10].parse().ok()?;
    let h: u64 = iso[11..13].parse().ok()?;
    let m: u64 = iso[14..16].parse().ok()?;
    let s: u64 = iso[17..19].parse().ok()?;
    let mut days = 0u64;
    for year in 1970..y {
        let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
        days += if leap { 366 } else { 365 };
    }
    let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
    let month_days = [31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    for md in &month_days[..(mo as usize - 1).min(12)] {
        days += *md as u64;
    }
    days += d - 1;
    Some(days * 86400 + h * 3600 + m * 60 + s)
}

fn deployed_duration(iso: &str) -> String {
    if iso.is_empty() { return "—".into(); }
    let deployed = match parse_iso_to_secs(iso) {
        Some(s) => s,
        None => return "—".into(),
    };
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if now <= deployed { return "just now".into(); }
    fmt_uptime(now - deployed)
}

fn write_happ_manifest(name: &str, version: &str, manifest: &str) -> Result<String, String> {
    let safe_name: String = name.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-').collect();
    let safe_ver: String = version.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '-').collect();
    if safe_name.is_empty() || safe_ver.is_empty() {
        return Err("Invalid app name or version for manifest file".into());
    }
    let _ = fs::create_dir_all(HAPP_MANIFESTS_DIR);
    let filename = format!("{}-{}.json", safe_name, safe_ver);
    let host_path = format!("{}/{}", HAPP_MANIFESTS_DIR, filename);
    fs::write(&host_path, manifest).map_err(|e| e.to_string())?;
    Ok(format!("/data/manifests/{}", filename))
}

fn extract_app_id_from_install_output(output: &str) -> String {
    for line in output.lines() {
        if let Some(start) = line.find('(') {
            if let Some(end) = line[start + 1..].find(')') {
                let candidate = &line[start + 1..start + 1 + end];
                if candidate.contains("::") && candidate.starts_with("uhC") == false {
                    return candidate.to_string();
                }
                if candidate.contains("::") {
                    return candidate.to_string();
                }
            }
        }
    }
    for part in output.split_whitespace() {
        if part.matches("::").count() >= 2 && part.len() > 10 {
            return part.trim_matches(|c: char| c == ')' || c == '(' || c == '!').to_string();
        }
    }
    String::new()
}

struct LiveHapp {
    app_id: String,
    enabled: bool,
}

fn parse_list_happs_output(output: &str) -> Vec<LiveHapp> {
    let mut out = Vec::new();
    let lower = output.to_lowercase();
    if lower.contains("installed") || lower.contains("enabled") {
        for line in output.lines() {
            let lid = line.to_lowercase();
            let enabled = lid.contains("enabled") && !lid.contains("disabled");
            let disabled = lid.contains("disabled");
            for token in line.split_whitespace() {
                if token.matches("::").count() >= 2 {
                    let app_id = token.trim_matches(|c: char| c == ',' || c == ')' || c == '(' || c == '"' || c == '\'');
                    if app_id.contains("::") {
                        out.push(LiveHapp {
                            app_id: app_id.to_string(),
                            enabled: if disabled { false } else { enabled || !lid.contains("disabled") },
                        });
                    }
                }
            }
        }
    }
    if out.is_empty() {
        for token in output.split(|c: char| c == '"' || c == ',' || c == ' ' || c == '\n' || c == '[' || c == ']') {
            if token.matches("::").count() >= 2 && token.len() > 5 {
                out.push(LiveHapp { app_id: token.to_string(), enabled: true });
            }
        }
    }
    out
}

fn list_installed_happs() -> Result<Vec<LiveHapp>, String> {
    if !edgenode_running() {
        return Err("EdgeNode is not running".into());
    }
    let (code, stdout, stderr) = podman_exec_nonroot("list_happs");
    if code != 0 && stdout.is_empty() {
        return Err(if stderr.is_empty() { format!("list_happs failed (exit {})", code) } else { stderr });
    }
    Ok(parse_list_happs_output(&format!("{}\n{}", stdout, stderr)))
}

fn validate_happ_manifest(container_path: &str) -> (bool, String) {
    let cmd = format!("happ_config_file validate --input {}", container_path);
    let (code, stdout, stderr) = podman_exec_nonroot(&cmd);
    let combined = format!("{}{}", stdout, stderr);
    (code == 0, combined)
}

fn run_install_happ(container_path: &str, node_name: &str) -> (i32, String) {
    let cmd = if node_name.is_empty() {
        format!("install_happ {}", container_path)
    } else {
        format!("install_happ {} {}", container_path, node_name)
    };
    let (code, stdout, stderr) = podman_exec_nonroot(&cmd);
    (code, format!("{}\n{}", stdout, stderr))
}

fn enable_happ(app_id: &str) -> Result<String, String> {
    let (code, stdout, stderr) = podman_exec_nonroot(&format!("enable_happ {}", app_id));
    let out = format!("{}\n{}", stdout, stderr);
    if code != 0 { Err(out) } else { Ok(out) }
}

fn disable_happ(app_id: &str) -> Result<String, String> {
    let (code, stdout, stderr) = podman_exec_nonroot(&format!("disable_happ {}", app_id));
    let out = format!("{}\n{}", stdout, stderr);
    if code != 0 { Err(out) } else { Ok(out) }
}

fn uninstall_happ(app_id: &str) -> Result<String, String> {
    let (code, stdout, stderr) = podman_exec_nonroot(&format!("uninstall_happ {}", app_id));
    let out = format!("{}\n{}", stdout, stderr);
    if code != 0 { Err(out) } else { Ok(out) }
}

fn read_happ_install_log(id: &str) -> String {
    let path = format!("{}/{}.log", HAPP_LOGS_DIR, id);
    fs::read_to_string(&path).unwrap_or_else(|_| "(no install log available)".into())
}

fn tail_container_log(container_path: &str, lines: usize) -> String {
    let cmd = format!("tail -n {} {}", lines, container_path);
    let (_, stdout, stderr) = podman_exec_nonroot(&cmd);
    let out = format!("{}{}", stdout, stderr);
    if out.trim().is_empty() { "(log empty or unavailable)".into() } else { out }
}

fn reconcile_deployment_status(d: &Deployment, live: &[LiveHapp]) -> String {
    if d.status == "installing" { return "installing".into(); }
    if d.app_id.is_empty() {
        return if d.status == "error" { "error".into() } else { d.status.clone() };
    }
    if let Some(h) = live.iter().find(|h| h.app_id == d.app_id) {
        if h.enabled { "running".into() } else { "paused".into() }
    } else if d.status == "error" {
        "error".into()
    } else {
        "error".into()
    }
}

fn happs_prereq_error(state: &AppState) -> Option<String> {
    if state.hw_mode.lock().unwrap().as_str() == "WIND_TUNNEL" {
        return Some("Switch to Standard EdgeNode mode in Mode before managing hApps.".into());
    }
    if !edgenode_running() {
        return Some("EdgeNode is not running. Start Standard EdgeNode mode first.".into());
    }
    None
}

fn spawn_install_job(deployment_id: String, container_path: String, node_name: String) {
    thread::spawn(move || {
        let _ = fs::create_dir_all(HAPP_LOGS_DIR);
        let log_path = format!("{}/{}.log", HAPP_LOGS_DIR, deployment_id);
        let (code, output) = run_install_happ(&container_path, &node_name);
        let _ = fs::write(&log_path, &output);
        let mut deployments = read_deployments();
        let app_id = extract_app_id_from_install_output(&output);
        if let Some(d) = deployments.iter_mut().find(|d| d.id == deployment_id) {
            if code == 0 && !app_id.is_empty() {
                d.status = "running".into();
                d.app_id = app_id;
                d.deployed_at = utc_now_iso();
                d.last_error = String::new();
            } else {
                d.status = "error".into();
                d.last_error = if output.len() > 2000 {
                    output[..2000].to_string()
                } else {
                    output.clone()
                };
            }
            write_deployments(&deployments);
        }
        eprintln!("[happs] Install job {} finished (exit {})", deployment_id, code);
    });
}

fn get_query_param(query: &str, key: &str) -> String {
    for pair in query.split('&') {
        if let Some(eq) = pair.find('=') {
            if &pair[..eq] == key {
                return url_decode(&pair[eq + 1..]);
            }
        } else if pair == key {
            return String::new();
        }
    }
    String::new()
}

// ── Self-update ────────────────────────────────────────────────────────────────

fn check_and_apply_update(repo: &str) {
    eprintln!("[update] Checking {} (current: v{})", repo, VERSION);
    let api_url = format!("https://api.github.com/repos/{}/releases/latest", repo);
    let json = match Command::new("curl").args(["-sf", "-H", "Accept: application/vnd.github+json", "-H", "User-Agent: holo-node-manager", &api_url]).output() {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
        _ => { eprintln!("[update] Could not reach GitHub Releases API"); return; }
    };
    let tag = extract_json_str(&json, "tag_name");
    if tag.is_empty() { eprintln!("[update] Could not parse tag_name"); return; }
    let tag_ver = tag.trim_start_matches('v');
    if tag_ver == VERSION { eprintln!("[update] Already at v{}", VERSION); return; }
    eprintln!("[update] New version: {} (have: {})", tag_ver, VERSION);
    let arch = detect_arch();
    let asset_name = format!("node-manager-{}", arch);
    let download_url = find_asset_download_url(&json, &asset_name);
    if download_url.is_empty() { eprintln!("[update] No asset '{}' in release {}", asset_name, tag); return; }
    let tmp = "/usr/local/bin/node-manager-update";
    let ok = Command::new("curl").args(["-sfL", "-o", tmp, &download_url]).output().map(|o| o.status.success()).unwrap_or(false);
    if !ok { eprintln!("[update] Download failed"); return; }
    let _ = Command::new("chmod").args(["+x", tmp]).output();
    let self_path = env::current_exe().unwrap_or_else(|_| "/usr/local/bin/node-manager".into());
    if let Err(e) = fs::rename(tmp, &self_path) { eprintln!("[update] Replace failed: {}", e); return; }
    eprintln!("[update] Binary replaced. Restarting...");
    let _ = Command::new("systemctl").args(["restart", "node-manager.service"]).output();
}

fn find_asset_download_url(release_json: &str, asset_name: &str) -> String {
    let needle = format!("\"name\":\"{}\"", asset_name);
    let pos = match release_json.find(&needle) { Some(p) => p, None => return String::new() };
    let url_key = "\"browser_download_url\":\"";
    let window = &release_json[pos..];
    let url_pos = match window.find(url_key) { Some(p) => p, None => return String::new() };
    let after = &window[url_pos + url_key.len()..];
    after[..after.find('"').unwrap_or(0)].to_string()
}

fn spawn_update_checker(repo: String) {
    thread::spawn(move || {
        thread::sleep(Duration::from_secs(90));
        loop { check_and_apply_update(&repo); thread::sleep(Duration::from_secs(UPDATE_INTERVAL_SECS)); }
    });
}

// ── Node operations ────────────────────────────────────────────────────────────

fn container_services_for_mode(hw_mode: &str) -> (&'static str, &'static str) {
    if hw_mode == "WIND_TUNNEL" {
        ("wind-tunnel.service", "edgenode.service")
    } else {
        ("edgenode.service", "wind-tunnel.service")
    }
}

fn sync_container_services(hw_mode: &str) {
    let (active, inactive) = container_services_for_mode(hw_mode);
    let _ = Command::new("systemctl").args(["disable", "--now", inactive]).output();
    let _ = Command::new("systemctl").args(["enable", "--now", active]).output();
    eprintln!("[container] enabled {} disabled {}", active, inactive);
}

fn apply_hardware_mode(new_mode: &str, state: &AppState) {
    let current = state.hw_mode.lock().unwrap().clone();
    let _ = fs::write("/var/lib/edgenode/mode_switch.txt", new_mode);
    *state.hw_mode.lock().unwrap() = new_mode.to_string();
    update_state_key("hw_mode", new_mode);
    write_quadlets_from_state(state);
    if current != new_mode {
        let (active, inactive) = container_services_for_mode(new_mode);
        eprintln!("[manage] Switching {} → {}", inactive, active);
        sync_container_services(new_mode);
    }
}

// ── JSON / HTML helpers ────────────────────────────────────────────────────────

fn json_has_key(json: &str, key: &str) -> bool {
    json.contains(&format!("\"{}\"", key))
}

fn json_bool(json: &str, key: &str, default: bool) -> bool {
    if !json_has_key(json, key) { return default; }
    let v = json_str(json, key);
    !matches!(v, "false" | "0")
}

fn json_str<'a>(json: &'a str, key: &str) -> &'a str {
    let needle = format!("\"{}\"", key);
    let pos = match json.find(&needle) { Some(p) => p, None => return "" };
    let after = json[pos + needle.len()..].splitn(2, ':').nth(1).unwrap_or("").trim_start();
    if after.starts_with('"') { let inner = &after[1..]; &inner[..inner.find('"').unwrap_or(0)] } else { "" }
}

fn json_raw_value(json: &str, key: &str) -> String {
    let needle = format!("\"{}\":", key);
    let pos = match json.find(&needle) { Some(p) => p, None => return String::new() };
    let after = json[pos + needle.len()..].trim_start();
    if after.starts_with('"') {
        let inner = &after[1..];
        let end = inner.find('"').unwrap_or(0);
        return inner[..end].to_string();
    }
    if after.starts_with('{') || after.starts_with('[') {
        let open = after.chars().next().unwrap();
        let close = if open == '{' { '}' } else { ']' };
        let mut depth = 0i32;
        for (i, ch) in after.char_indices() {
            if ch == open { depth += 1; }
            else if ch == close {
                depth -= 1;
                if depth == 0 { return after[..=i].to_string(); }
            }
        }
    }
    String::new()
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

fn parse_form(body: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for pair in body.split('&') {
        if let Some(eq) = pair.find('=') {
            map.insert(url_decode(&pair[..eq]), url_decode(&pair[eq + 1..]));
        }
    }
    map
}

fn url_encode_query(s: &str) -> String {
    let mut result = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                result.push(b as char);
            }
            _ => result.push_str(&format!("%{:02X}", b)),
        }
    }
    result
}

fn wt_status_url(wt_hostname: &str) -> String {
    format!(
        "https://wind-tunnel-runner-status.holochain.org/status?hostname={}",
        url_encode_query(wt_hostname)
    )
}

fn url_decode(s: &str) -> String {
    let mut result = String::new();
    let mut bytes = s.bytes().peekable();
    while let Some(b) = bytes.next() {
        if b == b'+' { result.push(' '); }
        else if b == b'%' {
            let h1 = bytes.next().unwrap_or(b'0') as char;
            let h2 = bytes.next().unwrap_or(b'0') as char;
            if let Ok(byte) = u8::from_str_radix(&format!("{}{}", h1, h2), 16) { result.push(byte as char); }
        } else { result.push(b as char); }
    }
    result
}

// ── HTTP helpers ───────────────────────────────────────────────────────────────

fn send_response(stream: &mut TcpStream, status: u16, reason: &str, ctype: &str, body: &[u8]) {
    let hdr = format!("HTTP/1.1 {status} {reason}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
    let _ = stream.write_all(hdr.as_bytes()); let _ = stream.write_all(body);
}
fn send_html(stream: &mut TcpStream, html: &str) { send_response(stream, 200, "OK", "text/html; charset=utf-8", html.as_bytes()); }
fn send_json_ok(stream: &mut TcpStream, body: &str) { send_response(stream, 200, "OK", "application/json", body.as_bytes()); }
fn send_json_err(stream: &mut TcpStream, status: u16, msg: &str) {
    let body = format!("{{\"error\":\"{}\"}}", json_escape(msg));
    send_response(stream, status, "Error", "application/json", body.as_bytes());
}
fn send_redirect(stream: &mut TcpStream, location: &str) {
    let _ = stream.write_all(format!("HTTP/1.1 302 Found\r\nLocation: {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", location).as_bytes());
}
fn send_redirect_with_cookie(stream: &mut TcpStream, location: &str, cookie: &str) {
    let _ = stream.write_all(format!("HTTP/1.1 302 Found\r\nLocation: {}\r\nSet-Cookie: {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", location, cookie).as_bytes());
}

struct Req { method: String, path: String, query: String, headers: String, body: String }

fn read_request(stream: &mut TcpStream) -> Option<Req> {
    let mut r = BufReader::new(stream.try_clone().ok()?);
    let mut line0 = String::new(); r.read_line(&mut line0).ok()?;
    let mut parts = line0.trim().splitn(3, ' ');
    let method   = parts.next()?.to_string();
    let path_raw = parts.next()?.to_string();
    let (path, query) = match path_raw.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (path_raw, String::new()),
    };
    let mut cl: usize = 0; let mut headers = String::new();
    loop {
        let mut line = String::new(); r.read_line(&mut line).ok()?;
        if line.trim().is_empty() { break; }
        let lower = line.to_lowercase();
        if lower.starts_with("content-length:") { cl = lower["content-length:".len()..].trim().parse().unwrap_or(0); }
        headers.push_str(&line);
    }
    let mut body = vec![0u8; cl.min(1 << 20)];
    if cl > 0 { r.read_exact(&mut body).ok()?; }
    Some(Req { method, path, query, headers, body: String::from_utf8_lossy(&body).into_owned() })
}

fn get_cookie(headers: &str, name: &str) -> Option<String> {
    for line in headers.lines() {
        if line.to_lowercase().starts_with("cookie:") {
            for pair in line["cookie:".len()..].trim().split(';') {
                let p = pair.trim();
                if let Some(eq) = p.find('=') {
                    if p[..eq].trim() == name { return Some(p[eq + 1..].trim().to_string()); }
                }
            }
        }
    }
    None
}

fn fmt_uptime(secs: u64) -> String {
    if secs < 60 { format!("{}s", secs) }
    else if secs < 3600 { format!("{}m", secs / 60) }
    else if secs < 86400 { format!("{}h {}m", secs / 3600, (secs % 3600) / 60) }
    else { format!("{}d {}h", secs / 86400, (secs % 86400) / 3600) }
}

// ── Common CSS ─────────────────────────────────────────────────────────────────

const COMMON_CSS: &str = r#"
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',system-ui,sans-serif;background:#0f1117;color:#e2e8f0;min-height:100vh;display:flex;align-items:flex-start;justify-content:center;padding:32px 16px}
.card{background:#1a1d27;border:1px solid #2d3148;border-radius:16px;width:100%;max-width:600px;overflow:hidden}
.hdr{background:linear-gradient(135deg,#1e2d5a,#2d1e5a);padding:24px 32px}
.hdr h1{font-size:20px;font-weight:700;color:#fff;letter-spacing:-.3px}
.hdr p{color:#94a3b8;font-size:13px;margin-top:4px}
.body{padding:28px 32px}
label{display:block;font-size:13px;font-weight:600;color:#94a3b8;margin-bottom:5px;margin-top:14px}
label:first-of-type{margin-top:0}
input[type=text],input[type=password],input[type=url],input[type=number],textarea,select{width:100%;padding:10px 12px;background:#0f1117;border:1px solid #2d3148;border-radius:8px;color:#e2e8f0;font-size:14px;outline:none;transition:border-color .2s;font-family:inherit}
textarea{resize:vertical;min-height:80px;font-size:12px;font-family:monospace}
input:focus,textarea:focus,select:focus{border-color:#6366f1}
select option{background:#1a1d27}
.hint{font-size:12px;color:#475569;margin-top:5px;line-height:1.5}
.hint a{color:#818cf8;text-decoration:none}
.ok-box{background:#0d2618;border:1px solid #166534;border-radius:8px;padding:11px 14px;color:#86efac;font-size:13px;margin-bottom:16px}
.err-box{background:#2d1515;border:1px solid #7f1d1d;border-radius:8px;padding:11px 14px;color:#fca5a5;font-size:13px;margin-bottom:16px}
.info-box{background:#0f172a;border:1px solid #1e40af;border-radius:8px;padding:11px 14px;font-size:12px;color:#93c5fd;line-height:1.6;margin-top:12px}
.btn{padding:10px 20px;border:none;border-radius:8px;font-size:14px;font-weight:700;cursor:pointer;font-family:inherit;transition:all .2s}
.btn-primary{background:linear-gradient(135deg,#6366f1,#8b5cf6);color:#fff}
.btn-primary:hover{opacity:.9;transform:translateY(-1px)}
.btn-primary:disabled{opacity:.4;cursor:not-allowed;transform:none}
.btn-secondary{background:#0f1117;border:1px solid #2d3148;color:#94a3b8}
.btn-secondary:hover{border-color:#6366f1;color:#e2e8f0}
.btn-danger{background:#7f1d1d;border:1px solid #991b1b;color:#fca5a5}
.btn-danger:hover{background:#991b1b}
.divider{height:1px;background:#2d3148;margin:20px 0}
code{background:#1e2740;padding:1px 5px;border-radius:4px;font-family:monospace;color:#a5b4fc;font-size:12px}
.hw-opts{display:flex;gap:8px;margin-bottom:10px}
.hw-opt{flex:1;padding:12px;background:#0f1117;border:2px solid #2d3148;border-radius:10px;cursor:pointer;transition:all .2s}
.hw-opt:hover,.hw-opt.sel{border-color:#6366f1}.hw-opt.sel{background:#1e1d3f}
.hw-opt-name{font-size:13px;font-weight:600;color:#e2e8f0}.hw-opt-desc{font-size:11px;color:#475569;margin-top:2px}
"#;

// ── Login page ─────────────────────────────────────────────────────────────────

fn build_login_html(error: bool) -> String {
    let err = if error { r#"<div class="err-box">Incorrect password. Try again.</div>"# } else { "" };
    format!(r#"<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Holo Node — Login</title>
<style>{css}body{{align-items:center}}.card{{max-width:400px}}.hdr{{text-align:center}}.icon{{font-size:42px;margin-bottom:10px}}form .btn{{width:100%;margin-top:18px}}</style></head><body>
<div class="card">
  <div class="hdr"><div class="icon">🜲</div><h1>Holo Node</h1><p>Enter your node password to continue.</p></div>
  <div class="body">{err}
    <form method="POST" action="/login">
      <label for="pw">Password</label>
      <input type="password" id="pw" name="password" autofocus autocomplete="current-password">
      <button type="submit" class="btn btn-primary">Unlock →</button>
    </form>
  </div>
</div></body></html>"#, css=COMMON_CSS, err=err)
}

// ── Onboarding page ────────────────────────────────────────────────────────────

const UNYT_INFO_COPY: &str = r#"<div class="info-box" style="margin-top:12px"><strong>HoloFuel compensation requires a Unyt Agent ID.</strong> Download the Unyt desktop app, sign in, and copy your Agent ID from the app settings. Setup can finish without it, but you will not receive HoloFuel payments until an Agent ID is saved.</div>"#;

fn build_onboarding_html(ap_mode: bool) -> String {
    let wifi_block = if ap_mode {
        r#"<div class="err-box">⚠ No Ethernet — connect to Wi-Fi to continue.</div>
<label>Wi-Fi SSID</label><input type="text" id="wifiSsid" placeholder="Network name">
<label>Wi-Fi Password</label><input type="password" id="wifiPass">"#
    } else {
        r#"<div class="ok-box">✓ Ethernet connected — you're online.</div>"#
    };

    format!(r#"<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Holo Node Setup</title>
<style>
{css}
.prog{{height:3px;background:#0f1117}}.prog-fill{{height:100%;background:linear-gradient(90deg,#6366f1,#8b5cf6);transition:width .4s ease}}
.step{{display:none}}.step.active{{display:block}}
.slbl{{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:#6366f1;margin-bottom:12px}}
.stit{{font-size:18px;font-weight:700;color:#f1f5f9;margin-bottom:5px}}
.sdsc{{font-size:13px;color:#64748b;margin-bottom:20px;line-height:1.6}}
.brow{{display:flex;gap:10px;margin-top:24px}}.brow .btn{{flex:1}}
.spin{{display:none;width:20px;height:20px;border:2px solid rgba(255,255,255,.3);border-top-color:#fff;border-radius:50%;animation:sp .6s linear infinite;margin:0 auto}}
@keyframes sp{{to{{transform:rotate(360deg)}}}}
.suc{{text-align:center;padding:24px 0}}.suc h2{{font-size:24px;font-weight:700;color:#86efac;margin-bottom:12px}}.suc p{{color:#64748b;font-size:14px;line-height:1.7}}
.rt{{width:100%;border-collapse:collapse;font-size:13px}}.rt tr{{border-bottom:1px solid #2d3148}}.rt tr:last-child{{border-bottom:none}}
.rt td{{padding:9px 0;vertical-align:top}}.rt td:first-child{{color:#64748b;width:130px;padding-right:12px}}.rt td:last-child{{color:#e2e8f0;font-weight:500;word-break:break-all}}
</style></head><body>
<div class="card">
  <div class="hdr"><h1>🜲 Holo Node</h1><p>One-time setup — about 2 minutes.</p></div>
  <div class="prog"><div class="prog-fill" id="prog" style="width:0%"></div></div>
  <div class="body">
    {wifi_block}

    <!-- STEP 1: IDENTITY + SSH -->
    <div class="step active" id="s1">
      <div class="slbl">Step 1 of 2</div>
      <div class="stit">Node identity &amp; SSH access</div>
      <div class="sdsc">Name your node and optionally add your SSH public key for remote access.</div>
      <label>Node name *</label>
      <input type="text" id="nodeName" placeholder="e.g. alice, home-node-01" oninput="chkS1()">
      <div class="hint" id="nameHint">Lowercase letters, numbers and hyphens only. Used as hostname slug.</div>
      <label>Mode</label>
      <select id="hw">
        <option value="STANDARD">Standard EdgeNode — always-on Holochain peer</option>
        <option value="WIND_TUNNEL">Holochain Wind Tunnel — network stress-tester</option>
      </select>
      <label>SSH public key <span style="color:#475569;font-weight:400">(recommended)</span></label>
      <textarea id="sshKey" placeholder="ssh-ed25519 AAAA...&#10;Leave blank to add keys later in /manage"></textarea>
      <label>Unyt Agent ID <span style="color:#475569;font-weight:400">(optional)</span></label>
      <input type="text" id="unytAgentId" placeholder="Paste your Agent ID from the Unyt desktop app" oninput="chkS1()">
      {unyt_copy}
      <div class="brow"><button class="btn btn-primary" id="b1" onclick="gTo(2)" disabled>Review →</button></div>
    </div>

    <!-- STEP 2: REVIEW -->
    <div class="step" id="s2">
      <div class="slbl">Step 2 of 2</div>
      <div class="stit">Review &amp; initialize</div>
      <div class="sdsc">Check your settings, then start the node.</div>
      <table class="rt">
        <tr><td>Node Name</td><td id="rv-nn">—</td></tr>
        <tr><td>Mode</td><td id="rv-hw">—</td></tr>
        <tr><td>SSH Key</td><td id="rv-sk">—</td></tr>
        <tr><td>Unyt Agent ID</td><td id="rv-unyt">—</td></tr>
        <tr id="rv-wt-row" style="display:none"><td>Wind Tunnel hostname</td><td id="rv-wt">—</td></tr>
      </table>
      <div class="info-box" style="margin-top:16px">After initialization:<br>
        1. SSH access is configured for the <code>holo</code> user<br>
        2. Podman Quadlet services are registered with systemd<br>
        3. You will be redirected to the management panel</div>
      <div class="brow">
        <button class="btn btn-secondary" onclick="gTo(1)">← Back</button>
        <button class="btn btn-primary" id="bsub" onclick="doSubmit()">
          <span id="slbl-btn">Initialize Node</span>
          <div class="spin" id="spin"></div>
        </button>
      </div>
    </div>

    <!-- SUCCESS -->
    <div class="step" id="suc"><div class="suc"><div style="font-size:48px;margin-bottom:16px">🜲</div><h2>Node Initialized!</h2><p>Redirecting to the management panel…</p></div></div>
  </div>
</div>
<script>
function v(id){{const e=document.getElementById(id);return e?e.value.trim():'';}}

function gTo(n){{
  document.querySelectorAll('.step').forEach(s=>s.classList.remove('active'));
  document.getElementById(n===3?'suc':'s'+n).classList.add('active');
  document.getElementById('prog').style.width=(Math.min(n,2)/2*100)+'%';
  if(n===2)bRev();
  window.scrollTo(0,0);
}}

function chkS1(){{
  const name=v('nodeName');
  const agent=v('unytAgentId');
  const ok=/^[a-z0-9-]+$/.test(name);
  document.getElementById('b1').disabled=!ok;
  const hint=document.getElementById('nameHint');
  if(!hint)return;
  if(!ok){{hint.textContent='Lowercase letters, numbers and hyphens only. Used as hostname slug.';return;}}
  const wtName=agent?name+'-'+agent.trim():name+'-'+('0'.repeat(16));
  if(wtName.length>63){{hint.textContent='With this Agent ID, node name must be at most '+(63-(1+(agent?agent.trim().length:16)))+' characters for Wind Tunnel client tracking.';document.getElementById('b1').disabled=true;return;}}
  hint.textContent='Lowercase letters, numbers and hyphens only. Used as hostname slug.';
}}

function wtNameLen(name,agent){{
  const a=agent.trim();
  return a?name.length+1+a.length:name.length+1+16;
}}

function wtHostname(name){{
  return 'nomad-client-'+name;
}}

function bRev(){{
  const sk=v('sshKey');
  const agent=v('unytAgentId');
  const set=(id,t)=>{{const e=document.getElementById(id);if(e)e.textContent=t;}};
  set('rv-nn',v('nodeName')||'—');
  set('rv-sk',sk?sk.split(' ')[0]+' ••••':'(not provided)');
  set('rv-unyt',agent||'(not provided — compensation unavailable)');
  set('rv-hw',v('hw')==='WIND_TUNNEL'?'Wind Tunnel':'Standard EdgeNode');
  const wtRow=document.getElementById('rv-wt-row');
  if(v('hw')==='WIND_TUNNEL'){{
    wtRow.style.display='';
    set('rv-wt',wtHostname(v('nodeName')));
  }}else{{wtRow.style.display='none';}}
}}

async function doSubmit(){{
  const nodeName=v('nodeName');
  const agent=v('unytAgentId');
  if(!nodeName)return alert('Node name is required.');
  if(!/^[a-z0-9-]+$/.test(nodeName))return alert('Node name must be lowercase letters, numbers and hyphens only.');
  if(wtNameLen(nodeName,agent)>63)return alert('Node name is too long for Wind Tunnel tracking with this Agent ID. Shorten the node name.');
  const btn=document.getElementById('bsub');
  btn.disabled=true;
  document.getElementById('slbl-btn').style.display='none';
  document.getElementById('spin').style.display='block';
  const p={{
    nodeName,
    sshKey:v('sshKey'),
    unytAgentId:agent,
    hwMode:v('hw'),
    wifiSsid:v('wifiSsid'),
    wifiPass:v('wifiPass'),
  }};
  try{{
    const r=await fetch('/submit',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify(p)}});
    if(r.ok){{gTo(3);setTimeout(()=>window.location.href='/manage',2000);}}
    else{{throw new Error('Server error '+r.status+': '+(await r.text()));}}
  }}catch(e){{
    btn.disabled=false;
    document.getElementById('slbl-btn').style.display='inline';
    document.getElementById('spin').style.display='none';
    alert('Error: '+e.message);
  }}
}}
</script>
</body></html>"#,
        css        = COMMON_CSS,
        wifi_block = wifi_block,
        unyt_copy  = UNYT_INFO_COPY,
    )
}

// ── build_manage_html ──────────────────────────────────────────────────────────

fn build_manage_html(state: &AppState) -> String {
    let node_name     = state.node_name.lock().unwrap().clone();
    let hw_mode       = state.hw_mode.lock().unwrap().clone();
    let unyt_agent_id  = state.unyt_agent_id.lock().unwrap().clone();
    let log_sender_endpoint = state.log_sender_endpoint.lock().unwrap().clone();
    let ssh_keys       = read_ssh_keys();
    let uptime_s       = state.start_time.elapsed().unwrap_or_default().as_secs();
    let ip             = get_local_ip();
    let wt_hostname    = build_wt_hostname(&node_name);
    let wt_image_override  = state.wt_image_override.lock().unwrap().clone();
    let wt_entrypoint_bind = state.wt_entrypoint_bind.lock().unwrap().clone();
    let wt_cfg = resolve_wind_tunnel_config(state);
    let wt_effective_image = wt_cfg.image.clone();
    let wt_entrypoint_display = wt_cfg.entrypoint_bind.as_deref().map(|s| s.to_string()).unwrap_or_else(|| "(none)".into());
    let wt_status_link = wt_status_url(&wt_hostname);

    let unyt_display = if unyt_agent_id.is_empty() {
        "(not set — compensation unavailable)".to_string()
    } else {
        unyt_agent_id.clone()
    };
    let unyt_badge = if unyt_agent_id.is_empty() { "badge-gray" } else { "badge-green" };
    let unyt_badge_text = if unyt_agent_id.is_empty() { "not set" } else { "set" };

    let keys_html: String = if ssh_keys.is_empty() {
        r#"<div class="no-keys">No SSH keys configured. Add one below to enable SSH access.</div>"#.to_string()
    } else {
        ssh_keys.iter().enumerate().map(|(i, k)| {
            let short = if k.len() > 72 { format!("{}…", &k[..72]) } else { k.clone() };
            format!(
                r#"<div class="key-row"><span class="key-type">{}</span><span class="key-val">{}</span><button class="btn btn-danger btn-sm" onclick="removeKey({})">Remove</button></div>"#,
                html_escape(k.split_whitespace().next().unwrap_or("key")),
                html_escape(&short), i
            )
        }).collect()
    };

    let sel_std = if hw_mode != "WIND_TUNNEL" { " sel" } else { "" };
    let sel_wt  = if hw_mode == "WIND_TUNNEL"  { " sel" } else { "" };
    let hw_mode_display = if hw_mode == "WIND_TUNNEL" { "Wind Tunnel" } else { "EdgeNode" };
    let happs_disabled = hw_mode == "WIND_TUNNEL";
    let happs_disabled_msg = if happs_disabled {
        r#"<div class="info-box" style="margin-bottom:14px">hApp hosting is only available in Standard EdgeNode mode. Switch to Standard EdgeNode mode above to host applications.</div>"#
    } else if !edgenode_running() {
        r#"<div class="err-box" style="margin-bottom:14px">EdgeNode is not running. Switch to Standard EdgeNode mode and ensure the container is started.</div>"#
    } else {
        ""
    };

    let ssh_count  = ssh_keys.len();
    let ssh_plural = if ssh_count == 1 { "" } else { "s" };

    format!(r#"<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Holo Node — {node_name}</title>
<style>
{css}
.toast{{position:fixed;bottom:24px;right:24px;padding:10px 16px;border-radius:8px;font-size:13px;font-weight:600;opacity:0;transform:translateY(8px);transition:all .3s;pointer-events:none;z-index:999}}
.toast.ok{{background:#0d2618;border:1px solid #166534;color:#86efac}}
.toast.err{{background:#2d1515;border:1px solid #7f1d1d;color:#fca5a5}}
.toast.vis{{opacity:1;transform:none}}
.page-hdr{{background:linear-gradient(135deg,#1e2d5a,#2d1e5a);padding:20px 32px;display:flex;align-items:center;justify-content:space-between}}
.page-hdr h1{{font-size:18px;font-weight:700;color:#fff}}
.page-hdr p{{color:#94a3b8;font-size:12px;margin-top:2px}}
.logout{{background:transparent;border:1px solid #3d4468;color:#94a3b8;padding:6px 14px;border-radius:6px;cursor:pointer;font-size:12px;font-family:inherit}}
.logout:hover{{border-color:#6366f1;color:#e2e8f0}}
.info-row{{display:flex;flex-wrap:wrap;gap:8px;padding:14px 32px;background:#13162a;border-bottom:1px solid #2d3148}}
.info-item{{font-size:12px;color:#64748b;display:flex;align-items:center;gap:6px}}
.info-item span{{background:#1a1d27;border:1px solid #2d3148;border-radius:6px;padding:2px 8px;color:#94a3b8;font-size:12px}}
.section{{border-bottom:1px solid #2d3148}}
.section:last-child{{border-bottom:none}}
.section-hdr{{padding:16px 32px;cursor:pointer;display:flex;align-items:center;justify-content:space-between;user-select:none}}
.section-hdr:hover{{background:#1e2030}}
.section-title{{font-size:14px;font-weight:600;color:#e2e8f0;display:flex;align-items:center;gap:8px}}
.section-badge{{font-size:11px;font-weight:700;padding:2px 8px;border-radius:10px}}
.badge-green{{background:#0d2618;border:1px solid #166534;color:#86efac}}
.badge-gray{{background:#1a1d27;border:1px solid #3d4468;color:#64748b}}
.section-arrow{{color:#475569;font-size:12px}}
.section-body{{padding:4px 32px 20px;display:none}}
.key-row{{display:flex;align-items:center;gap:8px;padding:8px 0;border-bottom:1px solid #1e2030}}
.key-row:last-child{{border-bottom:none}}
.key-type{{font-size:11px;font-weight:700;color:#6366f1;background:#1e1d3f;padding:2px 6px;border-radius:4px;flex-shrink:0}}
.key-val{{flex:1;font-size:12px;font-family:monospace;color:#94a3b8;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
.btn-sm{{padding:5px 10px;font-size:12px}}
.no-keys{{font-size:13px;color:#475569;padding:8px 0;margin-bottom:8px}}
.happ-row{{padding:12px 0;border-bottom:1px solid #1e2030}}
.happ-row:last-child{{border-bottom:none}}
.happ-name{{font-size:14px;font-weight:600;color:#e2e8f0}}
.happ-meta{{font-size:12px;color:#64748b;margin-top:4px}}
.happ-actions{{display:flex;gap:8px;margin-top:10px;flex-wrap:wrap}}
.badge-running{{background:#0d2618;border:1px solid #166534;color:#86efac}}
.badge-paused{{background:#1a1d27;border:1px solid #3d4468;color:#94a3b8}}
.badge-error{{background:#2d1515;border:1px solid #7f1d1d;color:#fca5a5}}
.badge-installing{{background:#1e1d3f;border:1px solid #4338ca;color:#a5b4fc}}
.tab-bar{{display:flex;gap:8px;margin-bottom:12px}}
.tab-btn{{padding:6px 12px;border-radius:6px;border:1px solid #2d3148;background:#0f1117;color:#94a3b8;cursor:pointer;font-size:12px;font-family:inherit}}
.tab-btn.active{{border-color:#6366f1;color:#e2e8f0;background:#1e1d3f}}
.log-box{{background:#0f1117;border:1px solid #2d3148;border-radius:8px;padding:10px;font-size:11px;font-family:monospace;color:#94a3b8;max-height:200px;overflow:auto;white-space:pre-wrap;margin-top:8px}}
</style></head><body style="align-items:flex-start;padding:0">
<div class="card" style="max-width:680px;border-radius:0 0 16px 16px;min-height:100vh">
  <div class="page-hdr">
    <div>
      <h1>🜲 {node_name}</h1>
      <p>Node Manager v{version} &nbsp;·&nbsp; {ip} &nbsp;·&nbsp; up {uptime}</p>
    </div>
    <form method="POST" action="/logout" style="margin:0"><button type="submit" class="logout">Log out</button></form>
  </div>
  <div class="info-row">
    <div class="info-item">Mode <span id="info-hw">{hw_mode_display}</span></div>
    <div class="info-item">Unyt <span id="info-unyt">{unyt_badge_text}</span></div>
  </div>

  <!-- NODE NAME -->
  <div class="section">
    <div class="section-hdr" onclick="toggleSection('name')">
      <div class="section-title"><span>🏷</span> Node Name</div>
      <span class="section-arrow" id="arr-name">▼</span>
    </div>
    <div class="section-body" id="sec-name">
      <label>Node name</label>
      <input type="text" id="nodeName" value="{node_name_escaped}" placeholder="e.g. alice, home-node-01" oninput="chkNodeName()">
      <div class="hint" id="nodeNameHint">Lowercase letters, numbers and hyphens only.</div>
      <div style="margin-top:10px"><button class="btn btn-primary" id="nodeNameBtn" onclick="saveNodeName()" disabled>Save Node Name</button></div>
    </div>
  </div>

  <!-- MODE -->
  <div class="section">
    <div class="section-hdr" onclick="toggleSection('hw')">
      <div class="section-title"><span>⚙️</span> Mode <span class="section-badge badge-green" id="hw-badge">{hw_mode_display}</span></div>
      <span class="section-arrow" id="arr-hw">▼</span>
    </div>
    <div class="section-body" id="sec-hw">
      <div class="hw-opts">
        <div class="hw-opt{sel_std}" onclick="selHw('STANDARD',this)">
          <div class="hw-opt-name">🌐 Standard EdgeNode</div>
          <div class="hw-opt-desc">Always-on Holochain peer</div>
        </div>
        <div class="hw-opt{sel_wt}" onclick="selHw('WIND_TUNNEL',this)">
          <div class="hw-opt-name">🌀 Wind Tunnel</div>
          <div class="hw-opt-desc">Network stress-tester</div>
        </div>
      </div>
      <div style="margin-top:10px"><button class="btn btn-primary" onclick="saveHardware()">Apply Mode</button></div>
    </div>
  </div>

  <!-- HOLOFUEL -->
  <div class="section">
    <div class="section-hdr" onclick="toggleSection('unyt')">
      <div class="section-title"><span>💰</span> HoloFuel <span class="section-badge {unyt_badge}" id="unyt-badge">{unyt_badge_text}</span></div>
      <span class="section-arrow" id="arr-unyt">▼</span>
    </div>
    <div class="section-body" id="sec-unyt">
      {unyt_copy}
      <p style="font-size:13px;color:#64748b;margin:14px 0">Current Agent ID: <strong style="color:#e2e8f0">{unyt_display}</strong></p>
      <label>Unyt Agent ID</label>
      <input type="text" id="unytAgentId" value="{unyt_agent_id_escaped}" placeholder="Paste your Agent ID from the Unyt desktop app">
      <div class="hint">Your Unyt public key — used for HoloFuel compensation and as LOG_SENDER_UNYT_PUB_KEY for hosted hApp invoicing.</div>
      <div style="margin-top:10px">
        <button class="btn btn-primary" onclick="saveUnyt()">Save Agent ID</button>
      </div>
    </div>
  </div>

  <!-- HOSTED HAPPS -->
  <div class="section">
    <div class="section-hdr" onclick="toggleSection('happs')">
      <div class="section-title"><span>📦</span> Hosted hApps</div>
      <span class="section-arrow" id="arr-happs">▼</span>
    </div>
    <div class="section-body" id="sec-happs" style="display:block">
      {happs_disabled_msg}
      <div id="happs-list"><p style="font-size:13px;color:#475569">Loading hosted applications…</p></div>
      <div style="margin-top:16px;padding-top:16px;border-top:1px solid #2d3148">
        <div class="section-title" style="margin-bottom:12px;font-size:13px"><span>➕</span> Add hApp</div>
        <div class="tab-bar">
          <button class="tab-btn active" id="tab-paste" onclick="switchManifestTab('paste')">Paste manifest</button>
          <button class="tab-btn" id="tab-manual" onclick="switchManifestTab('manual')">Manual entry</button>
        </div>
        <div id="manifest-paste">
          <label>hApp manifest (JSON)</label>
          <textarea id="manifestJson" rows="12" placeholder='{{"app":{{"name":"my_app",...}},"economics":{{...}}}}'></textarea>
        </div>
        <div id="manifest-manual" style="display:none">
          <label>app.name</label><input type="text" id="mf-name" placeholder="my_app">
          <label>app.version</label><input type="text" id="mf-version" placeholder="0.1.0">
          <label>app.happUrl</label><input type="url" id="mf-happUrl" placeholder="https://.../app.happ">
          <label>app.modifiers.networkSeed</label><input type="text" id="mf-networkSeed" placeholder="your-network-seed">
          <label>economics.agreementHash</label><input type="text" id="mf-agreementHash" placeholder="uhCkk...">
          <label>economics.payorUnytAgentPubKey</label><input type="text" id="mf-payor" placeholder="uhCAk...">
          <label>economics.priceSheetHash (optional)</label><input type="text" id="mf-priceSheet" placeholder="">
        </div>
        <div id="validate-result" style="display:none;margin-top:10px"></div>
        <div style="margin-top:12px;display:flex;gap:8px;flex-wrap:wrap">
          <button class="btn btn-secondary" onclick="validateManifest()" id="validate-btn">Validate</button>
          <button class="btn btn-primary" onclick="deployManifest()" id="deploy-btn">Deploy</button>
        </div>
      </div>
    </div>
  </div>

  <!-- SSH KEYS -->
  <div class="section">
    <div class="section-hdr" onclick="toggleSection('ssh')">
      <div class="section-title"><span>🔑</span> SSH Keys <span class="section-badge badge-green">{ssh_count} key{ssh_plural}</span></div>
      <span class="section-arrow" id="arr-ssh">▼</span>
    </div>
    <div class="section-body" id="sec-ssh" style="display:block">
      <div id="key-list">{keys_html}</div>
      <div style="margin-top:12px">
        <label>Add SSH public key</label>
        <textarea id="newKey" placeholder="ssh-ed25519 AAAA… or ssh-rsa AAAA…"></textarea>
        <div style="margin-top:8px"><button class="btn btn-primary" onclick="addKey()">Add Key</button></div>
      </div>
    </div>
  </div>

  <!-- ADVANCED -->
  <div class="section">
    <div class="section-hdr" onclick="toggleSection('adv')">
      <div class="section-title"><span>🔧</span> Advanced</div>
      <span class="section-arrow" id="arr-adv">▼</span>
    </div>
    <div class="section-body" id="sec-adv">
      <div class="info-box" style="margin-top:0;margin-bottom:16px">These settings are for support and feature testing only. Do not change them unless you are explicitly testing features or working with support. Changing them may interfere with your ability to earn HoloFuel.</div>
      <div class="section-title" style="margin-bottom:12px;font-size:13px"><span>📡</span> Log Collector URL</div>
      <label>Log Collector URL</label>
      <input type="url" id="logSenderEndpoint" value="{log_sender_endpoint_escaped}" placeholder="https://your-log-collector.example.com">
      <div class="hint">LOG_SENDER_ENDPOINT — required for Unyt resource accounting when hosting hApps with an economics section.</div>
      <div style="margin-top:10px"><button class="btn btn-secondary" onclick="saveLogSender()">Save Log Collector URL</button></div>
      <div style="margin-top:20px;padding-top:16px;border-top:1px solid #2d3148">
        <div class="section-title" style="margin-bottom:12px;font-size:13px"><span>🌀</span> Wind Tunnel</div>
        <p style="font-size:13px;color:#64748b;margin-bottom:14px">
          Nomad hostname: <code>{wt_hostname}</code><br>
          Effective image: <code>{wt_effective_image}</code><br>
          Entrypoint bind: <code>{wt_entrypoint_display}</code><br>
          <a href="{wt_status_link}" target="_blank" rel="noopener" style="color:#818cf8;font-size:12px">Check Wind Tunnel runner status</a>
        </p>
        <p style="font-size:12px;color:#475569;margin-bottom:14px">
          Optional overrides for testing patched entrypoints or custom images. Leave empty to use production defaults.
        </p>
        <label>Image override</label>
        <input type="text" id="wtImageOverride" value="{wt_image_override_escaped}" placeholder="ghcr.io/holochain/wind-tunnel-runner:latest">
        <div class="hint">Full image reference including tag. Empty = auto-resolve latest for this architecture.</div>
        <label style="margin-top:12px">Entrypoint bind</label>
        <input type="text" id="wtEntrypointBind" value="{wt_entrypoint_bind_escaped}" placeholder="/home/holo/entrypoint.sh">
        <div class="hint">Host path under /home/holo/ mounted read-only as /entrypoint.sh in the container.</div>
        <div style="margin-top:14px"><button class="btn btn-primary" onclick="applyWindTunnel()">Apply Wind Tunnel Config</button></div>
      </div>
    </div>
  </div>

  <!-- PASSWORD -->
  <div class="section">
    <div class="section-hdr" onclick="toggleSection('pw')">
      <div class="section-title"><span>🔐</span> Change Password</div>
      <span class="section-arrow" id="arr-pw">▼</span>
    </div>
    <div class="section-body" id="sec-pw">
      <div class="info-box" style="margin-top:0;margin-bottom:14px">Store your new password securely. It cannot be recovered if lost.</div>
      <label>Current password</label><input type="password" id="pw-cur" autocomplete="current-password">
      <label>New password</label><input type="password" id="pw-new" autocomplete="new-password">
      <label>Confirm new password</label><input type="password" id="pw-cfm" autocomplete="new-password">
      <div style="margin-top:14px"><button class="btn btn-primary" onclick="changePassword()">Update Password</button></div>
    </div>
  </div>

  <!-- SOFTWARE UPDATE -->
  <div class="section">
    <div class="section-hdr" onclick="toggleSection('upd')">
      <div class="section-title"><span>🔄</span> Software Update <span class="section-badge badge-gray">v{version}</span></div>
      <span class="section-arrow" id="arr-upd">▼</span>
    </div>
    <div class="section-body" id="sec-upd">
      <p style="font-size:13px;color:#64748b;margin-bottom:14px">Nodes check for updates automatically every hour from GitHub Releases. You can also trigger an immediate check.</p>
      <button class="btn btn-primary" onclick="triggerUpdate()" id="upd-btn">Check for Updates Now</button>
      <div id="upd-msg" style="margin-top:10px;font-size:13px;color:#64748b;display:none"></div>
    </div>
  </div>
</div>
<div class="toast" id="toast"></div>
<script>
let curHw='{hw_mode}';

function toggleSection(id){{
  const body=document.getElementById('sec-'+id);
  const arr=document.getElementById('arr-'+id);
  if(!body)return;
  const open=body.style.display==='block';
  body.style.display=open?'none':'block';
  if(arr)arr.textContent=open?'▶':'▼';
}}
['name','hw','unyt','happs','adv','pw','upd'].forEach(id=>toggleSection(id));
toggleSection('happs');
document.getElementById('sec-happs').style.display='block';
document.getElementById('arr-happs').textContent='▼';

let manifestTab='paste';
let happsPoll=null;

function switchManifestTab(tab){{
  manifestTab=tab;
  document.getElementById('tab-paste').classList.toggle('active',tab==='paste');
  document.getElementById('tab-manual').classList.toggle('active',tab==='manual');
  document.getElementById('manifest-paste').style.display=tab==='paste'?'block':'none';
  document.getElementById('manifest-manual').style.display=tab==='manual'?'block':'none';
  if(tab==='manual')syncManualToJson();
  else syncJsonToManual();
}}

function buildManifestFromFields(){{
  const name=v('mf-name'),ver=v('mf-version'),url=v('mf-happUrl'),seed=v('mf-networkSeed');
  const agreement=v('mf-agreementHash'),payor=v('mf-payor'),price=v('mf-priceSheet');
  return JSON.stringify({{
    app:{{name,version,happUrl:url,modifiers:{{networkSeed:seed,properties:""}}}},
    economics:{{payorUnytAgentPubKey:payor,agreementHash:agreement,priceSheetHash:price}}
  }},null,2);
}}

function syncManualToJson(){{
  document.getElementById('manifestJson').value=buildManifestFromFields();
}}

function syncJsonToManual(){{
  try{{
    const m=JSON.parse(document.getElementById('manifestJson').value||'{{}}');
    const app=m.app||{{}},mod=app.modifiers||{{}},eco=m.economics||{{}};
    document.getElementById('mf-name').value=app.name||'';
    document.getElementById('mf-version').value=app.version||'';
    document.getElementById('mf-happUrl').value=app.happUrl||'';
    document.getElementById('mf-networkSeed').value=mod.networkSeed||'';
    document.getElementById('mf-agreementHash').value=eco.agreementHash||'';
    document.getElementById('mf-payor').value=eco.payorUnytAgentPubKey||'';
    document.getElementById('mf-priceSheet').value=eco.priceSheetHash||'';
  }}catch(e){{}}
}}

function getManifest(){{
  if(manifestTab==='manual')return buildManifestFromFields();
  return document.getElementById('manifestJson').value.trim();
}}

function statusBadge(s){{
  const m={{running:'badge-running',paused:'badge-paused',error:'badge-error',installing:'badge-installing'}};
  const labels={{running:'Running',paused:'Paused',error:'Error',installing:'Installing'}};
  const cls=m[s]||'badge-gray';
  const lbl=labels[s]||s;
  return `<span class="section-badge ${{cls}}">${{lbl}}</span>`;
}}

async function loadHapps(){{
  try{{
    const r=await fetch('/manage/happs',{{credentials:'same-origin'}});
    if(r.status===401){{location.href='/login';return;}}
    const data=await r.json();
    const el=document.getElementById('happs-list');
    if(!data.happs||!data.happs.length){{
      el.innerHTML='<p style="font-size:13px;color:#475569">No hApps hosted yet. Add one below.</p>';
      return;
    }}
    el.innerHTML=data.happs.map(h=>{{
      const actions=[];
      if(h.status==='running')actions.push(`<button class="btn btn-secondary btn-sm" onclick="happAction('disable','${{esc(h.app_id)}}','${{esc(h.id)}}')">Pause</button>`);
      if(h.status==='paused')actions.push(`<button class="btn btn-secondary btn-sm" onclick="happAction('enable','${{esc(h.app_id)}}','${{esc(h.id)}}')">Resume</button>`);
      if(h.status!=='installing')actions.push(`<button class="btn btn-danger btn-sm" onclick="happAction('uninstall','${{esc(h.app_id)}}','${{esc(h.id)}}')">Remove</button>`);
      actions.push(`<button class="btn btn-secondary btn-sm" onclick="showHappLogs('${{esc(h.id)}}')">Logs</button>`);
      const err=h.last_error?`<div class="err-box" style="margin-top:8px;font-size:11px">${{esc(h.last_error)}}</div>`:'';
      const logs=`<div id="logs-${{esc(h.id)}}" style="display:none"></div>`;
      return `<div class="happ-row"><div class="happ-name">${{esc(h.app_name)}} <span style="color:#64748b;font-weight:400">v${{esc(h.app_version)}}</span> ${{statusBadge(h.status)}}</div><div class="happ-meta">Deployed: ${{esc(h.deployed_duration||'—')}} &nbsp;·&nbsp; ID: <code style="font-size:11px">${{esc(h.app_id||'(pending)')}}</code></div>${{err}}<div class="happ-actions">${{actions.join('')}}</div>${{logs}}</div>`;
    }}).join('');
    const installing=data.happs.some(h=>h.status==='installing');
    if(installing&&!happsPoll)happsPoll=setInterval(loadHapps,4000);
    else if(!installing&&happsPoll){{clearInterval(happsPoll);happsPoll=null;}}
  }}catch(e){{
    document.getElementById('happs-list').innerHTML='<p class="err-box">Failed to load hApps: '+esc(e.message)+'</p>';
  }}
}}

function esc(s){{return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');}}

async function happAction(action,appId,deploymentId){{
  if(action==='uninstall'&&!confirm('Remove this hApp from the node?'))return;
  const paths={{enable:'/manage/happs/enable',disable:'/manage/happs/disable',uninstall:'/manage/happs/uninstall'}};
  try{{
    const body=action==='uninstall'?{{deploymentId,appId}}:{{appId}};
    await api(paths[action],body);
    toast(action==='uninstall'?'hApp removed':(action==='enable'?'hApp resumed':'hApp paused'),true);
    loadHapps();
  }}catch(e){{toast('Error: '+e.message,false);}}
}}

async function showHappLogs(id){{
  const el=document.getElementById('logs-'+id);
  if(!el)return;
  if(el.style.display==='block'){{el.style.display='none';return;}}
  el.style.display='block';
  el.innerHTML='<p style="color:#64748b;font-size:12px">Loading logs…</p>';
  try{{
    const r=await fetch('/manage/happs/logs?id='+encodeURIComponent(id),{{credentials:'same-origin'}});
    const data=await r.json();
    const text='=== Install log ===\\n'+(data.install_log||'')+'\\n\\n=== Holochain log (tail) ===\\n'+(data.holochain_log||'')+'\\n\\n=== Log-sender log (tail) ===\\n'+(data.log_sender_log||'');
    el.innerHTML=`<div class="log-box" id="logbox-${{id}}">${{esc(text)}}</div><button class="btn btn-secondary btn-sm" style="margin-top:8px" onclick="copyLog('logbox-${{id}}')">Copy logs</button>`;
  }}catch(e){{el.innerHTML='<p class="err-box">'+esc(e.message)+'</p>';}}
}}

function copyLog(id){{
  const el=document.getElementById(id);
  if(!el)return;
  navigator.clipboard.writeText(el.textContent).then(()=>toast('Copied to clipboard',true)).catch(()=>toast('Copy failed',false));
}}

async function validateManifest(){{
  const raw=getManifest();
  if(!raw)return toast('Enter or paste a manifest first',false);
  let parsed;
  try{{parsed=JSON.parse(raw);}}catch(e){{return toast('Invalid JSON: '+e.message,false);}}
  const btn=document.getElementById('validate-btn');
  const res=document.getElementById('validate-result');
  btn.disabled=true;
  try{{
    const data=await api('/manage/happs/validate',{{manifest:parsed}});
    res.style.display='block';
    res.className=data.valid?'ok-box':'err-box';
    res.textContent=data.output||'(no output)';
  }}catch(e){{
    res.style.display='block';res.className='err-box';res.textContent=e.message;
  }}finally{{btn.disabled=false;}}
}}

async function deployManifest(){{
  const raw=getManifest();
  if(!raw)return toast('Enter or paste a manifest first',false);
  let parsed;
  try{{parsed=JSON.parse(raw);}}catch(e){{return toast('Invalid JSON: '+e.message,false);}}
  const btn=document.getElementById('deploy-btn');
  btn.disabled=true;btn.textContent='Deploying…';
  try{{
    await api('/manage/happs/deploy',{{manifest:parsed}});
    toast('Deploy started — watch status below',true);
    document.getElementById('validate-result').style.display='none';
    loadHapps();
    if(!happsPoll)happsPoll=setInterval(loadHapps,4000);
  }}catch(e){{toast('Error: '+e.message,false);}}
  finally{{btn.disabled=false;btn.textContent='Deploy';}}
}}

loadHapps();

const ORIGINAL_NODE_NAME='{node_name_js}';

function chkNodeName(){{
  const name=v('nodeName');
  const ok=/^[a-z0-9-]+$/.test(name);
  const changed=name!==ORIGINAL_NODE_NAME;
  const btn=document.getElementById('nodeNameBtn');
  const hint=document.getElementById('nodeNameHint');
  if(btn)btn.disabled=!ok||!name||!changed;
  if(!hint)return;
  if(!name){{hint.textContent='Node name is required.';return;}}
  if(!ok){{hint.textContent='Lowercase letters, numbers and hyphens only.';return;}}
  hint.textContent=changed?'Press Save to apply the new node name.':'Change the node name above to enable Save.';
}}

async function saveNodeName(){{
  const nodeName=v('nodeName');
  if(!nodeName)return toast('Node name is required',false);
  if(!/^[a-z0-9-]+$/.test(nodeName))return toast('Node name must be lowercase letters, numbers and hyphens only',false);
  try{{
    const r=await api('/manage/nodename',{{nodeName}});
    toast('Node name saved — reloading…',true);
    setTimeout(()=>location.reload(),800);
  }}catch(e){{toast('Error: '+e.message,false);}}
}}
chkNodeName();

function toast(msg,ok){{
  const t=document.getElementById('toast');
  t.textContent=msg;
  t.className='toast '+(ok?'ok':'err')+' vis';
  clearTimeout(t._t);t._t=setTimeout(()=>t.classList.remove('vis'),4000);
}}

async function api(path,payload){{
  const r=await fetch(path,{{method:'POST',headers:{{'Content-Type':'application/json'}},credentials:'same-origin',body:JSON.stringify(payload)}});
  if(r.status===401){{location.href='/login';throw new Error('Session expired — please log in again');}}
  const text=await r.text();
  if(!r.ok){{
    try{{const j=JSON.parse(text);throw new Error(j.error||text);}}catch(e){{if(e.message)throw e;throw new Error(text||'Server error '+r.status);}}
  }}
  try{{return JSON.parse(text);}}catch{{return {{}};}}
}}

function v(id){{const e=document.getElementById(id);return e?e.value.trim():'';}}

async function addKey(){{
  const key=document.getElementById('newKey').value.trim();
  if(!key)return toast('Paste a public key first',false);
  try{{await api('/manage/ssh/add',{{key}});document.getElementById('newKey').value='';toast('Key added — reloading…',true);setTimeout(()=>location.reload(),800);}}
  catch(e){{toast('Error: '+e.message,false);}}
}}
async function removeKey(i){{
  if(!confirm('Remove this SSH key?'))return;
  try{{await api('/manage/ssh/remove',{{index:i}});toast('Key removed — reloading…',true);setTimeout(()=>location.reload(),800);}}
  catch(e){{toast('Error: '+e.message,false);}}
}}

function selHw(mode,el){{
  curHw=mode;
  document.querySelectorAll('.hw-opt').forEach(o=>o.classList.remove('sel'));
  el.classList.add('sel');
}}

async function saveUnyt(){{
  const agent=v('unytAgentId');
  try{{
    await api('/manage/unyt',{{unytAgentId:agent}});
    toast('Unyt Agent ID saved — reloading…',true);
    setTimeout(()=>location.reload(),800);
  }}catch(e){{toast('Error: '+e.message,false);}}
}}

async function saveLogSender(){{
  const endpoint=v('logSenderEndpoint');
  try{{
    await api('/manage/log-sender',{{logSenderEndpoint:endpoint}});
    toast('Log Collector URL saved — EdgeNode will restart if running',true);
  }}catch(e){{toast('Error: '+e.message,false);}}
}}

async function applyWindTunnel(){{
  try{{
    const r=await api('/manage/wind-tunnel',{{
      wtImageOverride:v('wtImageOverride'),
      wtEntrypointBind:v('wtEntrypointBind'),
      apply:true
    }});
    toast('Wind Tunnel config applied — reloading…',true);
    setTimeout(()=>location.reload(),800);
  }}catch(e){{toast('Error: '+e.message,false);}}
}}

async function saveHardware(){{
  try{{
    await api('/manage/hardware',{{mode:curHw}});
    document.getElementById('hw-badge').textContent=curHw==='WIND_TUNNEL'?'Wind Tunnel':'EdgeNode';
    document.getElementById('info-hw').textContent=curHw==='WIND_TUNNEL'?'Wind Tunnel':'EdgeNode';
    toast('Mode updated',true);
  }}catch(e){{toast('Error: '+e.message,false);}}
}}

async function changePassword(){{
  const cur=v('pw-cur'),nw=v('pw-new'),cfm=v('pw-cfm');
  if(!cur||!nw)return toast('Fill in all password fields',false);
  if(nw!==cfm)return toast('New passwords do not match',false);
  if(nw.length<8)return toast('Password must be at least 8 characters',false);
  try{{
    await api('/manage/password',{{current:cur,newPassword:nw}});
    ['pw-cur','pw-new','pw-cfm'].forEach(id=>document.getElementById(id).value='');
    toast('Password updated',true);
  }}catch(e){{toast('Error: '+e.message,false);}}
}}

async function triggerUpdate(){{
  const btn=document.getElementById('upd-btn');
  const msg=document.getElementById('upd-msg');
  btn.disabled=true;btn.textContent='Checking…';msg.style.display='none';
  try{{
    await api('/manage/update',{{}});
    msg.textContent='Update check triggered. If a newer version is found the node will restart automatically.';
    msg.style.display='block';
  }}catch(e){{msg.textContent='Error: '+e.message;msg.style.display='block';}}
  finally{{btn.disabled=false;btn.textContent='Check for Updates Now';}}
}}
</script>
</body></html>"#,
        css                  = COMMON_CSS,
        node_name            = html_escape(&node_name),
        node_name_escaped    = html_escape(&node_name),
        node_name_js         = node_name.replace('\\', "\\\\").replace('\'', "\\'"),
        version              = VERSION,
        ip                   = html_escape(&ip),
        uptime               = fmt_uptime(uptime_s),
        keys_html            = keys_html,
        ssh_count            = ssh_count,
        ssh_plural           = ssh_plural,
        hw_mode              = hw_mode,
        hw_mode_display      = hw_mode_display,
        sel_std              = sel_std,
        sel_wt               = sel_wt,
        unyt_copy            = UNYT_INFO_COPY,
        unyt_display         = html_escape(&unyt_display),
        unyt_badge           = unyt_badge,
        unyt_badge_text      = unyt_badge_text,
        unyt_agent_id_escaped = html_escape(&unyt_agent_id),
        log_sender_endpoint_escaped = html_escape(&log_sender_endpoint),
        happs_disabled_msg     = happs_disabled_msg,
        wt_hostname          = html_escape(&wt_hostname),
        wt_effective_image   = html_escape(&wt_effective_image),
        wt_entrypoint_display = html_escape(&wt_entrypoint_display),
        wt_status_link       = html_escape(&wt_status_link),
        wt_image_override_escaped = html_escape(&wt_image_override),
        wt_entrypoint_bind_escaped = html_escape(&wt_entrypoint_bind),
    )
}

// ── Route handlers ─────────────────────────────────────────────────────────────

fn handle_submit(
    stream: &mut TcpStream,
    req: &Req,
    state: &AppState,
    _auth_hash: &Arc<Mutex<String>>,
) {
    let body           = &req.body;
    let node_name      = json_str(body, "nodeName");
    let ssh_key        = json_str(body, "sshKey");
    let hw_mode        = json_str(body, "hwMode");
    let unyt_agent_id  = json_str(body, "unytAgentId");

    if node_name.is_empty() { send_json_err(stream, 400, "nodeName is required"); return; }
    if let Some(msg) = wt_client_name_error(node_name, unyt_agent_id) {
        send_json_err(stream, 400, &msg); return;
    }

    // ── WiFi (AP mode) ───────────────────────────────────────────────────────
    let wifi_ssid = json_str(body, "wifiSsid");
    let wifi_pass = json_str(body, "wifiPass");
    if !wifi_ssid.is_empty() && !wifi_pass.is_empty() {
        eprintln!("[onboard] Connecting WiFi: {}", wifi_ssid);
        let _ = Command::new("nmcli")
            .args(["device", "wifi", "connect", wifi_ssid, "password", wifi_pass])
            .output();
        thread::sleep(Duration::from_secs(4));
    }

    // ── Ensure directories ───────────────────────────────────────────────────
    for dir in &["/etc/node-manager", QUADLET_DIR,
                 "/var/lib/edgenode", "/home/holo/.ssh"] {
        let _ = fs::create_dir_all(dir);
    }

    // ── SSH keys ─────────────────────────────────────────────────────────────
    if !ssh_key.trim().is_empty() {
        if !is_valid_ssh_pubkey(ssh_key) {
            send_json_err(stream, 400, "Invalid SSH public key format"); return;
        }
        if let Err(e) = write_ssh_keys(&[ssh_key.to_string()]) {
            send_json_err(stream, 500, &format!("Failed to write SSH key: {}", e)); return;
        }
        eprintln!("[onboard] SSH key written");
    }

    // ── Quadlets ─────────────────────────────────────────────────────────────
    let wt_suffix = generate_wt_suffix();
    let hw_mode_val = if hw_mode == "WIND_TUNNEL" { "WIND_TUNNEL" } else { "STANDARD" };

    *state.node_name.lock().unwrap()     = node_name.to_string();
    *state.hw_mode.lock().unwrap()       = hw_mode_val.to_string();
    *state.unyt_agent_id.lock().unwrap() = unyt_agent_id.to_string();
    *state.wt_suffix.lock().unwrap()     = wt_suffix.clone();
    state.onboarded.store(true, Ordering::Relaxed);

    let mut kv = HashMap::new();
    kv.insert("onboarded".into(), "true".into());
    kv.insert("node_name".into(), node_name.to_string());
    kv.insert("hw_mode".into(), hw_mode_val.to_string());
    kv.insert("unyt_agent_id".into(), unyt_agent_id.to_string());
    kv.insert("wt_suffix".into(), wt_suffix.clone());
    write_state_file(&kv);

    write_quadlets_from_state(state);

    let _ = fs::write("/var/lib/edgenode/mode_switch.txt", hw_mode_val);
    sync_container_services(hw_mode_val);

    eprintln!("[onboard] Complete. node={} hw={} unyt={}", node_name, hw_mode, if unyt_agent_id.is_empty() { "(none)" } else { "set" });
    send_json_ok(stream, r#"{"status":"ok"}"#);
}

fn handle_manage_status(stream: &mut TcpStream, state: &AppState) {
    let node_name     = state.node_name.lock().unwrap().clone();
    let hw_mode       = state.hw_mode.lock().unwrap().clone();
    let unyt_agent_id  = state.unyt_agent_id.lock().unwrap().clone();
    let wt_suffix      = ensure_wt_suffix(state);
    let wt_client_name = build_wt_client_name(&node_name, &unyt_agent_id, &wt_suffix);
    let wt_hostname    = build_wt_hostname(&node_name);
    let uptime    = state.start_time.elapsed().unwrap_or_default().as_secs();
    let keys      = read_ssh_keys();
    let keys_json: String = keys.iter()
        .map(|k| format!("\"{}\"", k.replace('\\', "\\\\").replace('"', "\\\"")))
        .collect::<Vec<_>>().join(",");
    let log_sender_endpoint = state.log_sender_endpoint.lock().unwrap().clone();
    let happs_count = read_deployments().len();
    let edgenode_up = edgenode_running();
    send_json_ok(stream, &format!(
        r#"{{"version":"{}","node_name":"{}","hw_mode":"{}","unyt_agent_id":"{}","log_sender_endpoint":"{}","edgenode_running":{},"happs_count":{},"wt_client_name":"{}","wt_hostname":"{}","ssh_key_count":{},"ssh_keys":[{}],"uptime_secs":{}}}"#,
        VERSION,
        node_name.replace('\\', "\\\\").replace('"', "\\\""),
        hw_mode,
        unyt_agent_id.replace('\\', "\\\\").replace('"', "\\\""),
        log_sender_endpoint.replace('\\', "\\\\").replace('"', "\\\""),
        if edgenode_up { "true" } else { "false" },
        happs_count,
        wt_client_name.replace('\\', "\\\\").replace('"', "\\\""),
        wt_hostname.replace('\\', "\\\\").replace('"', "\\\""),
        keys.len(), keys_json, uptime
    ));
}

fn handle_ssh_add(stream: &mut TcpStream, req: &Req) {
    let key = json_str(&req.body, "key");
    if key.is_empty() { send_json_err(stream, 400, "key is required"); return; }
    if !is_valid_ssh_pubkey(key) { send_json_err(stream, 400, "Invalid SSH public key format"); return; }
    let mut keys = read_ssh_keys();
    if keys.iter().any(|k| k == key) { send_json_err(stream, 409, "Key already present"); return; }
    keys.push(key.to_string());
    match write_ssh_keys(&keys) {
        Ok(()) => send_json_ok(stream, r#"{"status":"added"}"#),
        Err(e) => send_json_err(stream, 500, &e),
    }
}

fn handle_ssh_remove(stream: &mut TcpStream, req: &Req) {
    let idx_str = {
        let needle = "\"index\":";
        match req.body.find(needle) {
            None    => { send_json_err(stream, 400, "index is required"); return; }
            Some(p) => req.body[p + needle.len()..].trim_start()
                .split(|c: char| !c.is_ascii_digit()).next().unwrap_or("").to_string(),
        }
    };
    let idx: usize = match idx_str.parse() {
        Ok(i)  => i,
        Err(_) => { send_json_err(stream, 400, "invalid index"); return; }
    };
    let mut keys = read_ssh_keys();
    if idx >= keys.len() { send_json_err(stream, 404, "index out of range"); return; }
    keys.remove(idx);
    match write_ssh_keys(&keys) {
        Ok(()) => send_json_ok(stream, r#"{"status":"removed"}"#),
        Err(e) => send_json_err(stream, 500, &e),
    }
}

fn handle_nodename(
    stream: &mut TcpStream,
    req: &Req,
    state: &AppState,
) {
    let node_name = json_str(&req.body, "nodeName");
    if let Some(msg) = validate_node_name(node_name) {
        send_json_err(stream, 400, &msg); return;
    }
    if node_name == state.node_name.lock().unwrap().as_str() {
        send_json_err(stream, 400, "Node name unchanged"); return;
    }
    let unyt_agent_id = state.unyt_agent_id.lock().unwrap().clone();
    if let Some(msg) = wt_client_name_error(node_name, &unyt_agent_id) {
        send_json_err(stream, 400, &msg); return;
    }

    update_state_key("node_name", node_name);
    *state.node_name.lock().unwrap() = node_name.to_string();
    apply_wind_tunnel_config(state);

    let wt_hostname = build_wt_hostname(node_name);
    eprintln!("[manage] Node name updated to {} (wt_hostname={})", node_name, wt_hostname);
    send_json_ok(stream, &format!(
        r#"{{"status":"ok","node_name":"{}","wt_hostname":"{}"}}"#,
        node_name.replace('\\', "\\\\").replace('"', "\\\""),
        wt_hostname.replace('\\', "\\\\").replace('"', "\\\"")
    ));
}

fn handle_unyt(
    stream: &mut TcpStream,
    req: &Req,
    state: &AppState,
) {
    let unyt_agent_id = json_str(&req.body, "unytAgentId");
    let node_name     = state.node_name.lock().unwrap().clone();
    if let Some(msg) = wt_client_name_error(&node_name, unyt_agent_id) {
        send_json_err(stream, 400, &msg); return;
    }

    update_state_key("unyt_agent_id", unyt_agent_id);
    *state.unyt_agent_id.lock().unwrap() = unyt_agent_id.to_string();

    apply_wind_tunnel_config(state);
    apply_edgenode_config(state);

    let suffix    = ensure_wt_suffix(state);
    let wt_client_name = build_wt_client_name(&node_name, unyt_agent_id, &suffix);
    eprintln!("[manage] Unyt Agent ID updated. wt_client_name={}", wt_client_name);
    send_json_ok(stream, &format!(
        r#"{{"status":"ok","wt_client_name":"{}"}}"#,
        wt_client_name.replace('\\', "\\\\").replace('"', "\\\"")
    ));
}

fn handle_hardware(
    stream: &mut TcpStream,
    req: &Req,
    state: &AppState,
) {
    let mode = json_str(&req.body, "mode");
    let mode = if mode == "WIND_TUNNEL" { "WIND_TUNNEL" } else { "STANDARD" };
    apply_hardware_mode(mode, state);
    eprintln!("[manage] Hardware mode switched to {}", mode);
    send_json_ok(stream, r#"{"status":"ok"}"#);
}

fn handle_wind_tunnel(
    stream: &mut TcpStream,
    req: &Req,
    state: &AppState,
) {
    let body = &req.body;

    if json_has_key(body, "wtImageOverride") {
        let val = json_str(body, "wtImageOverride").trim().to_string();
        if let Some(msg) = validate_wt_image_override(&val) {
            send_json_err(stream, 400, &msg); return;
        }
        update_state_key("wt_image_override", &val);
        *state.wt_image_override.lock().unwrap() = val;
    }

    if json_has_key(body, "wtEntrypointBind") {
        let val = json_str(body, "wtEntrypointBind").trim().to_string();
        if let Some(msg) = validate_wt_entrypoint_bind(&val) {
            send_json_err(stream, 400, &msg); return;
        }
        update_state_key("wt_entrypoint_bind", &val);
        *state.wt_entrypoint_bind.lock().unwrap() = val;
    }

    if json_bool(body, "apply", true) {
        apply_wind_tunnel_config(state);
    }

    let cfg = resolve_wind_tunnel_config(state);
    let ep = cfg.entrypoint_bind.as_deref().unwrap_or("");
    eprintln!("[manage] Wind Tunnel config applied. image={} hostname={}", cfg.image, cfg.hostname);
    send_json_ok(stream, &format!(
        r#"{{"status":"ok","image":"{}","hostname":"{}","entrypoint_bind":"{}"}}"#,
        cfg.image.replace('\\', "\\\\").replace('"', "\\\""),
        cfg.hostname.replace('\\', "\\\\").replace('"', "\\\""),
        ep.replace('\\', "\\\\").replace('"', "\\\"")
    ));
}

fn handle_password(
    stream: &mut TcpStream,
    req: &Req,
    auth_hash: &Arc<Mutex<String>>,
) {
    let current      = json_str(&req.body, "current");
    let new_password = json_str(&req.body, "newPassword");

    if current.is_empty() || new_password.is_empty() {
        send_json_err(stream, 400, "current and newPassword are required"); return;
    }
    if new_password.len() < 8 {
        send_json_err(stream, 400, "Password must be at least 8 characters"); return;
    }

    let hash = auth_hash.lock().unwrap().clone();
    if !verify_password(current, &hash) {
        send_json_err(stream, 401, "Incorrect current password"); return;
    }

    let new_hash = hash_password(new_password);
    let _ = fs::write(AUTH_FILE, &new_hash);
    let _ = Command::new("chmod").args(["600", AUTH_FILE]).output();
    *auth_hash.lock().unwrap() = new_hash;

    eprintln!("[manage] Node password changed");
    send_json_ok(stream, r#"{"status":"ok"}"#);
}

fn handle_log_sender(
    stream: &mut TcpStream,
    req: &Req,
    state: &AppState,
) {
    let endpoint = json_str(&req.body, "logSenderEndpoint");
    if let Some(msg) = validate_log_sender_endpoint(endpoint) {
        send_json_err(stream, 400, &msg); return;
    }
    update_state_key("log_sender_endpoint", endpoint);
    *state.log_sender_endpoint.lock().unwrap() = endpoint.to_string();
    apply_edgenode_config(state);
    eprintln!("[manage] Log sender endpoint updated");
    send_json_ok(stream, r#"{"status":"ok"}"#);
}

fn handle_happs_list(stream: &mut TcpStream, state: &AppState) {
    let deployments = read_deployments();
    let live = list_installed_happs().unwrap_or_default();
    let mut items = String::new();
    for d in &deployments {
        let status = reconcile_deployment_status(d, &live);
        let duration = deployed_duration(&d.deployed_at);
        if !items.is_empty() { items.push(','); }
        items.push_str(&format!(
            r#"{{"id":"{}","app_name":"{}","app_version":"{}","app_id":"{}","status":"{}","deployed_at":"{}","deployed_duration":"{}","last_error":"{}"}}"#,
            json_escape(&d.id),
            json_escape(&d.app_name),
            json_escape(&d.app_version),
            json_escape(&d.app_id),
            json_escape(&status),
            json_escape(&d.deployed_at),
            json_escape(&duration),
            json_escape(&d.last_error),
        ));
    }
    let hw = state.hw_mode.lock().unwrap().clone();
    let edgenode_up = edgenode_running();
    let unyt = state.unyt_agent_id.lock().unwrap().clone();
    let endpoint = state.log_sender_endpoint.lock().unwrap().clone();
    let accounting_ready = !unyt.is_empty() && !endpoint.is_empty();
    send_json_ok(stream, &format!(
        r#"{{"happs":[{}],"hw_mode":"{}","edgenode_running":{},"accounting_ready":{},"unyt_configured":{},"log_sender_configured":{}}}"#,
        items,
        json_escape(&hw),
        if edgenode_up { "true" } else { "false" },
        if accounting_ready { "true" } else { "false" },
        if unyt.is_empty() { "false" } else { "true" },
        if endpoint.is_empty() { "false" } else { "true" },
    ));
}

fn handle_happs_validate(stream: &mut TcpStream, state: &AppState, req: &Req) {
    if let Some(msg) = happs_prereq_error(state) {
        send_json_err(stream, 400, &msg); return;
    }
    let manifest = json_raw_value(&req.body, "manifest");
    if manifest.is_empty() {
        send_json_err(stream, 400, "manifest is required"); return;
    }
    let name = manifest_app_name(&manifest);
    let version = manifest_app_version(&manifest);
    if name.is_empty() || version.is_empty() {
        send_json_err(stream, 400, "manifest must include app.name and app.version"); return;
    }
    let container_path = match write_happ_manifest(&name, &version, &manifest) {
        Ok(p) => p,
        Err(e) => { send_json_err(stream, 500, &e); return; }
    };
    let (ok, output) = validate_happ_manifest(&container_path);
    if ok {
        send_json_ok(stream, &format!(
            r#"{{"valid":true,"output":"{}"}}"#,
            json_escape(output.trim())
        ));
    } else {
        send_json_ok(stream, &format!(
            r#"{{"valid":false,"output":"{}"}}"#,
            json_escape(output.trim())
        ));
    }
}

fn handle_happs_deploy(stream: &mut TcpStream, state: &AppState, req: &Req) {
    if let Some(msg) = happs_prereq_error(state) {
        send_json_err(stream, 400, &msg); return;
    }
    let manifest = json_raw_value(&req.body, "manifest");
    if manifest.is_empty() {
        send_json_err(stream, 400, "manifest is required"); return;
    }
    let name = manifest_app_name(&manifest);
    let version = manifest_app_version(&manifest);
    if name.is_empty() || version.is_empty() {
        send_json_err(stream, 400, "manifest must include app.name and app.version"); return;
    }
    if manifest_has_economics_agreement(&manifest) {
        let unyt = state.unyt_agent_id.lock().unwrap().clone();
        let endpoint = state.log_sender_endpoint.lock().unwrap().clone();
        if unyt.is_empty() || endpoint.is_empty() {
            send_json_err(stream, 400, "Manifest includes economics.agreementHash but Unyt Agent ID and Log Collector URL must be configured in HoloFuel first."); return;
        }
    }
    let container_path = match write_happ_manifest(&name, &version, &manifest) {
        Ok(p) => p,
        Err(e) => { send_json_err(stream, 500, &e); return; }
    };
    let (valid, val_out) = validate_happ_manifest(&container_path);
    if !valid {
        send_json_err(stream, 400, &format!("Manifest validation failed: {}", val_out.trim())); return;
    }
    let id = generate_deployment_id();
    let deployment = Deployment {
        id: id.clone(),
        app_name: name.clone(),
        app_version: version.clone(),
        app_id: String::new(),
        status: "installing".into(),
        deployed_at: String::new(),
        last_error: String::new(),
        manifest: manifest.clone(),
    };
    let mut deployments = read_deployments();
    upsert_deployment(&mut deployments, deployment);
    let node_name = state.node_name.lock().unwrap().clone();
    spawn_install_job(id.clone(), container_path, node_name);
    eprintln!("[happs] Deploy started for {} v{} (id={})", name, version, id);
    send_json_ok(stream, &format!(
        r#"{{"status":"installing","deployment_id":"{}"}}"#,
        json_escape(&id)
    ));
}

fn handle_happs_enable(stream: &mut TcpStream, state: &AppState, req: &Req) {
    if let Some(msg) = happs_prereq_error(state) {
        send_json_err(stream, 400, &msg); return;
    }
    let app_id = json_str(&req.body, "appId");
    if app_id.is_empty() {
        send_json_err(stream, 400, "appId is required"); return;
    }
    match enable_happ(app_id) {
        Ok(out) => send_json_ok(stream, &format!(r#"{{"status":"ok","output":"{}"}}"#, json_escape(out.trim()))),
        Err(e) => send_json_err(stream, 500, &e),
    }
}

fn handle_happs_disable(stream: &mut TcpStream, state: &AppState, req: &Req) {
    if let Some(msg) = happs_prereq_error(state) {
        send_json_err(stream, 400, &msg); return;
    }
    let app_id = json_str(&req.body, "appId");
    if app_id.is_empty() {
        send_json_err(stream, 400, "appId is required"); return;
    }
    match disable_happ(app_id) {
        Ok(out) => send_json_ok(stream, &format!(r#"{{"status":"ok","output":"{}"}}"#, json_escape(out.trim()))),
        Err(e) => send_json_err(stream, 500, &e),
    }
}

fn handle_happs_uninstall(stream: &mut TcpStream, state: &AppState, req: &Req) {
    if let Some(msg) = happs_prereq_error(state) {
        send_json_err(stream, 400, &msg); return;
    }
    let deployment_id = json_str(&req.body, "deploymentId");
    let app_id = json_str(&req.body, "appId");
    if deployment_id.is_empty() {
        send_json_err(stream, 400, "deploymentId is required"); return;
    }
    let mut deployments = read_deployments();
    let stored_app_id = deployments.iter()
        .find(|d| d.id == deployment_id)
        .map(|d| d.app_id.clone())
        .unwrap_or_default();
    let target = if !app_id.is_empty() { app_id.to_string() } else { stored_app_id };
    if !target.is_empty() {
        if let Err(e) = uninstall_happ(&target) {
            send_json_err(stream, 500, &e); return;
        }
    }
    remove_deployment(&mut deployments, deployment_id);
    eprintln!("[happs] Uninstalled {}", target);
    send_json_ok(stream, r#"{"status":"ok"}"#);
}

fn handle_happs_logs(stream: &mut TcpStream, state: &AppState, query: &str) {
    if state.hw_mode.lock().unwrap().as_str() == "WIND_TUNNEL" {
        send_json_err(stream, 400, "hApp logs unavailable in Wind Tunnel mode"); return;
    }
    let id = get_query_param(query, "id");
    let install_log = if id.is_empty() {
        "(no deployment id specified)".into()
    } else {
        read_happ_install_log(&id)
    };
    let holochain_log = tail_container_log("/data/logs/holochain.log", 80);
    let log_sender_log = tail_container_log("/data/logs/log-sender.log", 40);
    send_json_ok(stream, &format!(
        r#"{{"install_log":"{}","holochain_log":"{}","log_sender_log":"{}"}}"#,
        json_escape(&install_log),
        json_escape(&holochain_log),
        json_escape(&log_sender_log),
    ));
}

fn handle_update(stream: &mut TcpStream) {
    let repo = env::var(UPDATE_REPO_ENV).unwrap_or_else(|_| UPDATE_REPO_DEFAULT.to_string());
    thread::spawn(move || { check_and_apply_update(&repo); });
    eprintln!("[manage] Manual software update check triggered");
    send_json_ok(stream, r#"{"status":"update_triggered"}"#);
}

// ── Main ───────────────────────────────────────────────────────────────────────

fn main() {
    eprintln!("[node-manager] Starting v{}", VERSION);

    let ap_mode = env::args().any(|a| a == "--ap-mode");
    let auth_hash = Arc::new(Mutex::new(load_or_create_auth()));
    let state = Arc::new(AppState::new(ap_mode));

    if state.onboarded.load(Ordering::Relaxed) {
        write_quadlets_from_state(&state);
        let hw_mode = state.hw_mode.lock().unwrap().clone();
        sync_container_services(&hw_mode);
    }

    // Spawn background update checker
    let repo = env::var(UPDATE_REPO_ENV).unwrap_or_else(|_| UPDATE_REPO_DEFAULT.to_string());
    spawn_update_checker(repo);

    let listener = TcpListener::bind("0.0.0.0:8080").expect("Cannot bind to 0.0.0.0:8080");
    eprintln!("[node-manager] Listening on http://0.0.0.0:8080");

    for stream in listener.incoming() {
        let mut stream = match stream { Ok(s) => s, Err(_) => continue };
        let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));

        let state = Arc::clone(&state);
        let auth_hash = Arc::clone(&auth_hash);

        thread::spawn(move || {
            let req = match read_request(&mut stream) { Some(r) => r, None => return };

            match (req.method.as_str(), req.path.as_str()) {
                // ── Public routes ──────────────────────────────────────────────
                ("GET", "/") => {
                    if state.onboarded.load(Ordering::Relaxed) {
                        send_redirect(&mut stream, "/manage");
                    } else {
                        send_html(&mut stream, &build_onboarding_html(state.ap_mode));
                    }
                },

                ("GET", "/login") => {
                    if is_authenticated(&req, &state) {
                        send_redirect(&mut stream, "/manage");
                    } else {
                        send_html(&mut stream, &build_login_html(false));
                    }
                },

                ("POST", "/login") => {
                    let form = parse_form(&req.body);
                    let password = form.get("password").map(|s| s.as_str()).unwrap_or("");
                    let hash = auth_hash.lock().unwrap().clone();
                    if verify_password(password, &hash) {
                        let token = create_session(&state);
                        send_redirect_with_cookie(&mut stream, "/manage", &session_cookie(&token));
                    } else {
                        send_html(&mut stream, &build_login_html(true));
                    }
                },

                ("POST", "/logout") => {
                    send_redirect_with_cookie(&mut stream, "/login", &clear_cookie());
                },

                ("POST", "/submit") => {
                    handle_submit(&mut stream, &req, &state, &auth_hash);
                },

                // ── Authenticated routes ───────────────────────────────────────
                ("GET", "/manage") => {
                    if !is_authenticated(&req, &state) {
                        send_redirect(&mut stream, "/login");
                    } else {
                        send_html(&mut stream, &build_manage_html(&state));
                    }
                },

                ("GET", "/manage/status") => {
                    if !is_authenticated(&req, &state) {
                        send_json_err(&mut stream, 401, "Not authenticated");
                    } else {
                        handle_manage_status(&mut stream, &state);
                    }
                },

                ("POST", "/manage/ssh/add") => {
                    if !is_authenticated(&req, &state) {
                        send_json_err(&mut stream, 401, "Not authenticated");
                    } else {
                        handle_ssh_add(&mut stream, &req);
                    }
                },

                ("POST", "/manage/ssh/remove") => {
                    if !is_authenticated(&req, &state) {
                        send_json_err(&mut stream, 401, "Not authenticated");
                    } else {
                        handle_ssh_remove(&mut stream, &req);
                    }
                },

                ("POST", "/manage/unyt") => {
                    if !is_authenticated(&req, &state) {
                        send_json_err(&mut stream, 401, "Not authenticated");
                    } else {
                        handle_unyt(&mut stream, &req, &state);
                    }
                },

                ("POST", "/manage/log-sender") => {
                    if !is_authenticated(&req, &state) {
                        send_json_err(&mut stream, 401, "Not authenticated");
                    } else {
                        handle_log_sender(&mut stream, &req, &state);
                    }
                },

                ("GET", "/manage/happs") => {
                    if !is_authenticated(&req, &state) {
                        send_json_err(&mut stream, 401, "Not authenticated");
                    } else {
                        handle_happs_list(&mut stream, &state);
                    }
                },

                ("GET", "/manage/happs/logs") => {
                    if !is_authenticated(&req, &state) {
                        send_json_err(&mut stream, 401, "Not authenticated");
                    } else {
                        handle_happs_logs(&mut stream, &state, &req.query);
                    }
                },

                ("POST", "/manage/happs/validate") => {
                    if !is_authenticated(&req, &state) {
                        send_json_err(&mut stream, 401, "Not authenticated");
                    } else {
                        handle_happs_validate(&mut stream, &state, &req);
                    }
                },

                ("POST", "/manage/happs/deploy") => {
                    if !is_authenticated(&req, &state) {
                        send_json_err(&mut stream, 401, "Not authenticated");
                    } else {
                        handle_happs_deploy(&mut stream, &state, &req);
                    }
                },

                ("POST", "/manage/happs/enable") => {
                    if !is_authenticated(&req, &state) {
                        send_json_err(&mut stream, 401, "Not authenticated");
                    } else {
                        handle_happs_enable(&mut stream, &state, &req);
                    }
                },

                ("POST", "/manage/happs/disable") => {
                    if !is_authenticated(&req, &state) {
                        send_json_err(&mut stream, 401, "Not authenticated");
                    } else {
                        handle_happs_disable(&mut stream, &state, &req);
                    }
                },

                ("POST", "/manage/happs/uninstall") => {
                    if !is_authenticated(&req, &state) {
                        send_json_err(&mut stream, 401, "Not authenticated");
                    } else {
                        handle_happs_uninstall(&mut stream, &state, &req);
                    }
                },

                ("POST", "/manage/nodename") => {
                    if !is_authenticated(&req, &state) {
                        send_json_err(&mut stream, 401, "Not authenticated");
                    } else {
                        handle_nodename(&mut stream, &req, &state);
                    }
                },

                ("POST", "/manage/hardware") => {
                    if !is_authenticated(&req, &state) {
                        send_json_err(&mut stream, 401, "Not authenticated");
                    } else {
                        handle_hardware(&mut stream, &req, &state);
                    }
                },

                ("POST", "/manage/wind-tunnel") => {
                    if !is_authenticated(&req, &state) {
                        send_json_err(&mut stream, 401, "Not authenticated");
                    } else {
                        handle_wind_tunnel(&mut stream, &req, &state);
                    }
                },

                ("POST", "/manage/password") => {
                    if !is_authenticated(&req, &state) {
                        send_json_err(&mut stream, 401, "Not authenticated");
                    } else {
                        handle_password(&mut stream, &req, &auth_hash);
                    }
                },

                ("POST", "/manage/update") => {
                    if !is_authenticated(&req, &state) {
                        send_json_err(&mut stream, 401, "Not authenticated");
                    } else {
                        handle_update(&mut stream);
                    }
                },

                _ => {
                    send_response(&mut stream, 404, "Not Found", "text/plain", b"404 Not Found");
                },
            }
        });
    }
}
