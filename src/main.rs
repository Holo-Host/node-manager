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

const VERSION: &str = "6.1.1";
const WT_HOSTNAME_MAX: usize = 63;
const WT_RANDOM_SUFFIX_LEN: usize = 16;
const NOMAD_CLIENT_PREFIX: &str = "nomad-client-";
const STATE_FILE: &str = "/etc/node-manager/state";
const AUTH_FILE: &str = "/etc/node-manager/auth";
const SESSIONS_FILE: &str = "/etc/node-manager/sessions";
const WIND_TUNNEL_CLIENT_META: &str = "/etc/node-manager/client-meta.json";
const WIND_TUNNEL_LEGACY_ENV: &str = "/etc/node-manager/wind-tunnel.env";
const QUADLET_DIR: &str = "/etc/containers/systemd";
const AUTHORIZED_KEYS: &str = "/home/holo/.ssh/authorized_keys";
const UPDATE_REPO_ENV: &str = "UPDATE_REPO";
const UPDATE_REPO_DEFAULT: &str = "holo-host/node-manager";
const SESSION_TTL_SECS: u64 = 86400;
const UPDATE_INTERVAL_SECS: u64 = 3600;

// ── Shared application state ───────────────────────────────────────────────────

struct AppState {
    ap_mode:        bool,
    start_time:     SystemTime,
    sessions:       Mutex<HashMap<String, SystemTime>>,
    onboarded:      AtomicBool,
    node_name:      Mutex<String>,
    hw_mode:        Mutex<String>,
    unyt_agent_id:  Mutex<String>,
    wt_suffix:      Mutex<String>,
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
            unyt_agent_id: Mutex::new(kv.get("unyt_agent_id").cloned().unwrap_or_default()),
            wt_suffix:     Mutex::new(kv.get("wt_suffix").cloned().unwrap_or_default()),
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

fn build_edgenode_quadlet(image: &str) -> String {
    format!("[Unit]\nDescription=Holo EdgeNode\nAfter=network-online.target\nConflicts=wind-tunnel.service\n\n[Container]\nImage={image}\nContainerName=edgenode\nVolume=/var/lib/edgenode:/data:Z\nLabel=io.containers.autoupdate=registry\n\n[Service]\nRestart=always\nRestartSec=5\n\n[Install]\nWantedBy=multi-user.target\n", image=image)
}

fn build_wind_tunnel_quadlet(hostname: &str, image: &str) -> String {
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

fn build_wt_client_name(node_name: &str, unyt_agent_id: &str, wt_suffix: &str) -> String {
    let agent = unyt_agent_id.trim();
    if agent.is_empty() {
        format!("{}-{}", node_name, wt_suffix)
    } else {
        format!("{}-{}", node_name, agent)
    }
}

fn build_wt_hostname_slug(node_name: &str, wt_suffix: &str) -> String {
    format!("{}-{}", node_name, wt_suffix)
}

fn build_wt_hostname(node_name: &str, wt_suffix: &str) -> String {
    format!("{}{}", NOMAD_CLIENT_PREFIX, build_wt_hostname_slug(node_name, wt_suffix))
}

fn wt_hostname_slug_error(node_name: &str) -> Option<String> {
    let overhead = 1 + WT_RANDOM_SUFFIX_LEN;
    if node_name.len() + overhead <= WT_HOSTNAME_MAX { return None; }
    let max_name = WT_HOSTNAME_MAX.saturating_sub(overhead);
    Some(format!(
        "Wind Tunnel hostname would exceed {} characters (node name + random suffix). Shorten node name to at most {} characters.",
        WT_HOSTNAME_MAX, max_name
    ))
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

fn write_quadlets(node_name: &str, wt_suffix: &str) {
    let edgenode_image = resolve_edgenode_image();
    let wt_image       = resolve_wind_tunnel_image();
    let hostname_slug  = build_wt_hostname_slug(node_name, wt_suffix);
    let _ = fs::write(format!("{}/edgenode.container", QUADLET_DIR),    build_edgenode_quadlet(&edgenode_image));
    let _ = fs::write(format!("{}/wind-tunnel.container", QUADLET_DIR), build_wind_tunnel_quadlet(&hostname_slug, &wt_image));
    let _ = Command::new("systemctl").args(["daemon-reload"]).output();
    eprintln!("[quadlet] WT hostname={}", build_wt_hostname(node_name, wt_suffix));
}

fn write_quadlets_for_state(state: &AppState) {
    let node_name = state.node_name.lock().unwrap().clone();
    let wt_suffix = ensure_wt_suffix(state);
    write_quadlets(&node_name, &wt_suffix);
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

fn apply_hardware_mode(new_mode: &str, state: &AppState) {
    let current = state.hw_mode.lock().unwrap().clone();
    let stop_svc  = if current == "WIND_TUNNEL" { "wind-tunnel.service" } else { "edgenode.service" };
    let start_svc = if new_mode == "WIND_TUNNEL"  { "wind-tunnel.service" } else { "edgenode.service" };
    let _ = fs::write("/var/lib/edgenode/mode_switch.txt", new_mode);
    if new_mode == "WIND_TUNNEL" {
        let unyt_agent_id = state.unyt_agent_id.lock().unwrap().clone();
        write_wind_tunnel_client_meta(&unyt_agent_id);
        write_quadlets_for_state(state);
    }
    if current != new_mode {
        eprintln!("[manage] Stopping {} → starting {}", stop_svc, start_svc);
        let _ = Command::new("systemctl").args(["stop",  stop_svc]).output();
        let _ = Command::new("systemctl").args(["start", start_svc]).output();
    }
    *state.hw_mode.lock().unwrap() = new_mode.to_string();
    update_state_key("hw_mode", new_mode);
}

// ── JSON / HTML helpers ────────────────────────────────────────────────────────

fn json_str<'a>(json: &'a str, key: &str) -> &'a str {
    let needle = format!("\"{}\"", key);
    let pos = match json.find(&needle) { Some(p) => p, None => return "" };
    let after = json[pos + needle.len()..].splitn(2, ':').nth(1).unwrap_or("").trim_start();
    if after.starts_with('"') { let inner = &after[1..]; &inner[..inner.find('"').unwrap_or(0)] } else { "" }
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
    let body = format!("{{\"error\":\"{}\"}}", msg.replace('"', "'"));
    send_response(stream, status, "Error", "application/json", body.as_bytes());
}
fn send_redirect(stream: &mut TcpStream, location: &str) {
    let _ = stream.write_all(format!("HTTP/1.1 302 Found\r\nLocation: {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", location).as_bytes());
}
fn send_redirect_with_cookie(stream: &mut TcpStream, location: &str, cookie: &str) {
    let _ = stream.write_all(format!("HTTP/1.1 302 Found\r\nLocation: {}\r\nSet-Cookie: {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", location, cookie).as_bytes());
}

struct Req { method: String, path: String, headers: String, body: String }

fn read_request(stream: &mut TcpStream) -> Option<Req> {
    let mut r = BufReader::new(stream.try_clone().ok()?);
    let mut line0 = String::new(); r.read_line(&mut line0).ok()?;
    let mut parts = line0.trim().splitn(3, ' ');
    let method   = parts.next()?.to_string();
    let path_raw = parts.next()?.to_string();
    let path     = path_raw.split('?').next().unwrap_or(&path_raw).to_string();
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
    Some(Req { method, path, headers, body: String::from_utf8_lossy(&body).into_owned() })
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

const UNYT_INFO_COPY: &str = r#"<div class="info-box" style="margin-top:12px"><strong>HoloFuel compensation requires a Unyt Agent ID.</strong> Download the Unyt desktop app, sign in, and copy your Agent ID from the app settings. Setup can finish without it, but you will not receive HoloFuel payments until an Agent ID is saved.<br><br>Without an Agent ID, a random suffix is assigned for Wind Tunnel client naming (<code>{node_name}-&lt;suffix&gt;</code>). With an Agent ID, the full ID is used (<code>{node_name}-&lt;agent_id&gt;</code>). Each physical node needs a unique node name + Agent ID pair — do not reuse the same combination on multiple machines.</div>"#;

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
      <div class="slbl">Step 1 of 3</div>
      <div class="stit">Node identity &amp; SSH access</div>
      <div class="sdsc">Name your node and optionally add your SSH public key for remote access.</div>
      <label>Node name *</label>
      <input type="text" id="nodeName" placeholder="e.g. alice, home-node-01" oninput="chkS1()">
      <div class="hint" id="nameHint">Lowercase letters, numbers and hyphens only. Used as hostname slug.</div>
      <label>SSH public key <span style="color:#475569;font-weight:400">(recommended)</span></label>
      <textarea id="sshKey" placeholder="ssh-ed25519 AAAA...&#10;Leave blank to add keys later in /manage"></textarea>
      <label>Unyt Agent ID <span style="color:#475569;font-weight:400">(optional)</span></label>
      <input type="text" id="unytAgentId" placeholder="Paste your Agent ID from the Unyt desktop app" oninput="chkS1()">
      {unyt_copy}
      <div class="brow"><button class="btn btn-primary" id="b1" onclick="gTo(2)" disabled>Continue →</button></div>
    </div>

    <!-- STEP 2: HARDWARE MODE -->
    <div class="step" id="s2">
      <div class="slbl">Step 2 of 3</div>
      <div class="stit">Hardware mode</div>
      <div class="sdsc">Choose the initial container mode for your node.</div>
      <label>Hardware mode</label>
      <select id="hw">
        <option value="STANDARD">Standard EdgeNode — always-on Holochain peer</option>
        <option value="WIND_TUNNEL">Holochain Wind Tunnel — network stress-tester</option>
      </select>
      <div class="brow">
        <button class="btn btn-secondary" onclick="gTo(1)">← Back</button>
        <button class="btn btn-primary" onclick="gTo(3)">Review →</button>
      </div>
    </div>

    <!-- STEP 3: REVIEW -->
    <div class="step" id="s3">
      <div class="slbl">Step 3 of 3</div>
      <div class="stit">Review &amp; initialize</div>
      <div class="sdsc">Check your settings, then start the node.</div>
      <table class="rt">
        <tr><td>Node Name</td><td id="rv-nn">—</td></tr>
        <tr><td>SSH Key</td><td id="rv-sk">—</td></tr>
        <tr><td>Unyt Agent ID</td><td id="rv-unyt">—</td></tr>
        <tr><td>Hardware Mode</td><td id="rv-hw">—</td></tr>
        <tr id="rv-wt-row" style="display:none"><td>Wind Tunnel hostname</td><td id="rv-wt">—</td></tr>
      </table>
      <div class="info-box" style="margin-top:16px">After initialization:<br>
        1. SSH access is configured for the <code>holo</code> user<br>
        2. Podman Quadlet services are registered with systemd<br>
        3. You will be redirected to the management panel</div>
      <div class="brow">
        <button class="btn btn-secondary" onclick="gTo(2)">← Back</button>
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
  document.getElementById(n===4?'suc':'s'+n).classList.add('active');
  document.getElementById('prog').style.width=(Math.min(n,3)/3*100)+'%';
  if(n===3)bRev();
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
  const wtSuffixLen=16;
  const wtName=agent?name+'-'+agent.trim():name+'-'+('0'.repeat(wtSuffixLen));
  const wtSlugLen=name.length+1+wtSuffixLen;
  if(wtName.length>63){{hint.textContent='With this Agent ID, node name must be at most '+(63-(1+(agent?agent.trim().length:wtSuffixLen)))+' characters for Wind Tunnel.';document.getElementById('b1').disabled=true;return;}}
  if(wtSlugLen>63){{hint.textContent='Node name must be at most '+(63-(1+wtSuffixLen))+' characters for Wind Tunnel hostname.';document.getElementById('b1').disabled=true;return;}}
  hint.textContent='Lowercase letters, numbers and hyphens only. Used as hostname slug.';
}}

function wtNameLen(name,agent){{
  const a=agent.trim();
  const suffixLen=16;
  return a?name.length+1+a.length:name.length+1+suffixLen;
}}

function wtHostname(name){{
  return 'nomad-client-'+name+'-&lt;random suffix&gt;';
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
  if(nodeName.length+1+16>63)return alert('Node name is too long for Wind Tunnel hostname. Shorten the node name.');
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
    if(r.ok){{gTo(4);setTimeout(()=>window.location.href='/manage',2000);}}
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
    let wt_suffix      = ensure_wt_suffix(state);
    let ssh_keys       = read_ssh_keys();
    let uptime_s       = state.start_time.elapsed().unwrap_or_default().as_secs();
    let ip             = get_local_ip();
    let wt_hostname    = build_wt_hostname(&node_name, &wt_suffix);

    let unyt_display = if unyt_agent_id.is_empty() {
        "(not set — compensation unavailable)".to_string()
    } else {
        unyt_agent_id.clone()
    };
    let unyt_badge = if unyt_agent_id.is_empty() { "badge-gray" } else { "badge-green" };
    let unyt_badge_text = if unyt_agent_id.is_empty() { "not set" } else { "linked" };

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

    let ssh_count  = ssh_keys.len();
    let ssh_plural = if ssh_count == 1 { "" } else { "s" };

    let wt_hostname_html = if hw_mode == "WIND_TUNNEL" {
        format!(
            r#"<p style="font-size:12px;color:#475569;margin-bottom:14px">Wind Tunnel hostname: <code>{wt_hostname}</code><br><span style="font-size:11px;color:#64748b">Copy this value into the <a href="https://wind-tunnel-runner-status.holochain.org/" target="_blank" rel="noopener" style="color:#818cf8">Wind Tunnel runner status page</a>.</span></p>"#,
            wt_hostname = html_escape(&wt_hostname)
        )
    } else {
        String::new()
    };

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
    <div class="info-item">Hardware <span id="info-hw">{hw_mode_display}</span></div>
    <div class="info-item">Unyt <span id="info-unyt">{unyt_badge_text}</span></div>
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
      {wt_hostname_html}
      <label>Unyt Agent ID</label>
      <input type="text" id="unytAgentId" value="{unyt_agent_id_escaped}" placeholder="Paste your Agent ID from the Unyt desktop app">
      <div style="margin-top:10px"><button class="btn btn-primary" onclick="saveUnyt()">Save Agent ID</button></div>
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

  <!-- HARDWARE MODE -->
  <div class="section">
    <div class="section-hdr" onclick="toggleSection('hw')">
      <div class="section-title"><span>⚙️</span> Hardware Mode <span class="section-badge badge-green" id="hw-badge">{hw_mode_display}</span></div>
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
['unyt','hw','pw','upd'].forEach(id=>toggleSection(id));

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
  if(!r.ok)throw new Error(text||'Server error '+r.status);
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

async function saveHardware(){{
  try{{
    await api('/manage/hardware',{{mode:curHw}});
    document.getElementById('hw-badge').textContent=curHw==='WIND_TUNNEL'?'Wind Tunnel':'EdgeNode';
    document.getElementById('info-hw').textContent=curHw==='WIND_TUNNEL'?'Wind Tunnel':'EdgeNode';
    toast('Hardware mode updated',true);
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
        wt_hostname_html     = wt_hostname_html,
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
    if let Some(msg) = wt_hostname_slug_error(node_name) {
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
    write_wind_tunnel_client_meta(unyt_agent_id);
    let wt_suffix = generate_wt_suffix();
    write_quadlets(node_name, &wt_suffix);

    let _ = fs::write("/var/lib/edgenode/mode_switch.txt",
        if hw_mode == "WIND_TUNNEL" { "WIND_TUNNEL" } else { "STANDARD" });
    let initial_svc = if hw_mode == "WIND_TUNNEL" { "wind-tunnel.service" } else { "edgenode.service" };
    let _ = Command::new("systemctl").args(["start", initial_svc]).output();

    // ── Persist state ────────────────────────────────────────────────────────
    let mut kv = HashMap::new();
    kv.insert("onboarded".into(), "true".into());
    kv.insert("node_name".into(), node_name.to_string());
    kv.insert("hw_mode".into(), if hw_mode == "WIND_TUNNEL" { "WIND_TUNNEL" } else { "STANDARD" }.to_string());
    kv.insert("unyt_agent_id".into(), unyt_agent_id.to_string());
    kv.insert("wt_suffix".into(), wt_suffix.clone());
    write_state_file(&kv);

    *state.node_name.lock().unwrap()     = node_name.to_string();
    *state.hw_mode.lock().unwrap()       = if hw_mode == "WIND_TUNNEL" { "WIND_TUNNEL" } else { "STANDARD" }.to_string();
    *state.unyt_agent_id.lock().unwrap() = unyt_agent_id.to_string();
    *state.wt_suffix.lock().unwrap()     = wt_suffix;
    state.onboarded.store(true, Ordering::Relaxed);

    eprintln!("[onboard] Complete. node={} hw={} unyt={}", node_name, hw_mode, if unyt_agent_id.is_empty() { "(none)" } else { "set" });
    send_json_ok(stream, r#"{"status":"ok"}"#);
}

fn handle_manage_status(stream: &mut TcpStream, state: &AppState) {
    let node_name     = state.node_name.lock().unwrap().clone();
    let hw_mode       = state.hw_mode.lock().unwrap().clone();
    let unyt_agent_id  = state.unyt_agent_id.lock().unwrap().clone();
    let wt_suffix      = ensure_wt_suffix(state);
    let wt_client_name = build_wt_client_name(&node_name, &unyt_agent_id, &wt_suffix);
    let wt_hostname    = build_wt_hostname(&node_name, &wt_suffix);
    let uptime    = state.start_time.elapsed().unwrap_or_default().as_secs();
    let keys      = read_ssh_keys();
    let keys_json: String = keys.iter()
        .map(|k| format!("\"{}\"", k.replace('\\', "\\\\").replace('"', "\\\"")))
        .collect::<Vec<_>>().join(",");
    send_json_ok(stream, &format!(
        r#"{{"version":"{}","node_name":"{}","hw_mode":"{}","unyt_agent_id":"{}","wt_client_name":"{}","wt_hostname":"{}","ssh_key_count":{},"ssh_keys":[{}],"uptime_secs":{}}}"#,
        VERSION,
        node_name.replace('\\', "\\\\").replace('"', "\\\""),
        hw_mode,
        unyt_agent_id.replace('\\', "\\\\").replace('"', "\\\""),
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

    write_wind_tunnel_client_meta(unyt_agent_id);
    write_quadlets_for_state(state);
    if state.hw_mode.lock().unwrap().as_str() == "WIND_TUNNEL" {
        restart_wind_tunnel_if_running();
    }

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
        write_quadlets_for_state(&state);
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

                ("POST", "/manage/hardware") => {
                    if !is_authenticated(&req, &state) {
                        send_json_err(&mut stream, 401, "Not authenticated");
                    } else {
                        handle_hardware(&mut stream, &req, &state);
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
