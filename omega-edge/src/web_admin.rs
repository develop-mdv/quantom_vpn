use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::session::{flow_id_from_hex, SessionManager};
use omega_control::identity::{
    parse_platform, IdentityStore, DEFAULT_MAX_CONCURRENT_SESSIONS, DEFAULT_MAX_DEVICES,
};

const MAX_REQUEST_SIZE: usize = 64 * 1024;

pub async fn run(
    bind_addr: String,
    identity_store: Arc<IdentityStore>,
    session_manager: Arc<SessionManager>,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(&bind_addr)
        .await
        .with_context(|| format!("failed to bind web admin on {}", bind_addr))?;

    tracing::info!(%bind_addr, "web admin started");

    loop {
        let (stream, peer) = listener.accept().await?;
        let identity = identity_store.clone();
        let sessions = session_manager.clone();

        tokio::spawn(async move {
            if let Err(err) = handle_connection(stream, identity, sessions).await {
                tracing::warn!(%peer, error = %err, "web admin request failed");
            }
        });
    }
}

struct HttpRequest {
    method: String,
    path: String,
    query: HashMap<String, String>,
    body: String,
}

async fn handle_connection(
    mut stream: TcpStream,
    identity_store: Arc<IdentityStore>,
    session_manager: Arc<SessionManager>,
) -> anyhow::Result<()> {
    let request = read_request(&mut stream).await?;

    let response = match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/healthz") => text_response(200, "OK", "ok"),
        ("GET", "/") => {
            let identity = identity_store.clone();
            let sessions = session_manager.clone();
            let message = request.query.get("msg").cloned();
            match tokio::time::timeout(
                Duration::from_secs(5),
                tokio::task::spawn_blocking(move || render_page(&identity, &sessions, message)),
            )
            .await
            {
                Ok(Ok(html)) => html_response(200, "OK", html),
                Ok(Err(err)) => {
                    tracing::error!(error = %err, "web admin renderer task failed");
                    text_response(
                        500,
                        "Internal Server Error",
                        "admin page render failed; try /healthz and refresh",
                    )
                }
                Err(_) => {
                    tracing::error!("web admin root render timed out");
                    text_response(
                        503,
                        "Service Unavailable",
                        "admin page render timed out; try /healthz and refresh",
                    )
                }
            }
        }
        ("POST", "/users/create") => {
            let form = parse_form(&request.body);
            let max_devices = parse_u32_field(form.get("max_devices"), DEFAULT_MAX_DEVICES);
            let max_sessions =
                parse_u32_field(form.get("max_sessions"), DEFAULT_MAX_CONCURRENT_SESSIONS);

            let msg = match identity_store.create_user(max_devices, max_sessions, "web_admin") {
                Ok(user) => format!(
                    "User created: {} (max_devices={}, max_sessions={})",
                    user.user_id, user.max_devices, user.max_concurrent_sessions
                ),
                Err(err) => format!("Create user error: {}", err),
            };
            redirect_with_message(msg)
        }
        ("POST", "/users/block") => {
            let form = parse_form(&request.body);
            let user_id = form.get("user_id").cloned().unwrap_or_default();
            let msg = match identity_store.block_user(&user_id, "web_admin") {
                Ok(_) => format!("User blocked: {}", user_id),
                Err(err) => format!("Block user error {}: {}", user_id, err),
            };
            redirect_with_message(msg)
        }
        ("POST", "/users/unblock") => {
            let form = parse_form(&request.body);
            let user_id = form.get("user_id").cloned().unwrap_or_default();
            let msg = match identity_store.unblock_user(&user_id, "web_admin") {
                Ok(_) => format!("User unblocked: {}", user_id),
                Err(err) => format!("Unblock user error {}: {}", user_id, err),
            };
            redirect_with_message(msg)
        }
        ("POST", "/users/delete") => {
            let form = parse_form(&request.body);
            let user_id = form.get("user_id").cloned().unwrap_or_default();
            let msg = match identity_store.delete_user(&user_id, "web_admin") {
                Ok(_) => format!("User deleted: {}", user_id),
                Err(err) => format!("Delete user error {}: {}", user_id, err),
            };
            redirect_with_message(msg)
        }
        ("POST", "/devices/register") => {
            let form = parse_form(&request.body);
            let user_id = form.get("user_id").cloned().unwrap_or_default();
            let device_name = form
                .get("device_name")
                .cloned()
                .unwrap_or_else(|| "device".to_string());
            let platform_text = form
                .get("platform")
                .cloned()
                .unwrap_or_else(|| "other".to_string());
            let fingerprint = form
                .get("fingerprint")
                .cloned()
                .unwrap_or_else(|| "manual".to_string());

            let msg = match parse_platform(&platform_text).and_then(|platform| {
                identity_store.register_device(
                    &user_id,
                    &device_name,
                    platform,
                    &fingerprint,
                    "web_admin",
                )
            }) {
                Ok(reg) => format!(
                    "Device registered successfully.\nSave token now (shown once): {}\n\nClient .env:\nOMEGA_SERVER={}\nOMEGA_DEVICE_ID={}\nOMEGA_DEVICE_TOKEN={}\nOMEGA_DEVICE_NAME={}\nOMEGA_PLATFORM={}",
                    reg.device_token,
                    client_server_hint(),
                    reg.device.device_id,
                    reg.device_token,
                    reg.device.device_name,
                    reg.device.platform.as_str()
                ),
                Err(err) => format!("Register device error: {}", err),
            };
            redirect_with_message(msg)
        }
        ("POST", "/devices/revoke") => {
            let form = parse_form(&request.body);
            let device_id = form.get("device_id").cloned().unwrap_or_default();
            let msg = match identity_store.revoke_device(&device_id, "web_admin") {
                Ok(_) => format!("Device revoked: {}", device_id),
                Err(err) => format!("Revoke device error {}: {}", device_id, err),
            };
            redirect_with_message(msg)
        }
        ("POST", "/sessions/terminate") => {
            let form = parse_form(&request.body);
            let flow = form.get("flow_id").cloned().unwrap_or_default();
            let msg = match flow_id_from_hex(&flow) {
                Some(fid) => {
                    if session_manager.terminate_session_with_reason(&fid, "web_admin") {
                        format!("Session terminated: {}", flow)
                    } else {
                        format!("Session not found: {}", flow)
                    }
                }
                None => format!("Invalid flow_id: {}", flow),
            };
            redirect_with_message(msg)
        }
        _ => text_response(404, "Not Found", "Not Found"),
    };

    stream.write_all(&response).await?;
    stream.flush().await?;
    Ok(())
}

async fn read_request(stream: &mut TcpStream) -> anyhow::Result<HttpRequest> {
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 2048];

    let mut header_end = None;
    let mut content_len = 0usize;

    loop {
        let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut tmp))
            .await
            .context("timed out while reading HTTP request")??;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);

        if buf.len() > MAX_REQUEST_SIZE {
            anyhow::bail!("request too large");
        }

        if header_end.is_none() {
            header_end = find_header_end(&buf);
            if let Some(end) = header_end {
                let header_bytes = &buf[..end];
                content_len = parse_content_length(header_bytes);
            }
        }

        if let Some(end) = header_end {
            let total = end + 4 + content_len;
            if buf.len() >= total {
                break;
            }
        }
    }

    let end = header_end.context("malformed HTTP request")?;
    let header_text = std::str::from_utf8(&buf[..end]).context("invalid HTTP header utf8")?;

    let mut lines = header_text.lines();
    let request_line = lines.next().context("empty HTTP request")?;
    let mut parts = request_line.split_whitespace();

    let method = parts.next().unwrap_or("GET").to_string();
    let target = parts.next().unwrap_or("/");
    let (path, query) = if let Some((p, q)) = target.split_once('?') {
        (p.to_string(), parse_form(q))
    } else {
        (target.to_string(), HashMap::new())
    };

    let body_start = end + 4;
    let body_end = (body_start + content_len).min(buf.len());
    let body = String::from_utf8_lossy(&buf[body_start..body_end]).to_string();

    Ok(HttpRequest {
        method,
        path,
        query,
        body,
    })
}

fn render_page(
    identity_store: &IdentityStore,
    session_manager: &SessionManager,
    message: Option<String>,
) -> String {
    let inventory = identity_store.admin_inventory();
    let sessions = session_manager.snapshot();
    let client_server = client_server_hint();
    let users = inventory.users;
    let devices_by_user = inventory.devices_by_user;

    let mut out = String::with_capacity(32 * 1024);
    out.push_str("<!doctype html><html><head><meta charset=\"utf-8\"><title>Omega Admin</title>");
    out.push_str("<style>");
    out.push_str(
        "body{font-family:Segoe UI,Arial,sans-serif;margin:24px;background:#f7f8fb;color:#1f2937}",
    );
    out.push_str("h1{margin:0 0 16px}h2{margin:20px 0 8px}");
    out.push_str(
        ".grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:16px}",
    );
    out.push_str(".card{background:#fff;border:1px solid #dbe1ea;border-radius:10px;padding:14px}");
    out.push_str("label{display:block;font-size:12px;margin:6px 0 4px;color:#4b5563}");
    out.push_str("input,select{width:100%;padding:8px;border:1px solid #c7d2e0;border-radius:8px}");
    out.push_str("button{margin-top:10px;padding:8px 12px;border:0;border-radius:8px;background:#2563eb;color:#fff;cursor:pointer}");
    out.push_str("table{width:100%;border-collapse:collapse;font-size:13px}");
    out.push_str(
        "th,td{border-bottom:1px solid #e5e7eb;padding:8px;vertical-align:top;text-align:left}",
    );
    out.push_str(".msg{padding:10px;background:#e0f2fe;border:1px solid #7dd3fc;border-radius:8px;margin-bottom:12px;white-space:pre-wrap}");
    out.push_str(".mini{display:inline-block;margin-right:8px}");
    out.push_str(".mini button{margin-top:0;padding:6px 10px;font-size:12px;background:#334155}");
    out.push_str(".env{margin:8px 0 0;padding:8px;background:#0f172a;color:#e2e8f0;border-radius:8px;white-space:pre-wrap;font-size:12px;line-height:1.35}");
    out.push_str(".note{display:block;margin-top:6px;font-size:12px;color:#64748b}");
    out.push_str(".copy-btn{margin-top:8px;padding:6px 10px;font-size:12px;background:#0ea5e9}");
    out.push_str(".copy-status{margin-left:8px;font-size:12px;color:#0f766e}");
    out.push_str("</style></head><body>");

    out.push_str("<h1>Omega VPN Admin</h1>");
    out.push_str("<p>Built-in web admin for users, devices and active sessions.</p>");

    if let Some(msg) = message {
        out.push_str("<div class=\"msg\">");
        out.push_str(&escape_html(&msg));
        out.push_str("</div>");
    }

    out.push_str("<div class=\"grid\">");
    out.push_str("<div class=\"card\"><h2>Create User</h2>");
    out.push_str("<form method=\"post\" action=\"/users/create\">");
    out.push_str("<label>Max devices</label><input name=\"max_devices\" value=\"5\" type=\"number\" min=\"1\" max=\"1000\">");
    out.push_str("<label>Max concurrent sessions</label><input name=\"max_sessions\" value=\"3\" type=\"number\" min=\"1\" max=\"1000\">");
    out.push_str("<button type=\"submit\">Create user</button></form></div>");

    out.push_str("<div class=\"card\"><h2>Register Device</h2>");
    out.push_str("<form method=\"post\" action=\"/devices/register\">");
    out.push_str("<label>User ID</label><input name=\"user_id\" required>");
    out.push_str(
        "<label>Device name</label><input name=\"device_name\" value=\"laptop\" required>",
    );
    out.push_str("<label>Platform</label><select name=\"platform\">");
    out.push_str("<option>windows</option><option>linux</option><option>macos</option><option>android</option><option>ios</option><option>other</option>");
    out.push_str("</select>");
    out.push_str(
        "<label>Fingerprint (optional)</label><input name=\"fingerprint\" value=\"manual\">",
    );
    out.push_str("<button type=\"submit\">Register device</button></form></div>");
    out.push_str("</div>");

    out.push_str("<h2>Users and Devices</h2>");
    out.push_str("<div class=\"card\"><table>");
    out.push_str("<thead><tr><th>User</th><th>Status/Limits</th><th>Devices</th><th>Actions</th></tr></thead><tbody>");

    for user in users {
        out.push_str("<tr><td>");
        out.push_str(&escape_html(&user.user_id));
        out.push_str("</td><td>");
        out.push_str(&format!(
            "status={:?}<br>max_devices={}<br>max_sessions={}",
            user.status, user.max_devices, user.max_concurrent_sessions
        ));
        out.push_str("</td><td>");

        if let Some(devices) = devices_by_user.get(&user.user_id) {
            for device in devices {
                out.push_str("<div style=\"margin-bottom:8px;padding:6px;border:1px solid #e5e7eb;border-radius:8px\">");
                out.push_str(&format!(
                    "<b>{}</b><br>{}<br>platform={} revoked={}<br>fingerprint={}",
                    escape_html(&device.device_name),
                    escape_html(&device.device_id),
                    device.platform.as_str(),
                    device.revoked,
                    escape_html(&device.public_key_fingerprint)
                ));
                let env_block = format!(
                    "OMEGA_SERVER={}\nOMEGA_DEVICE_ID={}\nOMEGA_DEVICE_TOKEN=<token_from_register_output>\nOMEGA_DEVICE_NAME={}\nOMEGA_PLATFORM={}",
                    client_server,
                    device.device_id,
                    device.device_name,
                    device.platform.as_str()
                );
                out.push_str("<pre class=\"env\">");
                out.push_str(&escape_html(&env_block));
                out.push_str("</pre>");
                out.push_str("<button type=\"button\" class=\"copy-btn\" onclick=\"copyEnv(this)\">Copy .env</button><span class=\"copy-status\"></span>");
                out.push_str("<span class=\"note\">OMEGA_DEVICE_TOKEN is shown only once during device registration.</span>");
                if !device.revoked {
                    out.push_str(
                        "<form method=\"post\" action=\"/devices/revoke\" class=\"mini\">",
                    );
                    out.push_str(&format!(
                        "<input type=\"hidden\" name=\"device_id\" value=\"{}\">",
                        escape_html(&device.device_id)
                    ));
                    out.push_str("<button type=\"submit\">Revoke</button></form>");
                }
                out.push_str("</div>");
            }
        } else {
            out.push_str("-");
        }

        out.push_str("</td><td>");
        out.push_str("<form method=\"post\" action=\"/users/block\" class=\"mini\">");
        out.push_str(&format!(
            "<input type=\"hidden\" name=\"user_id\" value=\"{}\"><button type=\"submit\">Block</button>",
            escape_html(&user.user_id)
        ));
        out.push_str("</form>");

        out.push_str("<form method=\"post\" action=\"/users/unblock\" class=\"mini\">");
        out.push_str(&format!(
            "<input type=\"hidden\" name=\"user_id\" value=\"{}\"><button type=\"submit\">Unblock</button>",
            escape_html(&user.user_id)
        ));
        out.push_str("</form>");

        out.push_str("<form method=\"post\" action=\"/users/delete\" class=\"mini\">");
        out.push_str(&format!(
            "<input type=\"hidden\" name=\"user_id\" value=\"{}\"><button type=\"submit\">Delete</button>",
            escape_html(&user.user_id)
        ));
        out.push_str("</form>");

        out.push_str("</td></tr>");
    }

    out.push_str("</tbody></table></div>");

    out.push_str("<h2>Active Sessions</h2>");
    out.push_str("<div class=\"card\"><table><thead><tr><th>Flow ID</th><th>User</th><th>Device</th><th>Tunnel IP</th><th>Peer</th><th>Idle(s)</th><th>Action</th></tr></thead><tbody>");
    if sessions.is_empty() {
        out.push_str("<tr><td colspan=\"7\">No active sessions</td></tr>");
    } else {
        for sess in sessions {
            out.push_str("<tr>");
            out.push_str(&format!("<td>{}</td>", escape_html(&sess.flow_id)));
            out.push_str(&format!("<td>{}</td>", escape_html(&sess.user_id)));
            out.push_str(&format!("<td>{}</td>", escape_html(&sess.device_id)));
            out.push_str(&format!("<td>{}</td>", escape_html(&sess.tunnel_ip)));
            out.push_str(&format!("<td>{}</td>", escape_html(&sess.client_addr)));
            out.push_str(&format!("<td>{}</td>", sess.idle_secs));
            out.push_str("<td><form method=\"post\" action=\"/sessions/terminate\">");
            out.push_str(&format!(
                "<input type=\"hidden\" name=\"flow_id\" value=\"{}\"><button type=\"submit\">Terminate</button>",
                escape_html(&sess.flow_id)
            ));
            out.push_str("</form></td>");
            out.push_str("</tr>");
        }
    }
    out.push_str("</tbody></table></div>");

    out.push_str("<script>");
    out.push_str("async function copyEnv(btn){const card=btn.closest('div');if(!card)return;const pre=card.querySelector('pre.env');const status=card.querySelector('.copy-status');if(!pre)return;const text=pre.innerText;try{if(navigator.clipboard&&window.isSecureContext){await navigator.clipboard.writeText(text);}else{const ta=document.createElement('textarea');ta.value=text;document.body.appendChild(ta);ta.select();document.execCommand('copy');ta.remove();}if(status){status.textContent='Copied';setTimeout(()=>status.textContent='',1500);}}catch(e){if(status){status.textContent='Copy failed';setTimeout(()=>status.textContent='',2000);}}}");
    out.push_str("</script>");
    out.push_str("</body></html>");
    out
}

fn parse_u32_field(value: Option<&String>, default: u32) -> u32 {
    value
        .and_then(|v| v.trim().parse::<u32>().ok())
        .unwrap_or(default)
}

fn parse_form(body: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for pair in body.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        out.insert(url_decode(key), url_decode(value));
    }
    out
}

fn redirect_with_message(message: String) -> Vec<u8> {
    let location = format!("/?msg={}", url_encode(&message));
    redirect_response(&location)
}

fn redirect_response(location: &str) -> Vec<u8> {
    let header = format!(
        "HTTP/1.1 303 See Other\r\nLocation: {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        location
    );
    header.into_bytes()
}

fn url_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len() * 3 / 2);
    for b in input.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push('%');
            out.push(hex_upper((b >> 4) & 0x0f));
            out.push(hex_upper(b & 0x0f));
        }
    }
    out
}

fn hex_upper(v: u8) -> char {
    match v {
        0..=9 => (b'0' + v) as char,
        10..=15 => (b'A' + (v - 10)) as char,
        _ => '0',
    }
}
fn url_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;

    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                if let (Some(hi), Some(lo)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                    out.push((hi << 4) | lo);
                    i += 3;
                } else {
                    out.push(bytes[i]);
                    i += 1;
                }
            }
            v => {
                out.push(v);
                i += 1;
            }
        }
    }

    String::from_utf8_lossy(&out).to_string()
}

fn hex_val(v: u8) -> Option<u8> {
    match v {
        b'0'..=b'9' => Some(v - b'0'),
        b'a'..=b'f' => Some(v - b'a' + 10),
        b'A'..=b'F' => Some(v - b'A' + 10),
        _ => None,
    }
}

fn escape_html(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn parse_content_length(header: &[u8]) -> usize {
    let text = String::from_utf8_lossy(header);
    for line in text.lines() {
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("content-length") {
                if let Ok(len) = value.trim().parse::<usize>() {
                    return len;
                }
            }
        }
    }
    0
}

fn client_server_hint() -> String {
    if let Ok(v) = std::env::var("OMEGA_CLIENT_SERVER") {
        let trimmed = v.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }

    let bind = std::env::var("OMEGA_BIND").unwrap_or_else(|_| "0.0.0.0:51820".to_string());
    if let Some(port) = bind.strip_prefix("0.0.0.0:") {
        return format!("<SERVER_IP>:{}", port);
    }
    if let Some(port) = bind.strip_prefix("[::]:") {
        return format!("<SERVER_IP>:{}", port);
    }

    bind
}

fn html_response(status: u16, reason: &str, body: String) -> Vec<u8> {
    let header = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        status,
        reason,
        body.len()
    );

    let mut out = Vec::with_capacity(header.len() + body.len());
    out.extend_from_slice(header.as_bytes());
    out.extend_from_slice(body.as_bytes());
    out
}

fn text_response(status: u16, reason: &str, body: &str) -> Vec<u8> {
    let header = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        status,
        reason,
        body.len()
    );

    let mut out = Vec::with_capacity(header.len() + body.len());
    out.extend_from_slice(header.as_bytes());
    out.extend_from_slice(body.as_bytes());
    out
}
