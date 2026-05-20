use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Context;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::identity::{
    parse_platform, IdentityStore, DEFAULT_MAX_CONCURRENT_SESSIONS, DEFAULT_MAX_DEVICES,
};
use crate::reality::config_store::StoredConfig as RealityStored;
use crate::reality::SharedController as RealityController;
use crate::session::{flow_id_from_hex, SessionManager};

const MAX_REQUEST_SIZE: usize = 64 * 1024;

pub async fn run(
    bind_addr: String,
    identity_store: Arc<IdentityStore>,
    session_manager: Arc<SessionManager>,
    reality: RealityController,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(&bind_addr)
        .await
        .with_context(|| format!("failed to bind web admin on {}", bind_addr))?;

    tracing::info!(%bind_addr, "web admin started");

    loop {
        let (stream, peer) = listener.accept().await?;
        let identity = identity_store.clone();
        let sessions = session_manager.clone();
        let reality = reality.clone();

        tokio::spawn(async move {
            if let Err(err) = handle_connection(stream, identity, sessions, reality).await {
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
    reality: RealityController,
) -> anyhow::Result<()> {
    let request = read_request(&mut stream).await?;

    let response = match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/") => {
            let reality_status = reality.status().await;
            let public_host = public_host_for_clients();
            let reality_code = reality.connection_code(&public_host).await;
            let html = render_page(
                &identity_store,
                &session_manager,
                &reality_status,
                reality_code.as_deref(),
                request.query.get("msg").cloned(),
                request.query.get("code").cloned(),
            );
            html_response(200, "OK", html)
        }
        ("GET", "/api/reality/status") => {
            let status = reality.status().await;
            let json = serde_json::to_string(&status).unwrap_or_else(|_| "{}".to_string());
            json_response(200, "OK", &json)
        }
        ("POST", "/reality/apply") => {
            let form = parse_form(&request.body);
            let mut current = reality.status().await.stored;
            current.enabled = form.get("enabled").map(|v| v == "1").unwrap_or(false);
            if let Some(v) = form.get("bind") {
                current.bind = v.trim().to_string();
            }
            if let Some(v) = form.get("dest") {
                if let Some((h, p)) = parse_host_port(v) {
                    current.dest_host = h;
                    current.dest_port = p;
                }
            }
            if let Some(v) = form.get("server_names") {
                current.server_names = v
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
            }
            if let Some(v) = form.get("short_ids") {
                current.short_ids_hex = v
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
            }
            if let Some(v) = form.get("fingerprint") {
                if !v.trim().is_empty() {
                    current.fingerprint_profile = v.trim().to_string();
                }
            }
            let msg = match reality.apply(current).await {
                Ok(_) => "REALITY: настройки применены".to_string(),
                Err(err) => format!("REALITY: ошибка применения — {err}"),
            };
            redirect_with_message(msg)
        }
        ("POST", "/reality/keygen") => {
            let msg = match reality.regenerate_keys().await {
                Ok(pubkey) => format!(
                    "REALITY: сгенерирован новый ключ. Раздайте клиентам публичный ключ: {pubkey}"
                ),
                Err(err) => format!("REALITY: ошибка генерации ключа — {err}"),
            };
            redirect_with_message(msg)
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

            match parse_platform(&platform_text).and_then(|platform| {
                identity_store.register_device(
                    &user_id,
                    &device_name,
                    platform,
                    &fingerprint,
                    "web_admin",
                )
            }) {
                Ok(reg) => {
                    let code = build_connection_code(
                        &client_server_hint(),
                        &reg.device.device_id,
                        &reg.device_token,
                        &reg.device.device_name,
                        reg.device.platform.as_str(),
                    );
                    redirect_with_message_and_code(
                        "Device registered successfully. Copy this connection code into the Windows client."
                            .to_string(),
                        code,
                    )
                }
                Err(err) => redirect_with_message(format!("Register device error: {}", err)),
            }
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
                    if session_manager.terminate_session(&fid) {
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
        let n = stream.read(&mut tmp).await?;
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

fn public_host_for_clients() -> String {
    let hint = client_server_hint();
    // hint can be "<SERVER_IP>:51820" or "1.2.3.4:51820" or "host:port".
    if let Some((host, _)) = hint.rsplit_once(':') {
        host.trim_matches(|c| c == '[' || c == ']').to_string()
    } else {
        hint
    }
}

fn render_page(
    identity_store: &IdentityStore,
    session_manager: &SessionManager,
    reality: &crate::reality::RealityStatus,
    reality_code: Option<&str>,
    message: Option<String>,
    connection_code: Option<String>,
) -> String {
    let users = identity_store.list_users();
    let sessions = session_manager.snapshot();

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
    out.push_str(".code{margin:8px 0 0;padding:10px;background:#0f172a;color:#e2e8f0;border-radius:8px;white-space:pre-wrap;word-break:break-all;font-size:12px;line-height:1.35}");
    out.push_str(".note{display:block;margin-top:6px;font-size:12px;color:#64748b}");
    out.push_str(".copy-btn{margin-top:8px;padding:6px 10px;font-size:12px;background:#0ea5e9}");
    out.push_str(".copy-status{margin-left:8px;font-size:12px;color:#0f766e}");
    // toggle switch styling (used on the REALITY card)
    out.push_str(".toggle{position:relative;display:inline-block;width:48px;height:26px;vertical-align:middle}");
    out.push_str(".toggle input{opacity:0;width:0;height:0}");
    out.push_str(".toggle .slider{position:absolute;cursor:pointer;top:0;left:0;right:0;bottom:0;background:#cbd5e1;transition:.25s;border-radius:13px}");
    out.push_str(".toggle .slider:before{position:absolute;content:'';height:20px;width:20px;left:3px;bottom:3px;background:#fff;transition:.25s;border-radius:50%;box-shadow:0 1px 3px rgba(0,0,0,.2)}");
    out.push_str(".toggle input:checked + .slider{background:#16a34a}");
    out.push_str(".toggle input:checked + .slider:before{transform:translateX(22px)}");
    out.push_str(".toggle-row{display:flex;align-items:center;gap:10px;margin:8px 0 12px}");
    out.push_str(".toggle-row label.text{cursor:pointer;font-weight:600}");
    out.push_str("</style></head><body>");

    out.push_str("<h1>Omega VPN Admin</h1>");
    out.push_str("<p>Built-in web admin for users, devices and active sessions.</p>");

    if let Some(msg) = message {
        out.push_str("<div class=\"msg\">");
        out.push_str(&escape_html(&msg));
        if let Some(code) = &connection_code {
            out.push_str("<pre class=\"code\">");
            out.push_str(&escape_html(code));
            out.push_str("</pre>");
            out.push_str("<button type=\"button\" class=\"copy-btn\" onclick=\"copyPreviousCode(this)\">Copy connection code</button><span class=\"copy-status\"></span>");
        }
        out.push_str("</div>");
    }

    render_reality_card(&mut out, reality, reality_code);

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
        let devices = identity_store.list_user_devices(&user.user_id);
        out.push_str("<tr><td>");
        out.push_str(&escape_html(&user.user_id));
        out.push_str("</td><td>");
        out.push_str(&format!(
            "status={:?}<br>max_devices={}<br>max_sessions={}",
            user.status, user.max_devices, user.max_concurrent_sessions
        ));
        out.push_str("</td><td>");

        if devices.is_empty() {
            out.push_str("-");
        } else {
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
                if let Some(token) = device.device_token.as_deref() {
                    let code = build_connection_code(
                        &client_server_hint(),
                        &device.device_id,
                        token,
                        &device.device_name,
                        device.platform.as_str(),
                    );
                    out.push_str(
                        "<span class=\"note\">Connection code for the Windows client</span>",
                    );
                    out.push_str("<pre class=\"code\">");
                    out.push_str(&escape_html(&code));
                    out.push_str("</pre>");
                    out.push_str("<button type=\"button\" class=\"copy-btn\" onclick=\"copyPreviousCode(this)\">Copy connection code</button><span class=\"copy-status\"></span>");
                    out.push_str("<span class=\"note\">OMEGA_DEVICE_TOKEN</span>");
                    out.push_str("<pre class=\"code\">OMEGA_DEVICE_TOKEN=");
                    out.push_str(&escape_html(token));
                    out.push_str("</pre>");
                    out.push_str("<button type=\"button\" class=\"copy-btn\" onclick=\"copyPreviousCode(this)\">Copy device token</button><span class=\"copy-status\"></span>");
                } else {
                    out.push_str("<span class=\"note\">This device was registered before token viewing was enabled. Re-register it to make the connection code and OMEGA_DEVICE_TOKEN available here.</span>");
                }
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
    out.push_str("<div class=\"card\"><table><thead><tr><th>Flow ID</th><th>User</th><th>Device</th><th>Tunnel</th><th>Peer</th><th>Idle(s)</th><th>Action</th></tr></thead><tbody>");
    if sessions.is_empty() {
        out.push_str("<tr><td colspan=\"7\">No active sessions</td></tr>");
    } else {
        for sess in sessions {
            out.push_str("<tr>");
            out.push_str(&format!("<td>{}</td>", escape_html(&sess.flow_id)));
            out.push_str(&format!("<td>{}</td>", escape_html(&sess.user_id)));
            out.push_str(&format!("<td>{}</td>", escape_html(&sess.device_id)));
            let tunnel_label = if let Some(tunnel_ipv6) = &sess.tunnel_ipv6 {
                format!("{}<br>{}", sess.tunnel_ip, tunnel_ipv6)
            } else {
                sess.tunnel_ip.clone()
            };
            out.push_str(&format!(
                "<td>{}</td>",
                escape_html(&tunnel_label).replace("&lt;br&gt;", "<br>")
            ));
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
    out.push_str("async function copyPreviousCode(btn){const pre=btn.previousElementSibling;const status=btn.nextElementSibling;if(!pre)return;const text=pre.innerText;try{if(navigator.clipboard&&window.isSecureContext){await navigator.clipboard.writeText(text);}else{const ta=document.createElement('textarea');ta.value=text;document.body.appendChild(ta);ta.select();document.execCommand('copy');ta.remove();}if(status){status.textContent='Copied';setTimeout(()=>status.textContent='',1500);}}catch(e){if(status){status.textContent='Copy failed';setTimeout(()=>status.textContent='',2000);}}}");
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

fn render_reality_card(
    out: &mut String,
    status: &crate::reality::RealityStatus,
    reality_code: Option<&str>,
) {
    let s: &RealityStored = &status.stored;
    out.push_str("<div class=\"card\" style=\"margin-bottom:16px\">");
    out.push_str("<h2>REALITY — обход белых списков (TLS-маскировка)</h2>");
    out.push_str("<p style=\"color:#475569;margin-top:0\">");
    out.push_str("Включите, если в стране/сети работают только TLS-соединения к доверенным сайтам. ");
    out.push_str("Сервер будет выглядеть как обычный <code>SNI</code>-сайт (например <code>gosuslugi.ru</code>), внутри идёт ваш VPN.");
    out.push_str("</p>");

    // Status badge
    let badge_color = if status.running { "#16a34a" } else { "#64748b" };
    let badge_text = if status.running { "Работает" } else { "Выключено" };
    out.push_str(&format!(
        "<p><b>Статус:</b> <span style=\"background:{};color:#fff;padding:2px 10px;border-radius:10px;font-size:12px\">{}</span>",
        badge_color, badge_text
    ));
    if let Some(uptime) = status.uptime_seconds {
        out.push_str(&format!(" <span style=\"color:#475569\">uptime: {} сек</span>", uptime));
    }
    out.push_str("</p>");

    // Готовый REALITY-код для клиентов (одна строка, paste в клиент).
    if let Some(code) = reality_code {
        out.push_str("<div style=\"background:#ecfdf5;border:1px solid #34d399;border-radius:8px;padding:10px;margin-bottom:12px\">");
        out.push_str("<b>REALITY-код для клиентов:</b><br>");
        out.push_str("<pre class=\"code reality-code\" style=\"background:#fff;padding:8px;border-radius:4px;font-size:13px;word-break:break-all;white-space:pre-wrap;margin:6px 0\">");
        out.push_str(&escape_html(code));
        out.push_str("</pre>");
        out.push_str("<button type=\"button\" class=\"copy-btn\" onclick=\"copyPreviousCode(this)\">Скопировать REALITY-код</button><span class=\"copy-status\"></span>");
        out.push_str("<br><small style=\"color:#475569\">Передайте эту единственную строку клиенту. На Windows/Android достаточно вставить её в поле «REALITY-код» и включить переключатель «Обход». Все остальные параметры зашиты внутри кода.</small>");
        out.push_str("</div>");
    } else if !status.key_file_exists {
        out.push_str("<div style=\"background:#fef3c7;border:1px solid #fbbf24;padding:10px;border-radius:8px;margin-bottom:12px\">");
        out.push_str("Ключевая пара REALITY ещё не сгенерирована. Нажмите «Сгенерировать ключ» ниже, затем включите REALITY и нажмите «Применить» — здесь появится готовый REALITY-код для клиентов.");
        out.push_str("</div>");
    } else if let Some(pubkey) = &status.public_key_b64 {
        out.push_str("<div style=\"background:#fef3c7;border:1px solid #fbbf24;padding:10px;border-radius:8px;margin-bottom:12px\">");
        out.push_str("REALITY выключен — включите ниже, чтобы получить готовый REALITY-код для клиентов.<br>");
        out.push_str("<small style=\"color:#475569\">Публичный ключ уже создан: <code>");
        out.push_str(&escape_html(pubkey));
        out.push_str("</code></small>");
        out.push_str("</div>");
    }

    // Apply form
    out.push_str("<form method=\"post\" action=\"/reality/apply\">");
    out.push_str("<div class=\"toggle-row\">");
    out.push_str("<label class=\"toggle\" for=\"reality-enabled\"><input type=\"checkbox\" id=\"reality-enabled\" name=\"enabled\" value=\"1\"");
    if s.enabled {
        out.push_str(" checked");
    }
    out.push_str("><span class=\"slider\"></span></label>");
    out.push_str("<label class=\"text\" for=\"reality-enabled\">Включить REALITY-обход</label>");
    out.push_str("</div>");

    out.push_str("<label>Слушать на адресе (host:port)</label>");
    out.push_str(&format!("<input name=\"bind\" value=\"{}\">", escape_html(&s.bind)));

    out.push_str("<label>Маскировка под сайт (host:port)</label>");
    let dest = format!("{}:{}", s.dest_host, s.dest_port);
    out.push_str(&format!(
        "<input name=\"dest\" value=\"{}\" placeholder=\"gosuslugi.ru:443\">",
        escape_html(&dest)
    ));

    out.push_str("<label>Разрешённые SNI (через запятую)</label>");
    let names = s.server_names.join(",");
    out.push_str(&format!(
        "<input name=\"server_names\" value=\"{}\" placeholder=\"gosuslugi.ru,www.gosuslugi.ru\">",
        escape_html(&names)
    ));

    out.push_str("<label>Short IDs (опционально, 16 hex через запятую — пусто = wildcard)</label>");
    let short = s.short_ids_hex.join(",");
    out.push_str(&format!(
        "<input name=\"short_ids\" value=\"{}\">",
        escape_html(&short)
    ));

    out.push_str("<label>uTLS-профиль (fingerprint)</label>");
    out.push_str("<select name=\"fingerprint\">");
    for opt in &["chrome_131", "chrome_120_no_ech"] {
        out.push_str(&format!(
            "<option value=\"{}\"{}>{}</option>",
            opt,
            if s.fingerprint_profile == *opt { " selected" } else { "" },
            opt
        ));
    }
    out.push_str("</select>");

    out.push_str("<button type=\"submit\">Применить</button>");
    out.push_str("</form>");

    // Keygen button
    out.push_str("<form method=\"post\" action=\"/reality/keygen\" style=\"margin-top:10px\" ");
    out.push_str("onsubmit=\"return confirm('Сгенерировать новый ключ? Старые клиенты перестанут подключаться, пока вы не раздадите им новый публичный ключ.');\">");
    out.push_str("<button type=\"submit\" style=\"background:#0ea5e9;color:#fff;border:none;padding:8px 14px;border-radius:6px;cursor:pointer\">Сгенерировать новый ключ</button>");
    out.push_str("</form>");

    // Cert snapshots
    if !status.cert_snapshots.is_empty() {
        out.push_str("<details style=\"margin-top:10px\"><summary>Кэшированные сертификаты (");
        out.push_str(&status.cert_snapshots.len().to_string());
        out.push_str(")</summary><ul style=\"font-size:13px;color:#475569\">");
        for snap in &status.cert_snapshots {
            out.push_str(&format!(
                "<li><b>{}</b> — sha256: {}…</li>",
                escape_html(&snap.sni),
                escape_html(&snap.leaf_sha256_hex.chars().take(16).collect::<String>())
            ));
        }
        out.push_str("</ul></details>");
    }

    out.push_str("</div>");
}

fn parse_host_port(raw: &str) -> Option<(String, u16)> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    let (host, port) = match raw.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse::<u16>().ok()?),
        None => (raw.to_string(), 443),
    };
    if host.is_empty() {
        return None;
    }
    Some((host.to_ascii_lowercase(), port))
}

fn redirect_with_message(message: String) -> Vec<u8> {
    let location = format!("/?msg={}", url_encode(&message));
    redirect_response(&location)
}

fn redirect_with_message_and_code(message: String, code: String) -> Vec<u8> {
    let location = format!("/?msg={}&code={}", url_encode(&message), url_encode(&code));
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

pub(crate) fn client_server_hint() -> String {
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

pub(crate) fn build_connection_code(
    server: &str,
    device_id: &str,
    token: &str,
    device_name: &str,
    platform: &str,
) -> String {
    let payload = serde_json::json!({
        "profile_name": device_name,
        "server": server,
        "device_id": device_id,
        "token": token,
        "device_name": device_name,
        "platform": platform,
        "transport": "auto",
        "tunnel_mode": "full",
        "dns_policy": "tunnel",
        "ipv6_policy": "tunnel",
    });
    let json = serde_json::to_string(&payload).unwrap_or_else(|_| "{}".to_string());
    format!("omega://connect/{}", base64_url_encode(json.as_bytes()))
}

fn base64_url_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(((bytes.len() + 2) / 3) * 4);
    let mut chunks = bytes.chunks_exact(3);

    for chunk in &mut chunks {
        let n = ((chunk[0] as u32) << 16) | ((chunk[1] as u32) << 8) | chunk[2] as u32;
        out.push(TABLE[((n >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 12) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 6) & 0x3f) as usize] as char);
        out.push(TABLE[(n & 0x3f) as usize] as char);
    }

    match chunks.remainder() {
        [a] => {
            let n = (*a as u32) << 16;
            out.push(TABLE[((n >> 18) & 0x3f) as usize] as char);
            out.push(TABLE[((n >> 12) & 0x3f) as usize] as char);
        }
        [a, b] => {
            let n = ((*a as u32) << 16) | ((*b as u32) << 8);
            out.push(TABLE[((n >> 18) & 0x3f) as usize] as char);
            out.push(TABLE[((n >> 12) & 0x3f) as usize] as char);
            out.push(TABLE[((n >> 6) & 0x3f) as usize] as char);
        }
        _ => {}
    }

    out
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

fn json_response(status: u16, reason: &str, body: &str) -> Vec<u8> {
    let header = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        status,
        reason,
        body.len()
    );
    let mut out = Vec::with_capacity(header.len() + body.len());
    out.extend_from_slice(header.as_bytes());
    out.extend_from_slice(body.as_bytes());
    out
}

#[cfg(test)]
mod tests {
    use std::fs;

    use crate::identity::{ensure_identity_file, now_ts, IdentityStore};
    use crate::session::SessionManager;

    use super::{build_connection_code, render_page};

    #[test]
    fn connection_code_contains_new_windows_client_payload() {
        let code = build_connection_code(
            "203.0.113.1:443",
            "11111111-2222-3333-4444-555555555555",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "home-pc",
            "windows",
        );

        assert!(code.starts_with("omega://connect/"));

        let payload = code.trim_start_matches("omega://connect/");
        let json = String::from_utf8(base64_url_decode(payload)).expect("payload utf8");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("payload json");

        assert_eq!(parsed["server"], "203.0.113.1:443");
        assert_eq!(parsed["device_id"], "11111111-2222-3333-4444-555555555555");
        assert_eq!(
            parsed["token"],
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );
        assert_eq!(parsed["device_name"], "home-pc");
        assert_eq!(parsed["transport"], "auto");
        assert_eq!(parsed["ipv6_policy"], "tunnel");
    }

    #[test]
    fn admin_page_shows_saved_connection_code_and_device_token() {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "omega_admin_token_test_{}_{}.json",
            std::process::id(),
            now_ts()
        ));
        ensure_identity_file(&path).expect("init identity file");

        let store = IdentityStore::load(path.clone()).expect("load store");
        let user = store.create_user(5, 3, "test").expect("create user");
        let registered = store
            .register_device(
                &user.user_id,
                "office-pc",
                crate::identity::devices::Platform::Windows,
                "fp-1",
                "test",
            )
            .expect("register device");
        let sessions = SessionManager::new(true);
        let reality = crate::reality::RealityStatus {
            running: false,
            stored: crate::reality::config_store::StoredConfig::default(),
            public_key_b64: None,
            bind: None,
            primary_sni: None,
            uptime_seconds: None,
            cert_snapshots: Vec::new(),
            key_file_exists: false,
        };

        let html = render_page(&store, &sessions, &reality, None, None, None);

        assert!(html.contains("omega://connect/"));
        assert!(html.contains("OMEGA_DEVICE_TOKEN="));
        assert!(html.contains(&registered.device_token));
        assert!(
            !html.contains("shown only once"),
            "admin should not tell operators the code is single-use visibility anymore"
        );

        let _ = fs::remove_file(path);
    }

    fn base64_url_decode(input: &str) -> Vec<u8> {
        let mut value = input.replace('-', "+").replace('_', "/");
        match value.len() % 4 {
            2 => value.push_str("=="),
            3 => value.push('='),
            _ => {}
        }

        decode_base64(&value)
    }

    fn decode_base64(input: &str) -> Vec<u8> {
        let mut out = Vec::new();
        let mut buffer = 0u32;
        let mut bits = 0u8;

        for byte in input.bytes() {
            if byte == b'=' {
                break;
            }

            let value = match byte {
                b'A'..=b'Z' => byte - b'A',
                b'a'..=b'z' => byte - b'a' + 26,
                b'0'..=b'9' => byte - b'0' + 52,
                b'+' => 62,
                b'/' => 63,
                _ => continue,
            } as u32;

            buffer = (buffer << 6) | value;
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push(((buffer >> bits) & 0xff) as u8);
            }
        }

        out
    }
}
