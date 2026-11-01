use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{bail, Context};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::{rngs::OsRng, RngCore};
use ring::{digest, pbkdf2};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use super::{
    escape_html, html_response, json_response, parse_form, redirect_response, text_response,
    HttpRequest,
};

const ITERATIONS: u32 = 600_000;
const SESSION_TTL: Duration = Duration::from_secs(8 * 60 * 60);
const LOGIN_WINDOW: Duration = Duration::from_secs(5 * 60);

#[derive(Clone, Serialize, Deserialize)]
struct Credentials {
    username: String,
    salt: String,
    password_hash: String,
    iterations: u32,
}

#[derive(Clone)]
pub(super) struct Session {
    pub csrf: String,
    expires: Instant,
}

struct State {
    credentials: Credentials,
    sessions: HashMap<String, Session>,
    attempts: HashMap<IpAddr, (Instant, u32)>,
    attempt_budget: (Instant, u32),
}

pub(super) struct Auth {
    path: PathBuf,
    secure: bool,
    state: Mutex<State>,
}

pub(super) enum Access {
    Reply(Vec<u8>),
    Granted(Session),
}

pub(crate) fn credentials_path() -> PathBuf {
    std::env::var_os("OMEGA_ADMIN_AUTH_DB")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            crate::identity::IdentityStore::default_path()
                .parent()
                .unwrap_or(Path::new("state"))
                .join("admin-auth.json")
        })
}

pub(crate) fn initialize(path: &Path, reset: bool) -> anyhow::Result<serde_json::Value> {
    if path.exists() && !reset {
        let existing = read_credentials(path)?;
        return Ok(serde_json::json!({"created": false, "login": existing.username}));
    }
    let username = format!("admin_{}", &random_token()[..10]);
    let password = random_token();
    let credentials = make_credentials(&username, &password);
    save_credentials(path, &credentials)?;
    if reset {
        let _ = fs::remove_file(path.with_file_name("admin-bootstrap.json"));
    }
    Ok(serde_json::json!({"created": true, "login": username, "password": password}))
}

fn random_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn token_hash(token: &str) -> String {
    URL_SAFE_NO_PAD.encode(digest::digest(&digest::SHA256, token.as_bytes()))
}

fn make_credentials(username: &str, password: &str) -> Credentials {
    let mut salt = [0u8; 32];
    OsRng.fill_bytes(&mut salt);
    let mut hash = [0u8; 32];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        NonZeroU32::new(ITERATIONS).unwrap(),
        &salt,
        password.as_bytes(),
        &mut hash,
    );
    Credentials {
        username: username.into(),
        salt: URL_SAFE_NO_PAD.encode(salt),
        password_hash: URL_SAFE_NO_PAD.encode(hash),
        iterations: ITERATIONS,
    }
}

fn verify_password(credentials: &Credentials, password: &str) -> bool {
    let Ok(salt) = URL_SAFE_NO_PAD.decode(&credentials.salt) else {
        return false;
    };
    let Ok(hash) = URL_SAFE_NO_PAD.decode(&credentials.password_hash) else {
        return false;
    };
    let Some(iterations) = NonZeroU32::new(credentials.iterations) else {
        return false;
    };
    pbkdf2::verify(
        pbkdf2::PBKDF2_HMAC_SHA256,
        iterations,
        &salt,
        password.as_bytes(),
        &hash,
    )
    .is_ok()
}

fn read_credentials(path: &Path) -> anyhow::Result<Credentials> {
    let credentials: Credentials = serde_json::from_slice(
        &fs::read(path)
            .context("Initialize admin credentials with: omega-server admin init_web")?,
    )?;
    if !(ITERATIONS..=2_000_000).contains(&credentials.iterations)
        || URL_SAFE_NO_PAD.decode(&credentials.salt)?.len() != 32
        || URL_SAFE_NO_PAD.decode(&credentials.password_hash)?.len() != 32
    {
        bail!("Invalid admin credential file");
    }
    Ok(credentials)
}

fn save_credentials(path: &Path, credentials: &Credentials) -> anyhow::Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    serde_json::to_writer_pretty(&mut file, credentials)?;
    file.flush()?;
    file.as_file().sync_all()?;
    file.persist(path).map_err(|e| e.error)?;
    Ok(())
}

pub(super) fn header(response: &mut Vec<u8>, name: &str, value: &str) {
    if let Some(end) = super::find_header_end(response) {
        response.splice(end..end, format!("\r\n{name}: {value}").bytes());
    }
}

pub(super) fn secure_response(mut response: Vec<u8>) -> Vec<u8> {
    for (name, value) in [
        ("Cache-Control", "no-store"), ("Referrer-Policy", "no-referrer"),
        ("X-Content-Type-Options", "nosniff"), ("X-Frame-Options", "DENY"),
        ("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"),
    ] { header(&mut response, name, value); }
    response
}

fn cookie<'a>(request: &'a HttpRequest, name: &str) -> Option<&'a str> {
    request.headers.get("cookie")?.split(';').find_map(|part| {
        let (key, value) = part.trim().split_once('=')?;
        (key == name).then_some(value)
    })
}

fn same_token(a: &str, b: &str) -> bool {
    a.len() == 43 && bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}

impl Auth {
    pub fn load(path: PathBuf, secure: bool) -> anyhow::Result<Self> {
        let credentials = read_credentials(&path)?;
        Ok(Self {
            path,
            secure,
            state: Mutex::new(State {
                credentials,
                sessions: HashMap::new(),
                attempts: HashMap::new(),
                attempt_budget: (Instant::now(), 0),
            }),
        })
    }

    pub fn username(&self) -> String {
        self.state.lock().unwrap().credentials.username.clone()
    }
    fn session_cookie(&self) -> &'static str {
        if self.secure {
            "__Host-omega_session"
        } else {
            "omega_session"
        }
    }
    fn login_cookie(&self) -> &'static str {
        if self.secure {
            "__Host-omega_login"
        } else {
            "omega_login"
        }
    }

    fn set_cookie(&self, response: &mut Vec<u8>, name: &str, value: &str, max_age: u64) {
        header(
            response,
            "Set-Cookie",
            &format!(
                "{name}={value}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}{}",
                if self.secure { "; Secure" } else { "" }
            ),
        );
    }

    fn session(&self, request: &HttpRequest) -> Option<Session> {
        let token = cookie(request, self.session_cookie())?;
        let mut state = self.state.lock().unwrap();
        state
            .sessions
            .retain(|_, session| session.expires > Instant::now());
        state.sessions.get(&token_hash(token)).cloned()
    }

    fn allow_attempt(&self, peer: IpAddr) -> bool {
        let mut state = self.state.lock().unwrap();
        state
            .attempts
            .retain(|_, (start, _)| start.elapsed() < LOGIN_WINDOW);
        if state.attempt_budget.0.elapsed() >= LOGIN_WINDOW {
            state.attempt_budget = (Instant::now(), 0);
        }
        if state.attempt_budget.1 >= 50 {
            return false;
        }
        if state.attempts.len() >= 1024 && !state.attempts.contains_key(&peer) {
            return false;
        }
        let (_, count) = state.attempts.entry(peer).or_insert((Instant::now(), 0));
        if *count >= 5 {
            return false;
        }
        *count += 1;
        state.attempt_budget.1 += 1;
        true
    }

    fn login(&self, username: &str, password: &str) -> Option<String> {
        if password.len() > 256 || username.len() > 64 {
            return None;
        }
        let credentials = self.state.lock().unwrap().credentials.clone();
        let valid_password = verify_password(&credentials, password);
        let mut state = self.state.lock().unwrap();
        if !valid_password
            || credentials.username != username
            || state.credentials.password_hash != credentials.password_hash
        {
            return None;
        }
        state
            .sessions
            .retain(|_, session| session.expires > Instant::now());
        if state.sessions.len() >= 128 {
            if let Some(oldest) = state
                .sessions
                .iter()
                .min_by_key(|(_, s)| s.expires)
                .map(|(key, _)| key.clone())
            {
                state.sessions.remove(&oldest);
            }
        }
        let token = random_token();
        state.sessions.insert(
            token_hash(&token),
            Session {
                csrf: random_token(),
                expires: Instant::now() + SESSION_TTL,
            },
        );
        Some(token)
    }

    fn change_credentials(
        &self,
        session_key: &str,
        current: &str,
        username: &str,
        password: &str,
        confirm: &str,
    ) -> anyhow::Result<()> {
        if username.is_empty()
            || username.len() > 64
            || !username
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.@-".contains(&b))
        {
            bail!("Логин: 1–64 символа, буквы, цифры, _, -, . или @.");
        }
        if current.len() > 256
            || password != confirm
            || (!password.is_empty() && !(12..=256).contains(&password.len()))
        {
            bail!("Новый пароль должен содержать от 12 до 256 байт и совпадать с подтверждением.");
        }
        let existing = self.state.lock().unwrap().credentials.clone();
        if !verify_password(&existing, current) {
            bail!("Текущий пароль неверен.");
        }
        let updated = make_credentials(
            username,
            if password.is_empty() {
                current
            } else {
                password
            },
        );
        let mut state = self.state.lock().unwrap();
        if !state
            .sessions
            .get(session_key)
            .is_some_and(|s| s.expires > Instant::now())
            || state.credentials.password_hash != existing.password_hash
        {
            bail!("Сессия завершена. Войдите снова.");
        }
        save_credentials(&self.path, &updated)?;
        let _ = fs::remove_file(self.path.with_file_name("admin-bootstrap.json"));
        state.credentials = updated;
        state.sessions.clear();
        Ok(())
    }

    pub async fn access(
        self: &Arc<Self>,
        request: &HttpRequest,
        peer: IpAddr,
    ) -> anyhow::Result<Access> {
        let session = self.session(request);
        let form = parse_form(&request.body);
        let value = |key: &str| form.get(key).cloned().unwrap_or_default();
        if request.path == "/favicon.ico" && request.method == "GET" {
            return Ok(Access::Reply(text_response(204, "No Content", "")));
        }
        if request.path == "/login" && request.method == "GET" {
            if session.is_some() {
                return Ok(Access::Reply(redirect_response("/")));
            }
            let token = login_nonce(cookie(request, self.login_cookie()));
            let message = if request.query.contains_key("updated") {
                "Данные входа изменены. Войдите снова."
            } else if request.query.contains_key("error") {
                "Неверный логин или пароль."
            } else {
                ""
            };
            let mut response = html_response(200, "OK", login_page(&token, message));
            self.set_cookie(&mut response, self.login_cookie(), &token, 600);
            return Ok(Access::Reply(response));
        }
        if request.path == "/login" && request.method == "POST" {
            if !same_token(
                cookie(request, self.login_cookie()).unwrap_or(""),
                &value("csrf"),
            ) {
                let token = login_nonce(cookie(request, self.login_cookie()));
                let mut response = html_response(
                    403,
                    "Forbidden",
                    login_page(
                        &token,
                        "Страница входа обновлена. Введите логин и пароль ещё раз.",
                    ),
                );
                self.set_cookie(&mut response, self.login_cookie(), &token, 600);
                return Ok(Access::Reply(response));
            }
            if !self.allow_attempt(peer) {
                let mut response = text_response(
                    429,
                    "Too Many Requests",
                    "Слишком много попыток. Повторите вход через 5 минут.",
                );
                header(&mut response, "Retry-After", "300");
                return Ok(Access::Reply(response));
            }
            let auth = self.clone();
            let username = value("username");
            let password = value("password");
            let token =
                tokio::task::spawn_blocking(move || auth.login(&username, &password)).await?;
            let mut response = redirect_response(if token.is_some() {
                "/"
            } else {
                "/login?error=1"
            });
            if let Some(token) = token {
                self.state.lock().unwrap().attempts.remove(&peer);
                self.set_cookie(
                    &mut response,
                    self.session_cookie(),
                    &token,
                    SESSION_TTL.as_secs(),
                );
                self.set_cookie(&mut response, self.login_cookie(), "", 0);
            }
            return Ok(Access::Reply(response));
        }
        let Some(session) = session else {
            return Ok(Access::Reply(if request.path.starts_with("/api/") {
                json_response(
                    401,
                    "Unauthorized",
                    "{\"error\":\"authentication_required\"}",
                )
            } else {
                redirect_response("/login")
            }));
        };
        if request.method == "POST" && !same_token(&session.csrf, &value("csrf")) {
            return Ok(Access::Reply(text_response(
                403,
                "Forbidden",
                "CSRF verification failed",
            )));
        }
        if request.path == "/auth/logout" && request.method == "POST" {
            if let Some(token) = cookie(request, self.session_cookie()) {
                self.state
                    .lock()
                    .unwrap()
                    .sessions
                    .remove(&token_hash(token));
            }
            let mut response = redirect_response("/login");
            self.set_cookie(&mut response, self.session_cookie(), "", 0);
            return Ok(Access::Reply(response));
        }
        if request.path == "/auth/credentials" && request.method == "POST" {
            let auth = self.clone();
            let key = token_hash(cookie(request, self.session_cookie()).unwrap_or(""));
            let (current, username, password, confirm) = (
                value("current_password"),
                value("username"),
                value("password"),
                value("confirm_password"),
            );
            let result = tokio::task::spawn_blocking(move || {
                auth.change_credentials(&key, &current, &username, &password, &confirm)
            })
            .await?;
            let mut response = match result {
                Ok(()) => redirect_response("/login?updated=1"),
                Err(error) => html_response(400, "Bad Request", format!("<html lang=\"ru\"><meta charset=\"utf-8\"><p>{}</p><a href=\"/\">Вернуться</a></html>", escape_html(&error.to_string()))),
            };
            if response.starts_with(b"HTTP/1.1 303") {
                self.set_cookie(&mut response, self.session_cookie(), "", 0);
            }
            return Ok(Access::Reply(response));
        }
        Ok(Access::Granted(session))
    }
}

fn login_nonce(existing: Option<&str>) -> String {
    existing
        .filter(|token| {
            token.len() == 43
                && URL_SAFE_NO_PAD
                    .decode(token)
                    .is_ok_and(|bytes| bytes.len() == 32)
        })
        .map(str::to_owned)
        .unwrap_or_else(random_token)
}

fn login_page(csrf: &str, message: &str) -> String {
    format!(
        r#"<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Вход — Omega VPN</title><style>body{{font:16px system-ui;background:#f1f5f9;margin:0;padding:24px}}main{{max-width:360px;margin:10vh auto;background:white;padding:32px;border-radius:16px}}label{{display:block;margin:16px 0 6px}}input,button{{box-sizing:border-box;width:100%;padding:12px;font:inherit}}button{{margin-top:24px;background:#2563eb;color:white;border:0;border-radius:8px}}p{{color:#475569}}</style></head><body><main><h1>Omega VPN</h1><p>Вход в панель управления</p><p>{}</p><form method="post" action="/login"><input type="hidden" name="csrf" value="{}"><label for="username">Логин</label><input id="username" name="username" autocomplete="username" maxlength="64" required autofocus><label for="password">Пароль</label><input id="password" name="password" type="password" autocomplete="current-password" maxlength="256" required><button>Войти</button></form></main></body></html>"#,
        escape_html(message),
        escape_html(csrf)
    )
}

pub(super) fn protect_forms(html: String, csrf: &str, username: &str) -> String {
    let account = format!(
        r#"<section class="card"><h2>Доступ к админке</h2><p>Вы вошли как <strong>{}</strong></p><form method="post" action="/auth/logout"><button>Выйти</button></form><details><summary>Изменить логин или пароль</summary><form method="post" action="/auth/credentials"><label>Текущий пароль</label><input type="password" name="current_password" autocomplete="current-password" maxlength="256" required><label>Логин</label><input name="username" value="{}" autocomplete="username" maxlength="64" required><label>Новый пароль (оставьте пустым, чтобы сохранить текущий)</label><input type="password" name="password" autocomplete="new-password" minlength="12" maxlength="256"><label>Повторите новый пароль</label><input type="password" name="confirm_password" autocomplete="new-password" maxlength="256"><button>Сохранить и завершить все сессии</button></form></details></section>"#,
        escape_html(username),
        escape_html(username)
    );
    let html = html.replacen("<body>", &format!("<body>{account}"), 1);
    let mut output = String::with_capacity(html.len() + 2048);
    let mut remaining = html.as_str();
    while let Some(start) = remaining.find("<form ") {
        let Some(end) = remaining[start..].find('>').map(|end| start + end + 1) else {
            break;
        };
        output.push_str(&remaining[..end]);
        output.push_str(&format!(
            "<input type=\"hidden\" name=\"csrf\" value=\"{}\">",
            escape_html(csrf)
        ));
        remaining = &remaining[end..];
    }
    output.push_str(remaining);
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (tempfile::TempDir, Arc<Auth>, String, String) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("admin-auth.json");
        let output = initialize(&path, false).unwrap();
        let auth = Arc::new(Auth::load(path, true).unwrap());
        (
            directory,
            auth,
            output["login"].as_str().unwrap().into(),
            output["password"].as_str().unwrap().into(),
        )
    }

    fn request(method: &str, path: &str, body: &str, cookies: &str) -> HttpRequest {
        HttpRequest {
            method: method.into(),
            path: path.into(),
            body: body.into(),
            query: HashMap::new(),
            headers: HashMap::from([("cookie".into(), cookies.into())]),
        }
    }

    async fn reply(auth: &Arc<Auth>, request: HttpRequest) -> String {
        match auth
            .access(&request, "127.0.0.1".parse().unwrap())
            .await
            .unwrap()
        {
            Access::Reply(bytes) => String::from_utf8(bytes).unwrap(),
            Access::Granted(_) => panic!("unexpected authorization"),
        }
    }

    #[test]
    fn passwords_are_salted_and_initialization_preserves_changed_credentials() {
        let (directory, auth, username, password) = fixture();
        let path = directory.path().join("admin-auth.json");
        let text = fs::read_to_string(&path).unwrap();
        assert!(!text.contains(&password));
        assert!(verify_password(
            &read_credentials(&path).unwrap(),
            &password
        ));
        assert!(!verify_password(
            &read_credentials(&path).unwrap(),
            "incorrect"
        ));
        let output = initialize(&path, false).unwrap();
        assert_eq!(output["created"], false);
        assert_eq!(output["login"], username);
        assert!(output.get("password").is_none());
        assert_eq!(fs::read_to_string(&path).unwrap(), text);
        assert!(auth.login(&username, "incorrect").is_none());
    }

    #[tokio::test]
    async fn all_admin_routes_require_authentication() {
        let (_dir, auth, _, _) = fixture();
        for path in [
            "/",
            "/users/create",
            "/users/delete",
            "/devices/register",
            "/sessions/terminate",
            "/reality/apply",
            "/auth/credentials",
        ] {
            let response = reply(&auth, request("POST", path, "", "")).await;
            assert!(response.contains("Location: /login"), "{path}");
        }
        assert!(reply(&auth, request("GET", "/api/reality/status", "", ""))
            .await
            .starts_with("HTTP/1.1 401"));
    }

    #[tokio::test]
    async fn login_requires_nonce_and_sets_secure_session_cookie() {
        let (_dir, auth, username, password) = fixture();
        assert!(reply(&auth, request("POST", "/login", "", ""))
            .await
            .starts_with("HTTP/1.1 403"));
        let page = reply(&auth, request("GET", "/login", "", "")).await;
        let nonce = page
            .split("__Host-omega_login=")
            .nth(1)
            .unwrap()
            .split(';')
            .next()
            .unwrap();
        let body = format!("csrf={nonce}&username={username}&password={password}");
        let response = reply(
            &auth,
            request(
                "POST",
                "/login",
                &body,
                &format!("__Host-omega_login={nonce}"),
            ),
        )
        .await;
        assert!(response.contains("Location: /\r\n"));
        assert!(response.contains("HttpOnly; SameSite=Strict; Max-Age=28800; Secure"));
        let token = response
            .split("__Host-omega_session=")
            .nth(1)
            .unwrap()
            .split(';')
            .next()
            .unwrap();
        assert!(auth
            .session(&request(
                "GET",
                "/",
                "",
                &format!("__Host-omega_session={token}")
            ))
            .is_some());
    }

    #[tokio::test]
    async fn favicon_and_second_tab_do_not_invalidate_login_form() {
        let (_dir, auth, username, password) = fixture();
        let page = reply(&auth, request("GET", "/login", "", "")).await;
        let nonce = page
            .split("__Host-omega_login=")
            .nth(1)
            .unwrap()
            .split(';')
            .next()
            .unwrap();
        let cookies = format!("__Host-omega_login={nonce}");
        let icon = reply(&auth, request("GET", "/favicon.ico", "", &cookies)).await;
        assert!(icon.starts_with("HTTP/1.1 204"));
        assert!(!icon.contains("Set-Cookie:"));
        let second_tab = reply(&auth, request("GET", "/login", "", &cookies)).await;
        assert!(second_tab.contains(&format!("name=\"csrf\" value=\"{nonce}\"")));
        let response = reply(
            &auth,
            request(
                "POST",
                "/login",
                &format!("csrf={nonce}&username={username}&password={password}"),
                &cookies,
            ),
        )
        .await;
        assert!(response.contains("Location: /\r\n"));
        assert!(response.contains("__Host-omega_session="));
        let expired = reply(&auth, request("POST", "/login", "csrf=expired", "")).await;
        assert!(expired.starts_with("HTTP/1.1 403"));
        assert!(expired.contains("<form method=\"post\" action=\"/login\">"));
        assert!(expired.contains("Set-Cookie: __Host-omega_login="));
    }

    #[tokio::test]
    async fn csrf_logout_expiry_and_credential_rotation_are_enforced() {
        let (_dir, auth, username, password) = fixture();
        let token = auth.login(&username, &password).unwrap();
        let cookies = format!("__Host-omega_session={token}");
        assert!(auth.session(&request("GET", "/", "", &cookies)).is_some());
        assert!(reply(
            &auth,
            request("POST", "/users/create", "csrf=invalid", &cookies)
        )
        .await
        .starts_with("HTTP/1.1 403"));
        assert!(auth
            .change_credentials(
                &token_hash(&token),
                "wrong",
                "owner",
                "long-enough-new-password",
                "long-enough-new-password"
            )
            .is_err());
        auth.change_credentials(
            &token_hash(&token),
            &password,
            "owner",
            "long-enough-new-password",
            "long-enough-new-password",
        )
        .unwrap();
        assert!(auth.session(&request("GET", "/", "", &cookies)).is_none());
        assert!(auth.login(&username, &password).is_none());
        let token = auth.login("owner", "long-enough-new-password").unwrap();
        let cookies = format!("__Host-omega_session={token}");
        let session = auth.session(&request("GET", "/", "", &cookies)).unwrap();
        let response = reply(
            &auth,
            request(
                "POST",
                "/auth/logout",
                &format!("csrf={}", session.csrf),
                &cookies,
            ),
        )
        .await;
        assert!(response.contains("Max-Age=0; Secure"));
        assert!(auth.session(&request("GET", "/", "", &cookies)).is_none());
        let token = auth.login("owner", "long-enough-new-password").unwrap();
        auth.state
            .lock()
            .unwrap()
            .sessions
            .get_mut(&token_hash(&token))
            .unwrap()
            .expires = Instant::now() - Duration::from_secs(1);
        assert!(auth
            .session(&request(
                "GET",
                "/",
                "",
                &format!("__Host-omega_session={token}")
            ))
            .is_none());
        assert_eq!(
            Auth::load(auth.path.clone(), true).unwrap().username(),
            "owner"
        );
        assert!(!initialize(&auth.path, false).unwrap()["created"]
            .as_bool()
            .unwrap());
    }

    #[test]
    fn rate_limits_and_form_tokens_cover_all_actions() {
        let (_dir, auth, _, _) = fixture();
        let ip = "192.0.2.1".parse().unwrap();
        for _ in 0..5 {
            assert!(auth.allow_attempt(ip));
        }
        assert!(!auth.allow_attempt(ip));
        let html = protect_forms("<html><body><form method=\"post\" action=\"/users/create\"><button>Create</button></form></body></html>".into(), "test-token", "owner");
        assert_eq!(
            html.matches("<form ").count(),
            html.matches("name=\"csrf\"").count()
        );
        assert!(html.contains("/auth/credentials"));
    }
}
