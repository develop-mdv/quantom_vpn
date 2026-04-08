use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use anyhow::Context;
use serde::{Deserialize, Serialize};

use crate::config::ConnectionProfile;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientLifecycleState {
    Starting,
    Handshaking,
    Connected,
    Degraded,
    Closing,
    Stopped,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientFailureScope {
    Config,
    Credentials,
    Handshake,
    Routing,
    Transport,
    Shutdown,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientLifecycleSnapshot {
    pub state: ClientLifecycleState,
    pub started_at_ms: u64,
    pub updated_at_ms: u64,
    pub pid: u32,
    pub server_endpoint: String,
    pub device_name: String,
    pub profile: ConnectionProfile,
    pub background_mode: bool,
    pub message: String,
    pub last_error: Option<String>,
    pub failure_scope: Option<ClientFailureScope>,
    pub suggested_action: Option<String>,
    pub handshake_rtt_ms: Option<u64>,
    pub tunnel_ip: Option<String>,
    pub reconnect_recommended: bool,
}

#[derive(Clone)]
pub struct ClientLifecycle {
    path: PathBuf,
    snapshot: Arc<Mutex<ClientLifecycleSnapshot>>,
}

impl ClientLifecycle {
    pub fn new(
        path: PathBuf,
        profile: ConnectionProfile,
        server_endpoint: impl Into<String>,
        device_name: impl Into<String>,
        background_mode: bool,
    ) -> Self {
        let now = now_ms();
        let snapshot = ClientLifecycleSnapshot {
            state: ClientLifecycleState::Starting,
            started_at_ms: now,
            updated_at_ms: now,
            pid: std::process::id(),
            server_endpoint: server_endpoint.into(),
            device_name: device_name.into(),
            profile,
            background_mode,
            message: "desktop runtime is starting".to_string(),
            last_error: None,
            failure_scope: None,
            suggested_action: None,
            handshake_rtt_ms: None,
            tunnel_ip: None,
            reconnect_recommended: false,
        };
        persist_snapshot(&path, &snapshot);
        Self {
            path,
            snapshot: Arc::new(Mutex::new(snapshot)),
        }
    }

    pub fn set_state(&self, state: ClientLifecycleState, message: impl Into<String>) {
        self.with_snapshot(|snapshot| {
            snapshot.state = state;
            snapshot.message = message.into();
            if !matches!(
                state,
                ClientLifecycleState::Failed | ClientLifecycleState::Degraded
            ) {
                snapshot.last_error = None;
                snapshot.failure_scope = None;
                snapshot.suggested_action = None;
                snapshot.reconnect_recommended = matches!(state, ClientLifecycleState::Connected);
            }
        });
    }

    pub fn mark_connected(&self, tunnel_ip: Ipv4Addr, rtt_ms: u64) {
        self.with_snapshot(|snapshot| {
            snapshot.state = ClientLifecycleState::Connected;
            snapshot.message = "tunnel is connected and running in background".to_string();
            snapshot.last_error = None;
            snapshot.failure_scope = None;
            snapshot.suggested_action = None;
            snapshot.handshake_rtt_ms = Some(rtt_ms);
            snapshot.tunnel_ip = Some(tunnel_ip.to_string());
            snapshot.reconnect_recommended = false;
        });
    }

    pub fn mark_degraded(&self, message: impl Into<String>, suggested_action: Option<String>) {
        self.with_snapshot(|snapshot| {
            snapshot.state = ClientLifecycleState::Degraded;
            snapshot.message = message.into();
            snapshot.suggested_action = suggested_action;
            snapshot.reconnect_recommended = true;
        });
    }

    pub fn mark_stopped(&self, message: impl Into<String>) {
        self.with_snapshot(|snapshot| {
            snapshot.state = ClientLifecycleState::Stopped;
            snapshot.message = message.into();
            snapshot.reconnect_recommended = false;
        });
    }

    pub fn record_failure(&self, scope: ClientFailureScope, error: impl Into<String>) {
        let error = normalize_message(error.into());
        let suggested_action = suggest_action(scope, &error);
        self.with_snapshot(|snapshot| {
            snapshot.state = ClientLifecycleState::Failed;
            snapshot.message = failure_summary(scope, &error);
            snapshot.last_error = Some(error);
            snapshot.failure_scope = Some(scope);
            snapshot.suggested_action = Some(suggested_action);
            snapshot.reconnect_recommended = !matches!(
                scope,
                ClientFailureScope::Config | ClientFailureScope::Credentials
            );
        });
    }

    pub fn snapshot(&self) -> ClientLifecycleSnapshot {
        self.snapshot.lock().unwrap().clone()
    }

    fn with_snapshot<F>(&self, f: F)
    where
        F: FnOnce(&mut ClientLifecycleSnapshot),
    {
        let serialized = {
            let mut guard = self.snapshot.lock().unwrap();
            f(&mut guard);
            guard.updated_at_ms = now_ms();
            guard.clone()
        };
        persist_snapshot(&self.path, &serialized);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeControlAction {
    Stop,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeControlCommand {
    pub action: RuntimeControlAction,
    pub requested_at_ms: u64,
    pub request_id: u64,
    pub reason: Option<String>,
}

pub fn write_runtime_command(
    path: &Path,
    action: RuntimeControlAction,
    reason: Option<String>,
) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed to create runtime control directory {}",
                parent.display()
            )
        })?;
    }

    let payload = RuntimeControlCommand {
        action,
        requested_at_ms: now_ms(),
        request_id: now_ms(),
        reason,
    };
    let json = serde_json::to_string_pretty(&payload)?;
    std::fs::write(path, json)
        .with_context(|| format!("failed to write runtime command {}", path.display()))?;
    Ok(())
}

pub async fn wait_for_runtime_stop(path: PathBuf) -> RuntimeControlCommand {
    loop {
        match tokio::fs::read_to_string(&path).await {
            Ok(raw) => {
                if let Ok(command) = serde_json::from_str::<RuntimeControlCommand>(&raw) {
                    if matches!(command.action, RuntimeControlAction::Stop) {
                        let _ = tokio::fs::remove_file(&path).await;
                        return command;
                    }
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                tracing::warn!(error = %err, path = %path.display(), "failed to read runtime control file");
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
}

pub fn load_lifecycle_snapshot(path: &Path) -> anyhow::Result<Option<ClientLifecycleSnapshot>> {
    match std::fs::read_to_string(path) {
        Ok(raw) => {
            let snapshot = serde_json::from_str(&raw).with_context(|| {
                format!("failed to parse lifecycle snapshot {}", path.display())
            })?;
            Ok(Some(snapshot))
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err)
            .with_context(|| format!("failed to read lifecycle snapshot {}", path.display())),
    }
}

fn persist_snapshot(path: &Path, snapshot: &ClientLifecycleSnapshot) {
    if let Some(parent) = path.parent() {
        if let Err(err) = std::fs::create_dir_all(parent) {
            tracing::warn!(error = %err, path = %path.display(), "failed to create lifecycle directory");
            return;
        }
    }

    match serde_json::to_string_pretty(snapshot) {
        Ok(json) => {
            if let Err(err) = std::fs::write(path, json) {
                tracing::warn!(error = %err, path = %path.display(), "failed to write lifecycle snapshot");
            }
        }
        Err(err) => {
            tracing::warn!(error = %err, path = %path.display(), "failed to serialize lifecycle snapshot");
        }
    }
}

fn normalize_message(message: String) -> String {
    message
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .trim()
        .to_string()
}

fn failure_summary(scope: ClientFailureScope, error: &str) -> String {
    match scope {
        ClientFailureScope::Config => format!("client configuration is incomplete: {error}"),
        ClientFailureScope::Credentials => {
            format!("device credentials were rejected or incomplete: {error}")
        }
        ClientFailureScope::Handshake => {
            format!("client could not complete the secure handshake: {error}")
        }
        ClientFailureScope::Routing => {
            format!("local tunnel routing failed after handshake: {error}")
        }
        ClientFailureScope::Transport => {
            format!("connected session stopped unexpectedly: {error}")
        }
        ClientFailureScope::Shutdown => {
            format!("client is stopping after control request: {error}")
        }
        ClientFailureScope::Unknown => format!("client stopped with an unexpected error: {error}"),
    }
}

fn suggest_action(scope: ClientFailureScope, error: &str) -> String {
    let lower = error.to_ascii_lowercase();

    if matches!(scope, ClientFailureScope::Credentials)
        || lower.contains("omega_device_token")
        || lower.contains("omega_device_id")
        || lower.contains("token")
    {
        return "verify the device id/token in the desktop client settings or rotate the device token from the admin side".to_string();
    }

    if matches!(scope, ClientFailureScope::Routing)
        || lower.contains("wintun")
        || lower.contains("route")
        || lower.contains("adapter")
    {
        return "close other VPN adapters, then reconnect so the client can rebuild local tunnel routes cleanly".to_string();
    }

    if matches!(scope, ClientFailureScope::Handshake)
        || lower.contains("timeout")
        || lower.contains("timed out")
        || lower.contains("cookie")
        || lower.contains("udp")
    {
        return "check server reachability and local firewall rules, or retry with the restricted fallback profile".to_string();
    }

    if lower.contains("permission") || lower.contains("access is denied") {
        return "run the desktop client with the privileges required to create the tunnel interface".to_string();
    }

    if matches!(scope, ClientFailureScope::Transport) {
        return "use reconnect first; if the issue repeats, export diagnostics and inspect the latest runtime log".to_string();
    }

    "export diagnostics and inspect the latest runtime log before retrying".to_string()
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
