use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use serde::Serialize;

use crate::metrics;
use crate::session::ActiveSessionView;

const DEFAULT_RUNTIME_SNAPSHOT_PATH: &str = "state/runtime.json";

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ServerProfile {
    Gaming,
    GeneralInternet,
    RestrictedFallback,
}

impl ServerProfile {
    pub fn from_env() -> Self {
        match std::env::var("OMEGA_PROFILE")
            .unwrap_or_else(|_| "gaming".to_string())
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "general" | "internet" | "default" => Self::GeneralInternet,
            "restricted" | "fallback" | "restricted_fallback" | "tcp-fallback" => {
                Self::RestrictedFallback
            }
            _ => Self::Gaming,
        }
    }

    pub fn default_mtu(self) -> u16 {
        match self {
            Self::Gaming => 1380,
            Self::GeneralInternet => 1360,
            Self::RestrictedFallback => 1280,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Ipv6Mode {
    Disabled,
}

#[derive(Debug, Clone, Serialize)]
pub struct ServerRuntimeConfig {
    pub profile: ServerProfile,
    pub bind_addr: String,
    pub metrics_bind: String,
    pub admin_web_bind: String,
    pub tunnel_ip: String,
    pub tunnel_prefix: u8,
    pub tunnel_mtu: u16,
    pub udp_rcvbuf: usize,
    pub udp_sndbuf: usize,
    pub transport: String,
    pub tunnel_family: String,
    pub ipv6_mode: Ipv6Mode,
    pub allow_legacy_v1: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuntimeSummary {
    pub active_sessions: usize,
    pub max_idle_secs: u64,
    pub max_age_secs: u64,
    pub avg_loss_ratio: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ServerRuntimeSnapshot {
    pub started_at_ms: u64,
    pub updated_at_ms: u64,
    pub config: ServerRuntimeConfig,
    pub summary: RuntimeSummary,
    pub sessions: Vec<ActiveSessionView>,
}

impl ServerRuntimeConfig {
    pub fn runtime_snapshot_path() -> PathBuf {
        std::env::var("OMEGA_RUNTIME_SNAPSHOT")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(DEFAULT_RUNTIME_SNAPSHOT_PATH))
    }
}

pub async fn spawn_runtime_snapshot_task(
    config: ServerRuntimeConfig,
    sessions: std::sync::Arc<crate::session::SessionManager>,
    path: PathBuf,
) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }

    let started_at_ms = now_ms();
    let mut interval = tokio::time::interval(Duration::from_secs(5));
    loop {
        interval.tick().await;
        let active_sessions = sessions.snapshot();
        let summary = RuntimeSummary::from_sessions(&active_sessions);
        metrics::update_runtime_summary(&summary);

        let payload = serde_json::to_string_pretty(&ServerRuntimeSnapshot {
            started_at_ms,
            updated_at_ms: now_ms(),
            config: config.clone(),
            summary,
            sessions: active_sessions,
        })?;
        tokio::fs::write(&path, payload).await?;
    }
}

impl RuntimeSummary {
    fn from_sessions(sessions: &[ActiveSessionView]) -> Self {
        let active_sessions = sessions.len();
        let max_idle_secs = sessions
            .iter()
            .map(|session| session.idle_secs)
            .max()
            .unwrap_or(0);
        let max_age_secs = sessions
            .iter()
            .map(|session| session.age_secs)
            .max()
            .unwrap_or(0);
        let avg_loss_ratio = if active_sessions == 0 {
            0.0
        } else {
            sessions
                .iter()
                .map(|session| session.loss_ratio)
                .sum::<f64>()
                / active_sessions as f64
        };

        Self {
            active_sessions,
            max_idle_secs,
            max_age_secs,
            avg_loss_ratio,
        }
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
