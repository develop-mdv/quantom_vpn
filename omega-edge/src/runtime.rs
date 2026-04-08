use std::collections::BTreeSet;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use omega_control::policy::{PrivilegeBoundary, SessionAdmission};
use omega_stealth::{MorphingPolicy, PersonaId, ProductMode};
use serde::{Deserialize, Serialize};

use crate::fabric::{FabricRuntimeView, SharedFabric};
use crate::metrics;
use crate::session::ActiveSessionView;

const DEFAULT_RUNTIME_SNAPSHOT_PATH: &str = "state/runtime.json";

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
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

pub fn default_mode(profile: ServerProfile) -> ProductMode {
    match profile {
        ServerProfile::Gaming => ProductMode::Fast,
        ServerProfile::GeneralInternet => ProductMode::Balanced,
        ServerProfile::RestrictedFallback => ProductMode::HostileNetwork,
    }
}

pub fn default_session_admission(profile: ServerProfile) -> SessionAdmission {
    SessionAdmission {
        policy_id: format!("profile:{}", profile_label(profile)),
        mode: default_mode(profile),
        relay_permitted: true,
        resumption_ttl_secs: 3_600,
        privileged_boundary: PrivilegeBoundary::Session,
    }
}

pub fn default_persona(profile: ServerProfile) -> PersonaId {
    match profile {
        ServerProfile::Gaming => PersonaId::Randomized,
        ServerProfile::GeneralInternet => PersonaId::QuicLike,
        ServerProfile::RestrictedFallback => PersonaId::HostileNetwork,
    }
}

pub fn morphing_policy_from_env(profile: ServerProfile) -> MorphingPolicy {
    let default = match profile {
        ServerProfile::Gaming => MorphingPolicy::Off,
        ServerProfile::GeneralInternet => MorphingPolicy::Balanced,
        ServerProfile::RestrictedFallback => MorphingPolicy::Full,
    };

    match std::env::var("OMEGA_MORPHING") {
        Ok(value) => match value.trim().to_ascii_lowercase().as_str() {
            "full" | "aggressive" => MorphingPolicy::Full,
            "balanced" | "auto" | "reduced" => MorphingPolicy::Balanced,
            "off" | "disabled" | "low_latency" | "low-latency" => MorphingPolicy::Off,
            _ => default,
        },
        Err(_) => default,
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ipv6Mode {
    Disabled,
}

#[derive(Debug, Clone, Serialize)]
pub struct ServerRuntimeConfig {
    pub profile: ServerProfile,
    pub mode: ProductMode,
    pub morphing_policy: MorphingPolicy,
    pub persona: PersonaId,
    pub node_role: String,
    pub fabric_node_id: String,
    pub fabric_region: String,
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

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuntimeSummary {
    pub active_sessions: usize,
    pub max_idle_secs: u64,
    pub max_age_secs: u64,
    pub avg_loss_ratio: f64,
    pub avg_path_quality_score: f64,
    pub avg_payload_budget: f64,
    pub avg_route_diversity_score: f64,
    pub blackhole_suspected_sessions: usize,
    pub active_fabric_routes: usize,
    pub total_fabric_failovers: u64,
    pub total_fec_frames_sent: u64,
    pub total_fec_frames_received: u64,
    pub total_fec_recoveries: u64,
    pub total_suppressed_duplicates: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ServerRuntimeSnapshot {
    pub started_at_ms: u64,
    pub updated_at_ms: u64,
    pub config: ServerRuntimeConfig,
    pub summary: RuntimeSummary,
    pub fabric: FabricRuntimeView,
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
    fabric: SharedFabric,
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
        let fabric_view = fabric.read().unwrap().runtime_view();
        metrics::update_fabric_summary(&fabric_view, &summary);

        let payload = serde_json::to_string_pretty(&ServerRuntimeSnapshot {
            started_at_ms,
            updated_at_ms: now_ms(),
            config: config.clone(),
            summary,
            fabric: fabric_view,
            sessions: active_sessions,
        })?;
        tokio::fs::write(&path, payload).await?;
    }
}

impl RuntimeSummary {
    pub fn from_sessions(sessions: &[ActiveSessionView]) -> Self {
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
        let avg_path_quality_score = if active_sessions == 0 {
            0.0
        } else {
            sessions
                .iter()
                .map(|session| session.path_quality_score as f64)
                .sum::<f64>()
                / active_sessions as f64
        };
        let avg_payload_budget = if active_sessions == 0 {
            0.0
        } else {
            sessions
                .iter()
                .map(|session| session.payload_budget as f64)
                .sum::<f64>()
                / active_sessions as f64
        };
        let avg_route_diversity_score = if active_sessions == 0 {
            0.0
        } else {
            sessions
                .iter()
                .map(|session| session.fabric_route_diversity_score)
                .sum::<f64>()
                / active_sessions as f64
        };
        let blackhole_suspected_sessions = sessions
            .iter()
            .filter(|session| session.blackhole_suspected)
            .count();
        let active_fabric_routes = sessions
            .iter()
            .map(|session| session.fabric_active_route_id.clone())
            .collect::<BTreeSet<_>>()
            .len();
        let total_fabric_failovers = sessions
            .iter()
            .map(|session| session.fabric_failover_count as u64)
            .sum();
        let total_fec_frames_sent = sessions.iter().map(|session| session.fec_frames_sent).sum();
        let total_fec_frames_received = sessions
            .iter()
            .map(|session| session.fec_frames_received)
            .sum();
        let total_fec_recoveries = sessions.iter().map(|session| session.fec_recoveries).sum();
        let total_suppressed_duplicates = sessions
            .iter()
            .map(|session| session.suppressed_duplicates)
            .sum();

        Self {
            active_sessions,
            max_idle_secs,
            max_age_secs,
            avg_loss_ratio,
            avg_path_quality_score,
            avg_payload_budget,
            avg_route_diversity_score,
            blackhole_suspected_sessions,
            active_fabric_routes,
            total_fabric_failovers,
            total_fec_frames_sent,
            total_fec_frames_received,
            total_fec_recoveries,
            total_suppressed_duplicates,
        }
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn profile_label(profile: ServerProfile) -> &'static str {
    match profile {
        ServerProfile::Gaming => "gaming",
        ServerProfile::GeneralInternet => "general",
        ServerProfile::RestrictedFallback => "restricted",
    }
}
