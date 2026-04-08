use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use metrics::{counter, gauge};
use metrics_exporter_prometheus::PrometheusBuilder;
use serde::{Deserialize, Serialize};

use crate::fabric::FabricRuntimeView;
use crate::runtime::RuntimeSummary;
use crate::session::ActiveSessionView;
use omega_control::control_plane::ControlPlaneSummary;

const PATH_MODES: &[&str] = &[
    "stable",
    "probing",
    "cautious",
    "roaming",
    "recovering",
    "blackhole_recovery",
];
const PATH_BELIEFS: &[&str] = &[
    "stable",
    "congested",
    "reordered",
    "blackhole_risk",
    "recovering",
];
const PERSONAS: &[&str] = &["randomized", "quic_like", "hostile_network", "off"];
const RECOVERY_STRATEGIES: &[&str] = &[
    "retransmit_only",
    "duplicate_once",
    "fec_low",
    "fec_medium",
    "fec_high",
];
const RECOVERY_CLASSES: &[&str] = &["control", "interactive", "bulk"];

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MetricsStateSnapshot {
    pub updated_at_ms: u64,
    pub packets_in_total: u64,
    pub packets_out_total: u64,
    pub bytes_in_total: u64,
    pub bytes_out_total: u64,
    pub handshake_success_total: u64,
    pub handshake_failures_total: u64,
    pub handshake_failures_by_reason: BTreeMap<String, u64>,
    pub handshake_success_by_platform: BTreeMap<String, u64>,
    pub handshake_pending: usize,
    pub handshake_rate_limited_total: u64,
    pub device_reconnect_total: u64,
    pub nack_sent_total: u64,
    pub nack_received_total: u64,
    pub retransmit_sent_total: u64,
    pub retransmit_dropped_total: u64,
    pub fec_recovery_total: u64,
    pub path_roam_total: u64,
    pub fabric_failover_total: u64,
    pub fabric_failover_within_budget_total: u64,
    pub fabric_operator_actions_total: u64,
    pub ip_leases_assigned_total: u64,
    pub ip_leases_released_total: u64,
    pub control_plane_revision: u64,
    pub control_plane_policy_conflicts: usize,
    pub control_plane_users: usize,
    pub control_plane_blocked_users: usize,
    pub control_plane_active_devices: usize,
    pub control_plane_active_sessions: usize,
    pub control_plane_issued_tickets: usize,
    pub control_plane_fabric_nodes: usize,
    pub sessions_by_path_mode: BTreeMap<String, usize>,
    pub sessions_by_path_belief: BTreeMap<String, usize>,
    pub sessions_by_persona: BTreeMap<String, usize>,
    pub sessions_by_recovery_strategy: BTreeMap<String, BTreeMap<String, usize>>,
}

static METRICS_STATE: OnceLock<Mutex<MetricsStateSnapshot>> = OnceLock::new();

pub fn init_metrics(bind: &str) -> anyhow::Result<()> {
    let addr: SocketAddr = bind.parse()?;
    PrometheusBuilder::new()
        .with_http_listener(addr)
        .install()?;

    gauge!("omega_active_sessions").set(0.0);
    gauge!("omega_runtime_max_idle_seconds").set(0.0);
    gauge!("omega_runtime_max_age_seconds").set(0.0);
    gauge!("omega_runtime_avg_loss_ratio").set(0.0);
    gauge!("omega_runtime_avg_path_quality_score").set(0.0);
    gauge!("omega_runtime_avg_payload_budget").set(0.0);
    gauge!("omega_runtime_avg_route_diversity_score").set(0.0);
    gauge!("omega_runtime_blackhole_sessions").set(0.0);
    gauge!("omega_runtime_active_fabric_routes").set(0.0);
    gauge!("omega_runtime_total_fabric_failovers").set(0.0);
    gauge!("omega_runtime_fec_frames_sent").set(0.0);
    gauge!("omega_runtime_fec_frames_received").set(0.0);
    gauge!("omega_runtime_fec_recoveries").set(0.0);
    gauge!("omega_runtime_suppressed_duplicates").set(0.0);
    gauge!("omega_fabric_total_nodes").set(0.0);
    gauge!("omega_fabric_healthy_nodes").set(0.0);
    gauge!("omega_fabric_last_simulation_within_budget").set(1.0);
    gauge!("omega_fabric_last_simulation_reroutes").set(0.0);
    gauge!("omega_fabric_last_simulation_disconnects").set(0.0);
    gauge!("omega_fabric_last_simulation_avg_failover_ms").set(0.0);
    gauge!("omega_control_plane_revision").set(0.0);
    gauge!("omega_control_plane_policy_conflicts").set(0.0);
    gauge!("omega_control_plane_users").set(0.0);
    gauge!("omega_control_plane_blocked_users").set(0.0);
    gauge!("omega_control_plane_active_devices").set(0.0);
    gauge!("omega_control_plane_active_sessions").set(0.0);
    gauge!("omega_control_plane_issued_tickets").set(0.0);
    gauge!("omega_control_plane_fabric_nodes").set(0.0);

    for mode in PATH_MODES {
        gauge!("omega_sessions_path_mode", "mode" => (*mode).to_string()).set(0.0);
    }
    for belief in PATH_BELIEFS {
        gauge!("omega_sessions_path_belief", "belief" => (*belief).to_string()).set(0.0);
    }
    for persona in PERSONAS {
        gauge!("omega_sessions_persona", "persona" => (*persona).to_string()).set(0.0);
    }
    for class in RECOVERY_CLASSES {
        for strategy in RECOVERY_STRATEGIES {
            gauge!(
                "omega_sessions_recovery_strategy",
                "traffic_class" => (*class).to_string(),
                "strategy" => (*strategy).to_string()
            )
            .set(0.0);
        }
    }

    tracing::info!(%addr, "prometheus metrics enabled");
    Ok(())
}

pub fn snapshot_state() -> MetricsStateSnapshot {
    metrics_state().lock().unwrap().clone()
}

pub fn record_packet_out(bytes: usize) {
    counter!("omega_packets_out_total").increment(1);
    counter!("omega_bytes_out_total").increment(bytes as u64);
    with_state(|state| {
        state.packets_out_total = state.packets_out_total.saturating_add(1);
        state.bytes_out_total = state.bytes_out_total.saturating_add(bytes as u64);
    });
}

pub fn record_packet_in(bytes: usize) {
    counter!("omega_packets_in_total").increment(1);
    counter!("omega_bytes_in_total").increment(bytes as u64);
    with_state(|state| {
        state.packets_in_total = state.packets_in_total.saturating_add(1);
        state.bytes_in_total = state.bytes_in_total.saturating_add(bytes as u64);
    });
}

pub fn update_session_count(count: usize) {
    gauge!("omega_active_sessions").set(count as f64);
}

pub fn update_user_session_count(user_id: &str, count: usize) {
    gauge!("omega_active_sessions_per_user", "user_id" => user_id.to_string()).set(count as f64);
}

pub fn update_handshake_pending(count: usize) {
    gauge!("omega_handshake_pending").set(count as f64);
    with_state(|state| {
        state.handshake_pending = count;
    });
}

pub fn record_handshake_success(user_id: String, platform: &str) {
    counter!("omega_handshake_success_total").increment(1);
    counter!("omega_handshake_platform_total", "platform" => platform.to_string()).increment(1);
    counter!("omega_handshake_success_per_user_total", "user_id" => user_id).increment(1);
    with_state(|state| {
        state.handshake_success_total = state.handshake_success_total.saturating_add(1);
        *state
            .handshake_success_by_platform
            .entry(platform.to_string())
            .or_default() += 1;
    });
}

pub fn record_device_reconnect(replaced_sessions: usize) {
    counter!("omega_device_reconnect_total").increment(1);
    counter!("omega_device_reconnect_replaced_sessions_total").increment(replaced_sessions as u64);
    with_state(|state| {
        state.device_reconnect_total = state.device_reconnect_total.saturating_add(1);
    });
}

pub fn record_handshake_rate_limited() {
    counter!("omega_handshake_rate_limited_total").increment(1);
    with_state(|state| {
        state.handshake_rate_limited_total = state.handshake_rate_limited_total.saturating_add(1);
    });
}

pub fn record_handshake_failure(reason: omega_core_wire::HandshakeRejectReason) {
    let reason_label = format!("{:?}", reason).to_ascii_lowercase();
    counter!("omega_handshake_failures_total", "reason" => reason_label.clone()).increment(1);
    with_state(|state| {
        state.handshake_failures_total = state.handshake_failures_total.saturating_add(1);
        *state
            .handshake_failures_by_reason
            .entry(reason_label)
            .or_default() += 1;
    });
}

pub fn record_ip_lease_assigned() {
    counter!("omega_ip_leases_assigned_total").increment(1);
    with_state(|state| {
        state.ip_leases_assigned_total = state.ip_leases_assigned_total.saturating_add(1);
    });
}

pub fn record_ip_lease_released() {
    counter!("omega_ip_leases_released_total").increment(1);
    with_state(|state| {
        state.ip_leases_released_total = state.ip_leases_released_total.saturating_add(1);
    });
}

pub fn record_nack_sent(missing_packets: u32) {
    counter!("omega_nack_sent_total").increment(1);
    counter!("omega_nack_sent_missing_packets_total").increment(missing_packets as u64);
    with_state(|state| {
        state.nack_sent_total = state.nack_sent_total.saturating_add(1);
    });
}

pub fn record_nack_received(missing_packets: u32) {
    counter!("omega_nack_received_total").increment(1);
    counter!("omega_nack_received_missing_packets_total").increment(missing_packets as u64);
    with_state(|state| {
        state.nack_received_total = state.nack_received_total.saturating_add(1);
    });
}

pub fn record_path_roam() {
    counter!("omega_path_roam_total").increment(1);
    with_state(|state| {
        state.path_roam_total = state.path_roam_total.saturating_add(1);
    });
}

pub fn record_retransmit_sent(sent_packets: usize, dropped_packets: usize) {
    counter!("omega_retransmit_sent_total").increment(sent_packets as u64);
    if dropped_packets > 0 {
        counter!("omega_retransmit_dropped_total").increment(dropped_packets as u64);
    }
    with_state(|state| {
        state.retransmit_sent_total = state
            .retransmit_sent_total
            .saturating_add(sent_packets as u64);
        state.retransmit_dropped_total = state
            .retransmit_dropped_total
            .saturating_add(dropped_packets as u64);
    });
}

pub fn record_fec_recovery(recovered_messages: usize) {
    if recovered_messages == 0 {
        return;
    }
    counter!("omega_fec_recovery_total").increment(recovered_messages as u64);
    with_state(|state| {
        state.fec_recovery_total = state
            .fec_recovery_total
            .saturating_add(recovered_messages as u64);
    });
}

pub fn record_fabric_failover(within_budget: bool) {
    counter!("omega_fabric_failover_total").increment(1);
    if within_budget {
        counter!("omega_fabric_failover_within_budget_total").increment(1);
    }
    with_state(|state| {
        state.fabric_failover_total = state.fabric_failover_total.saturating_add(1);
        if within_budget {
            state.fabric_failover_within_budget_total =
                state.fabric_failover_within_budget_total.saturating_add(1);
        }
    });
}

pub fn record_fabric_operator_action() {
    counter!("omega_fabric_operator_actions_total").increment(1);
    with_state(|state| {
        state.fabric_operator_actions_total = state.fabric_operator_actions_total.saturating_add(1);
    });
}

pub fn update_runtime_summary(summary: &RuntimeSummary) {
    gauge!("omega_runtime_max_idle_seconds").set(summary.max_idle_secs as f64);
    gauge!("omega_runtime_max_age_seconds").set(summary.max_age_secs as f64);
    gauge!("omega_runtime_avg_loss_ratio").set(summary.avg_loss_ratio);
    gauge!("omega_runtime_avg_path_quality_score").set(summary.avg_path_quality_score);
    gauge!("omega_runtime_avg_payload_budget").set(summary.avg_payload_budget);
    gauge!("omega_runtime_avg_route_diversity_score").set(summary.avg_route_diversity_score);
    gauge!("omega_runtime_blackhole_sessions").set(summary.blackhole_suspected_sessions as f64);
    gauge!("omega_runtime_active_fabric_routes").set(summary.active_fabric_routes as f64);
    gauge!("omega_runtime_total_fabric_failovers").set(summary.total_fabric_failovers as f64);
    gauge!("omega_runtime_fec_frames_sent").set(summary.total_fec_frames_sent as f64);
    gauge!("omega_runtime_fec_frames_received").set(summary.total_fec_frames_received as f64);
    gauge!("omega_runtime_fec_recoveries").set(summary.total_fec_recoveries as f64);
    gauge!("omega_runtime_suppressed_duplicates").set(summary.total_suppressed_duplicates as f64);
}

pub fn update_fabric_summary(fabric: &FabricRuntimeView, _summary: &RuntimeSummary) {
    gauge!("omega_fabric_total_nodes").set(fabric.total_nodes as f64);
    gauge!("omega_fabric_healthy_nodes").set(fabric.healthy_nodes as f64);
    gauge!("omega_fabric_last_simulation_within_budget").set(
        if fabric.last_simulation_within_budget {
            1.0
        } else {
            0.0
        },
    );
    gauge!("omega_fabric_last_simulation_reroutes").set(fabric.last_simulation_reroutes as f64);
    gauge!("omega_fabric_last_simulation_disconnects")
        .set(fabric.last_simulation_disconnects as f64);
    gauge!("omega_fabric_last_simulation_avg_failover_ms")
        .set(fabric.last_simulation_avg_failover_ms);
}

pub fn update_control_plane_summary(summary: &ControlPlaneSummary, policy_conflicts: usize) {
    gauge!("omega_control_plane_revision").set(summary.revision as f64);
    gauge!("omega_control_plane_policy_conflicts").set(policy_conflicts as f64);
    gauge!("omega_control_plane_users").set(summary.users as f64);
    gauge!("omega_control_plane_blocked_users").set(summary.blocked_users as f64);
    gauge!("omega_control_plane_active_devices").set(summary.active_devices as f64);
    gauge!("omega_control_plane_active_sessions").set(summary.active_sessions as f64);
    gauge!("omega_control_plane_issued_tickets").set(summary.issued_tickets as f64);
    gauge!("omega_control_plane_fabric_nodes").set(summary.fabric_nodes as f64);
    with_state(|state| {
        state.control_plane_revision = summary.revision;
        state.control_plane_policy_conflicts = policy_conflicts;
        state.control_plane_users = summary.users;
        state.control_plane_blocked_users = summary.blocked_users;
        state.control_plane_active_devices = summary.active_devices;
        state.control_plane_active_sessions = summary.active_sessions;
        state.control_plane_issued_tickets = summary.issued_tickets;
        state.control_plane_fabric_nodes = summary.fabric_nodes;
    });
}

pub fn update_session_distribution(sessions: &[ActiveSessionView]) {
    let path_modes = count_labels(sessions, |session| session.path_mode.clone());
    let path_beliefs = count_labels(sessions, |session| session.path_belief.clone());
    let personas = count_labels(sessions, |session| session.active_persona.clone());
    let mut recovery = BTreeMap::new();
    recovery.insert(
        "control".to_string(),
        count_labels(sessions, |session| {
            session.reliability_control_strategy.clone()
        }),
    );
    recovery.insert(
        "interactive".to_string(),
        count_labels(sessions, |session| {
            session.reliability_interactive_strategy.clone()
        }),
    );
    recovery.insert(
        "bulk".to_string(),
        count_labels(sessions, |session| {
            session.reliability_bulk_strategy.clone()
        }),
    );

    for mode in PATH_MODES {
        gauge!("omega_sessions_path_mode", "mode" => (*mode).to_string())
            .set(*path_modes.get(*mode).unwrap_or(&0) as f64);
    }
    for belief in PATH_BELIEFS {
        gauge!("omega_sessions_path_belief", "belief" => (*belief).to_string())
            .set(*path_beliefs.get(*belief).unwrap_or(&0) as f64);
    }
    for persona in PERSONAS {
        gauge!("omega_sessions_persona", "persona" => (*persona).to_string())
            .set(*personas.get(*persona).unwrap_or(&0) as f64);
    }
    for class in RECOVERY_CLASSES {
        let strategy_map = recovery.get(*class);
        for strategy in RECOVERY_STRATEGIES {
            gauge!(
                "omega_sessions_recovery_strategy",
                "traffic_class" => (*class).to_string(),
                "strategy" => (*strategy).to_string()
            )
            .set(
                strategy_map
                    .and_then(|counts| counts.get(*strategy))
                    .copied()
                    .unwrap_or(0) as f64,
            );
        }
    }

    with_state(|state| {
        state.sessions_by_path_mode = path_modes;
        state.sessions_by_path_belief = path_beliefs;
        state.sessions_by_persona = personas;
        state.sessions_by_recovery_strategy = recovery;
    });
}

fn count_labels<F>(sessions: &[ActiveSessionView], f: F) -> BTreeMap<String, usize>
where
    F: Fn(&ActiveSessionView) -> String,
{
    let mut counts = BTreeMap::new();
    for session in sessions {
        *counts.entry(f(session)).or_default() += 1;
    }
    counts
}

fn metrics_state() -> &'static Mutex<MetricsStateSnapshot> {
    METRICS_STATE.get_or_init(|| Mutex::new(MetricsStateSnapshot::default()))
}

fn with_state<F>(f: F)
where
    F: FnOnce(&mut MetricsStateSnapshot),
{
    let mut guard = metrics_state().lock().unwrap();
    f(&mut guard);
    guard.updated_at_ms = now_ms();
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
