use std::collections::{BTreeMap, VecDeque};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context;
use rand::Rng;
use serde::{Deserialize, Serialize};

use omega_control::identity::IdentityStore;
use omega_core_wire::ConnectionId;

use crate::fabric::SharedFabric;
use crate::handshake::HandshakeService;
use crate::metrics::{self, MetricsStateSnapshot};
use crate::runtime::RuntimeSummary;
use crate::session::SessionManager;

const DEFAULT_OBSERVABILITY_SNAPSHOT_PATH: &str = "state/observability.json";
const DEFAULT_TRACE_JOURNAL_PATH: &str = "state/trace.ndjson";
const DEFAULT_DP_EPSILON: f64 = 0.75;
const DEFAULT_CANARY_MIN_PATH_QUALITY_SCORE: f64 = 45.0;
const DEFAULT_CANARY_MAX_LOSS_RATIO: f64 = 0.08;
const DEFAULT_CANARY_MAX_BLACKHOLE_SESSIONS: usize = 0;
const DEFAULT_CANARY_MAX_POLICY_CONFLICTS: usize = 0;
const DEFAULT_CANARY_MIN_HEALTHY_FABRIC_NODES: usize = 1;
const DEFAULT_SPC_WINDOW: usize = 24;

static TRACE_JOURNAL: OnceLock<TraceJournal> = OnceLock::new();

#[derive(Debug, Clone)]
pub struct ObservabilityConfig {
    pub snapshot_path: PathBuf,
    pub trace_journal_path: PathBuf,
    pub dp_epsilon: f64,
    pub canary_min_path_quality_score: f64,
    pub canary_max_loss_ratio: f64,
    pub canary_max_blackhole_sessions: usize,
    pub canary_max_policy_conflicts: usize,
    pub canary_min_healthy_fabric_nodes: usize,
    pub spc_window: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservabilitySnapshot {
    pub started_at_ms: u64,
    pub updated_at_ms: u64,
    pub trace_journal_path: String,
    pub runtime_summary: RuntimeSummary,
    pub fabric: FabricSreSummary,
    pub control_plane: ControlPlaneSreSummary,
    pub metrics: MetricsStateSnapshot,
    pub metric_deltas: MetricsDeltaSnapshot,
    pub session_distribution: SessionDistributionSnapshot,
    pub alerts: Vec<KnownAlert>,
    pub spc_signals: Vec<SpcSignal>,
    pub differential_privacy: DifferentialPrivacyTelemetry,
    pub rollout_guard: RolloutGuard,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FabricSreSummary {
    pub local_node_id: String,
    pub local_role: String,
    pub region: String,
    pub operator: String,
    pub graph_revision: u64,
    pub total_nodes: usize,
    pub healthy_nodes: usize,
    pub last_simulation_within_budget: bool,
    pub last_simulation_reroutes: usize,
    pub last_simulation_disconnects: usize,
    pub last_simulation_avg_failover_ms: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlPlaneSreSummary {
    pub revision: u64,
    pub users: usize,
    pub blocked_users: usize,
    pub active_devices: usize,
    pub active_sessions: usize,
    pub issued_tickets: usize,
    pub fabric_nodes: usize,
    pub policy_conflicts: usize,
    pub recent_audit_events: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MetricsDeltaSnapshot {
    pub handshake_success_delta: u64,
    pub handshake_failures_delta: u64,
    pub handshake_rate_limited_delta: u64,
    pub path_roam_delta: u64,
    pub retransmit_delta: u64,
    pub retransmit_drop_delta: u64,
    pub fec_recovery_delta: u64,
    pub fabric_failover_delta: u64,
    pub fabric_operator_actions_delta: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SessionDistributionSnapshot {
    pub by_path_mode: BTreeMap<String, usize>,
    pub by_path_belief: BTreeMap<String, usize>,
    pub by_persona: BTreeMap<String, usize>,
    pub by_recovery_strategy: BTreeMap<String, BTreeMap<String, usize>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnownAlert {
    pub subsystem: String,
    pub severity: String,
    pub title: String,
    pub message: String,
    pub suggested_action: String,
    pub runbook_hint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpcSignal {
    pub metric: String,
    pub sample_count: usize,
    pub current: f64,
    pub mean: f64,
    pub sigma: f64,
    pub lower_control_limit: f64,
    pub upper_control_limit: f64,
    pub out_of_control: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DifferentialPrivacyTelemetry {
    pub epsilon: f64,
    pub excluded_fields: Vec<String>,
    pub sanitized_counts: BTreeMap<String, f64>,
    pub noisy_counts: BTreeMap<String, f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RolloutGuard {
    pub healthy: bool,
    pub checked_at_ms: u64,
    pub active_sessions_observed: usize,
    pub reasons: Vec<String>,
    pub recommended_action: String,
    pub evaluation_note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceEvent {
    pub ts_ms: u64,
    pub subsystem: String,
    pub severity: String,
    pub correlation_id: String,
    pub flow_id: Option<String>,
    pub message: String,
    pub details: serde_json::Value,
}

struct TraceJournal {
    path: PathBuf,
    lock: Mutex<()>,
}

#[derive(Default)]
struct SpcTracker {
    samples: VecDeque<f64>,
    window: usize,
}

impl ObservabilityConfig {
    pub fn from_env() -> Self {
        Self {
            snapshot_path: std::env::var("OMEGA_OBSERVABILITY_SNAPSHOT")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from(DEFAULT_OBSERVABILITY_SNAPSHOT_PATH)),
            trace_journal_path: std::env::var("OMEGA_TRACE_JOURNAL")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from(DEFAULT_TRACE_JOURNAL_PATH)),
            dp_epsilon: env_f64("OMEGA_DP_EPSILON", DEFAULT_DP_EPSILON).max(0.1),
            canary_min_path_quality_score: env_f64(
                "OMEGA_CANARY_MIN_PATH_QUALITY_SCORE",
                DEFAULT_CANARY_MIN_PATH_QUALITY_SCORE,
            )
            .clamp(0.0, 100.0),
            canary_max_loss_ratio: env_f64(
                "OMEGA_CANARY_MAX_LOSS_RATIO",
                DEFAULT_CANARY_MAX_LOSS_RATIO,
            )
            .clamp(0.0, 1.0),
            canary_max_blackhole_sessions: env_usize(
                "OMEGA_CANARY_MAX_BLACKHOLE_SESSIONS",
                DEFAULT_CANARY_MAX_BLACKHOLE_SESSIONS,
            ),
            canary_max_policy_conflicts: env_usize(
                "OMEGA_CANARY_MAX_POLICY_CONFLICTS",
                DEFAULT_CANARY_MAX_POLICY_CONFLICTS,
            ),
            canary_min_healthy_fabric_nodes: env_usize(
                "OMEGA_CANARY_MIN_HEALTHY_FABRIC_NODES",
                DEFAULT_CANARY_MIN_HEALTHY_FABRIC_NODES,
            )
            .max(1),
            spc_window: env_usize("OMEGA_SPC_WINDOW", DEFAULT_SPC_WINDOW).max(8),
        }
    }

    pub fn snapshot_path() -> PathBuf {
        std::env::var("OMEGA_OBSERVABILITY_SNAPSHOT")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(DEFAULT_OBSERVABILITY_SNAPSHOT_PATH))
    }
}

pub fn load_observability_snapshot(path: &Path) -> anyhow::Result<Option<ObservabilitySnapshot>> {
    match std::fs::read_to_string(path) {
        Ok(raw) => {
            let snapshot = serde_json::from_str(&raw).with_context(|| {
                format!("failed to parse observability snapshot {}", path.display())
            })?;
            Ok(Some(snapshot))
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err)
            .with_context(|| format!("failed to read observability snapshot {}", path.display())),
    }
}

pub fn assert_rollout_guard(path: &Path) -> anyhow::Result<RolloutGuard> {
    let snapshot = load_observability_snapshot(path)?.ok_or_else(|| {
        anyhow::anyhow!(
            "observability snapshot {} is not available yet",
            path.display()
        )
    })?;
    if snapshot.rollout_guard.healthy {
        Ok(snapshot.rollout_guard)
    } else {
        Err(anyhow::anyhow!(
            "rollout guard is unhealthy: {}",
            snapshot.rollout_guard.reasons.join("; ")
        ))
    }
}

pub async fn spawn_observability_task(
    config: ObservabilityConfig,
    sessions: Arc<SessionManager>,
    identity_store: Arc<IdentityStore>,
    fabric: SharedFabric,
    handshake_service: Arc<HandshakeService>,
) -> anyhow::Result<()> {
    if let Some(parent) = config.snapshot_path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }

    let started_at_ms = now_ms();
    let mut interval = tokio::time::interval(Duration::from_secs(5));
    let mut previous_metrics = MetricsStateSnapshot::default();
    let mut loss_spc = SpcTracker::new(config.spc_window);
    let mut quality_spc = SpcTracker::new(config.spc_window);
    let mut failover_spc = SpcTracker::new(config.spc_window);

    loop {
        interval.tick().await;

        metrics::update_handshake_pending(handshake_service.pending_count());
        let active_sessions = sessions.snapshot();
        metrics::update_session_distribution(&active_sessions);

        let runtime_summary = RuntimeSummary::from_sessions(&active_sessions);
        let fabric_view = fabric.read().unwrap().runtime_view();
        let fabric_summary = FabricSreSummary::from_runtime_view(&fabric_view);
        let control_plane_summary = identity_store.summary();
        let policy_conflicts = identity_store.policy_conflicts().len();
        metrics::update_control_plane_summary(&control_plane_summary, policy_conflicts);
        let metrics_snapshot = metrics::snapshot_state();
        let metric_deltas =
            MetricsDeltaSnapshot::from_snapshots(&previous_metrics, &metrics_snapshot);
        previous_metrics = metrics_snapshot.clone();

        let control_plane = ControlPlaneSreSummary {
            revision: control_plane_summary.revision,
            users: control_plane_summary.users,
            blocked_users: control_plane_summary.blocked_users,
            active_devices: control_plane_summary.active_devices,
            active_sessions: control_plane_summary.active_sessions,
            issued_tickets: control_plane_summary.issued_tickets,
            fabric_nodes: control_plane_summary.fabric_nodes,
            policy_conflicts,
            recent_audit_events: identity_store.recent_audit(50).len(),
        };
        let session_distribution = SessionDistributionSnapshot::from_metrics(&metrics_snapshot);
        let spc_signals = vec![
            loss_spc.observe("runtime.avg_loss_ratio", runtime_summary.avg_loss_ratio),
            quality_spc.observe(
                "runtime.avg_path_quality_score",
                runtime_summary.avg_path_quality_score,
            ),
            failover_spc.observe(
                "metrics.fabric_failover_delta",
                metric_deltas.fabric_failover_delta as f64,
            ),
        ];
        let alerts = build_alerts(
            &config,
            &runtime_summary,
            &fabric_summary,
            &control_plane,
            &metrics_snapshot,
            &metric_deltas,
            &spc_signals,
        );
        let differential_privacy = DifferentialPrivacyTelemetry::from_state(
            &config,
            &runtime_summary,
            &fabric_summary,
            &control_plane,
            &metrics_snapshot,
        );
        let rollout_guard = evaluate_rollout_guard(
            &config,
            &runtime_summary,
            &fabric_summary,
            &control_plane,
            &metrics_snapshot,
        );

        let snapshot = ObservabilitySnapshot {
            started_at_ms,
            updated_at_ms: now_ms(),
            trace_journal_path: config.trace_journal_path.display().to_string(),
            runtime_summary,
            fabric: fabric_summary,
            control_plane,
            metrics: metrics_snapshot,
            metric_deltas,
            session_distribution,
            alerts,
            spc_signals,
            differential_privacy,
            rollout_guard,
        };

        let payload = serde_json::to_string_pretty(&snapshot)?;
        tokio::fs::write(&config.snapshot_path, payload).await?;
    }
}

pub fn init_trace_journal(path: PathBuf) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed to create trace journal directory {}",
                parent.display()
            )
        })?;
    }
    let _ = TRACE_JOURNAL.get_or_init(|| TraceJournal {
        path,
        lock: Mutex::new(()),
    });
    Ok(())
}

pub fn record_trace_event(
    subsystem: &str,
    severity: &str,
    correlation_id: impl Into<String>,
    flow_id: Option<String>,
    message: impl Into<String>,
    details: serde_json::Value,
) {
    let message = message.into();
    let correlation_id = correlation_id.into();
    tracing::info!(
        subsystem = subsystem,
        severity = severity,
        correlation_id = %correlation_id,
        flow_id = %flow_id.clone().unwrap_or_else(|| "-".to_string()),
        message = %message,
        details = %details,
        "trace event"
    );

    let Some(journal) = TRACE_JOURNAL.get() else {
        return;
    };
    let _guard = journal.lock.lock().unwrap();
    let event = TraceEvent {
        ts_ms: now_ms(),
        subsystem: subsystem.to_string(),
        severity: severity.to_string(),
        correlation_id,
        flow_id,
        message,
        details,
    };
    if let Ok(line) = serde_json::to_string(&event) {
        if let Ok(mut file) = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&journal.path)
        {
            let _ = writeln!(file, "{}", line);
        }
    }
}

pub fn session_correlation_id(flow_id: &str) -> String {
    let short = &flow_id[..flow_id.len().min(12)];
    format!("sess-{}", short)
}

pub fn handshake_correlation_id(
    connection_id: &ConnectionId,
    client_addr: std::net::SocketAddr,
) -> String {
    let cid = connection_id
        .as_bytes()
        .iter()
        .map(|byte| format!("{:02x}", byte))
        .collect::<String>();
    format!("hs-{}-{}", &cid[..cid.len().min(12)], client_addr)
}

impl FabricSreSummary {
    fn from_runtime_view(view: &crate::fabric::FabricRuntimeView) -> Self {
        Self {
            local_node_id: view.local_node_id.clone(),
            local_role: view.local_role.clone(),
            region: view.region.clone(),
            operator: view.operator.clone(),
            graph_revision: view.graph_revision,
            total_nodes: view.total_nodes,
            healthy_nodes: view.healthy_nodes,
            last_simulation_within_budget: view.last_simulation_within_budget,
            last_simulation_reroutes: view.last_simulation_reroutes,
            last_simulation_disconnects: view.last_simulation_disconnects,
            last_simulation_avg_failover_ms: view.last_simulation_avg_failover_ms,
        }
    }
}

impl MetricsDeltaSnapshot {
    fn from_snapshots(previous: &MetricsStateSnapshot, current: &MetricsStateSnapshot) -> Self {
        Self {
            handshake_success_delta: current
                .handshake_success_total
                .saturating_sub(previous.handshake_success_total),
            handshake_failures_delta: current
                .handshake_failures_total
                .saturating_sub(previous.handshake_failures_total),
            handshake_rate_limited_delta: current
                .handshake_rate_limited_total
                .saturating_sub(previous.handshake_rate_limited_total),
            path_roam_delta: current
                .path_roam_total
                .saturating_sub(previous.path_roam_total),
            retransmit_delta: current
                .retransmit_sent_total
                .saturating_sub(previous.retransmit_sent_total),
            retransmit_drop_delta: current
                .retransmit_dropped_total
                .saturating_sub(previous.retransmit_dropped_total),
            fec_recovery_delta: current
                .fec_recovery_total
                .saturating_sub(previous.fec_recovery_total),
            fabric_failover_delta: current
                .fabric_failover_total
                .saturating_sub(previous.fabric_failover_total),
            fabric_operator_actions_delta: current
                .fabric_operator_actions_total
                .saturating_sub(previous.fabric_operator_actions_total),
        }
    }
}

impl SessionDistributionSnapshot {
    fn from_metrics(metrics: &MetricsStateSnapshot) -> Self {
        Self {
            by_path_mode: metrics.sessions_by_path_mode.clone(),
            by_path_belief: metrics.sessions_by_path_belief.clone(),
            by_persona: metrics.sessions_by_persona.clone(),
            by_recovery_strategy: metrics.sessions_by_recovery_strategy.clone(),
        }
    }
}

impl DifferentialPrivacyTelemetry {
    fn from_state(
        config: &ObservabilityConfig,
        runtime_summary: &RuntimeSummary,
        fabric: &FabricSreSummary,
        control_plane: &ControlPlaneSreSummary,
        metrics: &MetricsStateSnapshot,
    ) -> Self {
        let sanitized_counts = BTreeMap::from([
            (
                "active_sessions".to_string(),
                runtime_summary.active_sessions as f64,
            ),
            (
                "handshake_success_total".to_string(),
                metrics.handshake_success_total as f64,
            ),
            (
                "handshake_failures_total".to_string(),
                metrics.handshake_failures_total as f64,
            ),
            (
                "fabric_failover_total".to_string(),
                metrics.fabric_failover_total as f64,
            ),
            (
                "healthy_fabric_nodes".to_string(),
                fabric.healthy_nodes as f64,
            ),
            (
                "control_plane_active_devices".to_string(),
                control_plane.active_devices as f64,
            ),
            (
                "control_plane_active_sessions".to_string(),
                control_plane.active_sessions as f64,
            ),
        ]);
        let mut noisy_counts = BTreeMap::new();
        let scale = 1.0 / config.dp_epsilon.max(0.1);
        for (metric, value) in &sanitized_counts {
            noisy_counts.insert(metric.clone(), (value + laplace_noise(scale)).max(0.0));
        }

        Self {
            epsilon: config.dp_epsilon,
            excluded_fields: vec![
                "user_id".to_string(),
                "device_id".to_string(),
                "flow_id".to_string(),
                "client_addr".to_string(),
                "tunnel_ip".to_string(),
                "raw_trace_payloads".to_string(),
            ],
            sanitized_counts,
            noisy_counts,
        }
    }
}

impl SpcTracker {
    fn new(window: usize) -> Self {
        Self {
            samples: VecDeque::with_capacity(window),
            window,
        }
    }

    fn observe(&mut self, metric: &str, current: f64) -> SpcSignal {
        if self.samples.len() == self.window {
            self.samples.pop_front();
        }
        self.samples.push_back(current);

        let sample_count = self.samples.len();
        let mean = if sample_count == 0 {
            0.0
        } else {
            self.samples.iter().sum::<f64>() / sample_count as f64
        };
        let variance = if sample_count <= 1 {
            0.0
        } else {
            self.samples
                .iter()
                .map(|value| (*value - mean).powi(2))
                .sum::<f64>()
                / sample_count as f64
        };
        let sigma = variance.sqrt();
        let lower_control_limit = mean - (3.0 * sigma);
        let upper_control_limit = mean + (3.0 * sigma);
        let out_of_control = sample_count >= 8
            && sigma > 0.0
            && (current < lower_control_limit || current > upper_control_limit);

        SpcSignal {
            metric: metric.to_string(),
            sample_count,
            current,
            mean,
            sigma,
            lower_control_limit,
            upper_control_limit,
            out_of_control,
        }
    }
}

fn build_alerts(
    config: &ObservabilityConfig,
    runtime_summary: &RuntimeSummary,
    fabric: &FabricSreSummary,
    control_plane: &ControlPlaneSreSummary,
    metrics: &MetricsStateSnapshot,
    deltas: &MetricsDeltaSnapshot,
    spc_signals: &[SpcSignal],
) -> Vec<KnownAlert> {
    let mut alerts = Vec::new();

    if deltas.handshake_failures_delta > 0
        && deltas.handshake_failures_delta >= deltas.handshake_success_delta.saturating_add(1)
    {
        alerts.push(KnownAlert {
            subsystem: "handshake".to_string(),
            severity: "warning".to_string(),
            title: "Handshake failure spike".to_string(),
            message: format!(
                "Recent interval saw {} handshake failures vs {} successes.",
                deltas.handshake_failures_delta, deltas.handshake_success_delta
            ),
            suggested_action: "Inspect trace journal by handshake correlation id and compare auth failures with control-plane revocations.".to_string(),
            runbook_hint: "Handshake failures / control plane auth path".to_string(),
        });
    }

    if runtime_summary.active_sessions > 0
        && runtime_summary.avg_loss_ratio > config.canary_max_loss_ratio
    {
        alerts.push(KnownAlert {
            subsystem: "transport".to_string(),
            severity: "critical".to_string(),
            title: "Loss ratio exceeds SRE budget".to_string(),
            message: format!(
                "Average runtime loss ratio {:.3} is above budget {:.3}.",
                runtime_summary.avg_loss_ratio, config.canary_max_loss_ratio
            ),
            suggested_action: "Correlate path manager telemetry with relay route changes and verify whether a bad rollout changed pacing, MTU or FEC policy.".to_string(),
            runbook_hint: "Transport loss / DPLPMTUD / pacing".to_string(),
        });
    }

    if runtime_summary.blackhole_suspected_sessions > config.canary_max_blackhole_sessions {
        alerts.push(KnownAlert {
            subsystem: "path_manager".to_string(),
            severity: "critical".to_string(),
            title: "Blackhole recovery triggered".to_string(),
            message: format!(
                "{} sessions are in blackhole suspicion state.",
                runtime_summary.blackhole_suspected_sessions
            ),
            suggested_action: "Check MTU probes, recent route failovers and whether the rollout changed packet sizing behavior.".to_string(),
            runbook_hint: "Blackhole recovery / MTU regression".to_string(),
        });
    }

    if control_plane.policy_conflicts > config.canary_max_policy_conflicts {
        alerts.push(KnownAlert {
            subsystem: "control_plane".to_string(),
            severity: "critical".to_string(),
            title: "Policy conflicts detected".to_string(),
            message: format!(
                "Control plane currently reports {} conflicting policy rules.",
                control_plane.policy_conflicts
            ),
            suggested_action: "Freeze rollout, inspect policy conflicts and resolve deterministic admission rules before continuing.".to_string(),
            runbook_hint: "Policy conflict / admission regression".to_string(),
        });
    }

    if fabric.healthy_nodes < config.canary_min_healthy_fabric_nodes {
        alerts.push(KnownAlert {
            subsystem: "fabric".to_string(),
            severity: "critical".to_string(),
            title: "Fabric health below canary floor".to_string(),
            message: format!(
                "Only {} healthy fabric nodes remain, but at least {} are required.",
                fabric.healthy_nodes, config.canary_min_healthy_fabric_nodes
            ),
            suggested_action: "Stop the rollout, mark unhealthy nodes explicitly and verify route graph health before serving more traffic.".to_string(),
            runbook_hint: "Fabric health / failover".to_string(),
        });
    }

    if metrics.handshake_pending > 32 {
        alerts.push(KnownAlert {
            subsystem: "handshake".to_string(),
            severity: "warning".to_string(),
            title: "Pending handshake backlog".to_string(),
            message: format!(
                "{} pending handshakes are waiting for completion.",
                metrics.handshake_pending
            ),
            suggested_action: "Inspect anti-abuse path, retry pressure and recent CPU or packet drops before increasing rollout scope.".to_string(),
            runbook_hint: "Pending handshake backlog".to_string(),
        });
    }

    if deltas.handshake_rate_limited_delta > 0 {
        alerts.push(KnownAlert {
            subsystem: "handshake".to_string(),
            severity: "warning".to_string(),
            title: "Handshake rate limiter active".to_string(),
            message: format!(
                "Recent interval throttled {} handshake attempts.",
                deltas.handshake_rate_limited_delta
            ),
            suggested_action: "Verify whether the traffic is expected beta load or abuse, then inspect trace journal and source IP concentration before relaxing limits.".to_string(),
            runbook_hint: "Handshake anti-abuse / rate limit".to_string(),
        });
    }

    for signal in spc_signals.iter().filter(|signal| signal.out_of_control) {
        alerts.push(KnownAlert {
            subsystem: "spc".to_string(),
            severity: "warning".to_string(),
            title: format!("SPC signal for {}", signal.metric),
            message: format!(
                "Metric {} moved outside 3-sigma control limits ({:.3} .. {:.3}).",
                signal.metric, signal.lower_control_limit, signal.upper_control_limit
            ),
            suggested_action: "Compare the latest rollout window with the previous stable baseline and verify whether the anomaly is explained by active incident traffic.".to_string(),
            runbook_hint: "SPC / anomaly review".to_string(),
        });
    }

    alerts
}

fn evaluate_rollout_guard(
    config: &ObservabilityConfig,
    runtime_summary: &RuntimeSummary,
    fabric: &FabricSreSummary,
    control_plane: &ControlPlaneSreSummary,
    metrics: &MetricsStateSnapshot,
) -> RolloutGuard {
    let mut reasons = Vec::new();

    if control_plane.policy_conflicts > config.canary_max_policy_conflicts {
        reasons.push(format!(
            "control-plane policy conflicts={} exceed allowed {}",
            control_plane.policy_conflicts, config.canary_max_policy_conflicts
        ));
    }
    if fabric.healthy_nodes < config.canary_min_healthy_fabric_nodes {
        reasons.push(format!(
            "healthy fabric nodes={} below required {}",
            fabric.healthy_nodes, config.canary_min_healthy_fabric_nodes
        ));
    }
    if runtime_summary.blackhole_suspected_sessions > config.canary_max_blackhole_sessions {
        reasons.push(format!(
            "blackhole-suspected sessions={} exceed allowed {}",
            runtime_summary.blackhole_suspected_sessions, config.canary_max_blackhole_sessions
        ));
    }
    if runtime_summary.active_sessions > 0 {
        if runtime_summary.avg_loss_ratio > config.canary_max_loss_ratio {
            reasons.push(format!(
                "avg_loss_ratio={:.3} above budget {:.3}",
                runtime_summary.avg_loss_ratio, config.canary_max_loss_ratio
            ));
        }
        if runtime_summary.avg_path_quality_score < config.canary_min_path_quality_score {
            reasons.push(format!(
                "avg_path_quality_score={:.2} below floor {:.2}",
                runtime_summary.avg_path_quality_score, config.canary_min_path_quality_score
            ));
        }
    }
    if metrics.handshake_pending > 128 {
        reasons.push(format!(
            "pending handshakes={} exceed emergency backlog threshold 128",
            metrics.handshake_pending
        ));
    }

    let healthy = reasons.is_empty();
    RolloutGuard {
        healthy,
        checked_at_ms: now_ms(),
        active_sessions_observed: runtime_summary.active_sessions,
        reasons,
        recommended_action: if healthy {
            "proceed".to_string()
        } else {
            "rollback".to_string()
        },
        evaluation_note: if runtime_summary.active_sessions == 0 {
            "No live sessions observed during canary evaluation; guard is using passive readiness plus control-plane/fabric health.".to_string()
        } else {
            "Guard evaluated live traffic quality, blackhole risk and control-plane consistency."
                .to_string()
        },
    }
}

fn laplace_noise(scale: f64) -> f64 {
    if scale <= 0.0 {
        return 0.0;
    }
    let mut rng = rand::thread_rng();
    let centered = rng.gen_range(0.000_001f64..0.999_999f64) - 0.5;
    let sign = if centered < 0.0 { -1.0 } else { 1.0 };
    -scale * sign * (1.0 - 2.0 * centered.abs()).ln()
}

fn env_f64(name: &str, default: f64) -> f64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<f64>().ok())
        .unwrap_or(default)
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(default)
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rollout_guard_rejects_bad_loss_budget() {
        let config = ObservabilityConfig::from_env();
        let guard = evaluate_rollout_guard(
            &config,
            &RuntimeSummary {
                active_sessions: 3,
                max_idle_secs: 10,
                max_age_secs: 20,
                avg_loss_ratio: 0.25,
                avg_path_quality_score: 20.0,
                avg_payload_budget: 1000.0,
                avg_route_diversity_score: 1.0,
                blackhole_suspected_sessions: 1,
                active_fabric_routes: 1,
                total_fabric_failovers: 0,
                total_fec_frames_sent: 0,
                total_fec_frames_received: 0,
                total_fec_recoveries: 0,
                total_suppressed_duplicates: 0,
            },
            &FabricSreSummary {
                local_node_id: "edge-local".to_string(),
                local_role: "edge".to_string(),
                region: "primary".to_string(),
                operator: "omega-core".to_string(),
                graph_revision: 1,
                total_nodes: 2,
                healthy_nodes: 1,
                last_simulation_within_budget: true,
                last_simulation_reroutes: 0,
                last_simulation_disconnects: 0,
                last_simulation_avg_failover_ms: 10.0,
            },
            &ControlPlaneSreSummary {
                revision: 1,
                users: 1,
                blocked_users: 0,
                active_devices: 1,
                active_sessions: 1,
                issued_tickets: 1,
                fabric_nodes: 2,
                policy_conflicts: 0,
                recent_audit_events: 0,
            },
            &MetricsStateSnapshot::default(),
        );
        assert!(!guard.healthy);
        assert_eq!(guard.recommended_action, "rollback");
    }

    #[test]
    fn dp_telemetry_never_exposes_negative_counts() {
        let config = ObservabilityConfig::from_env();
        let telemetry = DifferentialPrivacyTelemetry::from_state(
            &config,
            &RuntimeSummary::default(),
            &FabricSreSummary {
                local_node_id: "edge-local".to_string(),
                local_role: "edge".to_string(),
                region: "primary".to_string(),
                operator: "omega-core".to_string(),
                graph_revision: 1,
                total_nodes: 1,
                healthy_nodes: 1,
                last_simulation_within_budget: true,
                last_simulation_reroutes: 0,
                last_simulation_disconnects: 0,
                last_simulation_avg_failover_ms: 0.0,
            },
            &ControlPlaneSreSummary {
                revision: 1,
                users: 0,
                blocked_users: 0,
                active_devices: 0,
                active_sessions: 0,
                issued_tickets: 0,
                fabric_nodes: 1,
                policy_conflicts: 0,
                recent_audit_events: 0,
            },
            &MetricsStateSnapshot::default(),
        );
        assert!(telemetry.noisy_counts.values().all(|value| *value >= 0.0));
    }
}
