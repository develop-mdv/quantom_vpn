use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

use omega_stealth::StealthSnapshot;
use omega_transport::reliability::{RecoveryStrategy, ReliabilitySnapshot};
use omega_transport::transport_v2::{PathBelief, PathMode, TransportSnapshot};

use crate::config::ClientConfig;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UdpCheckStatus {
    Pending,
    Passed {
        target: String,
        responder: String,
        checked_at_ms: u64,
    },
    Failed {
        reason: String,
        checked_at_ms: u64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientDiagnosticsSnapshot {
    pub status: String,
    pub started_at_ms: u64,
    pub updated_at_ms: u64,
    pub server_endpoint: String,
    pub device_name: String,
    pub platform: String,
    pub profile: crate::config::ConnectionProfile,
    pub morphing_policy: crate::config::MorphingPolicy,
    pub persona: crate::config::PersonaId,
    pub tunnel_mode: crate::config::TunnelMode,
    pub dns_policy: crate::config::DnsPolicy,
    pub ipv6_policy: crate::config::Ipv6Policy,
    pub requested_mtu: u16,
    pub negotiated_mtu: Option<u16>,
    pub keepalive_secs: u64,
    pub udp_rcvbuf: usize,
    pub udp_sndbuf: usize,
    pub dns_servers: Vec<String>,
    pub split_routes: Vec<String>,
    pub handshake_attempts: u32,
    pub handshake_timeout_ms: u64,
    pub handshake_backoff_ms: u64,
    pub handshake_rtt_ms: Option<u64>,
    pub interface_name: Option<String>,
    pub tunnel_ip: Option<String>,
    pub udp_dns_check: UdpCheckStatus,
    pub estimated_rx_loss_ratio: f64,
    pub estimated_rx_loss_percent: f64,
    pub arq_rtt_ms: u64,
    pub transport_rtt_ms: u64,
    pub path_jitter_ms: u64,
    pub path_reordering_percent: f64,
    pub active_padding_budget: usize,
    pub active_redundancy_extra: u8,
    pub configured_persona: String,
    pub active_persona: String,
    pub persona_target_payload: usize,
    pub persona_cover_budget_bytes: usize,
    pub persona_timing_budget_ms: u16,
    pub persona_detectability_improvement_percent: f64,
    pub persona_invalid_probe_response: String,
    pub persona_observable_response_classes: u8,
    pub persona_explanation: String,
    pub transport_payload_budget: usize,
    pub path_confirmed_payload: usize,
    pub path_probe_payload: Option<usize>,
    pub path_quality: String,
    pub path_quality_score: u8,
    pub path_mode: String,
    pub path_belief: String,
    pub path_belief_confidence_percent: f64,
    pub path_route_action: String,
    pub path_blackhole_suspected: bool,
    pub path_last_action: String,
    pub path_explanation: String,
    pub reliability_control_strategy: String,
    pub reliability_interactive_strategy: String,
    pub reliability_bulk_strategy: String,
    pub reliability_explanation: String,
    pub fec_frames_sent: u64,
    pub fec_frames_received: u64,
    pub fec_recoveries: u64,
    pub duplicate_packets_sent: u64,
    pub suppressed_duplicates: u64,
    pub suspected_issue: Option<String>,
    pub last_server_packet_ms: Option<u64>,
    pub last_tun_packet_ms: Option<u64>,
    pub nacks_sent: u64,
    pub nacks_received: u64,
    pub retransmits_sent: u64,
}

#[derive(Clone)]
pub struct ClientDiagnostics {
    path: PathBuf,
    snapshot: Arc<Mutex<ClientDiagnosticsSnapshot>>,
}

impl ClientDiagnostics {
    pub fn new(
        path: PathBuf,
        config: &ClientConfig,
        server_endpoint: SocketAddr,
        device_name: &str,
        platform: &str,
    ) -> Self {
        let now = now_ms();
        Self {
            path,
            snapshot: Arc::new(Mutex::new(ClientDiagnosticsSnapshot {
                status: "starting".to_string(),
                started_at_ms: now,
                updated_at_ms: now,
                server_endpoint: server_endpoint.to_string(),
                device_name: device_name.to_string(),
                platform: platform.to_string(),
                profile: config.profile,
                morphing_policy: config.morphing_policy,
                persona: config.persona,
                tunnel_mode: config.tunnel_mode,
                dns_policy: config.dns_policy,
                ipv6_policy: config.ipv6_policy,
                requested_mtu: config.requested_mtu,
                negotiated_mtu: None,
                keepalive_secs: config.keepalive_secs,
                udp_rcvbuf: config.udp_rcvbuf,
                udp_sndbuf: config.udp_sndbuf,
                dns_servers: config.dns_servers.clone(),
                split_routes: config
                    .split_routes
                    .iter()
                    .map(|route| route.cidr.clone())
                    .collect(),
                handshake_attempts: config.handshake_attempts,
                handshake_timeout_ms: config.handshake_timeout_ms,
                handshake_backoff_ms: config.handshake_backoff_ms,
                handshake_rtt_ms: None,
                interface_name: None,
                tunnel_ip: None,
                udp_dns_check: UdpCheckStatus::Pending,
                estimated_rx_loss_ratio: 0.0,
                estimated_rx_loss_percent: 0.0,
                arq_rtt_ms: 350,
                transport_rtt_ms: 350,
                path_jitter_ms: 0,
                path_reordering_percent: 0.0,
                active_padding_budget: config.morphing_policy.padding_budget_cap(),
                active_redundancy_extra: 0,
                configured_persona: config.persona.label().to_string(),
                active_persona: config.persona.label().to_string(),
                persona_target_payload: 0,
                persona_cover_budget_bytes: config.morphing_policy.padding_budget_cap(),
                persona_timing_budget_ms: 0,
                persona_detectability_improvement_percent: 0.0,
                persona_invalid_probe_response: "uniform_reject".to_string(),
                persona_observable_response_classes: 0,
                persona_explanation: "stealth engine is waiting for live transport telemetry"
                    .to_string(),
                transport_payload_budget: 0,
                path_confirmed_payload: 0,
                path_probe_payload: None,
                path_quality: "starting".to_string(),
                path_quality_score: 0,
                path_mode: "starting".to_string(),
                path_belief: "stable".to_string(),
                path_belief_confidence_percent: 0.0,
                path_route_action: "hold_route".to_string(),
                path_blackhole_suspected: false,
                path_last_action: "handshake pending".to_string(),
                path_explanation: "path manager is waiting for live transport telemetry"
                    .to_string(),
                reliability_control_strategy: "retransmit_only".to_string(),
                reliability_interactive_strategy: "retransmit_only".to_string(),
                reliability_bulk_strategy: "retransmit_only".to_string(),
                reliability_explanation:
                    "reliability controller is waiting for live path telemetry".to_string(),
                fec_frames_sent: 0,
                fec_frames_received: 0,
                fec_recoveries: 0,
                duplicate_packets_sent: 0,
                suppressed_duplicates: 0,
                suspected_issue: None,
                last_server_packet_ms: None,
                last_tun_packet_ms: None,
                nacks_sent: 0,
                nacks_received: 0,
                retransmits_sent: 0,
            })),
        }
    }

    pub fn spawn_writer(&self) {
        let path = self.path.clone();
        let snapshot = self.snapshot.clone();
        tokio::spawn(async move {
            if let Some(parent) = path.parent() {
                if let Err(err) = tokio::fs::create_dir_all(parent).await {
                    tracing::warn!(error = %err, path = %path.display(), "failed to create diagnostics directory");
                    return;
                }
            }

            let mut interval = tokio::time::interval(Duration::from_secs(5));
            loop {
                interval.tick().await;
                let payload = {
                    let mut guard = snapshot.lock().unwrap();
                    guard.updated_at_ms = now_ms();
                    match serde_json::to_string_pretty(&*guard) {
                        Ok(json) => json,
                        Err(err) => {
                            tracing::warn!(error = %err, "failed to serialize client diagnostics");
                            continue;
                        }
                    }
                };

                if let Err(err) = tokio::fs::write(&path, payload).await {
                    tracing::warn!(error = %err, path = %path.display(), "failed to write client diagnostics");
                }
            }
        });
    }

    pub fn set_status(&self, status: impl Into<String>) {
        self.with_snapshot(|snapshot| {
            snapshot.status = status.into();
        });
    }

    pub fn set_handshake(&self, tunnel_ip: std::net::Ipv4Addr, negotiated_mtu: u16, rtt_ms: u64) {
        self.with_snapshot(|snapshot| {
            snapshot.status = "connected".to_string();
            snapshot.tunnel_ip = Some(tunnel_ip.to_string());
            snapshot.negotiated_mtu = Some(negotiated_mtu);
            snapshot.handshake_rtt_ms = Some(rtt_ms);
            let (quality, suspected_issue) = summarize_path(snapshot);
            snapshot.path_quality = quality;
            snapshot.suspected_issue = suspected_issue;
        });
    }

    pub fn set_interface_name(&self, interface_name: String) {
        self.with_snapshot(|snapshot| {
            snapshot.interface_name = Some(interface_name);
        });
    }

    pub fn note_server_packet(&self) {
        self.with_snapshot(|snapshot| {
            snapshot.last_server_packet_ms = Some(now_ms());
        });
    }

    pub fn note_tun_packet(&self) {
        self.with_snapshot(|snapshot| {
            snapshot.last_tun_packet_ms = Some(now_ms());
        });
    }

    pub fn record_nack_sent(&self) {
        self.with_snapshot(|snapshot| {
            snapshot.nacks_sent += 1;
        });
    }

    pub fn record_nack_received(&self) {
        self.with_snapshot(|snapshot| {
            snapshot.nacks_received += 1;
        });
    }

    pub fn record_retransmits(&self, count: usize) {
        if count == 0 {
            return;
        }
        self.with_snapshot(|snapshot| {
            snapshot.retransmits_sent += count as u64;
        });
    }

    pub fn udp_check_passed(&self, target: SocketAddr, responder: SocketAddr) {
        self.with_snapshot(|snapshot| {
            snapshot.udp_dns_check = UdpCheckStatus::Passed {
                target: target.to_string(),
                responder: responder.to_string(),
                checked_at_ms: now_ms(),
            };
            let (quality, suspected_issue) = summarize_path(snapshot);
            snapshot.path_quality = quality;
            snapshot.suspected_issue = suspected_issue;
        });
    }

    pub fn udp_check_failed(&self, reason: impl Into<String>) {
        self.with_snapshot(|snapshot| {
            snapshot.udp_dns_check = UdpCheckStatus::Failed {
                reason: reason.into(),
                checked_at_ms: now_ms(),
            };
            let (quality, suspected_issue) = summarize_path(snapshot);
            snapshot.path_quality = quality;
            snapshot.suspected_issue = suspected_issue;
        });
    }

    pub fn update_path_metrics(
        &self,
        transport: &TransportSnapshot,
        padding_budget: usize,
        redundancy_extra: usize,
    ) {
        self.with_snapshot(|snapshot| {
            snapshot.estimated_rx_loss_ratio =
                (transport.path.loss_percent / 100.0).clamp(0.0, 1.0);
            snapshot.estimated_rx_loss_percent = transport.path.loss_percent;
            snapshot.arq_rtt_ms = transport.srtt_ms;
            snapshot.transport_rtt_ms = transport.srtt_ms;
            snapshot.path_jitter_ms = transport.path.jitter_ms;
            snapshot.path_reordering_percent = transport.path.reordering_percent;
            snapshot.active_padding_budget = padding_budget;
            snapshot.active_redundancy_extra = redundancy_extra.min(u8::MAX as usize) as u8;
            snapshot.transport_payload_budget = transport.path.payload_budget;
            snapshot.path_confirmed_payload = transport.path.confirmed_payload;
            snapshot.path_probe_payload = transport.path.probe_target_payload;
            snapshot.path_quality = transport.path.quality_bucket.clone();
            snapshot.path_quality_score = transport.path.quality_score;
            snapshot.path_mode = mode_label(transport.path.mode).to_string();
            snapshot.path_belief = belief_label(transport.path.belief).to_string();
            snapshot.path_belief_confidence_percent = transport.path.belief_confidence;
            snapshot.path_route_action = transport.path.route_action.clone();
            snapshot.path_blackhole_suspected = transport.path.blackhole_suspected;
            snapshot.path_last_action = transport.path.last_action.clone();
            snapshot.path_explanation = transport.path.explanation.clone();

            let (quality, suspected_issue) = summarize_path(snapshot);
            snapshot.path_quality = quality;
            snapshot.suspected_issue = suspected_issue;
        });
    }

    pub fn update_stealth_metrics(&self, stealth: &StealthSnapshot) {
        self.with_snapshot(|snapshot| {
            snapshot.configured_persona = stealth.configured_persona.label().to_string();
            snapshot.active_persona = stealth.active_persona.label().to_string();
            snapshot.persona_target_payload = stealth.target_payload_floor;
            snapshot.persona_cover_budget_bytes = stealth.cover_budget_bytes;
            snapshot.persona_timing_budget_ms = stealth.timing_budget_ms;
            snapshot.persona_detectability_improvement_percent =
                stealth.detectability_improvement_percent;
            snapshot.persona_invalid_probe_response = match stealth.invalid_probe_response {
                omega_stealth::ProbeResponseClass::SilentDrop => "silent_drop".to_string(),
                omega_stealth::ProbeResponseClass::UniformReject => "uniform_reject".to_string(),
            };
            snapshot.persona_observable_response_classes = stealth.observable_response_classes;
            snapshot.persona_explanation = stealth.explanation.clone();
        });
    }
    pub fn update_reliability_metrics(
        &self,
        reliability: &ReliabilitySnapshot,
        fec_frames_sent: u64,
        fec_frames_received: u64,
        fec_recoveries: u64,
        duplicate_packets_sent: u64,
        suppressed_duplicates: u64,
    ) {
        self.with_snapshot(|snapshot| {
            snapshot.reliability_control_strategy =
                recovery_strategy_label(reliability.control_strategy).to_string();
            snapshot.reliability_interactive_strategy =
                recovery_strategy_label(reliability.interactive_strategy).to_string();
            snapshot.reliability_bulk_strategy =
                recovery_strategy_label(reliability.bulk_strategy).to_string();
            snapshot.reliability_explanation = reliability.explainability.clone();
            snapshot.fec_frames_sent = fec_frames_sent;
            snapshot.fec_frames_received = fec_frames_received;
            snapshot.fec_recoveries = fec_recoveries;
            snapshot.duplicate_packets_sent = duplicate_packets_sent;
            snapshot.suppressed_duplicates = suppressed_duplicates;
        });
    }
    fn with_snapshot<F>(&self, f: F)
    where
        F: FnOnce(&mut ClientDiagnosticsSnapshot),
    {
        let mut guard = self.snapshot.lock().unwrap();
        f(&mut guard);
        guard.updated_at_ms = now_ms();
    }
}

fn summarize_path(snapshot: &ClientDiagnosticsSnapshot) -> (String, Option<String>) {
    let udp_diag_failed = matches!(snapshot.udp_dns_check, UdpCheckStatus::Failed { .. });

    if udp_diag_failed {
        return (
            "critical".to_string(),
            Some(
                "generic UDP inside the tunnel is failing; check server NAT, outbound UDP rules, or upstream filtering"
                    .to_string(),
            ),
        );
    }

    if snapshot.path_blackhole_suspected {
        return (
            "critical".to_string(),
            Some(
                "path manager detected a blackhole pattern and reduced payload size; the active route is dropping larger packets"
                    .to_string(),
            ),
        );
    }

    if snapshot.estimated_rx_loss_percent >= 12.0 || snapshot.path_quality_score <= 30 {
        return (
            "critical".to_string(),
            Some(
                "the active network path is severely degraded; sustained loss or reordering is overwhelming recovery"
                    .to_string(),
            ),
        );
    }

    if snapshot.estimated_rx_loss_percent >= 5.0
        || snapshot.path_jitter_ms >= 30
        || snapshot.path_quality_score <= 50
    {
        return (
            "poor".to_string(),
            Some(
                "short-term congestion or unstable packet ordering is forcing the tunnel into a cautious mode"
                    .to_string(),
            ),
        );
    }

    let handshake_rtt_ms = snapshot
        .handshake_rtt_ms
        .unwrap_or(snapshot.transport_rtt_ms);
    if handshake_rtt_ms >= 350 {
        return (
            "fair".to_string(),
            Some(
                "base RTT to the VPN server is already high; route length or server location is the likely bottleneck"
                    .to_string(),
            ),
        );
    }

    if snapshot.path_quality_score <= 70
        || snapshot.transport_rtt_ms >= 220
        || snapshot.path_reordering_percent >= 3.0
        || snapshot.active_redundancy_extra > 0
    {
        return ("fair".to_string(), None);
    }

    if snapshot.path_quality_score >= 88 && snapshot.transport_rtt_ms < 140 {
        return ("excellent".to_string(), None);
    }

    ("good".to_string(), None)
}

fn mode_label(mode: PathMode) -> &'static str {
    match mode {
        PathMode::Stable => "stable",
        PathMode::Probing => "probing",
        PathMode::Cautious => "cautious",
        PathMode::Roaming => "roaming",
        PathMode::Recovering => "recovering",
        PathMode::BlackholeRecovery => "blackhole_recovery",
    }
}

fn belief_label(belief: PathBelief) -> &'static str {
    match belief {
        PathBelief::Stable => "stable",
        PathBelief::Congested => "congested",
        PathBelief::Reordered => "reordered",
        PathBelief::BlackholeRisk => "blackhole_risk",
        PathBelief::Recovering => "recovering",
    }
}

fn recovery_strategy_label(strategy: RecoveryStrategy) -> &'static str {
    match strategy {
        RecoveryStrategy::RetransmitOnly => "retransmit_only",
        RecoveryStrategy::DuplicateOnce => "duplicate_once",
        RecoveryStrategy::FecLow => "fec_low",
        RecoveryStrategy::FecMedium => "fec_medium",
        RecoveryStrategy::FecHigh => "fec_high",
    }
}

pub fn load_snapshot(path: &Path) -> anyhow::Result<Option<ClientDiagnosticsSnapshot>> {
    match std::fs::read_to_string(path) {
        Ok(raw) => {
            match serde_json::from_str(&raw) {
                Ok(snapshot) => Ok(Some(snapshot)),
                Err(err) => {
                    tracing::warn!(
                        error = %err,
                        path = %path.display(),
                        "failed to parse diagnostics snapshot; treating it as stale state"
                    );
                    Ok(None)
                }
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(anyhow::anyhow!(
            "failed to read diagnostics snapshot {}: {err}",
            path.display()
        )),
    }
}
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
