use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use omega_control::control_plane::SessionActivation;
use omega_control::identity::IdentityStore;
use omega_core_crypto::SessionKeys;
use omega_core_wire::{
    ConnectionId, FlowId, HeaderProtectionKey, NackMessage, TrafficClass, TransportFrame,
    TOTAL_OVERHEAD,
};
use omega_relay::{FailoverDecision, SessionFabricState};
use omega_stealth::{ChaosPrng, PersonaId, StealthEngine, StealthSnapshot};
use omega_transport::arq::{GapDetector, LossEstimator, RetransmitQueue};
use omega_transport::raptorq_mgr::{
    build_live_fec_frames, FecConfig, FecEncoder, FecState, LiveFecReceiver,
};
use omega_transport::reliability::{RecoveryStrategy, ReliabilityController, ReliabilitySnapshot};
use omega_transport::replay::ReplayFilter;
use omega_transport::transport_v2::{
    CompletedMessage, PathBelief, PathMode, TransportConfig, TransportEndpoint, TransportSnapshot,
};
use serde::Serialize;

use crate::{metrics, observability};

const SESSION_TTL: Duration = Duration::from_secs(120);
const CLEANUP_INTERVAL: Duration = Duration::from_secs(30);
const MAX_SESSIONS: usize = 10_000;

const POOL_START: u32 = 2; // 10.7.0.2
const POOL_END: u32 = 65_534; // 10.7.255.254
const POOL_SIZE: u32 = POOL_END - POOL_START + 1;
const DEFAULT_INITIAL_ARQ_RTT_MS: u64 = 350;
const PADDING_BUDGET_MIN: usize = 0;
const PADDING_RECOVERY_STEP: usize = 24;
const PADDING_RECOVERY_INTERVAL_SECS: u64 = 2;
const REDUNDANCY_EXTRA_MAX: u8 = 2;
const REDUNDANCY_DECAY_SECS: u64 = 8;

pub struct SessionState {
    pub keys: SessionKeys,
    pub chaos: ChaosPrng,
    pub replay_filter: ReplayFilter,
    pub send_seq: u32,
    pub max_send_seq: u32,
    pub rtp_seq: u16,
    pub rtp_timestamp: u32,
    pub ssrc: u32,
    pub morphing_policy: omega_stealth::MorphingPolicy,
    pub stealth: StealthEngine,
    pub fabric: SessionFabricState,
    pub client_addr: SocketAddr,
    pub tunnel_ip: Ipv4Addr,
    pub user_id: String,
    pub device_id: String,
    pub created_at: Instant,
    pub last_seen: Instant,
    pub fec_enabled: bool,
    pub padding_budget: usize,
    pub last_padding_adjust: Instant,
    pub redundancy_extra: u8,
    pub last_redundancy_adjust: Instant,

    pub retransmit_queue: RetransmitQueue,
    pub gap_detector: GapDetector,
    pub loss_estimator: LossEstimator,
    pub transport: TransportEndpoint,
    pub header_protection: HeaderProtectionKey,
    pub transport_payload_budget: usize,
    pub reliability: ReliabilityController,
    pub live_fec: LiveFecReceiver,
    pub fec_encoder: FecEncoder,
    pub fec_state: FecState,
    pub fec_frames_sent: u64,
    pub fec_frames_received: u64,
    pub fec_recoveries: u64,
    pub duplicate_packets_sent: u64,
    pub suppressed_duplicates: u64,

    pub loss_est_seq: u32,
    pub loss_est_init: bool,
}

impl SessionState {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        keys: SessionKeys,
        client_addr: SocketAddr,
        tunnel_ip: Ipv4Addr,
        user_id: String,
        device_id: String,
        chaos_seed: u64,
        fec_enabled: bool,
        morphing_policy: omega_stealth::MorphingPolicy,
        fabric: SessionFabricState,
        persona: PersonaId,
        ssrc: u32,
    ) -> Self {
        let fec_config = FecConfig::default();
        let fec_state = FecState::new(fec_config);
        let fec_encoder = FecEncoder::new(fec_config);
        let stealth = StealthEngine::new(persona);
        let max_cover_budget = stealth.max_cover_budget_bytes();

        Self {
            keys,
            chaos: ChaosPrng::new(chaos_seed),
            replay_filter: ReplayFilter::new(),
            send_seq: 0,
            max_send_seq: 0,
            rtp_seq: 0,
            rtp_timestamp: 0,
            ssrc,
            morphing_policy,
            stealth,
            fabric,
            client_addr,
            tunnel_ip,
            user_id,
            device_id,
            created_at: Instant::now(),
            last_seen: Instant::now(),
            fec_enabled,
            padding_budget: morphing_policy.padding_budget_cap().max(max_cover_budget),
            last_padding_adjust: Instant::now(),
            redundancy_extra: 0,
            last_redundancy_adjust: Instant::now(),
            retransmit_queue: RetransmitQueue::with_initial_rtt(DEFAULT_INITIAL_ARQ_RTT_MS),
            gap_detector: GapDetector::new(),
            loss_estimator: LossEstimator::new(),
            transport: TransportEndpoint::new(
                ConnectionId([0u8; 8]),
                [0u8; 32],
                TransportConfig::default(),
            ),
            header_protection: HeaderProtectionKey::derive(&[0u8; 32]),
            transport_payload_budget: TransportConfig::default().max_datagram_payload,
            reliability: ReliabilityController::new(),
            live_fec: LiveFecReceiver::new(),
            fec_encoder,
            fec_state,
            fec_frames_sent: 0,
            fec_frames_received: 0,
            fec_recoveries: 0,
            duplicate_packets_sent: 0,
            suppressed_duplicates: 0,
            loss_est_seq: 0,
            loss_est_init: false,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_transport(
        keys: SessionKeys,
        client_addr: SocketAddr,
        tunnel_ip: Ipv4Addr,
        user_id: String,
        device_id: String,
        chaos_seed: u64,
        fec_enabled: bool,
        morphing_policy: omega_stealth::MorphingPolicy,
        fabric: SessionFabricState,
        persona: PersonaId,
        ssrc: u32,
        connection_id: ConnectionId,
        transport_secret: [u8; 32],
        header_secret: [u8; 32],
        mtu: u16,
    ) -> Self {
        let max_payload = (mtu as usize).saturating_sub(TOTAL_OVERHEAD).max(256);
        let mut state = Self::new(
            keys,
            client_addr,
            tunnel_ip,
            user_id,
            device_id,
            chaos_seed,
            fec_enabled,
            morphing_policy,
            fabric,
            persona,
            ssrc,
        );
        state.transport_payload_budget = max_payload;
        state.header_protection = HeaderProtectionKey::derive(&header_secret);
        state.transport = TransportEndpoint::new(
            connection_id,
            transport_secret,
            TransportConfig {
                max_datagram_payload: max_payload,
                ..TransportConfig::default()
            },
        );
        state
    }
    pub fn next_send_seq(&mut self) -> u32 {
        let seq = self.send_seq;
        self.send_seq = self.send_seq.wrapping_add(1);
        seq
    }

    pub fn next_rtp_seq(&mut self) -> u16 {
        let seq = self.rtp_seq;
        self.rtp_seq = self.rtp_seq.wrapping_add(1);
        seq
    }

    pub fn advance_rtp_timestamp(&mut self, is_audio: bool) {
        self.rtp_timestamp = self
            .rtp_timestamp
            .wrapping_add(if is_audio { 960 } else { 3000 });
    }

    pub fn update_loss_stats(&mut self, received_seq: u32) {
        if !self.loss_est_init {
            self.loss_est_seq = received_seq;
            self.loss_est_init = true;
            self.loss_estimator.record(true);
            return;
        }

        let diff = received_seq.wrapping_sub(self.loss_est_seq);
        if diff == 0 {
            return;
        }

        if diff < 0x8000_0000 {
            let lost_count = diff - 1;
            let to_record_lost = lost_count.min(256);

            for _ in 0..to_record_lost {
                self.loss_estimator.record(false);
            }
            self.loss_estimator.record(true);
            self.loss_est_seq = received_seq;
        }
    }

    pub fn loss_ratio(&self) -> f64 {
        self.loss_estimator.loss_ratio()
    }

    pub fn observe_inbound_seq(&mut self, seq: u32) -> Option<NackMessage> {
        let nack = self.gap_detector.record_received(seq);
        self.update_loss_stats(seq);
        nack
    }

    pub fn touch(&mut self) {
        self.last_seen = Instant::now();
    }

    pub fn current_padding_budget(&mut self) -> usize {
        let padding_cap = self
            .morphing_policy
            .padding_budget_cap()
            .max(self.stealth.max_cover_budget_bytes());
        if padding_cap == 0 {
            self.padding_budget = 0;
            return 0;
        }

        let elapsed = self.last_padding_adjust.elapsed().as_secs();
        let ticks = elapsed / PADDING_RECOVERY_INTERVAL_SECS;
        if ticks > 0 {
            let growth = (ticks as usize).saturating_mul(PADDING_RECOVERY_STEP);
            self.padding_budget = self.padding_budget.saturating_add(growth).min(padding_cap);
            self.last_padding_adjust = Instant::now();
        }
        self.padding_budget.min(padding_cap)
    }

    pub fn on_remote_nack(&mut self, nack: &NackMessage) {
        let missing = nack.bitmap.count_ones() as usize;
        if missing == 0 {
            return;
        }

        if matches!(self.morphing_policy, omega_stealth::MorphingPolicy::Off)
            && self.stealth.max_cover_budget_bytes() == 0
        {
            self.padding_budget = 0;
            self.redundancy_extra = 0;
            self.last_padding_adjust = Instant::now();
            self.last_redundancy_adjust = Instant::now();
            return;
        }

        let penalty = 16 + missing.saturating_mul(8);
        self.padding_budget = self
            .padding_budget
            .saturating_sub(penalty)
            .max(PADDING_BUDGET_MIN);
        self.last_padding_adjust = Instant::now();

        let bump = if missing >= 16 { 2 } else { 1 };
        self.redundancy_extra = self
            .redundancy_extra
            .saturating_add(bump)
            .min(REDUNDANCY_EXTRA_MAX);
        self.last_redundancy_adjust = Instant::now();
    }

    pub fn current_redundancy_extra(&mut self) -> usize {
        if matches!(self.morphing_policy, omega_stealth::MorphingPolicy::Off) {
            self.redundancy_extra = 0;
            return 0;
        }

        let elapsed = self.last_redundancy_adjust.elapsed().as_secs();
        let ticks = elapsed / REDUNDANCY_DECAY_SECS;
        if ticks > 0 {
            self.redundancy_extra = self.redundancy_extra.saturating_sub(ticks as u8);
            self.last_redundancy_adjust = Instant::now();
        }
        self.redundancy_extra as usize
    }

    pub fn observe_transport_snapshot(&mut self, snapshot: &TransportSnapshot) {
        self.reliability.observe_path(&snapshot.path);
        self.fec_state.update(snapshot.path.loss_percent);
        let reliability = self.reliability.snapshot();
        self.stealth.observe_network(&snapshot.path, &reliability);
        self.live_fec.prune(Instant::now());
    }

    pub fn queue_protected_message(&mut self, class: TrafficClass, payload: Vec<u8>) -> u32 {
        let snapshot = self.transport.snapshot();
        self.observe_transport_snapshot(&snapshot);

        let message_id = self.transport.queue_message(class, payload.clone());
        if !self.fec_enabled {
            return message_id;
        }

        if let Some(plan) = self.reliability.plan_for(class, payload.len()) {
            for _ in 0..plan.duplicate_packets {
                self.transport
                    .queue_duplicate_message(message_id, class, payload.clone());
                self.duplicate_packets_sent += 1;
            }

            if plan.repair_packets > 0 {
                if let Some(block) = self.fec_encoder.encode_live_block(
                    &payload,
                    plan.symbol_size,
                    plan.repair_packets,
                ) {
                    let frames =
                        build_live_fec_frames(message_id, class, &block.oti, &block.packets);
                    self.fec_frames_sent += frames.len() as u64;
                    for frame in frames {
                        self.transport.queue_fec_frame(frame);
                    }
                }
            }
        }

        message_id
    }

    pub fn accept_transport_messages(
        &mut self,
        now: Instant,
        messages: Vec<CompletedMessage>,
    ) -> Vec<CompletedMessage> {
        let mut accepted = Vec::with_capacity(messages.len());
        for message in messages {
            if self
                .live_fec
                .accept_transport_message(now, message.message_id)
            {
                accepted.push(message);
            } else {
                self.suppressed_duplicates += 1;
            }
        }
        accepted
    }

    pub fn recover_fec_messages(
        &mut self,
        now: Instant,
        frames: &[TransportFrame],
    ) -> Vec<CompletedMessage> {
        let mut recovered = Vec::new();
        for frame in frames {
            let TransportFrame::Fec(fec) = frame else {
                continue;
            };
            self.fec_frames_received += 1;
            if let Some(block) = self.live_fec.observe_frame(now, fec) {
                self.transport.discard_message(block.block_id);
                self.fec_recoveries += 1;
                recovered.push(CompletedMessage {
                    message_id: block.block_id,
                    class: block.class,
                    payload: block.payload,
                });
            }
        }
        recovered
    }

    pub fn stealth_padding_floor(
        &mut self,
        encoded_len: usize,
        payload_budget: usize,
        dynamic_padding_budget: usize,
    ) -> Option<usize> {
        self.stealth.target_padding_floor(
            encoded_len,
            payload_budget,
            dynamic_padding_budget,
            &mut self.chaos,
        )
    }

    pub fn stealth_snapshot(&self) -> StealthSnapshot {
        self.stealth.snapshot()
    }

    pub fn apply_fabric_failover(&mut self, decision: FailoverDecision) {
        self.fabric.apply_failover(decision);
        self.transport.note_peer_roam(Instant::now());
        self.touch();
    }

    pub fn reliability_snapshot(&self) -> ReliabilitySnapshot {
        self.reliability.snapshot()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ActiveSessionView {
    pub correlation_id: String,
    pub flow_id: String,
    pub user_id: String,
    pub device_id: String,
    pub tunnel_ip: String,
    pub client_addr: String,
    pub age_secs: u64,
    pub idle_secs: u64,
    pub loss_ratio: f64,
    pub fec_enabled: bool,
    pub payload_budget: usize,
    pub path_quality_score: u8,
    pub path_mode: String,
    pub path_belief: String,
    pub blackhole_suspected: bool,
    pub path_explanation: String,
    pub reliability_control_strategy: String,
    pub reliability_interactive_strategy: String,
    pub reliability_bulk_strategy: String,
    pub reliability_explanation: String,
    pub configured_persona: String,
    pub active_persona: String,
    pub persona_target_payload: usize,
    pub persona_cover_budget_bytes: usize,
    pub persona_timing_budget_ms: u16,
    pub persona_detectability_improvement_percent: f64,
    pub persona_invalid_probe_response: String,
    pub persona_explanation: String,
    pub fabric_local_node_id: String,
    pub fabric_active_route_id: String,
    pub fabric_active_nodes: Vec<String>,
    pub fabric_backup_route_ids: Vec<String>,
    pub fabric_route_diversity_score: f64,
    pub fabric_failover_count: u32,
    pub fabric_last_failover_reason: String,
    pub fabric_last_failover_ms: u64,
    pub fabric_ticket_generation: u32,
    pub fabric_ticket_expires_ms: u64,
    pub fec_frames_sent: u64,
    pub fec_frames_received: u64,
    pub fec_recoveries: u64,
    pub duplicate_packets_sent: u64,
    pub suppressed_duplicates: u64,
}

pub struct SessionManager {
    sessions: Arc<DashMap<FlowId, SessionState>>,
    tunnel_ip_to_flow: Arc<DashMap<Ipv4Addr, FlowId>>,
    flow_to_user: Arc<DashMap<FlowId, String>>,
    flow_to_device: Arc<DashMap<FlowId, String>>,
    user_to_flows: Arc<DashMap<String, Vec<FlowId>>>,
    device_to_flows: Arc<DashMap<String, Vec<FlowId>>>,
    device_leases: Arc<DashMap<String, Ipv4Addr>>,
    lease_to_device: Arc<DashMap<Ipv4Addr, String>>,
    next_ip_cursor: AtomicU32,
    control_plane: Option<Arc<IdentityStore>>,
}

impl SessionManager {
    pub fn new() -> Self {
        Self::with_control_plane_opt(None)
    }

    pub fn with_control_plane(control_plane: Arc<IdentityStore>) -> Self {
        Self::with_control_plane_opt(Some(control_plane))
    }

    fn with_control_plane_opt(control_plane: Option<Arc<IdentityStore>>) -> Self {
        Self {
            sessions: Arc::new(DashMap::with_capacity(1_024)),
            tunnel_ip_to_flow: Arc::new(DashMap::with_capacity(1_024)),
            flow_to_user: Arc::new(DashMap::with_capacity(1_024)),
            flow_to_device: Arc::new(DashMap::with_capacity(1_024)),
            user_to_flows: Arc::new(DashMap::with_capacity(1_024)),
            device_to_flows: Arc::new(DashMap::with_capacity(1_024)),
            device_leases: Arc::new(DashMap::with_capacity(1_024)),
            lease_to_device: Arc::new(DashMap::with_capacity(1_024)),
            next_ip_cursor: AtomicU32::new(POOL_START),
            control_plane,
        }
    }

    pub fn insert(
        &self,
        flow_id: FlowId,
        state: SessionState,
        activation: SessionActivation,
    ) -> bool {
        if self.sessions.len() >= MAX_SESSIONS {
            return false;
        }

        let user_id = state.user_id.clone();
        let device_id = state.device_id.clone();
        let tunnel_ip = state.tunnel_ip;
        let client_addr = state.client_addr.to_string();
        let fec_enabled = state.fec_enabled;
        let active_route_id = activation.active_route_id.clone();
        let policy_id = activation.policy_id.clone();
        let mode = format!("{:?}", activation.mode).to_ascii_lowercase();

        self.tunnel_ip_to_flow.insert(tunnel_ip, flow_id);
        self.flow_to_user.insert(flow_id, user_id.clone());
        self.flow_to_device.insert(flow_id, device_id.clone());
        push_flow(&self.user_to_flows, &user_id, flow_id);
        push_flow(&self.device_to_flows, &device_id, flow_id);
        self.sessions.insert(flow_id, state);

        if let Some(control_plane) = &self.control_plane {
            if let Err(err) = control_plane.activate_session(activation, "session_manager") {
                tracing::warn!(error = %err, flow_id = %flow_id_to_hex(&flow_id), "failed to project active session into control plane");
            }
        }

        metrics::update_session_count(self.count());
        metrics::update_user_session_count(&user_id, self.count_user_sessions(&user_id));

        let flow_hex = flow_id_to_hex(&flow_id);
        observability::record_trace_event(
            "session",
            "info",
            observability::session_correlation_id(&flow_hex),
            Some(flow_hex),
            "session activated",
            serde_json::json!({
                "policy_id": policy_id,
                "mode": mode,
                "active_route_id": active_route_id,
                "client_addr": client_addr,
                "tunnel_ip": tunnel_ip.to_string(),
                "fec_enabled": fec_enabled,
                "active_sessions": self.count(),
            }),
        );
        true
    }

    pub fn get(
        &self,
        flow_id: &FlowId,
    ) -> Option<dashmap::mapref::one::RefMut<'_, FlowId, SessionState>> {
        self.sessions.get_mut(flow_id)
    }

    pub fn flow_by_tunnel_ip(&self, ip: Ipv4Addr) -> Option<FlowId> {
        self.tunnel_ip_to_flow.get(&ip).map(|v| *v)
    }

    pub fn remove(&self, flow_id: &FlowId) -> Option<SessionState> {
        self.remove_with_reason(flow_id, "runtime_remove")
    }

    pub fn remove_with_reason(&self, flow_id: &FlowId, reason: &str) -> Option<SessionState> {
        let removed = self.sessions.remove(flow_id)?;
        let (_flow, state) = removed;

        let user_id = state.user_id.clone();
        let device_id = state.device_id.clone();
        let tunnel_ip = state.tunnel_ip;

        self.flow_to_user.remove(flow_id);
        self.flow_to_device.remove(flow_id);
        remove_flow(&self.user_to_flows, &user_id, *flow_id);
        remove_flow(&self.device_to_flows, &device_id, *flow_id);

        let mapped = self.tunnel_ip_to_flow.get(&tunnel_ip).map(|v| *v);
        if mapped == Some(*flow_id) {
            if let Some(next) = self
                .device_to_flows
                .get(&device_id)
                .and_then(|v| v.first().copied())
            {
                self.tunnel_ip_to_flow.insert(tunnel_ip, next);
            } else {
                self.tunnel_ip_to_flow.remove(&tunnel_ip);
            }
        }

        if let Some(control_plane) = &self.control_plane {
            if let Err(err) = control_plane.terminate_session_record(
                &flow_id_to_hex(flow_id),
                reason,
                "session_manager",
            ) {
                tracing::warn!(error = %err, flow_id = %flow_id_to_hex(flow_id), "failed to project terminated session into control plane");
            }
        }

        metrics::update_session_count(self.count());
        metrics::update_user_session_count(&user_id, self.count_user_sessions(&user_id));

        let flow_hex = flow_id_to_hex(flow_id);
        observability::record_trace_event(
            "session",
            "info",
            observability::session_correlation_id(&flow_hex),
            Some(flow_hex),
            "session removed",
            serde_json::json!({
                "reason": reason,
                "client_addr": state.client_addr.to_string(),
                "tunnel_ip": state.tunnel_ip.to_string(),
                "age_secs": state.created_at.elapsed().as_secs(),
                "idle_secs": state.last_seen.elapsed().as_secs(),
                "active_sessions": self.count(),
            }),
        );

        Some(state)
    }

    pub fn terminate_session(&self, flow_id: &FlowId) -> bool {
        self.terminate_session_with_reason(flow_id, "session_terminated")
    }

    pub fn terminate_session_with_reason(&self, flow_id: &FlowId, reason: &str) -> bool {
        self.remove_with_reason(flow_id, reason).is_some()
    }

    pub fn terminate_device_sessions(&self, device_id: &str) -> usize {
        let flows = self
            .device_to_flows
            .get(device_id)
            .map(|v| v.clone())
            .unwrap_or_default();
        let mut removed = 0;
        for flow_id in flows {
            if self.terminate_session_with_reason(&flow_id, "device_replaced") {
                removed += 1;
            }
        }
        removed
    }

    pub fn count(&self) -> usize {
        self.sessions.len()
    }

    pub fn count_user_sessions(&self, user_id: &str) -> usize {
        self.user_to_flows
            .get(user_id)
            .map(|v| v.len())
            .unwrap_or(0)
    }

    pub fn count_device_sessions(&self, device_id: &str) -> usize {
        self.device_to_flows
            .get(device_id)
            .map(|v| v.len())
            .unwrap_or(0)
    }

    pub fn flow_ids(&self) -> Vec<FlowId> {
        self.sessions.iter().map(|entry| *entry.key()).collect()
    }

    pub fn allocate_tunnel_ip(&self, device_id: &str) -> Option<Ipv4Addr> {
        if let Some(ip) = self.device_leases.get(device_id).map(|v| *v) {
            return Some(ip);
        }

        for _ in 0..POOL_SIZE {
            let cursor = self
                .next_ip_cursor
                .fetch_add(1, Ordering::Relaxed)
                .wrapping_sub(POOL_START)
                % POOL_SIZE
                + POOL_START;
            let ip = ip_from_cursor(cursor);
            if self.lease_to_device.contains_key(&ip) {
                continue;
            }

            self.lease_to_device.insert(ip, device_id.to_string());
            self.device_leases.insert(device_id.to_string(), ip);
            metrics::record_ip_lease_assigned();
            return Some(ip);
        }

        None
    }

    pub fn release_device_lease(&self, device_id: &str) -> Option<Ipv4Addr> {
        let ip = self.device_leases.remove(device_id).map(|(_, ip)| ip)?;
        self.lease_to_device.remove(&ip);
        metrics::record_ip_lease_released();
        Some(ip)
    }

    pub fn cleanup_stale(&self) -> usize {
        let now = Instant::now();
        let stale = self
            .sessions
            .iter()
            .filter_map(|entry| {
                if now.duration_since(entry.value().last_seen) >= SESSION_TTL {
                    Some(*entry.key())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        let mut removed = 0;
        for flow_id in stale {
            if self.terminate_session_with_reason(&flow_id, "idle_timeout") {
                removed += 1;
            }
        }
        removed
    }

    pub fn snapshot(&self) -> Vec<ActiveSessionView> {
        let now = Instant::now();
        self.sessions
            .iter()
            .map(|entry| {
                let transport = entry.value().transport.snapshot();
                let reliability = entry.value().reliability_snapshot();
                let stealth = entry.value().stealth_snapshot();
                let fabric = entry.value().fabric.clone();
                let flow_id = flow_id_to_hex(entry.key());
                ActiveSessionView {
                    correlation_id: observability::session_correlation_id(&flow_id),
                    flow_id,
                    user_id: entry.value().user_id.clone(),
                    device_id: entry.value().device_id.clone(),
                    tunnel_ip: entry.value().tunnel_ip.to_string(),
                    client_addr: entry.value().client_addr.to_string(),
                    age_secs: now.duration_since(entry.value().created_at).as_secs(),
                    idle_secs: now.duration_since(entry.value().last_seen).as_secs(),
                    loss_ratio: entry.value().loss_ratio(),
                    fec_enabled: entry.value().fec_enabled,
                    payload_budget: transport.path.payload_budget,
                    path_quality_score: transport.path.quality_score,
                    path_mode: path_mode_label(transport.path.mode).to_string(),
                    path_belief: path_belief_label(transport.path.belief).to_string(),
                    blackhole_suspected: transport.path.blackhole_suspected,
                    path_explanation: transport.path.explanation,
                    reliability_control_strategy: recovery_strategy_label(
                        reliability.control_strategy,
                    )
                    .to_string(),
                    reliability_interactive_strategy: recovery_strategy_label(
                        reliability.interactive_strategy,
                    )
                    .to_string(),
                    reliability_bulk_strategy: recovery_strategy_label(reliability.bulk_strategy)
                        .to_string(),
                    reliability_explanation: reliability.explainability,
                    configured_persona: stealth.configured_persona.label().to_string(),
                    active_persona: stealth.active_persona.label().to_string(),
                    persona_target_payload: stealth.target_payload_floor,
                    persona_cover_budget_bytes: stealth.cover_budget_bytes,
                    persona_timing_budget_ms: stealth.timing_budget_ms,
                    persona_detectability_improvement_percent: stealth
                        .detectability_improvement_percent,
                    persona_invalid_probe_response: probe_response_label(
                        stealth.invalid_probe_response,
                    )
                    .to_string(),
                    persona_explanation: stealth.explanation,
                    fabric_local_node_id: fabric.local_node_id.clone(),
                    fabric_active_route_id: fabric.active_route.route_id.clone(),
                    fabric_active_nodes: fabric.active_route.nodes.clone(),
                    fabric_backup_route_ids: fabric
                        .backup_routes
                        .iter()
                        .map(|route| route.route_id.clone())
                        .collect(),
                    fabric_route_diversity_score: fabric.route_diversity_score,
                    fabric_failover_count: fabric.failover_count,
                    fabric_last_failover_reason: fabric
                        .last_failover_reason
                        .map(|reason| format!("{:?}", reason).to_ascii_lowercase())
                        .unwrap_or_else(|| "none".to_string()),
                    fabric_last_failover_ms: fabric.last_failover_ms.unwrap_or(0),
                    fabric_ticket_generation: fabric.handoff_ticket.generation,
                    fabric_ticket_expires_ms: fabric.handoff_ticket.expires_at_ms,
                    fec_frames_sent: entry.value().fec_frames_sent,
                    fec_frames_received: entry.value().fec_frames_received,
                    fec_recoveries: entry.value().fec_recoveries,
                    duplicate_packets_sent: entry.value().duplicate_packets_sent,
                    suppressed_duplicates: entry.value().suppressed_duplicates,
                }
            })
            .collect()
    }
}

pub async fn spawn_cleanup_task(manager: Arc<SessionManager>) {
    let mut interval = tokio::time::interval(CLEANUP_INTERVAL);
    loop {
        interval.tick().await;
        let removed = manager.cleanup_stale();
        if removed > 0 {
            tracing::info!(
                removed,
                active = manager.count(),
                "TTL cleanup removed stale sessions"
            );
            observability::record_trace_event(
                "session",
                "warning",
                "session-ttl-cleanup",
                None,
                "TTL cleanup removed stale sessions",
                serde_json::json!({
                    "removed": removed,
                    "active_sessions": manager.count(),
                    "ttl_secs": SESSION_TTL.as_secs(),
                }),
            );
        }
    }
}

fn ip_from_cursor(cursor: u32) -> Ipv4Addr {
    let host = cursor;
    let third = (host / 256) as u8;
    let fourth = (host % 256) as u8;
    Ipv4Addr::new(10, 7, third, fourth)
}

fn push_flow(map: &DashMap<String, Vec<FlowId>>, key: &str, flow_id: FlowId) {
    if let Some(mut entry) = map.get_mut(key) {
        let exists = entry.iter().any(|v| *v == flow_id);
        if !exists {
            entry.push(flow_id);
        }
    } else {
        map.insert(key.to_string(), vec![flow_id]);
    }
}

fn remove_flow(map: &DashMap<String, Vec<FlowId>>, key: &str, flow_id: FlowId) {
    if let Some(mut entry) = map.get_mut(key) {
        entry.retain(|v| *v != flow_id);
        if entry.is_empty() {
            drop(entry);
            map.remove(key);
        }
    }
}

pub fn flow_id_to_hex(flow_id: &FlowId) -> String {
    let mut out = String::with_capacity(32);
    for byte in &flow_id.0 {
        out.push(nibble_to_hex((byte >> 4) & 0x0f));
        out.push(nibble_to_hex(byte & 0x0f));
    }
    out
}

pub fn flow_id_from_hex(value: &str) -> Option<FlowId> {
    if value.len() != 32 {
        return None;
    }

    let mut bytes = [0u8; 16];
    let chars = value.as_bytes();
    for i in 0..16 {
        let hi = hex_to_nibble(chars[i * 2])?;
        let lo = hex_to_nibble(chars[i * 2 + 1])?;
        bytes[i] = (hi << 4) | lo;
    }
    Some(FlowId(bytes))
}

fn nibble_to_hex(nibble: u8) -> char {
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        10..=15 => (b'a' + (nibble - 10)) as char,
        _ => '0',
    }
}

fn path_mode_label(mode: PathMode) -> &'static str {
    match mode {
        PathMode::Stable => "stable",
        PathMode::Probing => "probing",
        PathMode::Cautious => "cautious",
        PathMode::Roaming => "roaming",
        PathMode::Recovering => "recovering",
        PathMode::BlackholeRecovery => "blackhole_recovery",
    }
}

fn path_belief_label(belief: PathBelief) -> &'static str {
    match belief {
        PathBelief::Stable => "stable",
        PathBelief::Congested => "congested",
        PathBelief::Reordered => "reordered",
        PathBelief::BlackholeRisk => "blackhole_risk",
        PathBelief::Recovering => "recovering",
    }
}

fn probe_response_label(response: omega_stealth::ProbeResponseClass) -> &'static str {
    match response {
        omega_stealth::ProbeResponseClass::SilentDrop => "silent_drop",
        omega_stealth::ProbeResponseClass::UniformReject => "uniform_reject",
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

fn hex_to_nibble(ch: u8) -> Option<u8> {
    match ch {
        b'0'..=b'9' => Some(ch - b'0'),
        b'a'..=b'f' => Some(ch - b'a' + 10),
        b'A'..=b'F' => Some(ch - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use omega_control::policy::SessionAdmission;
    use omega_core_crypto::SessionKeys;

    fn session_fabric_state() -> SessionFabricState {
        let admission = SessionAdmission::default();
        let graph = omega_relay::FabricGraph::default_topology(
            "edge-local",
            omega_relay::RelayRole::Edge,
            "test",
            "omega-core",
        );
        omega_relay::RoutingEngine::new(graph)
            .plan_session("edge-local", &admission, "session-test")
            .expect("fabric route")
    }

    fn session_state() -> SessionState {
        let shared_secret = [0x42u8; 32];
        let keys = SessionKeys::from_shared_secret(&shared_secret, true).unwrap();
        SessionState::new(
            keys,
            "127.0.0.1:5000".parse().unwrap(),
            Ipv4Addr::new(10, 7, 0, 2),
            "user".to_string(),
            "device".to_string(),
            7,
            false,
            omega_stealth::MorphingPolicy::Balanced,
            session_fabric_state(),
            PersonaId::QuicLike,
            0xDEADBEEF,
        )
    }

    #[test]
    fn observed_control_seq_does_not_create_false_gap() {
        let mut session = session_state();

        assert!(session.observe_inbound_seq(100).is_none());
        assert!(session.observe_inbound_seq(101).is_none());
        assert!(session.observe_inbound_seq(102).is_none());
        assert_eq!(session.loss_ratio(), 0.0);
    }

    #[test]
    fn missing_seq_is_still_reported_after_control_packet() {
        let mut session = session_state();

        assert!(session.observe_inbound_seq(10).is_none());
        assert!(session.observe_inbound_seq(11).is_none());
        assert!(session.observe_inbound_seq(13).is_none());
        let mut emitted_nack = false;
        for seq in 14..30 {
            if session.observe_inbound_seq(seq).is_some() {
                emitted_nack = true;
                break;
            }
        }
        assert!(emitted_nack, "gap should eventually trigger a nack");
        assert!(session.loss_ratio() > 0.0);
    }
}
