use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use omega_core::arq::{GapDetector, LossEstimator, RetransmitQueue};
use omega_core::chaos::ChaosPrng;
use omega_core::crypto::SessionKeys;
use omega_core::protocol::{FlowId, NackMessage};
use omega_core::replay::ReplayFilter;
use serde::Serialize;

#[cfg(feature = "fec")]
use omega_core::raptorq_mgr::{FecConfig, FecDecoder, FecState};

use crate::metrics;

const SESSION_TTL: Duration = Duration::from_secs(120);
const CLEANUP_INTERVAL: Duration = Duration::from_secs(30);
const MAX_SESSIONS: usize = 10_000;

const POOL_START: u32 = 2; // 10.7.0.2
const POOL_END: u32 = 65_534; // 10.7.255.254
const POOL_SIZE: u32 = POOL_END - POOL_START + 1;
const DEFAULT_INITIAL_ARQ_RTT_MS: u64 = 350;
const PADDING_BUDGET_MIN: usize = 0;
const PADDING_BUDGET_MAX: usize = 256;
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
    pub client_addr: SocketAddr,
    pub tunnel_ip: Ipv4Addr,
    pub user_id: String,
    pub device_id: String,
    pub last_seen: Instant,
    pub fec_enabled: bool,
    pub padding_budget: usize,
    pub last_padding_adjust: Instant,
    pub redundancy_extra: u8,
    pub last_redundancy_adjust: Instant,

    pub retransmit_queue: RetransmitQueue,
    pub gap_detector: GapDetector,
    pub loss_estimator: LossEstimator,

    #[cfg(feature = "fec")]
    pub fec_state: FecState,
    #[cfg(feature = "fec")]
    pub fec_decoder: Option<FecDecoder>,
    #[cfg(feature = "fec")]
    pub current_block_id: Option<u32>,

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
        ssrc: u32,
    ) -> Self {
        #[cfg(feature = "fec")]
        let fec_state = FecState::new(FecConfig::default());

        Self {
            keys,
            chaos: ChaosPrng::new(chaos_seed),
            replay_filter: ReplayFilter::new(),
            send_seq: 0,
            max_send_seq: 0,
            rtp_seq: 0,
            rtp_timestamp: 0,
            ssrc,
            client_addr,
            tunnel_ip,
            user_id,
            device_id,
            last_seen: Instant::now(),
            fec_enabled,
            padding_budget: PADDING_BUDGET_MAX,
            last_padding_adjust: Instant::now(),
            redundancy_extra: 0,
            last_redundancy_adjust: Instant::now(),
            retransmit_queue: RetransmitQueue::with_initial_rtt(DEFAULT_INITIAL_ARQ_RTT_MS),
            gap_detector: GapDetector::new(),
            loss_estimator: LossEstimator::new(),
            #[cfg(feature = "fec")]
            fec_state,
            #[cfg(feature = "fec")]
            fec_decoder: None,
            #[cfg(feature = "fec")]
            current_block_id: None,
            loss_est_seq: 0,
            loss_est_init: false,
        }
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

    pub fn touch(&mut self) {
        self.last_seen = Instant::now();
    }

    pub fn current_padding_budget(&mut self) -> usize {
        let elapsed = self.last_padding_adjust.elapsed().as_secs();
        let ticks = elapsed / PADDING_RECOVERY_INTERVAL_SECS;
        if ticks > 0 {
            let growth = (ticks as usize).saturating_mul(PADDING_RECOVERY_STEP);
            self.padding_budget = self
                .padding_budget
                .saturating_add(growth)
                .min(PADDING_BUDGET_MAX);
            self.last_padding_adjust = Instant::now();
        }
        self.padding_budget
    }

    pub fn on_remote_nack(&mut self, nack: &NackMessage) {
        let missing = nack.bitmap.count_ones() as usize;
        if missing == 0 {
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
        let elapsed = self.last_redundancy_adjust.elapsed().as_secs();
        let ticks = elapsed / REDUNDANCY_DECAY_SECS;
        if ticks > 0 {
            self.redundancy_extra = self.redundancy_extra.saturating_sub(ticks as u8);
            self.last_redundancy_adjust = Instant::now();
        }
        self.redundancy_extra as usize
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ActiveSessionView {
    pub flow_id: String,
    pub user_id: String,
    pub device_id: String,
    pub tunnel_ip: String,
    pub client_addr: String,
    pub idle_secs: u64,
    pub fec_enabled: bool,
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
}

impl SessionManager {
    pub fn new() -> Self {
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
        }
    }

    pub fn insert(&self, flow_id: FlowId, state: SessionState) -> bool {
        if self.sessions.len() >= MAX_SESSIONS {
            return false;
        }

        let user_id = state.user_id.clone();
        let device_id = state.device_id.clone();
        let tunnel_ip = state.tunnel_ip;

        self.tunnel_ip_to_flow.insert(tunnel_ip, flow_id);
        self.flow_to_user.insert(flow_id, user_id.clone());
        self.flow_to_device.insert(flow_id, device_id.clone());
        push_flow(&self.user_to_flows, &user_id, flow_id);
        push_flow(&self.device_to_flows, &device_id, flow_id);
        self.sessions.insert(flow_id, state);

        metrics::update_session_count(self.count());
        metrics::update_user_session_count(&user_id, self.count_user_sessions(&user_id));
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

        metrics::update_session_count(self.count());
        metrics::update_user_session_count(&user_id, self.count_user_sessions(&user_id));

        Some(state)
    }

    pub fn terminate_session(&self, flow_id: &FlowId) -> bool {
        self.remove(flow_id).is_some()
    }

    pub fn terminate_device_sessions(&self, device_id: &str) -> usize {
        let flows = self
            .device_to_flows
            .get(device_id)
            .map(|v| v.clone())
            .unwrap_or_default();
        let mut removed = 0;
        for flow_id in flows {
            if self.terminate_session(&flow_id) {
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
            if self.remove(&flow_id).is_some() {
                removed += 1;
            }
        }
        removed
    }

    pub fn snapshot(&self) -> Vec<ActiveSessionView> {
        let now = Instant::now();
        self.sessions
            .iter()
            .map(|entry| ActiveSessionView {
                flow_id: flow_id_to_hex(entry.key()),
                user_id: entry.value().user_id.clone(),
                device_id: entry.value().device_id.clone(),
                tunnel_ip: entry.value().tunnel_ip.to_string(),
                client_addr: entry.value().client_addr.to_string(),
                idle_secs: now.duration_since(entry.value().last_seen).as_secs(),
                fec_enabled: entry.value().fec_enabled,
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

fn hex_to_nibble(ch: u8) -> Option<u8> {
    match ch {
        b'0'..=b'9' => Some(ch - b'0'),
        b'a'..=b'f' => Some(ch - b'a' + 10),
        b'A'..=b'F' => Some(ch - b'A' + 10),
        _ => None,
    }
}
