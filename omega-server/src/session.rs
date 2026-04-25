use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use dashmap::DashMap;
use omega_core::arq::{GapDetector, LossEstimator, RetransmitQueue};
use omega_core::chaos::ChaosPrng;
use omega_core::crypto::SessionKeys;
use omega_core::protocol::{FlowId, NackMessage};
use omega_core::replay::ReplayFilter;
use serde::Serialize;
use tokio::sync::mpsc;

#[cfg(feature = "fec")]
use omega_core::raptorq_mgr::{FecConfig, FecDecoder, FecState};

use crate::metrics;

const SESSION_TTL: Duration = Duration::from_secs(120);
const CLEANUP_INTERVAL: Duration = Duration::from_secs(30);
const MAX_SESSIONS: usize = 10_000;

const POOL_START: u32 = 2; // 10.7.0.2 / fd70:7::2
const POOL_END: u32 = 65_534; // 10.7.255.254 / fd70:7::fffe
const POOL_SIZE: u32 = POOL_END - POOL_START + 1;
const DEFAULT_INITIAL_ARQ_RTT_MS: u64 = 350;
const PADDING_BUDGET_MIN: usize = 0;
const PADDING_RECOVERY_STEP: usize = 24;
const PADDING_RECOVERY_INTERVAL_SECS: u64 = 2;
const REDUNDANCY_EXTRA_MAX: u8 = 2;
const REDUNDANCY_DECAY_SECS: u64 = 8;
const IPV6_PREFIX_HIGH: u16 = 0xfd70;
const IPV6_PREFIX_LOW: u16 = 0x0007;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TunnelAddrs {
    pub ipv4: Ipv4Addr,
    pub ipv6: Option<Ipv6Addr>,
}

pub struct SessionState {
    pub keys: SessionKeys,
    pub chaos: ChaosPrng,
    pub replay_filter: ReplayFilter,
    pub send_seq: u32,
    pub max_send_seq: u32,
    pub rtp_seq: u16,
    pub rtp_timestamp: u32,
    pub ssrc: u32,
    pub morphing_policy: crate::runtime::MorphingPolicy,
    pub client_addr: SocketAddr,
    pub tcp_egress: Option<mpsc::Sender<Bytes>>,
    pub tunnel_ip: Ipv4Addr,
    pub tunnel_ipv6: Option<Ipv6Addr>,
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
        tunnel_ipv6: Option<Ipv6Addr>,
        user_id: String,
        device_id: String,
        chaos_seed: u64,
        fec_enabled: bool,
        morphing_policy: crate::runtime::MorphingPolicy,
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
            morphing_policy,
            client_addr,
            tcp_egress: None,
            tunnel_ip,
            tunnel_ipv6,
            user_id,
            device_id,
            created_at: Instant::now(),
            last_seen: Instant::now(),
            fec_enabled,
            padding_budget: morphing_policy.padding_budget_cap(),
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

    pub fn observe_inbound_seq(&mut self, seq: u32) -> Option<NackMessage> {
        let nack = self.gap_detector.record_received(seq);
        self.update_loss_stats(seq);
        nack
    }

    pub fn touch(&mut self) {
        self.last_seen = Instant::now();
    }

    pub fn set_tcp_egress(&mut self, tx: mpsc::Sender<Bytes>) {
        self.tcp_egress = Some(tx);
    }

    pub fn clear_tcp_egress(&mut self) {
        self.tcp_egress = None;
    }

    pub fn current_padding_budget(&mut self) -> usize {
        let padding_cap = self.morphing_policy.padding_budget_cap();
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

        if matches!(self.morphing_policy, crate::runtime::MorphingPolicy::Off) {
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
        if matches!(self.morphing_policy, crate::runtime::MorphingPolicy::Off) {
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
}

#[derive(Debug, Clone, Serialize)]
pub struct ActiveSessionView {
    pub flow_id: String,
    pub user_id: String,
    pub device_id: String,
    pub tunnel_ip: String,
    pub tunnel_ipv6: Option<String>,
    pub client_addr: String,
    pub age_secs: u64,
    pub idle_secs: u64,
    pub loss_ratio: f64,
    pub fec_enabled: bool,
}

pub struct SessionManager {
    sessions: Arc<DashMap<FlowId, SessionState>>,
    tunnel_addr_to_flow: Arc<DashMap<IpAddr, FlowId>>,
    flow_to_user: Arc<DashMap<FlowId, String>>,
    flow_to_device: Arc<DashMap<FlowId, String>>,
    user_to_flows: Arc<DashMap<String, Vec<FlowId>>>,
    device_to_flows: Arc<DashMap<String, Vec<FlowId>>>,
    device_leases: Arc<DashMap<String, TunnelAddrs>>,
    lease_to_device_v4: Arc<DashMap<Ipv4Addr, String>>,
    lease_to_device_v6: Arc<DashMap<Ipv6Addr, String>>,
    next_ip_cursor: AtomicU32,
    ipv6_enabled: bool,
}

impl SessionManager {
    pub fn new(ipv6_enabled: bool) -> Self {
        Self {
            sessions: Arc::new(DashMap::with_capacity(1_024)),
            tunnel_addr_to_flow: Arc::new(DashMap::with_capacity(2_048)),
            flow_to_user: Arc::new(DashMap::with_capacity(1_024)),
            flow_to_device: Arc::new(DashMap::with_capacity(1_024)),
            user_to_flows: Arc::new(DashMap::with_capacity(1_024)),
            device_to_flows: Arc::new(DashMap::with_capacity(1_024)),
            device_leases: Arc::new(DashMap::with_capacity(1_024)),
            lease_to_device_v4: Arc::new(DashMap::with_capacity(1_024)),
            lease_to_device_v6: Arc::new(DashMap::with_capacity(1_024)),
            next_ip_cursor: AtomicU32::new(POOL_START),
            ipv6_enabled,
        }
    }

    pub fn insert(&self, flow_id: FlowId, state: SessionState) -> bool {
        if self.sessions.len() >= MAX_SESSIONS {
            return false;
        }

        let user_id = state.user_id.clone();
        let device_id = state.device_id.clone();
        let tunnel_ip = state.tunnel_ip;
        let tunnel_ipv6 = state.tunnel_ipv6;

        self.tunnel_addr_to_flow
            .insert(IpAddr::V4(tunnel_ip), flow_id);
        if let Some(ipv6) = tunnel_ipv6 {
            self.tunnel_addr_to_flow.insert(IpAddr::V6(ipv6), flow_id);
        }
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

    pub fn flow_by_tunnel_addr(&self, ip: IpAddr) -> Option<FlowId> {
        self.tunnel_addr_to_flow.get(&ip).map(|v| *v)
    }

    pub fn remove(&self, flow_id: &FlowId) -> Option<SessionState> {
        let removed = self.sessions.remove(flow_id)?;
        let (_flow, state) = removed;

        let user_id = state.user_id.clone();
        let device_id = state.device_id.clone();
        let tunnel_ip = state.tunnel_ip;
        let tunnel_ipv6 = state.tunnel_ipv6;

        self.flow_to_user.remove(flow_id);
        self.flow_to_device.remove(flow_id);
        remove_flow(&self.user_to_flows, &user_id, *flow_id);
        remove_flow(&self.device_to_flows, &device_id, *flow_id);

        self.rebind_tunnel_addr(IpAddr::V4(tunnel_ip), &device_id, flow_id);
        if let Some(ipv6) = tunnel_ipv6 {
            self.rebind_tunnel_addr(IpAddr::V6(ipv6), &device_id, flow_id);
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

    pub fn allocate_tunnel_addrs(&self, device_id: &str) -> Option<TunnelAddrs> {
        if let Some(addrs) = self.device_leases.get(device_id).map(|v| *v) {
            return Some(addrs);
        }

        for _ in 0..POOL_SIZE {
            let cursor = self
                .next_ip_cursor
                .fetch_add(1, Ordering::Relaxed)
                .wrapping_sub(POOL_START)
                % POOL_SIZE
                + POOL_START;
            let ipv4 = ip_from_cursor(cursor);
            if self.lease_to_device_v4.contains_key(&ipv4) {
                continue;
            }

            let ipv6 = self.ipv6_enabled.then(|| ipv6_from_cursor(cursor));
            if let Some(ipv6) = ipv6 {
                if self.lease_to_device_v6.contains_key(&ipv6) {
                    continue;
                }
            }

            let addrs = TunnelAddrs { ipv4, ipv6 };
            self.lease_to_device_v4.insert(ipv4, device_id.to_string());
            if let Some(ipv6) = ipv6 {
                self.lease_to_device_v6.insert(ipv6, device_id.to_string());
            }
            self.device_leases.insert(device_id.to_string(), addrs);
            metrics::record_ip_lease_assigned();
            return Some(addrs);
        }

        None
    }

    pub fn release_device_lease(&self, device_id: &str) -> Option<TunnelAddrs> {
        let addrs = self
            .device_leases
            .remove(device_id)
            .map(|(_, addrs)| addrs)?;
        self.lease_to_device_v4.remove(&addrs.ipv4);
        if let Some(ipv6) = addrs.ipv6 {
            self.lease_to_device_v6.remove(&ipv6);
        }
        metrics::record_ip_lease_released();
        Some(addrs)
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
                tunnel_ipv6: entry.value().tunnel_ipv6.map(|value| value.to_string()),
                client_addr: entry.value().client_addr.to_string(),
                age_secs: now.duration_since(entry.value().created_at).as_secs(),
                idle_secs: now.duration_since(entry.value().last_seen).as_secs(),
                loss_ratio: entry.value().loss_ratio(),
                fec_enabled: entry.value().fec_enabled,
            })
            .collect()
    }

    fn rebind_tunnel_addr(&self, addr: IpAddr, device_id: &str, removed_flow: &FlowId) {
        let mapped = self.tunnel_addr_to_flow.get(&addr).map(|v| *v);
        if mapped != Some(*removed_flow) {
            return;
        }

        if let Some(next) = self
            .device_to_flows
            .get(device_id)
            .and_then(|v| v.first().copied())
        {
            if let Some(state) = self.sessions.get(&next) {
                let owns_addr = match addr {
                    IpAddr::V4(ipv4) => state.tunnel_ip == ipv4,
                    IpAddr::V6(ipv6) => state.tunnel_ipv6 == Some(ipv6),
                };
                if owns_addr {
                    self.tunnel_addr_to_flow.insert(addr, next);
                    return;
                }
            }
        }

        self.tunnel_addr_to_flow.remove(&addr);
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

fn ipv6_from_cursor(cursor: u32) -> Ipv6Addr {
    let high = ((cursor >> 16) & 0xffff) as u16;
    let low = (cursor & 0xffff) as u16;
    Ipv6Addr::new(IPV6_PREFIX_HIGH, IPV6_PREFIX_LOW, 0, 0, 0, 0, high, low)
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

#[cfg(test)]
mod tests {
    use super::*;
    use omega_core::crypto::SessionKeys;

    fn session_state() -> SessionState {
        let shared_secret = [0x42u8; 32];
        let keys = SessionKeys::from_shared_secret(&shared_secret, true).unwrap();
        SessionState::new(
            keys,
            "127.0.0.1:5000".parse().unwrap(),
            Ipv4Addr::new(10, 7, 0, 2),
            Some("fd70:7::2".parse().unwrap()),
            "user".to_string(),
            "device".to_string(),
            7,
            false,
            crate::runtime::MorphingPolicy::Balanced,
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

    #[test]
    fn allocates_dual_stack_tunnel_leases_when_ipv6_enabled() {
        let manager = SessionManager::new(true);
        let lease = manager.allocate_tunnel_addrs("device").unwrap();

        assert_eq!(lease.ipv4, Ipv4Addr::new(10, 7, 0, 2));
        assert_eq!(lease.ipv6, Some("fd70:7::2".parse().unwrap()));
    }
}
