/// Session manager — per-connection state with DashMap and TTL cleanup.

use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use omega_core::chaos::ChaosPrng;
use omega_core::crypto::SessionKeys;
use omega_core::protocol::FlowId;
use omega_core::replay::ReplayFilter;

use omega_core::arq::{GapDetector, LossEstimator, RetransmitQueue};
#[cfg(feature = "fec")]
use omega_core::raptorq_mgr::{FecConfig, FecDecoder, FecState};

/// Per-connection session state.
pub struct SessionState {
    /// AEAD keys for this session.
    pub keys: SessionKeys,
    /// Chaos PRNG for traffic morphing.
    pub chaos: ChaosPrng,
    /// Anti-replay sliding window.
    pub replay_filter: ReplayFilter,
    /// Send sequence counter (Omega header seq).
    pub send_seq: u32,
    /// Maximum sent sequence number (for ARQ caching).
    pub max_send_seq: u32,
    /// RTP sequence counter (cover header).
    pub rtp_seq: u16,
    /// RTP timestamp counter.
    pub rtp_timestamp: u32,
    /// SSRC derived from FlowId.
    pub ssrc: u32,
    /// Client address (for sending responses).
    pub client_addr: std::net::SocketAddr,
    /// Assigned tunnel IP for this client.
    pub tunnel_ip: std::net::Ipv4Addr,
    /// Last activity timestamp (for TTL cleanup).
    pub last_seen: Instant,
    /// Whether FEC is enabled for this session.
    pub fec_enabled: bool,
    
    // ── ARQ / FEC State ──────────────────────────────
    pub retransmit_queue: RetransmitQueue,
    pub gap_detector: GapDetector,
    pub loss_estimator: LossEstimator,
    
    #[cfg(feature = "fec")]
    pub fec_state: FecState,
    #[cfg(feature = "fec")]
    pub fec_decoder: Option<FecDecoder>, // Current block decoder
    #[cfg(feature = "fec")]
    pub current_block_id: Option<u32>,   // Sequence of current decoding block

    /// Last sequence number processed by loss estimator.
    pub loss_est_seq: u32,
    /// Has the estimator been initialized with the first packet?
    pub loss_est_init: bool,
}

impl SessionState {
    pub fn new(
        keys: SessionKeys,
        client_addr: std::net::SocketAddr,
        tunnel_ip: std::net::Ipv4Addr,
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
            last_seen: Instant::now(),
            fec_enabled,
            retransmit_queue: RetransmitQueue::new(),
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

    /// Advance send sequence and return the current value.
    pub fn next_send_seq(&mut self) -> u32 {
        let seq = self.send_seq;
        self.send_seq = self.send_seq.wrapping_add(1);
        seq
    }

    /// Advance RTP sequence counter.
    pub fn next_rtp_seq(&mut self) -> u16 {
        let seq = self.rtp_seq;
        self.rtp_seq = self.rtp_seq.wrapping_add(1);
        seq
    }

    /// Advance RTP timestamp (audio: +960 per 20ms frame, video: +3000 per 33ms frame).
    pub fn advance_rtp_timestamp(&mut self, is_audio: bool) {
        self.rtp_timestamp = self.rtp_timestamp.wrapping_add(if is_audio { 960 } else { 3000 });
    }

    /// Update loss estimator.
    pub fn update_loss_stats(&mut self, received_seq: u32) {
        if !self.loss_est_init {
            self.loss_est_seq = received_seq;
            self.loss_est_init = true;
            self.loss_estimator.record(true);
            return;
        }

        let diff = received_seq.wrapping_sub(self.loss_est_seq);
        if diff == 0 {
            // Duplicate or same seq, ignore
            return;
        }
        
        if diff < 0x8000_0000 {
            // Newer packet
            // If diff > 1, we have gaps (lost packets)
            let lost_count = diff - 1;
            // Cap lost count to avoid filling ring with junk on huge jumps
            let to_record_lost = lost_count.min(256); 
            
            for _ in 0..to_record_lost {
                self.loss_estimator.record(false);
            }
            self.loss_estimator.record(true);
            self.loss_est_seq = received_seq;
        }
        // Else: old packet (diff is large positive), ignore for stats
        // (If we wanted to be precise, we'd go back and flip a 'false' to 'true' in history,
        // but LossEstimator is a simple ring buffer without sequence mapping).
    }

    /// Estimated packet loss ratio [0.0, 1.0].
    pub fn loss_ratio(&self) -> f64 {
        self.loss_estimator.loss_ratio()
    }

    /// Touch last_seen to prevent TTL expiry.
    pub fn touch(&mut self) {
        self.last_seen = Instant::now();
    }
}

// ── Session Manager ────────────────────────────────────────────────

/// Default session idle timeout before cleanup.
const SESSION_TTL: Duration = Duration::from_secs(120);

/// Cleanup interval.
const CLEANUP_INTERVAL: Duration = Duration::from_secs(30);

/// Concurrent session map.
pub struct SessionManager {
    sessions: Arc<DashMap<FlowId, SessionState>>,
    /// Pool of assignable tunnel IPs (10.7.0.2 - 10.7.0.254).
    next_ip_octet: std::sync::atomic::AtomicU8,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(DashMap::with_capacity(64)),
            next_ip_octet: std::sync::atomic::AtomicU8::new(2),
        }
    }

/// Maximum number of concurrent sessions to prevent DoS (memory exhaustion).
const MAX_SESSIONS: usize = 10000;

    /// Insert a new session. Returns true if inserted, false if table full.
    pub fn insert(&self, flow_id: FlowId, state: SessionState) -> bool {
        if self.sessions.len() >= Self::MAX_SESSIONS {
            return false;
        }
        self.sessions.insert(flow_id, state);
        true
    }

    /// Look up a session by FlowId.
    pub fn get(
        &self,
        flow_id: &FlowId,
    ) -> Option<dashmap::mapref::one::RefMut<'_, FlowId, SessionState>> {
        self.sessions.get_mut(flow_id)
    }

    /// Look up a session by tunnel IP (for TUN → UDP direction).
    pub fn find_by_tunnel_ip(
        &self,
        ip: std::net::Ipv4Addr,
    ) -> Option<dashmap::mapref::one::RefMut<'_, FlowId, SessionState>> {
        // Linear scan — acceptable for ≤50 sessions.
        for entry in self.sessions.iter_mut() {
            if entry.value().tunnel_ip == ip {
                return Some(self.sessions.get_mut(entry.key()).unwrap());
            }
        }
        None
    }

    /// Allocate next tunnel IP from the pool.
    pub fn allocate_tunnel_ip(&self) -> std::net::Ipv4Addr {
        let octet = self
            .next_ip_octet
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        // Wrap around at 254 → 2
        if octet == 0 {
            self.next_ip_octet
                .store(3, std::sync::atomic::Ordering::Relaxed);
        }
        std::net::Ipv4Addr::new(10, 7, 0, octet)
    }

    /// Remove a session.
    pub fn remove(&self, flow_id: &FlowId) {
        self.sessions.remove(flow_id);
    }

    /// Active session count.
    pub fn count(&self) -> usize {
        self.sessions.len()
    }

    /// Clone the inner Arc for sharing across tasks.
    pub fn shared(&self) -> Arc<DashMap<FlowId, SessionState>> {
        self.sessions.clone()
    }

    /// Run TTL cleanup: remove sessions idle longer than SESSION_TTL.
    /// Returns the number of removed sessions.
    pub fn cleanup_stale(&self) -> usize {
        let now = Instant::now();
        let mut removed = 0;
        self.sessions.retain(|_flow_id, session| {
            let alive = now.duration_since(session.last_seen) < SESSION_TTL;
            if !alive {
                removed += 1;
            }
            alive
        });
        removed
    }
}

/// Spawn a background TTL cleanup task.
pub async fn spawn_cleanup_task(manager: Arc<DashMap<FlowId, SessionState>>) {
    let mut interval = tokio::time::interval(CLEANUP_INTERVAL);
    loop {
        interval.tick().await;
        let now = Instant::now();
        let before = manager.len();
        manager.retain(|_fid, session| {
            now.duration_since(session.last_seen) < SESSION_TTL
        });
        let removed = before - manager.len();
        if removed > 0 {
            tracing::info!("TTL cleanup: removed {} stale sessions, {} active", removed, manager.len());
        }
    }
}
