/// ARQ — Automatic Repeat reQuest with NACK-based retransmission.
///
/// Two sides:
/// - **Sender** (`RetransmitQueue`): caches recently sent packets, services NACKs.
/// - **Receiver** (`GapDetector`): detects missing sequence numbers, emits NACK bitmaps.
///
/// Design constraints:
/// - Max 64 outstanding packets in retransmit queue (bounded memory).
/// - NACK bitmap: 64 bits → covers 64 consecutive seq numbers.
/// - Timeout: retransmit queue entries expire after 3×RTT.

extern crate alloc;
use alloc::collections::VecDeque;
use alloc::vec::Vec;

use crate::protocol::NackMessage;

// ── Sender: Retransmit Queue ───────────────────────────────────────

/// Maximum cached packets for retransmission.
const RETRANSMIT_CACHE_SIZE: usize = 64;

/// A cached packet ready for retransmission.
#[derive(Clone)]
pub struct CachedPacket {
    /// Omega sequence number.
    pub seq: u32,
    /// The fully-formed encrypted packet (ready to send again).
    pub data: Vec<u8>,
    /// Monotonic timestamp (in ms since session start).
    pub sent_at_ms: u64,
}

/// Sender-side retransmit queue.
///
/// Caches recently sent packets so they can be resent on NACK.
pub struct RetransmitQueue {
    cache: VecDeque<CachedPacket>,
    /// Estimated RTT in milliseconds.
    rtt_ms: u64,
}

impl RetransmitQueue {
    pub fn new() -> Self {
        Self {
            cache: VecDeque::with_capacity(RETRANSMIT_CACHE_SIZE),
            rtt_ms: 100, // Initial RTT estimate
        }
    }

    /// Cache a sent packet for possible retransmission.
    pub fn cache_packet(&mut self, seq: u32, data: Vec<u8>, now_ms: u64) {
        if self.cache.len() >= RETRANSMIT_CACHE_SIZE {
            self.cache.pop_front();
        }
        self.cache.push_back(CachedPacket {
            seq,
            data,
            sent_at_ms: now_ms,
        });
    }

    /// Process a NACK: return packets that should be retransmitted.
    pub fn process_nack(&self, nack: &NackMessage) -> Vec<&CachedPacket> {
        let mut out = Vec::new();
        for missing_seq in nack.missing_seqs() {
            if let Some(pkt) = self.cache.iter().find(|p| p.seq == missing_seq) {
                out.push(pkt);
            }
        }
        out
    }

    /// Purge packets older than 3×RTT.
    pub fn purge_expired(&mut self, now_ms: u64) {
        let threshold = now_ms.saturating_sub(self.rtt_ms * 3);
        while let Some(front) = self.cache.front() {
            if front.sent_at_ms < threshold {
                self.cache.pop_front();
            } else {
                break;
            }
        }
    }

    /// Update RTT estimate (EWMA: 7/8 old + 1/8 new).
    pub fn update_rtt(&mut self, sample_ms: u64) {
        self.rtt_ms = (self.rtt_ms * 7 + sample_ms) / 8;
    }

    pub fn rtt_ms(&self) -> u64 {
        self.rtt_ms
    }

    pub fn len(&self) -> usize {
        self.cache.len()
    }

    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }
}

// ── Receiver: Gap Detector ─────────────────────────────────────────

const GAP_WINDOW: u32 = 64;

/// Receiver-side gap detector.
///
/// Tracks received sequence numbers and generates NACKs for missing ones.
pub struct GapDetector {
    highest_seq: u32,
    /// Bit i set → seq (highest_seq - 63 + i) received.
    received_bitmap: u64,
    initialized: bool,
    pending_nacks: u32,
    nack_cooldown: u32,
}

impl GapDetector {
    pub fn new() -> Self {
        Self {
            highest_seq: 0,
            received_bitmap: 0,
            initialized: false,
            pending_nacks: 0,
            nack_cooldown: 0,
        }
    }

    /// Record a received packet. Returns `Some(NackMessage)` if gaps detected
    /// and rate limit allows.
    pub fn record_received(&mut self, seq: u32) -> Option<NackMessage> {
        if !self.initialized {
            self.highest_seq = seq;
            self.received_bitmap = !0u64;
            self.initialized = true;
            return None;
        }

        if seq > self.highest_seq {
            let jump = seq - self.highest_seq;
            if jump < GAP_WINDOW {
                self.received_bitmap >>= jump;
                self.received_bitmap |= 1u64 << 63;
            } else {
                self.received_bitmap = 1u64 << 63;
            }
            self.highest_seq = seq;
        } else {
            let age = self.highest_seq - seq;
            if age < GAP_WINDOW {
                let bit_pos = 63 - age;
                self.received_bitmap |= 1u64 << bit_pos;
            }
            return None;
        }

        self.nack_cooldown = self.nack_cooldown.saturating_sub(1);
        if self.nack_cooldown == 0 {
            let nack = self.check_gaps();
            if nack.is_some() {
                self.nack_cooldown = 10;
                self.pending_nacks += 1;
            }
            nack
        } else {
            None
        }
    }

    fn check_gaps(&self) -> Option<NackMessage> {
        let base_seq = self.highest_seq.wrapping_sub(63);
        let reorder_threshold = 3;
        let missing = !self.received_bitmap;
        let mask = if reorder_threshold < 64 {
            !0u64 >> reorder_threshold
        } else {
            0
        };
        let nack_bitmap = missing & mask;

        if nack_bitmap == 0 {
            return None;
        }

        Some(NackMessage {
            base_seq,
            bitmap: nack_bitmap,
        })
    }

    pub fn nack_count(&self) -> u32 {
        self.pending_nacks
    }

    pub fn highest_seq(&self) -> u32 {
        self.highest_seq
    }
}

// ── Loss Estimator ─────────────────────────────────────────────────

/// 256-sample sliding window loss estimator.
pub struct LossEstimator {
    window: [bool; 256],
    pos: u8,
    expected: u64,
    received: u64,
}

impl LossEstimator {
    pub fn new() -> Self {
        Self {
            window: [true; 256],
            pos: 0,
            expected: 256,
            received: 256,
        }
    }

    /// Record a packet event. `was_received` = true if packet arrived.
    pub fn record(&mut self, was_received: bool) {
        if self.window[self.pos as usize] {
            self.received -= 1;
        }
        self.expected -= 1;

        self.window[self.pos as usize] = was_received;
        self.expected += 1;
        if was_received {
            self.received += 1;
        }

        self.pos = self.pos.wrapping_add(1);
    }

    /// Current loss ratio [0.0, 1.0].
    pub fn loss_ratio(&self) -> f64 {
        if self.expected == 0 {
            return 0.0;
        }
        1.0 - (self.received as f64 / self.expected as f64)
    }

    /// Loss percentage (0-100).
    pub fn loss_percent(&self) -> f64 {
        self.loss_ratio() * 100.0
    }

    /// Whether FEC should be activated (loss > threshold).
    pub fn should_activate_fec(&self, threshold_percent: f64) -> bool {
        self.loss_percent() > threshold_percent
    }
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_retransmit_queue_basic() {
        let mut q = RetransmitQueue::new();
        q.cache_packet(0, vec![1, 2, 3], 0);
        q.cache_packet(1, vec![4, 5, 6], 10);
        q.cache_packet(2, vec![7, 8, 9], 20);
        assert_eq!(q.len(), 3);

        let nack = NackMessage {
            base_seq: 0,
            bitmap: 0b101, // missing seq 0 and 2
        };
        let resend = q.process_nack(&nack);
        assert_eq!(resend.len(), 2);
        assert_eq!(resend[0].seq, 0);
        assert_eq!(resend[1].seq, 2);
    }

    #[test]
    fn test_retransmit_queue_eviction() {
        let mut q = RetransmitQueue::new();
        for i in 0..RETRANSMIT_CACHE_SIZE + 10 {
            q.cache_packet(i as u32, vec![0], i as u64);
        }
        assert_eq!(q.len(), RETRANSMIT_CACHE_SIZE);
    }

    #[test]
    fn test_retransmit_queue_purge() {
        let mut q = RetransmitQueue::new();
        q.cache_packet(0, vec![1], 0);
        q.cache_packet(1, vec![2], 50);
        q.cache_packet(2, vec![3], 200);
        q.update_rtt(100);
        q.purge_expired(400);
        assert_eq!(q.len(), 1);
        assert_eq!(q.cache.front().unwrap().seq, 2);
    }

    #[test]
    fn test_rtt_smoothing() {
        let mut q = RetransmitQueue::new();
        q.update_rtt(200);
        assert_eq!(q.rtt_ms(), 112);
    }

    #[test]
    fn test_gap_detector_no_gaps() {
        let mut gd = GapDetector::new();
        for i in 0..10u32 {
            let nack = gd.record_received(i);
            assert!(nack.is_none(), "unexpected nack at seq {}", i);
        }
    }

    #[test]
    fn test_gap_detector_detects_gap() {
        let mut gd = GapDetector::new();
        gd.record_received(0);
        gd.record_received(1);
        // Skip 2 and 3
        gd.record_received(4);
        gd.record_received(5);
        gd.record_received(6);
        gd.record_received(7);
        let mut found_nack = false;
        for i in 8..20u32 {
            if let Some(nack) = gd.record_received(i) {
                found_nack = true;
                let missing: Vec<u32> = nack.missing_seqs().collect();
                assert!(
                    missing.iter().any(|&s| s == 2) || missing.iter().any(|&s| s == 3),
                    "NACK should include 2 or 3, got {:?}",
                    missing
                );
                break;
            }
        }
        assert!(found_nack, "should have generated a NACK");
    }

    #[test]
    fn test_gap_detector_out_of_order_fill() {
        let mut gd = GapDetector::new();
        gd.record_received(0);
        gd.record_received(1);
        gd.record_received(3); // skip 2
        gd.record_received(2); // late arrival
        for i in 4..20u32 {
            if let Some(nack) = gd.record_received(i) {
                let missing: Vec<u32> = nack.missing_seqs().collect();
                assert!(!missing.contains(&2), "seq 2 filled but in NACK");
            }
        }
    }

    #[test]
    fn test_loss_estimator_no_loss() {
        let le = LossEstimator::new();
        assert_eq!(le.loss_ratio(), 0.0);
        assert!(!le.should_activate_fec(2.0));
    }

    #[test]
    fn test_loss_estimator_some_loss() {
        let mut le = LossEstimator::new();
        for i in 0..256u32 {
            le.record(i % 10 != 0);
        }
        let loss = le.loss_percent();
        assert!(loss > 8.0 && loss < 12.0, "expected ~10%, got {}", loss);
        assert!(le.should_activate_fec(2.0));
    }

    #[test]
    fn test_loss_estimator_recovers() {
        let mut le = LossEstimator::new();
        for _ in 0..256 {
            le.record(false);
        }
        assert!(le.loss_percent() > 90.0);
        for _ in 0..256 {
            le.record(true);
        }
        assert!(le.loss_percent() < 1.0);
    }
}
