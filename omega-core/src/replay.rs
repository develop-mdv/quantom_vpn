/// ReplayFilter — Sliding window anti-replay protection for UDP.
///
/// Maintains a 128-bit bitmap tracking which sequence numbers have been
/// received within a window of the highest seen sequence. Rejects
/// duplicates and packets that fall behind the window.
///
/// Per-connection cost: 24 bytes (u128 bitmap + u64 window_top).

/// Window size in bits. Must be a power of 2 for efficient masking.
const WINDOW_SIZE: u64 = 128;

#[derive(Debug, Clone)]
pub struct ReplayFilter {
    /// Bitmap of received sequence numbers within the window.
    /// Bit 0 = window_top, bit 1 = window_top-1, etc.
    bitmap: u128,
    /// Highest sequence number accepted so far.
    window_top: u64,
    /// Whether any packet has been received yet.
    initialized: bool,
}

impl ReplayFilter {
    pub fn new() -> Self {
        Self {
            bitmap: 0,
            window_top: 0,
            initialized: false,
        }
    }

    /// Check if a packet with the given sequence number should be accepted.
    ///
    /// Returns `true` if the packet is new (not a replay), `false` if it
    /// should be rejected (duplicate or too old).
    ///
    /// If accepted, the internal state is updated to mark this sequence
    /// as received.
    /// Check if a packet would be accepted, without updating state.
    pub fn check(&self, seq: u64) -> bool {
        if !self.initialized {
            return true;
        }
        if seq > self.window_top {
            true
        } else {
            let diff = self.window_top - seq;
            if diff >= WINDOW_SIZE {
                false
            } else {
                let bit = 1u128 << diff;
                self.bitmap & bit == 0
            }
        }
    }

    /// Update state to mark sequence as received.
    /// Should only be called after authentication!
    pub fn update(&mut self, seq: u64) {
        if !self.initialized {
            self.initialized = true;
            self.window_top = seq;
            self.bitmap = 1;
            return;
        }

        if seq > self.window_top {
            let shift = seq - self.window_top;
            if shift >= WINDOW_SIZE {
                self.bitmap = 1;
            } else {
                self.bitmap = self.bitmap.checked_shl(shift as u32).unwrap_or(0);
                self.bitmap |= 1;
            }
            self.window_top = seq;
        } else {
            let diff = self.window_top - seq;
            if diff < WINDOW_SIZE {
                let bit = 1u128 << diff;
                self.bitmap |= bit;
            }
        }
    }

    /// Atomic check and update (legacy/convenience).
    pub fn check_and_update(&mut self, seq: u64) -> bool {
        if self.check(seq) {
            self.update(seq);
            true
        } else {
            false
        }
    }

    /// Returns the current highest accepted sequence number.
    pub fn window_top(&self) -> u64 {
        self.window_top
    }
}

impl Default for ReplayFilter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sequential_accept() {
        let mut rf = ReplayFilter::new();
        for i in 0..256 {
            assert!(rf.check_and_update(i), "seq {} should be accepted", i);
        }
    }

    #[test]
    fn test_duplicate_reject() {
        let mut rf = ReplayFilter::new();
        assert!(rf.check_and_update(5));
        assert!(!rf.check_and_update(5), "duplicate should be rejected");
    }

    #[test]
    fn test_out_of_order_within_window() {
        let mut rf = ReplayFilter::new();
        assert!(rf.check_and_update(10));
        assert!(rf.check_and_update(8)); // 2 behind, within window
        assert!(rf.check_and_update(9)); // 1 behind, within window
        assert!(!rf.check_and_update(8)); // duplicate
    }

    #[test]
    fn test_too_old_rejected() {
        let mut rf = ReplayFilter::new();
        assert!(rf.check_and_update(0));
        assert!(rf.check_and_update(200)); // advance window far ahead
        assert!(
            !rf.check_and_update(10),
            "seq 10 should be too old (window at 200, size 128)"
        );
        // But seq 200-127 = 73 should still be in window if not seen
        assert!(
            rf.check_and_update(73),
            "seq 73 should be within window"
        );
    }

    #[test]
    fn test_window_boundary() {
        let mut rf = ReplayFilter::new();
        assert!(rf.check_and_update(0));
        assert!(rf.check_and_update(127)); // advance to 127
        // seq 0 is exactly at window boundary (127 - 0 = 127 < 128) → should accept
        // But we already received seq 0 above
        assert!(!rf.check_and_update(0), "already received");
        // seq 1 is at diff 126, not yet received
        assert!(rf.check_and_update(1));
    }

    #[test]
    fn test_window_just_outside() {
        let mut rf = ReplayFilter::new();
        assert!(rf.check_and_update(0));
        assert!(rf.check_and_update(128)); // window_top=128
        // seq 0: diff = 128 = WINDOW_SIZE → too old
        assert!(
            !rf.check_and_update(0),
            "seq 0 should be outside window (diff=128)"
        );
    }

    #[test]
    fn test_large_jump() {
        let mut rf = ReplayFilter::new();
        assert!(rf.check_and_update(0));
        assert!(rf.check_and_update(10_000)); // huge jump
        assert_eq!(rf.window_top(), 10_000);
        // Everything before 10_000 - 127 = 9873 is too old
        assert!(!rf.check_and_update(9872));
        assert!(rf.check_and_update(9873));
    }

    #[test]
    fn test_first_packet_any_seq() {
        let mut rf = ReplayFilter::new();
        assert!(rf.check_and_update(42));
        assert_eq!(rf.window_top(), 42);
    }

    #[test]
    fn test_stress_random_order() {
        let mut rf = ReplayFilter::new();
        // Send 0..256 in reverse order
        for i in (0..256u64).rev() {
            let accepted = rf.check_and_update(i);
            // First call (i=255) is always accepted.
            // Then i=254..128 should be accepted (within window of 255).
            // i=127..0 will be too old once window_top=255.
            if i >= 128 {
                assert!(accepted, "seq {} should be accepted", i);
            }
        }
    }
}
