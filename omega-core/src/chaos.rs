/// ChaosPrng — Ultra-lightweight chaotic PRNG for traffic morphing.
///
/// Uses a logistic map in Q64.64 fixed-point arithmetic, producing
/// deterministic bimodal packet sizes that mimic WebRTC audio/video
/// interleave patterns.
///
/// Per-connection cost: 16 bytes (seed + state).
/// Per-iteration cost: ~5 ns (two 128-bit multiplies).

/// Logistic map parameter mu ≈ 4.0 in Q64.64.
/// mu = (4 << 64) - 1 = 0x3_FFFF_FFFF_FFFF_FFFF
const MU: u128 = (4u128 << 64) - 1;

/// Small packet range: mimics Opus audio frames (80-200 bytes).
const SMALL_MIN: u16 = 80;
const SMALL_MAX: u16 = 200;

/// Large packet range: mimics VP8 video frames (1000-1200 bytes).
const LARGE_MIN: u16 = 1000;
const LARGE_MAX: u16 = 1200;

#[derive(Debug, Clone)]
pub struct ChaosPrng {
    /// Current state x ∈ (0, 1) represented as Q0.64 fixed-point.
    x: u64,
    /// Original seed for reproducibility / re-init.
    seed: u64,
}

impl ChaosPrng {
    /// Create a new ChaosPrng from a 64-bit seed.
    ///
    /// The seed must not be 0 or u64::MAX (fixed points of the logistic map).
    /// If an invalid seed is given, it is adjusted to avoid degenerate orbits.
    pub fn new(seed: u64) -> Self {
        let safe_seed = match seed {
            0 => 1,
            u64::MAX => u64::MAX - 1,
            s => s,
        };
        Self {
            x: safe_seed,
            seed: safe_seed,
        }
    }

    /// Advance the logistic map by one iteration and return the new state.
    ///
    /// Computes x_{n+1} = mu * x_n * (1 - x_n) in Q64.64:
    ///   tmp = x * ((1 << 64) - x)       [Q0.128, take upper 64 bits → Q0.64]
    ///   x'  = (mu * tmp) >> 64           [Q64.128 → Q0.64]
    #[inline(always)]
    pub fn next(&mut self) -> u64 {
        let x = self.x as u128;
        let one_minus_x = (1u128 << 64) - x;
        let tmp = (x * one_minus_x) >> 64; // Q0.64
        self.x = ((MU * tmp) >> 64) as u64;
        self.x
    }

    /// Generate a target packet size using bimodal distribution.
    ///
    /// If the high bit of the state is set → small packet (Opus audio profile).
    /// Otherwise → large packet (VP8 video profile).
    ///
    /// The remaining bits are used to uniformly select within the range,
    /// without any external PRNG or allocation.
    #[inline]
    pub fn get_target_size(&mut self) -> u16 {
        let raw = self.next();
        let high_bit = raw >> 63;

        // Use bits [16..63) for uniform range selection
        let selector = ((raw >> 16) & 0x7FFF_FFFF_FFFF) as u64;

        if high_bit == 1 {
            // Small packet: audio frame
            let range = (SMALL_MAX - SMALL_MIN) as u64 + 1; // 121
            SMALL_MIN + (selector % range) as u16
        } else {
            // Large packet: video frame
            let range = (LARGE_MAX - LARGE_MIN) as u64 + 1; // 201
            LARGE_MIN + (selector % range) as u16
        }
    }

    /// Get the current raw state (useful for external seeding or eBPF sync).
    #[inline]
    pub fn state(&self) -> u64 {
        self.x
    }

    /// Reset to the original seed.
    pub fn reset(&mut self) {
        self.x = self.seed;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_determinism() {
        let mut a = ChaosPrng::new(0xDEAD_BEEF_CAFE_BABEu64);
        let mut b = ChaosPrng::new(0xDEAD_BEEF_CAFE_BABEu64);

        for _ in 0..1000 {
            assert_eq!(a.next(), b.next());
        }
    }

    #[test]
    fn test_no_fixed_point() {
        let mut prng = ChaosPrng::new(42);
        let first = prng.next();
        let mut stuck = true;
        for _ in 0..100 {
            if prng.next() != first {
                stuck = false;
                break;
            }
        }
        assert!(!stuck, "PRNG stuck at fixed point");
    }

    #[test]
    fn test_seed_zero_adjusted() {
        let prng = ChaosPrng::new(0);
        assert_eq!(prng.x, 1);
    }

    #[test]
    fn test_seed_max_adjusted() {
        let prng = ChaosPrng::new(u64::MAX);
        assert_eq!(prng.x, u64::MAX - 1);
    }

    #[test]
    fn test_bimodal_distribution() {
        let mut prng = ChaosPrng::new(0x1234_5678_9ABC_DEF0u64);
        let mut small_count = 0u32;
        let mut large_count = 0u32;
        let n = 10_000;

        for _ in 0..n {
            let size = prng.get_target_size();
            if size >= SMALL_MIN && size <= SMALL_MAX {
                small_count += 1;
            } else if size >= LARGE_MIN && size <= LARGE_MAX {
                large_count += 1;
            } else {
                panic!("size {} out of both ranges", size);
            }
        }

        // Both modes should be represented (logistic map is ~50/50 on high bit)
        assert!(
            small_count > n / 5,
            "too few small packets: {}/{}",
            small_count,
            n
        );
        assert!(
            large_count > n / 5,
            "too few large packets: {}/{}",
            large_count,
            n
        );
        assert_eq!(small_count + large_count, n);
    }

    #[test]
    fn test_size_ranges() {
        let mut prng = ChaosPrng::new(0xAAAA_BBBB_CCCC_DDDDu64);
        for _ in 0..5000 {
            let size = prng.get_target_size();
            let in_small = size >= SMALL_MIN && size <= SMALL_MAX;
            let in_large = size >= LARGE_MIN && size <= LARGE_MAX;
            assert!(
                in_small || in_large,
                "size {} not in any valid range",
                size
            );
        }
    }

    #[test]
    fn test_reset() {
        let mut prng = ChaosPrng::new(999);
        let seq1: Vec<u64> = (0..10).map(|_| prng.next()).collect();
        prng.reset();
        let seq2: Vec<u64> = (0..10).map(|_| prng.next()).collect();
        assert_eq!(seq1, seq2);
    }
}
