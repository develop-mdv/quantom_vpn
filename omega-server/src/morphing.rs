/// User-space morphing stub (Phase 6).
///
/// Currently a no-op pass-through. Will be implemented in Phase 6
/// with ChaosPrng bimodal padding and RTP profile matching.

pub struct MorphingConfig {
    /// 0 = off, 1 = jitter only, 2 = full bimodal
    pub aggressiveness: u8,
}

impl Default for MorphingConfig {
    fn default() -> Self {
        Self { aggressiveness: 0 }
    }
}
