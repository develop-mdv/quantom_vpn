/// RaptorQ FEC Manager — adaptive forward error correction.
///
/// Uses `raptorq` crate 2.0 (RFC 6330). Activated dynamically when
/// packet loss exceeds threshold (default 2%).
///
/// Design:
/// - Small blocks: K = 32–64 source symbols via max_packet_size.
/// - Dynamic repair: +3 at low loss, up to +10 at high loss.
/// - Uses `Encoder::get_encoded_packets(repair_count)` which returns
///   all source + repair packets in a single call.

extern crate alloc;
use alloc::vec::Vec;

use raptorq::{Decoder, Encoder, EncodingPacket, ObjectTransmissionInformation};

/// FEC configuration.
#[derive(Debug, Clone, Copy)]
pub struct FecConfig {
    /// Maximum transmission unit / packet size for encoding.
    pub max_packet_size: u16,
    /// Minimum repair symbols to add per block.
    pub min_repair: u32,
    /// Maximum repair symbols to add per block.
    pub max_repair: u32,
    /// Loss threshold to activate FEC (percentage).
    pub activation_threshold: f64,
}

impl Default for FecConfig {
    fn default() -> Self {
        Self {
            max_packet_size: 128, // Each encoding packet ≤ 128 bytes
            min_repair: 3,
            max_repair: 10,
            activation_threshold: 2.0,
        }
    }
}

/// FEC encoder for one block of source data.
pub struct FecEncoder {
    config: FecConfig,
}

impl FecEncoder {
    pub fn new(config: FecConfig) -> Self {
        Self { config }
    }

    /// Encode a block of data into source + repair packets.
    ///
    /// `data` is the raw payload to protect.
    /// `loss_percent` determines how many repair symbols to generate.
    ///
    /// Returns a list of `EncodingPacket` (source + repair).
    pub fn encode_block(&self, data: &[u8], loss_percent: f64) -> Vec<EncodingPacket> {
        let repair_count = self.compute_repair_count(loss_percent);
        let encoder = Encoder::with_defaults(data, self.config.max_packet_size);
        // get_encoded_packets returns source + N repair packets per block
        encoder.get_encoded_packets(repair_count)
    }

    /// Compute dynamic repair count based on loss.
    pub fn compute_repair_count(&self, loss_percent: f64) -> u32 {
        if loss_percent <= self.config.activation_threshold {
            return self.config.min_repair;
        }

        // Linear scale: at threshold → min_repair, at 10% → max_repair
        let range = self.config.max_repair - self.config.min_repair;
        let loss_range = 10.0 - self.config.activation_threshold;
        let scale = ((loss_percent - self.config.activation_threshold) / loss_range)
            .min(1.0)
            .max(0.0);
        let extra = (range as f64 * scale) as u32;
        self.config.min_repair + extra
    }

    pub fn config(&self) -> &FecConfig {
        &self.config
    }
}

/// FEC decoder for one block.
pub struct FecDecoder {
    decoder: Decoder,
    recovered: Option<Vec<u8>>,
}

impl FecDecoder {
    /// Create a new decoder for a block with given transmission info.
    pub fn new(config: ObjectTransmissionInformation) -> Self {
        Self {
            decoder: Decoder::new(config),
            recovered: None,
        }
    }

    /// Create from expected data length and max packet size.
    pub fn from_data_len(data_len: u64, max_packet_size: u16) -> Self {
        let oti = ObjectTransmissionInformation::with_defaults(data_len, max_packet_size);
        Self::new(oti)
    }

    /// Feed a received packet into the decoder.
    /// Returns `Some(data)` if the block is now fully recovered.
    pub fn add_packet(&mut self, packet: EncodingPacket) -> Option<&[u8]> {
        if self.recovered.is_some() {
            return self.recovered.as_deref();
        }

        if let Some(data) = self.decoder.decode(packet) {
            self.recovered = Some(data);
            return self.recovered.as_deref();
        }

        None
    }

    pub fn is_recovered(&self) -> bool {
        self.recovered.is_some()
    }

    pub fn take_recovered(&mut self) -> Option<Vec<u8>> {
        self.recovered.take()
    }
}

/// FEC state machine for a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FecMode {
    /// FEC disabled — pure ARQ.
    Off,
    /// FEC active — encoding/decoding.
    Active,
}

/// Per-session FEC state with hysteresis.
pub struct FecState {
    pub mode: FecMode,
    pub config: FecConfig,
    pub block_seq: u32,
    /// Consecutive low-loss samples needed to deactivate.
    deactivate_countdown: u8,
}

impl FecState {
    pub fn new(config: FecConfig) -> Self {
        Self {
            mode: FecMode::Off,
            config,
            block_seq: 0,
            deactivate_countdown: 0,
        }
    }

    /// Update FEC state based on current loss estimate.
    pub fn update(&mut self, loss_percent: f64) {
        match self.mode {
            FecMode::Off => {
                if loss_percent > self.config.activation_threshold {
                    self.mode = FecMode::Active;
                    self.deactivate_countdown = 0;
                }
            }
            FecMode::Active => {
                if loss_percent <= self.config.activation_threshold * 0.5 {
                    self.deactivate_countdown += 1;
                    if self.deactivate_countdown >= 10 {
                        self.mode = FecMode::Off;
                        self.deactivate_countdown = 0;
                    }
                } else {
                    self.deactivate_countdown = 0;
                }
            }
        }
    }

    pub fn next_block_seq(&mut self) -> u32 {
        let seq = self.block_seq;
        self.block_seq = self.block_seq.wrapping_add(1);
        seq
    }
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fec_encode_decode_roundtrip() {
        let config = FecConfig::default();
        let encoder = FecEncoder::new(config);

        let original = b"Hello, this is a test payload for RaptorQ FEC encoding and decoding roundtrip!";
        let packets = encoder.encode_block(original, 5.0);
        assert!(!packets.is_empty());

        // Decode using the encoder's config
        let enc = Encoder::with_defaults(original, config.max_packet_size);
        let oti = enc.get_config();
        let mut decoder = FecDecoder::new(oti);
        for pkt in packets {
            if let Some(data) = decoder.add_packet(pkt) {
                assert_eq!(&data[..original.len()], original.as_slice());
                return;
            }
        }
        panic!("should have recovered");
    }

    #[test]
    fn test_fec_recovery_with_loss() {
        let config = FecConfig {
            max_packet_size: 64,
            min_repair: 5,
            max_repair: 10,
            activation_threshold: 2.0,
        };
        let encoder = FecEncoder::new(config);

        let original = vec![42u8; 256];
        let packets = encoder.encode_block(&original, 5.0);

        // Get OTI for decoder
        let enc = Encoder::with_defaults(&original, config.max_packet_size);
        let oti = enc.get_config();

        // Drop first 2 packets (simulate loss)
        let mut decoder = FecDecoder::new(oti);
        for pkt in packets.into_iter().skip(2) {
            if let Some(data) = decoder.add_packet(pkt) {
                assert_eq!(&data[..original.len()], original.as_slice());
                return;
            }
        }
        panic!("should recover with 5 repair vs 2 lost");
    }

    #[test]
    fn test_repair_count_scaling() {
        let config = FecConfig::default();
        let encoder = FecEncoder::new(config);

        assert_eq!(encoder.compute_repair_count(0.0), 3);
        assert_eq!(encoder.compute_repair_count(2.0), 3);
        assert_eq!(encoder.compute_repair_count(6.0), 6);
        assert_eq!(encoder.compute_repair_count(10.0), 10);
        assert_eq!(encoder.compute_repair_count(20.0), 10);
    }

    #[test]
    fn test_fec_state_activation() {
        let mut state = FecState::new(FecConfig::default());
        assert_eq!(state.mode, FecMode::Off);
        state.update(3.0);
        assert_eq!(state.mode, FecMode::Active);
    }

    #[test]
    fn test_fec_state_hysteresis() {
        let mut state = FecState::new(FecConfig::default());
        state.update(5.0);
        assert_eq!(state.mode, FecMode::Active);

        for _ in 0..9 {
            state.update(0.5);
            assert_eq!(state.mode, FecMode::Active);
        }
        state.update(0.5);
        assert_eq!(state.mode, FecMode::Off);
    }

    #[test]
    fn test_fec_state_hysteresis_reset() {
        let mut state = FecState::new(FecConfig::default());
        state.update(5.0);

        for _ in 0..5 {
            state.update(0.5);
        }
        state.update(3.0); // spike
        assert_eq!(state.mode, FecMode::Active);

        for _ in 0..9 {
            state.update(0.5);
            assert_eq!(state.mode, FecMode::Active);
        }
        state.update(0.5);
        assert_eq!(state.mode, FecMode::Off);
    }
}
