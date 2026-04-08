use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

use omega_core_wire::{FecFrame, TrafficClass};
use raptorq::{Decoder, Encoder, EncodingPacket, ObjectTransmissionInformation};

const LIVE_FEC_WIRE_VERSION: u8 = 1;
const LIVE_FEC_HEADER_LEN: usize = 1 + 1 + 12;
const LIVE_FEC_MESSAGE_TTL: Duration = Duration::from_secs(20);

#[derive(Debug, Clone, Copy)]
pub struct FecConfig {
    pub max_packet_size: u16,
    pub min_repair: u32,
    pub max_repair: u32,
    pub activation_threshold: f64,
}

impl Default for FecConfig {
    fn default() -> Self {
        Self {
            max_packet_size: 128,
            min_repair: 3,
            max_repair: 10,
            activation_threshold: 2.0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct FecEncodingBlock {
    pub oti: ObjectTransmissionInformation,
    pub packets: Vec<EncodingPacket>,
    pub source_symbols: u32,
}

pub struct FecEncoder {
    config: FecConfig,
}

impl FecEncoder {
    pub fn new(config: FecConfig) -> Self {
        Self { config }
    }

    pub fn encode_block(&self, data: &[u8], loss_percent: f64) -> Vec<EncodingPacket> {
        let repair_count = self.compute_repair_count(loss_percent);
        self.encode_block_with_repair(data, repair_count).packets
    }

    pub fn encode_block_with_repair(&self, data: &[u8], repair_count: u32) -> FecEncodingBlock {
        let encoder = Encoder::with_defaults(data, self.config.max_packet_size);
        let oti = encoder.get_config();
        let packets = encoder.get_encoded_packets(repair_count);
        let source_symbols = source_symbol_count(&oti);
        FecEncodingBlock {
            oti,
            packets,
            source_symbols,
        }
    }

    pub fn encode_live_block(
        &self,
        data: &[u8],
        symbol_size: u16,
        repair_count: u32,
    ) -> Option<FecEncodingBlock> {
        if data.is_empty() || repair_count == 0 {
            return None;
        }

        let aligned_symbol_size = symbol_size.max(8) - (symbol_size.max(8) % 8);
        let encoder = Encoder::with_defaults(data, aligned_symbol_size.max(8));
        let oti = encoder.get_config();
        let source_symbols = source_symbol_count(&oti);
        if source_symbols != 1 {
            return None;
        }

        let packets = encoder
            .get_encoded_packets(repair_count)
            .into_iter()
            .skip(source_symbols as usize)
            .collect();

        Some(FecEncodingBlock {
            oti,
            packets,
            source_symbols,
        })
    }

    pub fn compute_repair_count(&self, loss_percent: f64) -> u32 {
        if loss_percent <= self.config.activation_threshold {
            return self.config.min_repair;
        }

        let range = self.config.max_repair - self.config.min_repair;
        let loss_range = 10.0 - self.config.activation_threshold;
        let scale =
            ((loss_percent - self.config.activation_threshold) / loss_range).clamp(0.0, 1.0);
        let extra = (range as f64 * scale) as u32;
        self.config.min_repair + extra
    }

    pub fn config(&self) -> &FecConfig {
        &self.config
    }
}

pub struct FecDecoder {
    decoder: Decoder,
    recovered: Option<Vec<u8>>,
}

impl FecDecoder {
    pub fn new(config: ObjectTransmissionInformation) -> Self {
        Self {
            decoder: Decoder::new(config),
            recovered: None,
        }
    }

    pub fn from_data_len(data_len: u64, max_packet_size: u16) -> Self {
        let oti = ObjectTransmissionInformation::with_defaults(data_len, max_packet_size);
        Self::new(oti)
    }

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FecMode {
    Off,
    Active,
}

pub struct FecState {
    pub mode: FecMode,
    pub config: FecConfig,
    pub block_seq: u32,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredFecBlock {
    pub block_id: u32,
    pub class: TrafficClass,
    pub payload: Vec<u8>,
}

struct LiveFecBlock {
    class: TrafficClass,
    transfer_length: usize,
    decoder: FecDecoder,
    seen_shards: BTreeSet<u16>,
    last_update: Instant,
}

pub struct LiveFecReceiver {
    blocks: BTreeMap<u32, LiveFecBlock>,
    delivered: BTreeMap<u32, Instant>,
    ttl: Duration,
}

impl Default for LiveFecReceiver {
    fn default() -> Self {
        Self::new()
    }
}

impl LiveFecReceiver {
    pub fn new() -> Self {
        Self {
            blocks: BTreeMap::new(),
            delivered: BTreeMap::new(),
            ttl: LIVE_FEC_MESSAGE_TTL,
        }
    }

    pub fn accept_transport_message(&mut self, now: Instant, message_id: u32) -> bool {
        self.prune(now);
        if self.delivered.contains_key(&message_id) {
            return false;
        }

        self.blocks.remove(&message_id);
        self.delivered.insert(message_id, now);
        true
    }

    pub fn observe_frame(&mut self, now: Instant, frame: &FecFrame) -> Option<RecoveredFecBlock> {
        self.prune(now);
        if self.delivered.contains_key(&frame.block_id) {
            return None;
        }

        let (class, oti, packet) = parse_live_fec_frame(frame)?;
        let transfer_length = oti.transfer_length().min(usize::MAX as u64) as usize;
        let mut recovered = None;
        {
            let block = self
                .blocks
                .entry(frame.block_id)
                .or_insert_with(|| LiveFecBlock {
                    class,
                    transfer_length,
                    decoder: FecDecoder::new(oti),
                    seen_shards: BTreeSet::new(),
                    last_update: now,
                });
            block.last_update = now;
            if !block.seen_shards.insert(frame.shard_index) {
                return None;
            }
            if let Some(data) = block.decoder.add_packet(packet) {
                let mut payload = data.to_vec();
                payload.truncate(block.transfer_length);
                recovered = Some((block.class, payload));
            }
        }

        if let Some((class, payload)) = recovered {
            self.blocks.remove(&frame.block_id);
            self.delivered.insert(frame.block_id, now);
            return Some(RecoveredFecBlock {
                block_id: frame.block_id,
                class,
                payload,
            });
        }

        None
    }

    pub fn prune(&mut self, now: Instant) {
        self.blocks
            .retain(|_, block| now.duration_since(block.last_update) <= self.ttl);
        self.delivered
            .retain(|_, delivered_at| now.duration_since(*delivered_at) <= self.ttl);
    }
}

pub fn build_live_fec_frames(
    block_id: u32,
    original_class: TrafficClass,
    oti: &ObjectTransmissionInformation,
    packets: &[EncodingPacket],
) -> Vec<FecFrame> {
    let total = packets.len().min(u16::MAX as usize) as u16;
    let oti_bytes = oti.serialize();
    packets
        .iter()
        .enumerate()
        .map(|(index, packet)| {
            let packet_bytes = packet.serialize();
            let mut payload = Vec::with_capacity(LIVE_FEC_HEADER_LEN + packet_bytes.len());
            payload.push(LIVE_FEC_WIRE_VERSION);
            payload.push(original_class as u8);
            payload.extend_from_slice(&oti_bytes);
            payload.extend_from_slice(&packet_bytes);
            FecFrame {
                block_id,
                shard_index: index.min(u16::MAX as usize) as u16,
                shard_count: total,
                payload,
            }
        })
        .collect()
}

pub fn parse_live_fec_frame(
    frame: &FecFrame,
) -> Option<(TrafficClass, ObjectTransmissionInformation, EncodingPacket)> {
    if frame.payload.len() < LIVE_FEC_HEADER_LEN + 4 {
        return None;
    }
    if frame.payload[0] != LIVE_FEC_WIRE_VERSION {
        return None;
    }

    let class = TrafficClass::from_u8(frame.payload[1])?;
    let mut oti_bytes = [0u8; 12];
    oti_bytes.copy_from_slice(&frame.payload[2..14]);
    let oti = ObjectTransmissionInformation::deserialize(&oti_bytes);
    let packet = EncodingPacket::deserialize(&frame.payload[14..]);
    Some((class, oti, packet))
}

fn source_symbol_count(oti: &ObjectTransmissionInformation) -> u32 {
    let transfer_length = oti.transfer_length();
    let symbol_size = oti.symbol_size().max(1) as u64;
    transfer_length.div_ceil(symbol_size).max(1) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fec_encode_decode_roundtrip() {
        let config = FecConfig::default();
        let encoder = FecEncoder::new(config);

        let original =
            b"Hello, this is a test payload for RaptorQ FEC encoding and decoding roundtrip!";
        let packets = encoder.encode_block(original, 5.0);
        assert!(!packets.is_empty());

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
        let block = encoder.encode_block_with_repair(&original, 5);
        let mut decoder = FecDecoder::new(block.oti);
        for pkt in block.packets.into_iter().skip(2) {
            if let Some(data) = decoder.add_packet(pkt) {
                assert_eq!(&data[..original.len()], original.as_slice());
                return;
            }
        }
        panic!("should recover with 5 repair vs 2 lost");
    }

    #[test]
    fn test_live_fec_frame_roundtrip() {
        let encoder = FecEncoder::new(FecConfig {
            max_packet_size: 96,
            min_repair: 2,
            max_repair: 2,
            activation_threshold: 1.0,
        });
        let block = encoder.encode_block_with_repair(b"omega-live-fec", 2);
        let frames =
            build_live_fec_frames(7, TrafficClass::Interactive, &block.oti, &block.packets);
        assert!(!frames.is_empty());

        let (class, oti, packet) = parse_live_fec_frame(&frames[0]).unwrap();
        assert_eq!(class, TrafficClass::Interactive);
        let mut decoder = FecDecoder::new(oti);
        let _ = decoder.add_packet(packet);
    }

    #[test]
    fn test_live_repair_only_recovers_single_symbol_block() {
        let encoder = FecEncoder::new(FecConfig::default());
        let original = b"burst-safe-interactive-payload".to_vec();
        let symbol_size = ((original.len() + 16) as u16 + 7) / 8 * 8;
        let block = encoder
            .encode_live_block(&original, symbol_size, 2)
            .expect("single-symbol repair block");
        assert_eq!(block.source_symbols, 1);
        assert_eq!(block.packets.len(), 2);

        let mut decoder = FecDecoder::new(block.oti);
        let recovered = decoder
            .add_packet(block.packets[0].clone())
            .expect("repair packet should recover single-symbol block");
        assert_eq!(&recovered[..original.len()], original.as_slice());
    }

    #[test]
    fn test_live_fec_receiver_suppresses_duplicates() {
        let encoder = FecEncoder::new(FecConfig::default());
        let original = b"interactive-recovery".to_vec();
        let symbol_size = ((original.len() + 16) as u16 + 7) / 8 * 8;
        let block = encoder
            .encode_live_block(&original, symbol_size, 1)
            .unwrap();
        let frames =
            build_live_fec_frames(11, TrafficClass::Interactive, &block.oti, &block.packets);
        let now = Instant::now();
        let mut receiver = LiveFecReceiver::new();

        let recovered = receiver.observe_frame(now, &frames[0]).unwrap();
        assert_eq!(recovered.block_id, 11);
        assert_eq!(recovered.payload, original);
        assert!(!receiver.accept_transport_message(now + Duration::from_millis(10), 11));
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
        state.update(3.0);
        assert_eq!(state.mode, FecMode::Active);

        for _ in 0..9 {
            state.update(0.5);
            assert_eq!(state.mode, FecMode::Active);
        }
        state.update(0.5);
        assert_eq!(state.mode, FecMode::Off);
    }
}
