use sha2::{Digest, Sha256};

use omega_core_wire::{ConnectionId, DataFrame, TrafficClass, TransportFrame};

#[derive(Debug, Clone)]
pub(crate) struct QueuedMessage {
    pub class: TrafficClass,
    pub message_id: u32,
    pub payload: Vec<u8>,
    pub offset: usize,
}

impl QueuedMessage {
    pub(crate) fn take_fragment(&mut self, max_payload: usize) -> Option<DataFrame> {
        let remaining = self.payload.len().saturating_sub(self.offset);
        if remaining == 0 || max_payload == 0 {
            return None;
        }
        let chunk_len = remaining.min(max_payload).min(u16::MAX as usize);
        let start = self.offset;
        let end = start + chunk_len;
        self.offset = end;
        Some(DataFrame {
            class: self.class,
            message_id: self.message_id,
            fragment_offset: start.min(u16::MAX as usize) as u16,
            message_len: self.payload.len().min(u16::MAX as usize) as u16,
            fin: end >= self.payload.len(),
            payload: self.payload[start..end].to_vec(),
        })
    }

    pub(crate) fn as_single_frame(&self) -> DataFrame {
        DataFrame {
            class: self.class,
            message_id: self.message_id,
            fragment_offset: 0,
            message_len: self.payload.len().min(u16::MAX as usize) as u16,
            fin: true,
            payload: self.payload.clone(),
        }
    }

    pub(crate) fn is_complete(&self) -> bool {
        self.offset >= self.payload.len()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SentStatus {
    InFlight,
    Lost,
    Acked,
}

#[derive(Debug, Clone)]
pub(crate) struct SentPacket {
    pub sent_at: std::time::Instant,
    pub bytes: usize,
    pub congestion_controlled: bool,
    pub principal_class: TrafficClass,
    pub frames: Vec<TransportFrame>,
    pub status: SentStatus,
    pub path_probe_target: Option<usize>,
}

pub(crate) fn derive_connection_id(secret: &[u8; 32], epoch: u32) -> ConnectionId {
    let mut hasher = Sha256::new();
    hasher.update(b"omega-v2-transport-cid");
    hasher.update(secret);
    hasher.update(epoch.to_be_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; 8];
    out.copy_from_slice(&digest[..8]);
    ConnectionId(out)
}

pub(crate) fn principal_class(frames: &[TransportFrame]) -> TrafficClass {
    for frame in frames {
        if let TransportFrame::Data(data) = frame {
            return data.class;
        }
    }
    TrafficClass::Control
}

pub(crate) fn data_frame_overhead() -> usize {
    3 + 1 + 4 + 2 + 2 + 1
}

pub(crate) fn packet_is_lost(
    packet_number: u32,
    largest_observed: u32,
    sent_at: std::time::Instant,
    now: std::time::Instant,
    loss_delay: std::time::Duration,
    packet_threshold: u32,
) -> bool {
    largest_observed.saturating_sub(packet_number) >= packet_threshold
        || now.saturating_duration_since(sent_at) >= loss_delay
}
