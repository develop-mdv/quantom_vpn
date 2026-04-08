use byteorder::{BigEndian, ByteOrder};
use sha2::{Digest, Sha256};

use crate::{handshake_v2::ConnectionId, FlowId, OmegaHeader, PacketType, RtpHeader};

pub const MAX_ACK_RANGES: usize = 8;
pub const MAX_CONTROL_DATA_LEN: usize = 255;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameType {
    Data = 1,
    Ack = 2,
    Control = 3,
    Path = 4,
    Fec = 5,
    Padding = 6,
}

impl FrameType {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Data),
            2 => Some(Self::Ack),
            3 => Some(Self::Control),
            4 => Some(Self::Path),
            5 => Some(Self::Fec),
            6 => Some(Self::Padding),
            _ => None,
        }
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrafficClass {
    Control = 0,
    Interactive = 1,
    Bulk = 2,
}

impl TrafficClass {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Control),
            1 => Some(Self::Interactive),
            2 => Some(Self::Bulk),
            _ => None,
        }
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlKind {
    KeepAlive = 1,
    Close = 2,
    KeyUpdate = 3,
    AckFrequency = 4,
    PacingHint = 5,
}

impl ControlKind {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::KeepAlive),
            2 => Some(Self::Close),
            3 => Some(Self::KeyUpdate),
            4 => Some(Self::AckFrequency),
            5 => Some(Self::PacingHint),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataFrame {
    pub class: TrafficClass,
    pub message_id: u32,
    pub fragment_offset: u16,
    pub message_len: u16,
    pub fin: bool,
    pub payload: Vec<u8>,
}

impl DataFrame {
    const HEADER_LEN: usize = 1 + 4 + 2 + 2 + 1;

    fn body_len(&self) -> usize {
        Self::HEADER_LEN + self.payload.len()
    }

    fn write_body(&self, out: &mut Vec<u8>) {
        out.push(self.class as u8);
        out.extend_from_slice(&self.message_id.to_be_bytes());
        out.extend_from_slice(&self.fragment_offset.to_be_bytes());
        out.extend_from_slice(&self.message_len.to_be_bytes());
        out.push(if self.fin { 1 } else { 0 });
        out.extend_from_slice(&self.payload);
    }

    fn read_body(body: &[u8]) -> Option<Self> {
        if body.len() < Self::HEADER_LEN {
            return None;
        }
        Some(Self {
            class: TrafficClass::from_u8(body[0])?,
            message_id: BigEndian::read_u32(&body[1..5]),
            fragment_offset: BigEndian::read_u16(&body[5..7]),
            message_len: BigEndian::read_u16(&body[7..9]),
            fin: (body[9] & 1) != 0,
            payload: body[10..].to_vec(),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AckRange {
    pub start: u32,
    pub end: u32,
}

impl AckRange {
    pub fn new(start: u32, end: u32) -> Self {
        if start <= end {
            Self { start, end }
        } else {
            Self {
                start: end,
                end: start,
            }
        }
    }

    pub fn contains(&self, packet_number: u32) -> bool {
        packet_number >= self.start && packet_number <= self.end
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AckFrame {
    pub ack_delay_micros: u32,
    pub ranges: Vec<AckRange>,
}

impl AckFrame {
    const FIXED_LEN: usize = 4 + 1;

    pub fn normalized(mut ranges: Vec<AckRange>, ack_delay_micros: u32) -> Self {
        ranges.sort_by(|a, b| b.end.cmp(&a.end).then_with(|| b.start.cmp(&a.start)));
        let mut merged: Vec<AckRange> = Vec::with_capacity(ranges.len().min(MAX_ACK_RANGES));
        for range in ranges {
            if let Some(last) = merged.last_mut() {
                if range.end.saturating_add(1) >= last.start {
                    last.start = last.start.min(range.start);
                    last.end = last.end.max(range.end);
                    continue;
                }
            }
            if merged.len() >= MAX_ACK_RANGES {
                break;
            }
            merged.push(range);
        }
        Self {
            ack_delay_micros,
            ranges: merged,
        }
    }

    pub fn largest_acked(&self) -> Option<u32> {
        self.ranges.iter().map(|range| range.end).max()
    }

    pub fn acks_packet(&self, packet_number: u32) -> bool {
        self.ranges
            .iter()
            .any(|range| range.contains(packet_number))
    }

    fn body_len(&self) -> usize {
        Self::FIXED_LEN + self.ranges.len() * 8
    }

    fn write_body(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.ack_delay_micros.to_be_bytes());
        out.push(self.ranges.len().min(MAX_ACK_RANGES) as u8);
        for range in self.ranges.iter().take(MAX_ACK_RANGES) {
            out.extend_from_slice(&range.start.to_be_bytes());
            out.extend_from_slice(&range.end.to_be_bytes());
        }
    }

    fn read_body(body: &[u8]) -> Option<Self> {
        if body.len() < Self::FIXED_LEN {
            return None;
        }
        let count = body[4] as usize;
        let expected = Self::FIXED_LEN + count * 8;
        if body.len() != expected || count > MAX_ACK_RANGES {
            return None;
        }

        let mut ranges = Vec::with_capacity(count);
        let mut offset = 5;
        for _ in 0..count {
            let start = BigEndian::read_u32(&body[offset..offset + 4]);
            let end = BigEndian::read_u32(&body[offset + 4..offset + 8]);
            ranges.push(AckRange::new(start, end));
            offset += 8;
        }

        Some(Self::normalized(ranges, BigEndian::read_u32(&body[0..4])))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlFrame {
    pub kind: ControlKind,
    pub data: Vec<u8>,
}

impl ControlFrame {
    const HEADER_LEN: usize = 1 + 1;

    fn body_len(&self) -> usize {
        Self::HEADER_LEN + self.data.len().min(MAX_CONTROL_DATA_LEN)
    }

    fn write_body(&self, out: &mut Vec<u8>) {
        let data_len = self.data.len().min(MAX_CONTROL_DATA_LEN);
        out.push(self.kind as u8);
        out.push(data_len as u8);
        out.extend_from_slice(&self.data[..data_len]);
    }

    fn read_body(body: &[u8]) -> Option<Self> {
        if body.len() < Self::HEADER_LEN {
            return None;
        }
        let data_len = body[1] as usize;
        if body.len() != Self::HEADER_LEN + data_len {
            return None;
        }
        Some(Self {
            kind: ControlKind::from_u8(body[0])?,
            data: body[2..].to_vec(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathFrame {
    pub flags: u8,
    pub observed_rtt_micros: u32,
    pub delivery_rate_kbps: u32,
    pub next_connection_id: ConnectionId,
    pub rotation_epoch: u32,
}

impl PathFrame {
    const BODY_LEN: usize = 1 + 4 + 4 + 8 + 4;

    fn body_len(&self) -> usize {
        Self::BODY_LEN
    }

    fn write_body(&self, out: &mut Vec<u8>) {
        out.push(self.flags);
        out.extend_from_slice(&self.observed_rtt_micros.to_be_bytes());
        out.extend_from_slice(&self.delivery_rate_kbps.to_be_bytes());
        out.extend_from_slice(self.next_connection_id.as_bytes());
        out.extend_from_slice(&self.rotation_epoch.to_be_bytes());
    }

    fn read_body(body: &[u8]) -> Option<Self> {
        if body.len() != Self::BODY_LEN {
            return None;
        }
        Some(Self {
            flags: body[0],
            observed_rtt_micros: BigEndian::read_u32(&body[1..5]),
            delivery_rate_kbps: BigEndian::read_u32(&body[5..9]),
            next_connection_id: ConnectionId::from_bytes(&body[9..17])?,
            rotation_epoch: BigEndian::read_u32(&body[17..21]),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FecFrame {
    pub block_id: u32,
    pub shard_index: u16,
    pub shard_count: u16,
    pub payload: Vec<u8>,
}

impl FecFrame {
    const HEADER_LEN: usize = 4 + 2 + 2;

    fn body_len(&self) -> usize {
        Self::HEADER_LEN + self.payload.len()
    }

    fn write_body(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.block_id.to_be_bytes());
        out.extend_from_slice(&self.shard_index.to_be_bytes());
        out.extend_from_slice(&self.shard_count.to_be_bytes());
        out.extend_from_slice(&self.payload);
    }

    fn read_body(body: &[u8]) -> Option<Self> {
        if body.len() < Self::HEADER_LEN {
            return None;
        }
        Some(Self {
            block_id: BigEndian::read_u32(&body[0..4]),
            shard_index: BigEndian::read_u16(&body[4..6]),
            shard_count: BigEndian::read_u16(&body[6..8]),
            payload: body[8..].to_vec(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportFrame {
    Data(DataFrame),
    Ack(AckFrame),
    Control(ControlFrame),
    Path(PathFrame),
    Fec(FecFrame),
    Padding(usize),
}

impl TransportFrame {
    pub fn frame_type(&self) -> FrameType {
        match self {
            Self::Data(_) => FrameType::Data,
            Self::Ack(_) => FrameType::Ack,
            Self::Control(_) => FrameType::Control,
            Self::Path(_) => FrameType::Path,
            Self::Fec(_) => FrameType::Fec,
            Self::Padding(_) => FrameType::Padding,
        }
    }

    pub fn body_len(&self) -> usize {
        match self {
            Self::Data(frame) => frame.body_len(),
            Self::Ack(frame) => frame.body_len(),
            Self::Control(frame) => frame.body_len(),
            Self::Path(frame) => frame.body_len(),
            Self::Fec(frame) => frame.body_len(),
            Self::Padding(len) => *len,
        }
    }

    pub fn encoded_len(&self) -> usize {
        3 + self.body_len()
    }

    pub fn is_ack_eliciting(&self) -> bool {
        matches!(
            self,
            Self::Data(_) | Self::Control(_) | Self::Path(_) | Self::Fec(_)
        )
    }

    pub fn congestion_controlled(&self) -> bool {
        !matches!(self, Self::Ack(_) | Self::Padding(_))
    }
}

pub fn encode_transport_frames(frames: &[TransportFrame]) -> Vec<u8> {
    let total_len = frames.iter().map(TransportFrame::encoded_len).sum();
    let mut out = Vec::with_capacity(total_len);
    for frame in frames {
        let body_len = frame.body_len();
        out.push(frame.frame_type() as u8);
        out.extend_from_slice(&(body_len as u16).to_be_bytes());
        match frame {
            TransportFrame::Data(inner) => inner.write_body(&mut out),
            TransportFrame::Ack(inner) => inner.write_body(&mut out),
            TransportFrame::Control(inner) => inner.write_body(&mut out),
            TransportFrame::Path(inner) => inner.write_body(&mut out),
            TransportFrame::Fec(inner) => inner.write_body(&mut out),
            TransportFrame::Padding(len) => out.extend(std::iter::repeat(0).take(*len)),
        }
    }
    out
}

pub fn decode_transport_frames(buf: &[u8]) -> Option<Vec<TransportFrame>> {
    let mut out = Vec::new();
    let mut offset = 0;
    while offset < buf.len() {
        if buf.len().saturating_sub(offset) < 3 {
            return None;
        }
        let frame_type = FrameType::from_u8(buf[offset])?;
        let body_len = BigEndian::read_u16(&buf[offset + 1..offset + 3]) as usize;
        offset += 3;
        if buf.len().saturating_sub(offset) < body_len {
            return None;
        }
        let body = &buf[offset..offset + body_len];
        let frame = match frame_type {
            FrameType::Data => TransportFrame::Data(DataFrame::read_body(body)?),
            FrameType::Ack => TransportFrame::Ack(AckFrame::read_body(body)?),
            FrameType::Control => TransportFrame::Control(ControlFrame::read_body(body)?),
            FrameType::Path => TransportFrame::Path(PathFrame::read_body(body)?),
            FrameType::Fec => TransportFrame::Fec(FecFrame::read_body(body)?),
            FrameType::Padding => TransportFrame::Padding(body_len),
        };
        out.push(frame);
        offset += body_len;
    }
    Some(out)
}

#[derive(Debug, Clone)]
pub struct HeaderProtectionKey([u8; 32]);

impl HeaderProtectionKey {
    pub fn derive(secret: &[u8; 32]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"omega-v2-header-protection");
        hasher.update(secret);
        let digest = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        Self(out)
    }

    fn mask(&self, flow_id: &FlowId, rtp: &RtpHeader) -> [u8; 5] {
        let mut hasher = Sha256::new();
        hasher.update(self.0);
        hasher.update(flow_id.as_bytes());
        hasher.update(rtp.sequence.to_be_bytes());
        hasher.update(rtp.timestamp.to_be_bytes());
        hasher.update(rtp.ssrc.to_be_bytes());
        let digest = hasher.finalize();
        let mut out = [0u8; 5];
        out.copy_from_slice(&digest[..5]);
        out
    }
}

pub fn write_protected_omega_header(
    header: &OmegaHeader,
    rtp: &RtpHeader,
    key: &HeaderProtectionKey,
    buf: &mut [u8],
) {
    header.write_to(buf);
    let mask = key.mask(&header.flow_id, rtp);
    for (byte, mask_byte) in buf[16..20].iter_mut().zip(mask[..4].iter()) {
        *byte ^= *mask_byte;
    }
    buf[20] ^= mask[4] & 0x07;
}

pub fn read_protected_omega_header(
    rtp: &RtpHeader,
    key: &HeaderProtectionKey,
    buf: &[u8],
) -> Option<OmegaHeader> {
    if buf.len() < 21 {
        return None;
    }
    let flow_id = FlowId::from_bytes(&buf[..16])?;
    let mask = key.mask(&flow_id, rtp);
    let mut unmasked = [0u8; 21];
    unmasked.copy_from_slice(&buf[..21]);
    for (byte, mask_byte) in unmasked[16..20].iter_mut().zip(mask[..4].iter()) {
        *byte ^= *mask_byte;
    }
    unmasked[20] ^= mask[4] & 0x07;
    let header = OmegaHeader::read_from(&unmasked)?;
    if header.flow_id != flow_id {
        return None;
    }
    Some(header)
}

pub fn encode_path_signal(
    observed_rtt_micros: u32,
    delivery_rate_kbps: u32,
    next_connection_id: ConnectionId,
    rotation_epoch: u32,
) -> TransportFrame {
    TransportFrame::Path(PathFrame {
        flags: 0,
        observed_rtt_micros,
        delivery_rate_kbps,
        next_connection_id,
        rotation_epoch,
    })
}

pub fn encode_keepalive() -> TransportFrame {
    TransportFrame::Control(ControlFrame {
        kind: ControlKind::KeepAlive,
        data: Vec::new(),
    })
}

pub fn encode_close() -> TransportFrame {
    TransportFrame::Control(ControlFrame {
        kind: ControlKind::Close,
        data: Vec::new(),
    })
}

pub fn control_packet_type(frames: &[TransportFrame]) -> PacketType {
    if frames.iter().any(|frame| {
        matches!(
            frame,
            TransportFrame::Control(ControlFrame {
                kind: ControlKind::Close,
                ..
            })
        )
    }) {
        PacketType::Close
    } else {
        PacketType::Data
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_roundtrip() {
        let frames = vec![
            TransportFrame::Data(DataFrame {
                class: TrafficClass::Interactive,
                message_id: 7,
                fragment_offset: 0,
                message_len: 5,
                fin: true,
                payload: b"hello".to_vec(),
            }),
            TransportFrame::Ack(AckFrame::normalized(
                vec![AckRange::new(40, 44), AckRange::new(30, 31)],
                1200,
            )),
            encode_keepalive(),
            encode_path_signal(12_500, 8_000, ConnectionId([7u8; 8]), 2),
            TransportFrame::Padding(11),
        ];

        let raw = encode_transport_frames(&frames);
        let parsed = decode_transport_frames(&raw).unwrap();
        assert_eq!(parsed, frames);
    }

    #[test]
    fn ack_ranges_merge_and_match() {
        let ack = AckFrame::normalized(
            vec![
                AckRange::new(10, 15),
                AckRange::new(16, 20),
                AckRange::new(2, 4),
            ],
            500,
        );
        assert_eq!(ack.ranges.len(), 2);
        assert!(ack.acks_packet(18));
        assert!(!ack.acks_packet(9));
        assert_eq!(ack.largest_acked(), Some(20));
    }

    #[test]
    fn omega_header_protection_roundtrip() {
        let flow_id = FlowId([9u8; 16]);
        let rtp = RtpHeader::opus(55, 44_100, 0x0102_0304);
        let key = HeaderProtectionKey::derive(&[3u8; 32]);
        let header = OmegaHeader {
            flow_id,
            seq: 0xDEAD_BEEF,
            packet_type: PacketType::Data,
        };

        let mut buf = [0u8; 21];
        write_protected_omega_header(&header, &rtp, &key, &mut buf);
        assert_ne!(&buf[16..20], &0xDEAD_BEEFu32.to_be_bytes());
        let parsed = read_protected_omega_header(&rtp, &key, &buf).unwrap();
        assert_eq!(parsed.flow_id, flow_id);
        assert_eq!(parsed.seq, 0xDEAD_BEEF);
        assert_eq!(parsed.packet_type, PacketType::Data);
    }
}
