/// Wire protocol definitions for Omega VPN.
///
/// Packet structure (on the wire, inside UDP payload):
///
/// ```text
/// [RTP Header: 12B][FlowID: 16B][Seq: 4B][Flags: 1B][Encrypted Payload][Poly1305 Tag: 16B]
/// ```
///
/// - RTP header provides WebRTC cover (Opus/VP8 profiles).
/// - FlowID identifies the session (derived from handshake).
/// - Seq is a monotonic 32-bit counter (wraps at 2^32).
/// - Flags encode packet type and options.
/// - Encrypted payload is ChaCha20 ciphertext.
/// - Poly1305 tag is appended by AEAD.
///
/// Handshake packets use STUN Binding Request/Response framing.
use byteorder::{BigEndian, ByteOrder};

// ── Constants ──────────────────────────────────────────────────────

/// Size of an RTP header (fixed, no CSRC or extensions).
pub const RTP_HEADER_LEN: usize = 12;

/// Size of the Omega inner header (FlowID + Seq + Flags).
pub const OMEGA_HEADER_LEN: usize = 16 + 4 + 1; // 21 bytes

/// ChaCha20-Poly1305 authentication tag length.
pub const AEAD_TAG_LEN: usize = 16;

/// Total overhead before payload: RTP + Omega header.
pub const TOTAL_HEADER_LEN: usize = RTP_HEADER_LEN + OMEGA_HEADER_LEN; // 33

/// Total overhead: header + AEAD tag.
pub const TOTAL_OVERHEAD: usize = TOTAL_HEADER_LEN + AEAD_TAG_LEN; // 49

/// Negotiated TUN MTU.
pub const TUN_MTU: u16 = 1280;

/// Maximum inner payload size after all overhead.
pub const MAX_PAYLOAD: usize = 1400 - TOTAL_OVERHEAD; // 1351 bytes, fits in 1400 UDP

/// STUN magic cookie (RFC 5389).
pub const STUN_MAGIC_COOKIE: u32 = 0x2112A442;

/// STUN Binding Request type.
pub const STUN_BINDING_REQUEST: u16 = 0x0001;

/// STUN Binding Response type.
pub const STUN_BINDING_RESPONSE: u16 = 0x0101;

// ── Flow ID ────────────────────────────────────────────────────────

/// 128-bit flow identifier, derived from handshake shared secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowId(pub [u8; 16]);

impl FlowId {
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() < 16 {
            return None;
        }
        let mut id = [0u8; 16];
        id.copy_from_slice(&b[..16]);
        Some(Self(id))
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

// ── Packet Flags ───────────────────────────────────────────────────

/// Bit flags for the Flags byte.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketType {
    /// Normal tunneled data.
    Data = 0x00,
    /// Handshake (KEM exchange).
    Handshake = 0x01,
    /// Keep-alive ping.
    KeepAlive = 0x02,
    /// Graceful session close.
    Close = 0x03,
    /// ARQ NACK (retransmit request).
    Nack = 0x04,
    /// FEC negotiation / control.
    FecControl = 0x05,
}

impl PacketType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x00 => Some(Self::Data),
            0x01 => Some(Self::Handshake),
            0x02 => Some(Self::KeepAlive),
            0x03 => Some(Self::Close),
            0x04 => Some(Self::Nack),
            0x05 => Some(Self::FecControl),
            _ => None,
        }
    }
}

// ── RTP Header ─────────────────────────────────────────────────────

/// RTP header for WebRTC cover traffic.
///
/// Layout (12 bytes, big-endian):
/// ```text
/// [V=2, P=0, X=0, CC=0: 1B][M + PT: 1B][Sequence: 2B][Timestamp: 4B][SSRC: 4B]
/// ```
#[derive(Debug, Clone, Copy)]
pub struct RtpHeader {
    /// Payload type (e.g., 111 = Opus, 96 = VP8).
    pub payload_type: u8,
    /// Marker bit (frame boundary for video).
    pub marker: bool,
    /// RTP sequence number (independent of Omega seq).
    pub sequence: u16,
    /// RTP timestamp.
    pub timestamp: u32,
    /// Synchronization source — derived from FlowId for consistency.
    pub ssrc: u32,
}

impl RtpHeader {
    /// Create an Opus audio profile header (small packets).
    pub fn opus(sequence: u16, timestamp: u32, ssrc: u32) -> Self {
        Self {
            payload_type: 111,
            marker: false,
            sequence,
            timestamp,
            ssrc,
        }
    }

    /// Create a VP8 video profile header (large packets).
    pub fn vp8(sequence: u16, timestamp: u32, ssrc: u32, marker: bool) -> Self {
        Self {
            payload_type: 96,
            marker,
            sequence,
            timestamp,
            ssrc,
        }
    }

    /// Serialize into 12 bytes (big-endian).
    pub fn write_to(&self, buf: &mut [u8]) {
        debug_assert!(buf.len() >= RTP_HEADER_LEN);
        // Byte 0: V=2 (bits 6-7), P=0, X=0, CC=0
        buf[0] = 0x80; // Version 2
                       // Byte 1: Marker (bit 7) | PT (bits 0-6)
        buf[1] = (if self.marker { 0x80 } else { 0 }) | (self.payload_type & 0x7F);
        BigEndian::write_u16(&mut buf[2..4], self.sequence);
        BigEndian::write_u32(&mut buf[4..8], self.timestamp);
        BigEndian::write_u32(&mut buf[8..12], self.ssrc);
    }

    /// Parse from 12 bytes.
    pub fn read_from(buf: &[u8]) -> Option<Self> {
        if buf.len() < RTP_HEADER_LEN {
            return None;
        }
        // Check version = 2
        if (buf[0] >> 6) != 2 {
            return None;
        }
        Some(Self {
            marker: (buf[1] & 0x80) != 0,
            payload_type: buf[1] & 0x7F,
            sequence: BigEndian::read_u16(&buf[2..4]),
            timestamp: BigEndian::read_u32(&buf[4..8]),
            ssrc: BigEndian::read_u32(&buf[8..12]),
        })
    }
}

// ── Omega Header ───────────────────────────────────────────────────

/// Inner Omega header after the RTP cover.
#[derive(Debug, Clone, Copy)]
pub struct OmegaHeader {
    pub flow_id: FlowId,
    pub seq: u32,
    pub packet_type: PacketType,
}

impl OmegaHeader {
    /// Write 21 bytes: [FlowID:16][Seq:4][Flags:1].
    pub fn write_to(&self, buf: &mut [u8]) {
        debug_assert!(buf.len() >= OMEGA_HEADER_LEN);
        buf[..16].copy_from_slice(&self.flow_id.0);
        BigEndian::write_u32(&mut buf[16..20], self.seq);
        buf[20] = self.packet_type as u8;
    }

    /// Parse 21 bytes.
    pub fn read_from(buf: &[u8]) -> Option<Self> {
        if buf.len() < OMEGA_HEADER_LEN {
            return None;
        }
        let flow_id = FlowId::from_bytes(&buf[..16])?;
        let seq = BigEndian::read_u32(&buf[16..20]);
        let packet_type = PacketType::from_u8(buf[20])?;
        Some(Self {
            flow_id,
            seq,
            packet_type,
        })
    }
}

// ── STUN Wrapper (Handshake Only) ──────────────────────────────────

/// STUN message header (20 bytes) for handshake cover.
///
/// ```text
/// [Type: 2B][Length: 2B][Magic Cookie: 4B][Transaction ID: 12B]
/// ```
pub struct StunWrapper;

impl StunWrapper {
    /// Wrap a handshake payload in a STUN Binding Request.
    /// Returns the full STUN message.
    pub fn wrap_request(transaction_id: &[u8; 12], payload: &[u8]) -> Vec<u8> {
        let mut msg = vec![0u8; 20 + payload.len()];
        BigEndian::write_u16(&mut msg[0..2], STUN_BINDING_REQUEST);
        BigEndian::write_u16(&mut msg[2..4], payload.len() as u16);
        BigEndian::write_u32(&mut msg[4..8], STUN_MAGIC_COOKIE);
        msg[8..20].copy_from_slice(transaction_id);
        msg[20..].copy_from_slice(payload);
        msg
    }

    /// Wrap a handshake payload in a STUN Binding Response.
    pub fn wrap_response(transaction_id: &[u8; 12], payload: &[u8]) -> Vec<u8> {
        let mut msg = vec![0u8; 20 + payload.len()];
        BigEndian::write_u16(&mut msg[0..2], STUN_BINDING_RESPONSE);
        BigEndian::write_u16(&mut msg[2..4], payload.len() as u16);
        BigEndian::write_u32(&mut msg[4..8], STUN_MAGIC_COOKIE);
        msg[8..20].copy_from_slice(transaction_id);
        msg[20..].copy_from_slice(payload);
        msg
    }

    /// Parse a STUN message. Returns (is_request, transaction_id, payload).
    pub fn parse(buf: &[u8]) -> Option<(bool, [u8; 12], &[u8])> {
        if buf.len() < 20 {
            return None;
        }
        let msg_type = BigEndian::read_u16(&buf[0..2]);
        let length = BigEndian::read_u16(&buf[2..4]) as usize;
        let cookie = BigEndian::read_u32(&buf[4..8]);

        if cookie != STUN_MAGIC_COOKIE {
            return None;
        }
        if buf.len() < 20 + length {
            return None;
        }

        let is_request = match msg_type {
            STUN_BINDING_REQUEST => true,
            STUN_BINDING_RESPONSE => false,
            _ => return None,
        };

        let mut txn_id = [0u8; 12];
        txn_id.copy_from_slice(&buf[8..20]);

        Some((is_request, txn_id, &buf[20..20 + length]))
    }
}

// ── Handshake Payload Structures ───────────────────────────────────

/// Client → Server: ML-KEM-768 encapsulation key + client config.
///
/// ```text
/// [Version: 1B][ClientMTU: 2B][FecSupport: 1B][EncapsKey: 1184B]
/// ```
pub const HANDSHAKE_VERSION: u8 = 2;
pub const MLKEM768_EK_LEN: usize = 1184;
pub const MLKEM768_CT_LEN: usize = 1088;
pub const DEVICE_TOKEN_LEN: usize = 32;
pub const DEVICE_NAME_MAX_LEN: usize = 255;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DevicePlatform {
    Windows = 1,
    Linux = 2,
    Macos = 3,
    Android = 4,
    Ios = 5,
    Other = 255,
}

impl DevicePlatform {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Windows),
            2 => Some(Self::Linux),
            3 => Some(Self::Macos),
            4 => Some(Self::Android),
            5 => Some(Self::Ios),
            255 => Some(Self::Other),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ClientAuth {
    pub device_id: [u8; 16],
    pub device_token: [u8; DEVICE_TOKEN_LEN],
    pub platform: DevicePlatform,
    pub device_name: String,
}

pub struct ClientHello {
    pub version: u8,
    pub client_mtu: u16,
    pub fec_support: bool,
    pub encaps_key: Vec<u8>,
    pub auth: Option<ClientAuth>,
}

impl ClientHello {
    pub fn serialize(&self) -> Vec<u8> {
        let auth_len = self
            .auth
            .as_ref()
            .map(|a| 16 + DEVICE_TOKEN_LEN + 2 + a.device_name.len().min(DEVICE_NAME_MAX_LEN))
            .unwrap_or(0);
        let mut buf = Vec::with_capacity(4 + self.encaps_key.len() + auth_len);
        buf.push(self.version);
        buf.push((self.client_mtu >> 8) as u8);
        buf.push(self.client_mtu as u8);
        buf.push(if self.fec_support { 1 } else { 0 });
        buf.extend_from_slice(&self.encaps_key);

        if let Some(auth) = &self.auth {
            let name = auth.device_name.as_bytes();
            let name_len = name.len().min(DEVICE_NAME_MAX_LEN);
            buf.extend_from_slice(&auth.device_id);
            buf.extend_from_slice(&auth.device_token);
            buf.push(auth.platform as u8);
            buf.push(name_len as u8);
            buf.extend_from_slice(&name[..name_len]);
        }

        buf
    }

    pub fn deserialize(buf: &[u8]) -> Option<Self> {
        if buf.len() < 4 + MLKEM768_EK_LEN {
            return None;
        }

        let version = buf[0];
        let mut auth = None;

        if version >= 2 {
            let auth_base = 4 + MLKEM768_EK_LEN;
            if buf.len() < auth_base + 16 + DEVICE_TOKEN_LEN + 2 {
                return None;
            }

            let mut device_id = [0u8; 16];
            device_id.copy_from_slice(&buf[auth_base..auth_base + 16]);

            let mut device_token = [0u8; DEVICE_TOKEN_LEN];
            let token_start = auth_base + 16;
            let token_end = token_start + DEVICE_TOKEN_LEN;
            device_token.copy_from_slice(&buf[token_start..token_end]);

            let platform = DevicePlatform::from_u8(buf[token_end])?;
            let name_len = buf[token_end + 1] as usize;
            let name_start = token_end + 2;
            let name_end = name_start + name_len;
            if buf.len() < name_end {
                return None;
            }

            let device_name = std::str::from_utf8(&buf[name_start..name_end])
                .ok()?
                .to_string();
            auth = Some(ClientAuth {
                device_id,
                device_token,
                platform,
                device_name,
            });
        }

        Some(Self {
            version,
            client_mtu: ((buf[1] as u16) << 8) | (buf[2] as u16),
            fec_support: buf[3] != 0,
            encaps_key: buf[4..4 + MLKEM768_EK_LEN].to_vec(),
            auth,
        })
    }
}

pub struct ServerHello {
    pub version: u8,
    pub server_mtu: u16,
    pub fec_enabled: bool,
    pub flow_id: FlowId,
    pub tunnel_ip: std::net::Ipv4Addr,
    pub tunnel_ipv6: Option<std::net::Ipv6Addr>,
    pub ciphertext: Vec<u8>,
}

impl ServerHello {
    pub fn serialize(&self) -> Vec<u8> {
        let addr_len = if self.tunnel_ipv6.is_some() { 20 } else { 4 };
        let mut buf = Vec::with_capacity(20 + addr_len + self.ciphertext.len());
        buf.push(self.version);
        buf.push((self.server_mtu >> 8) as u8);
        buf.push(self.server_mtu as u8);
        buf.push(if self.fec_enabled { 1 } else { 0 });
        buf.extend_from_slice(&self.flow_id.0);
        buf.extend_from_slice(&self.tunnel_ip.octets());
        if let Some(tunnel_ipv6) = self.tunnel_ipv6 {
            buf.extend_from_slice(&tunnel_ipv6.octets());
        }
        buf.extend_from_slice(&self.ciphertext);
        buf
    }

    pub fn deserialize(buf: &[u8]) -> Option<Self> {
        if buf.len() < 20 + MLKEM768_CT_LEN {
            return None;
        }

        let flow_id = FlowId::from_bytes(&buf[4..20])?;
        let has_ipv4 = buf.len() >= 24 + MLKEM768_CT_LEN;
        let has_ipv6 = buf.len() >= 40 + MLKEM768_CT_LEN;
        let tunnel_ip = if has_ipv4 {
            std::net::Ipv4Addr::new(buf[20], buf[21], buf[22], buf[23])
        } else {
            std::net::Ipv4Addr::new(10, 7, 0, 2)
        };
        let tunnel_ipv6 = if has_ipv6 {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[24..40]);
            Some(std::net::Ipv6Addr::from(octets))
        } else {
            None
        };
        let ct_offset = if has_ipv6 {
            40
        } else if has_ipv4 {
            24
        } else {
            20
        };

        Some(Self {
            version: buf[0],
            server_mtu: ((buf[1] as u16) << 8) | (buf[2] as u16),
            fec_enabled: buf[3] != 0,
            flow_id,
            tunnel_ip,
            tunnel_ipv6,
            ciphertext: buf[ct_offset..ct_offset + MLKEM768_CT_LEN].to_vec(),
        })
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeRejectReason {
    AuthFailed = 1,
    DeviceRevoked = 2,
    UserBlocked = 3,
    LimitExceeded = 4,
    IpPoolExhausted = 5,
    VersionMismatch = 6,
    Malformed = 7,
    ServerBusy = 8,
}

impl HandshakeRejectReason {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::AuthFailed),
            2 => Some(Self::DeviceRevoked),
            3 => Some(Self::UserBlocked),
            4 => Some(Self::LimitExceeded),
            5 => Some(Self::IpPoolExhausted),
            6 => Some(Self::VersionMismatch),
            7 => Some(Self::Malformed),
            8 => Some(Self::ServerBusy),
            _ => None,
        }
    }
}

pub struct HandshakeReject {
    pub version: u8,
    pub reason: HandshakeRejectReason,
}

impl HandshakeReject {
    pub fn serialize(&self) -> [u8; 2] {
        [self.version, self.reason as u8]
    }

    pub fn deserialize(buf: &[u8]) -> Option<Self> {
        if buf.len() < 2 {
            return None;
        }

        Some(Self {
            version: buf[0],
            reason: HandshakeRejectReason::from_u8(buf[1])?,
        })
    }
}

// -- ARQ NACK Format ----------------------------------------------------------------

/// ARQ NACK message: requests retransmission of missing packets.
///
/// ```text
/// [BaseSeq: 4B][Bitmap: 8B]
/// ```
///
/// Bitmap: bit N = 1 means packet (BaseSeq + N) is missing.
#[derive(Debug, Clone, Copy)]
pub struct NackMessage {
    pub base_seq: u32,
    pub bitmap: u64,
}

impl NackMessage {
    pub fn write_to(&self, buf: &mut [u8]) {
        debug_assert!(buf.len() >= 12);
        BigEndian::write_u32(&mut buf[0..4], self.base_seq);
        BigEndian::write_u64(&mut buf[4..12], self.bitmap);
    }

    pub fn read_from(buf: &[u8]) -> Option<Self> {
        if buf.len() < 12 {
            return None;
        }
        Some(Self {
            base_seq: BigEndian::read_u32(&buf[0..4]),
            bitmap: BigEndian::read_u64(&buf[4..12]),
        })
    }

    /// Iterate over the sequence numbers marked as missing.
    pub fn missing_seqs(&self) -> impl Iterator<Item = u32> + '_ {
        (0..64u32).filter_map(move |i| {
            if self.bitmap & (1u64 << i) != 0 {
                Some(self.base_seq.wrapping_add(i))
            } else {
                None
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rtp_roundtrip() {
        let hdr = RtpHeader::opus(1234, 48000, 0xDEADBEEF);
        let mut buf = [0u8; 12];
        hdr.write_to(&mut buf);
        let parsed = RtpHeader::read_from(&buf).unwrap();
        assert_eq!(parsed.payload_type, 111);
        assert!(!parsed.marker);
        assert_eq!(parsed.sequence, 1234);
        assert_eq!(parsed.timestamp, 48000);
        assert_eq!(parsed.ssrc, 0xDEADBEEF);
    }

    #[test]
    fn test_rtp_vp8_marker() {
        let hdr = RtpHeader::vp8(42, 90000, 0xCAFE, true);
        let mut buf = [0u8; 12];
        hdr.write_to(&mut buf);
        let parsed = RtpHeader::read_from(&buf).unwrap();
        assert_eq!(parsed.payload_type, 96);
        assert!(parsed.marker);
    }

    #[test]
    fn test_omega_header_roundtrip() {
        let hdr = OmegaHeader {
            flow_id: FlowId([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
            seq: 0x12345678,
            packet_type: PacketType::Data,
        };
        let mut buf = [0u8; 21];
        hdr.write_to(&mut buf);
        let parsed = OmegaHeader::read_from(&buf).unwrap();
        assert_eq!(parsed.flow_id, hdr.flow_id);
        assert_eq!(parsed.seq, 0x12345678);
        assert_eq!(parsed.packet_type, PacketType::Data);
    }

    #[test]
    fn test_stun_roundtrip() {
        let txn_id = [1u8; 12];
        let payload = b"hello KEM";
        let msg = StunWrapper::wrap_request(&txn_id, payload);
        let (is_req, parsed_txn, parsed_payload) = StunWrapper::parse(&msg).unwrap();
        assert!(is_req);
        assert_eq!(parsed_txn, txn_id);
        assert_eq!(parsed_payload, payload);
    }

    #[test]
    fn test_stun_response() {
        let txn_id = [0xAB; 12];
        let payload = b"server reply";
        let msg = StunWrapper::wrap_response(&txn_id, payload);
        let (is_req, _, _) = StunWrapper::parse(&msg).unwrap();
        assert!(!is_req);
    }

    #[test]
    fn test_nack_missing_seqs() {
        let nack = NackMessage {
            base_seq: 100,
            bitmap: 0b1010_0101,
        };
        let missing: Vec<u32> = nack.missing_seqs().collect();
        assert_eq!(missing, vec![100, 102, 105, 107]);
    }

    #[test]
    fn test_nack_roundtrip() {
        let nack = NackMessage {
            base_seq: 999,
            bitmap: 0xDEAD_BEEF_CAFE_BABE,
        };
        let mut buf = [0u8; 12];
        nack.write_to(&mut buf);
        let parsed = NackMessage::read_from(&buf).unwrap();
        assert_eq!(parsed.base_seq, 999);
        assert_eq!(parsed.bitmap, 0xDEAD_BEEF_CAFE_BABE);
    }

    #[test]
    fn test_overhead_fits_mtu() {
        // Verify our overhead budget: 1280 payload + overhead < 1500
        assert!(TUN_MTU as usize + TOTAL_OVERHEAD + 28 <= 1500);
        // 1280 + 49 + 28 = 1357 < 1500 ✓
    }

    #[test]
    fn test_client_hello_roundtrip() {
        let ch = ClientHello {
            version: HANDSHAKE_VERSION,
            client_mtu: 1280,
            fec_support: true,
            encaps_key: vec![0xAA; MLKEM768_EK_LEN],
            auth: Some(ClientAuth {
                device_id: [0x11; 16],
                device_token: [0x22; DEVICE_TOKEN_LEN],
                platform: DevicePlatform::Windows,
                device_name: "desktop".to_string(),
            }),
        };
        let serialized = ch.serialize();
        let parsed = ClientHello::deserialize(&serialized).unwrap();
        assert_eq!(parsed.version, HANDSHAKE_VERSION);
        assert_eq!(parsed.client_mtu, 1280);
        assert!(parsed.fec_support);
        assert_eq!(parsed.encaps_key.len(), MLKEM768_EK_LEN);
        let auth = parsed.auth.unwrap();
        assert_eq!(auth.device_id, [0x11; 16]);
        assert_eq!(auth.device_token, [0x22; DEVICE_TOKEN_LEN]);
        assert_eq!(auth.platform, DevicePlatform::Windows);
        assert_eq!(auth.device_name, "desktop");
    }

    #[test]
    fn test_client_hello_v1_compat() {
        let ch = ClientHello {
            version: 1,
            client_mtu: 1280,
            fec_support: false,
            encaps_key: vec![0xAB; MLKEM768_EK_LEN],
            auth: None,
        };
        let serialized = ch.serialize();
        let parsed = ClientHello::deserialize(&serialized).unwrap();
        assert_eq!(parsed.version, 1);
        assert!(parsed.auth.is_none());
    }

    #[test]
    fn test_server_hello_roundtrip() {
        let sh = ServerHello {
            version: HANDSHAKE_VERSION,
            server_mtu: 1280,
            fec_enabled: false,
            flow_id: FlowId([7u8; 16]),
            tunnel_ip: std::net::Ipv4Addr::new(10, 7, 2, 5),
            tunnel_ipv6: Some("fd70:7::205".parse().unwrap()),
            ciphertext: vec![0xBB; MLKEM768_CT_LEN],
        };
        let serialized = sh.serialize();
        let parsed = ServerHello::deserialize(&serialized).unwrap();
        assert_eq!(parsed.version, HANDSHAKE_VERSION);
        assert_eq!(parsed.server_mtu, 1280);
        assert!(!parsed.fec_enabled);
        assert_eq!(parsed.flow_id, FlowId([7u8; 16]));
        assert_eq!(parsed.tunnel_ip, std::net::Ipv4Addr::new(10, 7, 2, 5));
        assert_eq!(parsed.tunnel_ipv6, Some("fd70:7::205".parse().unwrap()));
        assert_eq!(parsed.ciphertext.len(), MLKEM768_CT_LEN);
    }

    #[test]
    fn test_server_hello_ipv4_only_backward_compat() {
        let mut serialized = Vec::with_capacity(24 + MLKEM768_CT_LEN);
        serialized.push(HANDSHAKE_VERSION);
        serialized.push(0x05);
        serialized.push(0x00);
        serialized.push(0);
        serialized.extend_from_slice(&[7u8; 16]);
        serialized.extend_from_slice(&[10, 7, 2, 5]);
        serialized.extend_from_slice(&vec![0xBB; MLKEM768_CT_LEN]);

        let parsed = ServerHello::deserialize(&serialized).unwrap();
        assert_eq!(parsed.tunnel_ip, std::net::Ipv4Addr::new(10, 7, 2, 5));
        assert!(parsed.tunnel_ipv6.is_none());
    }

    #[test]
    fn test_handshake_reject_roundtrip() {
        let reject = HandshakeReject {
            version: HANDSHAKE_VERSION,
            reason: HandshakeRejectReason::DeviceRevoked,
        };
        let raw = reject.serialize();
        let parsed = HandshakeReject::deserialize(&raw).unwrap();
        assert_eq!(parsed.version, HANDSHAKE_VERSION);
        assert_eq!(parsed.reason, HandshakeRejectReason::DeviceRevoked);
    }
}
