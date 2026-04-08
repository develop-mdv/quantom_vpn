use std::net::Ipv4Addr;

use crate::{DevicePlatform, FlowId, DEVICE_TOKEN_LEN, MLKEM768_CT_LEN};

pub const HANDSHAKE_V2_VERSION: u8 = 3;
pub const HANDSHAKE_INIT_BUDGET: usize = 900;
pub const HANDSHAKE_SAFE_DATAGRAM_BUDGET: usize = 1232;
pub const HANDSHAKE_CONN_ID_LEN: usize = 8;
pub const HANDSHAKE_COOKIE_MAX_LEN: usize = 160;
pub const HANDSHAKE_TICKET_MAX_LEN: usize = 160;
pub const HANDSHAKE_GREASE_MAX_LEN: usize = 255;
pub const CREDENTIAL_NONCE_LEN: usize = 12;
pub const DEFAULT_KEM_CHUNK_LEN: usize = 768;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeV2Kind {
    ClientInit = 1,
    ServerRetry = 2,
    ClientAuth = 3,
    ClientKemChunk = 4,
    ClientResume = 5,
    ServerComplete = 6,
    KeyUpdate = 7,
}

impl HandshakeV2Kind {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::ClientInit),
            2 => Some(Self::ServerRetry),
            3 => Some(Self::ClientAuth),
            4 => Some(Self::ClientKemChunk),
            5 => Some(Self::ClientResume),
            6 => Some(Self::ServerComplete),
            7 => Some(Self::KeyUpdate),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionId(pub [u8; HANDSHAKE_CONN_ID_LEN]);

impl ConnectionId {
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < HANDSHAKE_CONN_ID_LEN {
            return None;
        }
        let mut out = [0u8; HANDSHAKE_CONN_ID_LEN];
        out.copy_from_slice(&bytes[..HANDSHAKE_CONN_ID_LEN]);
        Some(Self(out))
    }

    pub fn as_bytes(&self) -> &[u8; HANDSHAKE_CONN_ID_LEN] {
        &self.0
    }
}

#[derive(Debug, Clone)]
pub struct ClientInitV2 {
    pub connection_id: ConnectionId,
    pub client_mtu: u16,
    pub fec_support: bool,
    pub client_x25519_public: [u8; 32],
    pub grease: Vec<u8>,
}

impl ClientInitV2 {
    pub fn serialize(&self) -> Vec<u8> {
        let grease_len = self.grease.len().min(HANDSHAKE_GREASE_MAX_LEN);
        let mut buf = Vec::with_capacity(2 + HANDSHAKE_CONN_ID_LEN + 2 + 1 + 32 + 1 + grease_len);
        buf.push(HANDSHAKE_V2_VERSION);
        buf.push(HandshakeV2Kind::ClientInit as u8);
        buf.extend_from_slice(self.connection_id.as_bytes());
        buf.extend_from_slice(&self.client_mtu.to_be_bytes());
        buf.push(if self.fec_support { 1 } else { 0 });
        buf.extend_from_slice(&self.client_x25519_public);
        buf.push(grease_len as u8);
        buf.extend_from_slice(&self.grease[..grease_len]);
        buf
    }

    pub fn deserialize(buf: &[u8]) -> Option<Self> {
        if buf.len() < 2 + HANDSHAKE_CONN_ID_LEN + 2 + 1 + 32 + 1 {
            return None;
        }
        if buf[0] != HANDSHAKE_V2_VERSION
            || HandshakeV2Kind::from_u8(buf[1])? != HandshakeV2Kind::ClientInit
        {
            return None;
        }
        let connection_id = ConnectionId::from_bytes(&buf[2..2 + HANDSHAKE_CONN_ID_LEN])?;
        let client_mtu = u16::from_be_bytes([
            buf[2 + HANDSHAKE_CONN_ID_LEN],
            buf[3 + HANDSHAKE_CONN_ID_LEN],
        ]);
        let fec_support = buf[4 + HANDSHAKE_CONN_ID_LEN] != 0;
        let key_start = 5 + HANDSHAKE_CONN_ID_LEN;
        let mut client_x25519_public = [0u8; 32];
        client_x25519_public.copy_from_slice(&buf[key_start..key_start + 32]);
        let grease_len = buf[key_start + 32] as usize;
        let grease_start = key_start + 33;
        let grease_end = grease_start + grease_len;
        if buf.len() < grease_end {
            return None;
        }
        Some(Self {
            connection_id,
            client_mtu,
            fec_support,
            client_x25519_public,
            grease: buf[grease_start..grease_end].to_vec(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct ServerRetryV2 {
    pub connection_id: ConnectionId,
    pub server_mtu_hint: u16,
    pub server_x25519_public: [u8; 32],
    pub cookie: Vec<u8>,
    pub grease: Vec<u8>,
}

impl ServerRetryV2 {
    pub fn serialize(&self) -> Vec<u8> {
        let cookie_len = self.cookie.len().min(HANDSHAKE_COOKIE_MAX_LEN);
        let grease_len = self.grease.len().min(HANDSHAKE_GREASE_MAX_LEN);
        let mut buf = Vec::with_capacity(
            2 + HANDSHAKE_CONN_ID_LEN + 2 + 32 + 2 + cookie_len + 1 + grease_len,
        );
        buf.push(HANDSHAKE_V2_VERSION);
        buf.push(HandshakeV2Kind::ServerRetry as u8);
        buf.extend_from_slice(self.connection_id.as_bytes());
        buf.extend_from_slice(&self.server_mtu_hint.to_be_bytes());
        buf.extend_from_slice(&self.server_x25519_public);
        buf.extend_from_slice(&(cookie_len as u16).to_be_bytes());
        buf.extend_from_slice(&self.cookie[..cookie_len]);
        buf.push(grease_len as u8);
        buf.extend_from_slice(&self.grease[..grease_len]);
        buf
    }

    pub fn deserialize(buf: &[u8]) -> Option<Self> {
        if buf.len() < 2 + HANDSHAKE_CONN_ID_LEN + 2 + 32 + 2 + 1 {
            return None;
        }
        if buf[0] != HANDSHAKE_V2_VERSION
            || HandshakeV2Kind::from_u8(buf[1])? != HandshakeV2Kind::ServerRetry
        {
            return None;
        }
        let connection_id = ConnectionId::from_bytes(&buf[2..2 + HANDSHAKE_CONN_ID_LEN])?;
        let mtu_start = 2 + HANDSHAKE_CONN_ID_LEN;
        let server_mtu_hint = u16::from_be_bytes([buf[mtu_start], buf[mtu_start + 1]]);
        let key_start = mtu_start + 2;
        let mut server_x25519_public = [0u8; 32];
        server_x25519_public.copy_from_slice(&buf[key_start..key_start + 32]);
        let cookie_len_start = key_start + 32;
        let cookie_len =
            u16::from_be_bytes([buf[cookie_len_start], buf[cookie_len_start + 1]]) as usize;
        if cookie_len > HANDSHAKE_COOKIE_MAX_LEN {
            return None;
        }
        let cookie_start = cookie_len_start + 2;
        let cookie_end = cookie_start + cookie_len;
        if buf.len() < cookie_end + 1 {
            return None;
        }
        let grease_len = buf[cookie_end] as usize;
        let grease_start = cookie_end + 1;
        let grease_end = grease_start + grease_len;
        if buf.len() < grease_end {
            return None;
        }
        Some(Self {
            connection_id,
            server_mtu_hint,
            server_x25519_public,
            cookie: buf[cookie_start..cookie_end].to_vec(),
            grease: buf[grease_start..grease_end].to_vec(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct ClientCredentialPayload {
    pub device_id: [u8; 16],
    pub device_token: [u8; DEVICE_TOKEN_LEN],
    pub platform: DevicePlatform,
    pub device_name: String,
}

impl ClientCredentialPayload {
    pub fn serialize(&self) -> Vec<u8> {
        let name = self.device_name.as_bytes();
        let name_len = name.len().min(255);
        let mut buf = Vec::with_capacity(16 + DEVICE_TOKEN_LEN + 2 + name_len);
        buf.extend_from_slice(&self.device_id);
        buf.extend_from_slice(&self.device_token);
        buf.push(self.platform as u8);
        buf.push(name_len as u8);
        buf.extend_from_slice(&name[..name_len]);
        buf
    }

    pub fn deserialize(buf: &[u8]) -> Option<Self> {
        if buf.len() < 16 + DEVICE_TOKEN_LEN + 2 {
            return None;
        }
        let mut device_id = [0u8; 16];
        device_id.copy_from_slice(&buf[..16]);
        let mut device_token = [0u8; DEVICE_TOKEN_LEN];
        device_token.copy_from_slice(&buf[16..16 + DEVICE_TOKEN_LEN]);
        let platform = DevicePlatform::from_u8(buf[16 + DEVICE_TOKEN_LEN])?;
        let name_len = buf[16 + DEVICE_TOKEN_LEN + 1] as usize;
        let name_start = 16 + DEVICE_TOKEN_LEN + 2;
        let name_end = name_start + name_len;
        if buf.len() < name_end {
            return None;
        }
        let device_name = std::str::from_utf8(&buf[name_start..name_end])
            .ok()?
            .to_string();
        Some(Self {
            device_id,
            device_token,
            platform,
            device_name,
        })
    }
}

#[derive(Debug, Clone)]
pub struct ClientAuthV2 {
    pub connection_id: ConnectionId,
    pub client_x25519_public: [u8; 32],
    pub cookie: Vec<u8>,
    pub credential_nonce: [u8; CREDENTIAL_NONCE_LEN],
    pub credential_ciphertext: Vec<u8>,
}

impl ClientAuthV2 {
    pub fn serialize(&self) -> Vec<u8> {
        let cookie_len = self.cookie.len().min(HANDSHAKE_COOKIE_MAX_LEN);
        let credential_len = self.credential_ciphertext.len().min(u16::MAX as usize);
        let mut buf = Vec::with_capacity(
            2 + HANDSHAKE_CONN_ID_LEN
                + 32
                + 2
                + cookie_len
                + CREDENTIAL_NONCE_LEN
                + 2
                + credential_len,
        );
        buf.push(HANDSHAKE_V2_VERSION);
        buf.push(HandshakeV2Kind::ClientAuth as u8);
        buf.extend_from_slice(self.connection_id.as_bytes());
        buf.extend_from_slice(&self.client_x25519_public);
        buf.extend_from_slice(&(cookie_len as u16).to_be_bytes());
        buf.extend_from_slice(&self.cookie[..cookie_len]);
        buf.extend_from_slice(&self.credential_nonce);
        buf.extend_from_slice(&(credential_len as u16).to_be_bytes());
        buf.extend_from_slice(&self.credential_ciphertext[..credential_len]);
        buf
    }

    pub fn deserialize(buf: &[u8]) -> Option<Self> {
        if buf.len() < 2 + HANDSHAKE_CONN_ID_LEN + 32 + 2 + CREDENTIAL_NONCE_LEN + 2 {
            return None;
        }
        if buf[0] != HANDSHAKE_V2_VERSION
            || HandshakeV2Kind::from_u8(buf[1])? != HandshakeV2Kind::ClientAuth
        {
            return None;
        }
        let connection_id = ConnectionId::from_bytes(&buf[2..2 + HANDSHAKE_CONN_ID_LEN])?;
        let key_start = 2 + HANDSHAKE_CONN_ID_LEN;
        let mut client_x25519_public = [0u8; 32];
        client_x25519_public.copy_from_slice(&buf[key_start..key_start + 32]);
        let cookie_len_start = key_start + 32;
        let cookie_len =
            u16::from_be_bytes([buf[cookie_len_start], buf[cookie_len_start + 1]]) as usize;
        if cookie_len > HANDSHAKE_COOKIE_MAX_LEN {
            return None;
        }
        let cookie_start = cookie_len_start + 2;
        let cookie_end = cookie_start + cookie_len;
        if buf.len() < cookie_end + CREDENTIAL_NONCE_LEN + 2 {
            return None;
        }
        let mut credential_nonce = [0u8; CREDENTIAL_NONCE_LEN];
        credential_nonce.copy_from_slice(&buf[cookie_end..cookie_end + CREDENTIAL_NONCE_LEN]);
        let credential_len_start = cookie_end + CREDENTIAL_NONCE_LEN;
        let credential_len =
            u16::from_be_bytes([buf[credential_len_start], buf[credential_len_start + 1]]) as usize;
        let credential_start = credential_len_start + 2;
        let credential_end = credential_start + credential_len;
        if buf.len() < credential_end {
            return None;
        }
        Some(Self {
            connection_id,
            client_x25519_public,
            cookie: buf[cookie_start..cookie_end].to_vec(),
            credential_nonce,
            credential_ciphertext: buf[credential_start..credential_end].to_vec(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct ClientKemChunkV2 {
    pub connection_id: ConnectionId,
    pub chunk_index: u8,
    pub chunk_count: u8,
    pub total_len: u16,
    pub chunk: Vec<u8>,
}

impl ClientKemChunkV2 {
    pub fn serialize(&self) -> Vec<u8> {
        let chunk_len = self.chunk.len().min(u16::MAX as usize);
        let mut buf = Vec::with_capacity(2 + HANDSHAKE_CONN_ID_LEN + 1 + 1 + 2 + 2 + chunk_len);
        buf.push(HANDSHAKE_V2_VERSION);
        buf.push(HandshakeV2Kind::ClientKemChunk as u8);
        buf.extend_from_slice(self.connection_id.as_bytes());
        buf.push(self.chunk_index);
        buf.push(self.chunk_count);
        buf.extend_from_slice(&self.total_len.to_be_bytes());
        buf.extend_from_slice(&(chunk_len as u16).to_be_bytes());
        buf.extend_from_slice(&self.chunk[..chunk_len]);
        buf
    }

    pub fn deserialize(buf: &[u8]) -> Option<Self> {
        if buf.len() < 2 + HANDSHAKE_CONN_ID_LEN + 1 + 1 + 2 + 2 {
            return None;
        }
        if buf[0] != HANDSHAKE_V2_VERSION
            || HandshakeV2Kind::from_u8(buf[1])? != HandshakeV2Kind::ClientKemChunk
        {
            return None;
        }
        let connection_id = ConnectionId::from_bytes(&buf[2..2 + HANDSHAKE_CONN_ID_LEN])?;
        let meta_start = 2 + HANDSHAKE_CONN_ID_LEN;
        let chunk_index = buf[meta_start];
        let chunk_count = buf[meta_start + 1];
        let total_len = u16::from_be_bytes([buf[meta_start + 2], buf[meta_start + 3]]);
        let chunk_len = u16::from_be_bytes([buf[meta_start + 4], buf[meta_start + 5]]) as usize;
        let chunk_start = meta_start + 6;
        let chunk_end = chunk_start + chunk_len;
        if buf.len() < chunk_end {
            return None;
        }
        Some(Self {
            connection_id,
            chunk_index,
            chunk_count,
            total_len,
            chunk: buf[chunk_start..chunk_end].to_vec(),
        })
    }

    pub fn split(connection_id: ConnectionId, full_key: &[u8], chunk_len: usize) -> Vec<Self> {
        let effective = chunk_len.max(128).min(HANDSHAKE_SAFE_DATAGRAM_BUDGET);
        let total_len = full_key.len() as u16;
        let chunk_count = ((full_key.len() + effective - 1) / effective) as u8;
        full_key
            .chunks(effective)
            .enumerate()
            .map(|(idx, chunk)| Self {
                connection_id,
                chunk_index: idx as u8,
                chunk_count,
                total_len,
                chunk: chunk.to_vec(),
            })
            .collect()
    }
}

#[derive(Debug, Clone)]
pub struct ClientResumeV2 {
    pub connection_id: ConnectionId,
    pub client_x25519_public: [u8; 32],
    pub cookie: Vec<u8>,
    pub ticket: Vec<u8>,
}

impl ClientResumeV2 {
    pub fn serialize(&self) -> Vec<u8> {
        let cookie_len = self.cookie.len().min(HANDSHAKE_COOKIE_MAX_LEN);
        let ticket_len = self.ticket.len().min(HANDSHAKE_TICKET_MAX_LEN);
        let mut buf =
            Vec::with_capacity(2 + HANDSHAKE_CONN_ID_LEN + 32 + 2 + cookie_len + 2 + ticket_len);
        buf.push(HANDSHAKE_V2_VERSION);
        buf.push(HandshakeV2Kind::ClientResume as u8);
        buf.extend_from_slice(self.connection_id.as_bytes());
        buf.extend_from_slice(&self.client_x25519_public);
        buf.extend_from_slice(&(cookie_len as u16).to_be_bytes());
        buf.extend_from_slice(&self.cookie[..cookie_len]);
        buf.extend_from_slice(&(ticket_len as u16).to_be_bytes());
        buf.extend_from_slice(&self.ticket[..ticket_len]);
        buf
    }

    pub fn deserialize(buf: &[u8]) -> Option<Self> {
        if buf.len() < 2 + HANDSHAKE_CONN_ID_LEN + 32 + 2 + 2 {
            return None;
        }
        if buf[0] != HANDSHAKE_V2_VERSION
            || HandshakeV2Kind::from_u8(buf[1])? != HandshakeV2Kind::ClientResume
        {
            return None;
        }
        let connection_id = ConnectionId::from_bytes(&buf[2..2 + HANDSHAKE_CONN_ID_LEN])?;
        let key_start = 2 + HANDSHAKE_CONN_ID_LEN;
        let mut client_x25519_public = [0u8; 32];
        client_x25519_public.copy_from_slice(&buf[key_start..key_start + 32]);
        let cookie_len_start = key_start + 32;
        let cookie_len =
            u16::from_be_bytes([buf[cookie_len_start], buf[cookie_len_start + 1]]) as usize;
        if cookie_len > HANDSHAKE_COOKIE_MAX_LEN {
            return None;
        }
        let cookie_start = cookie_len_start + 2;
        let cookie_end = cookie_start + cookie_len;
        if buf.len() < cookie_end + 2 {
            return None;
        }
        let ticket_len = u16::from_be_bytes([buf[cookie_end], buf[cookie_end + 1]]) as usize;
        if ticket_len > HANDSHAKE_TICKET_MAX_LEN {
            return None;
        }
        let ticket_start = cookie_end + 2;
        let ticket_end = ticket_start + ticket_len;
        if buf.len() < ticket_end {
            return None;
        }
        Some(Self {
            connection_id,
            client_x25519_public,
            cookie: buf[cookie_start..cookie_end].to_vec(),
            ticket: buf[ticket_start..ticket_end].to_vec(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct ServerCompleteV2 {
    pub connection_id: ConnectionId,
    pub resumed: bool,
    pub fec_enabled: bool,
    pub flow_id: FlowId,
    pub tunnel_ip: Ipv4Addr,
    pub server_mtu: u16,
    pub ciphertext: Vec<u8>,
    pub resumption_ticket: Vec<u8>,
}

impl ServerCompleteV2 {
    pub fn serialize(&self) -> Vec<u8> {
        let ciphertext_len = self.ciphertext.len().min(MLKEM768_CT_LEN);
        let ticket_len = self.resumption_ticket.len().min(HANDSHAKE_TICKET_MAX_LEN);
        let mut flags = 0u8;
        if self.resumed {
            flags |= 0x01;
        }
        if self.fec_enabled {
            flags |= 0x02;
        }
        let mut buf = Vec::with_capacity(
            2 + 1 + HANDSHAKE_CONN_ID_LEN + 16 + 4 + 2 + 2 + ciphertext_len + 2 + ticket_len,
        );
        buf.push(HANDSHAKE_V2_VERSION);
        buf.push(HandshakeV2Kind::ServerComplete as u8);
        buf.push(flags);
        buf.extend_from_slice(self.connection_id.as_bytes());
        buf.extend_from_slice(self.flow_id.as_bytes());
        buf.extend_from_slice(&self.tunnel_ip.octets());
        buf.extend_from_slice(&self.server_mtu.to_be_bytes());
        buf.extend_from_slice(&(ciphertext_len as u16).to_be_bytes());
        buf.extend_from_slice(&self.ciphertext[..ciphertext_len]);
        buf.extend_from_slice(&(ticket_len as u16).to_be_bytes());
        buf.extend_from_slice(&self.resumption_ticket[..ticket_len]);
        buf
    }

    pub fn deserialize(buf: &[u8]) -> Option<Self> {
        if buf.len() < 2 + 1 + HANDSHAKE_CONN_ID_LEN + 16 + 4 + 2 + 2 + 2 {
            return None;
        }
        if buf[0] != HANDSHAKE_V2_VERSION
            || HandshakeV2Kind::from_u8(buf[1])? != HandshakeV2Kind::ServerComplete
        {
            return None;
        }
        let flags = buf[2];
        let connection_id = ConnectionId::from_bytes(&buf[3..3 + HANDSHAKE_CONN_ID_LEN])?;
        let flow_id_start = 3 + HANDSHAKE_CONN_ID_LEN;
        let flow_id = FlowId::from_bytes(&buf[flow_id_start..flow_id_start + 16])?;
        let ip_start = flow_id_start + 16;
        let tunnel_ip = Ipv4Addr::new(
            buf[ip_start],
            buf[ip_start + 1],
            buf[ip_start + 2],
            buf[ip_start + 3],
        );
        let mtu_start = ip_start + 4;
        let server_mtu = u16::from_be_bytes([buf[mtu_start], buf[mtu_start + 1]]);
        let ct_len_start = mtu_start + 2;
        let ciphertext_len =
            u16::from_be_bytes([buf[ct_len_start], buf[ct_len_start + 1]]) as usize;
        let ct_start = ct_len_start + 2;
        let ct_end = ct_start + ciphertext_len;
        if buf.len() < ct_end + 2 {
            return None;
        }
        let ticket_len = u16::from_be_bytes([buf[ct_end], buf[ct_end + 1]]) as usize;
        if ticket_len > HANDSHAKE_TICKET_MAX_LEN {
            return None;
        }
        let ticket_start = ct_end + 2;
        let ticket_end = ticket_start + ticket_len;
        if buf.len() < ticket_end {
            return None;
        }
        Some(Self {
            connection_id,
            resumed: (flags & 0x01) != 0,
            fec_enabled: (flags & 0x02) != 0,
            flow_id,
            tunnel_ip,
            server_mtu,
            ciphertext: buf[ct_start..ct_end].to_vec(),
            resumption_ticket: buf[ticket_start..ticket_end].to_vec(),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyUpdateFrameV2 {
    pub next_epoch: u32,
}

impl KeyUpdateFrameV2 {
    pub fn serialize(&self) -> [u8; 6] {
        let mut buf = [0u8; 6];
        buf[0] = HANDSHAKE_V2_VERSION;
        buf[1] = HandshakeV2Kind::KeyUpdate as u8;
        buf[2..6].copy_from_slice(&self.next_epoch.to_be_bytes());
        buf
    }

    pub fn deserialize(buf: &[u8]) -> Option<Self> {
        if buf.len() < 6 {
            return None;
        }
        if buf[0] != HANDSHAKE_V2_VERSION
            || HandshakeV2Kind::from_u8(buf[1])? != HandshakeV2Kind::KeyUpdate
        {
            return None;
        }
        Some(Self {
            next_epoch: u32::from_be_bytes([buf[2], buf[3], buf[4], buf[5]]),
        })
    }
}

pub fn estimate_client_init_size(grease_len: usize) -> usize {
    2 + HANDSHAKE_CONN_ID_LEN + 2 + 1 + 32 + 1 + grease_len.min(HANDSHAKE_GREASE_MAX_LEN)
}

pub fn estimate_client_auth_size(cookie_len: usize, credential_len: usize) -> usize {
    2 + HANDSHAKE_CONN_ID_LEN
        + 32
        + 2
        + cookie_len.min(HANDSHAKE_COOKIE_MAX_LEN)
        + CREDENTIAL_NONCE_LEN
        + 2
        + credential_len
}

pub fn estimate_kem_chunk_size(chunk_len: usize) -> usize {
    2 + HANDSHAKE_CONN_ID_LEN + 1 + 1 + 2 + 2 + chunk_len
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_init_roundtrip() {
        let msg = ClientInitV2 {
            connection_id: ConnectionId([1, 2, 3, 4, 5, 6, 7, 8]),
            client_mtu: 1280,
            fec_support: true,
            client_x25519_public: [9u8; 32],
            grease: vec![0xaa; 48],
        };
        let raw = msg.serialize();
        assert!(raw.len() <= HANDSHAKE_INIT_BUDGET);
        let parsed = ClientInitV2::deserialize(&raw).unwrap();
        assert_eq!(parsed.connection_id, msg.connection_id);
        assert_eq!(parsed.client_mtu, 1280);
        assert!(parsed.fec_support);
        assert_eq!(parsed.client_x25519_public, [9u8; 32]);
        assert_eq!(parsed.grease.len(), 48);
    }

    #[test]
    fn auth_payload_roundtrip() {
        let msg = ClientCredentialPayload {
            device_id: [0x11; 16],
            device_token: [0x22; DEVICE_TOKEN_LEN],
            platform: DevicePlatform::Linux,
            device_name: "workstation".to_string(),
        };
        let raw = msg.serialize();
        let parsed = ClientCredentialPayload::deserialize(&raw).unwrap();
        assert_eq!(parsed.device_id, [0x11; 16]);
        assert_eq!(parsed.device_token, [0x22; DEVICE_TOKEN_LEN]);
        assert_eq!(parsed.platform, DevicePlatform::Linux);
        assert_eq!(parsed.device_name, "workstation");
    }

    #[test]
    fn kem_key_splits_under_budget() {
        let conn = ConnectionId([7u8; HANDSHAKE_CONN_ID_LEN]);
        let chunks =
            ClientKemChunkV2::split(conn, &[0x55; crate::MLKEM768_EK_LEN], DEFAULT_KEM_CHUNK_LEN);
        assert_eq!(chunks.len(), 2);
        assert!(chunks
            .iter()
            .all(|chunk| chunk.serialize().len() <= HANDSHAKE_SAFE_DATAGRAM_BUDGET));
    }

    #[test]
    fn server_complete_roundtrip() {
        let msg = ServerCompleteV2 {
            connection_id: ConnectionId([3u8; HANDSHAKE_CONN_ID_LEN]),
            resumed: false,
            fec_enabled: true,
            flow_id: FlowId([4u8; 16]),
            tunnel_ip: Ipv4Addr::new(10, 7, 1, 9),
            server_mtu: 1280,
            ciphertext: vec![0x44; MLKEM768_CT_LEN],
            resumption_ticket: vec![0x99; 64],
        };
        let raw = msg.serialize();
        assert!(raw.len() <= HANDSHAKE_SAFE_DATAGRAM_BUDGET);
        let parsed = ServerCompleteV2::deserialize(&raw).unwrap();
        assert!(!parsed.resumed);
        assert!(parsed.fec_enabled);
        assert_eq!(parsed.flow_id, FlowId([4u8; 16]));
        assert_eq!(parsed.tunnel_ip, Ipv4Addr::new(10, 7, 1, 9));
        assert_eq!(parsed.ciphertext.len(), MLKEM768_CT_LEN);
        assert_eq!(parsed.resumption_ticket.len(), 64);
    }

    #[test]
    fn key_update_roundtrip() {
        let frame = KeyUpdateFrameV2 { next_epoch: 7 };
        let raw = frame.serialize();
        let parsed = KeyUpdateFrameV2::deserialize(&raw).unwrap();
        assert_eq!(parsed.next_epoch, 7);
    }
}
