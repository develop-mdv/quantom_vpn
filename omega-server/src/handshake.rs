/// Handshake handler — ML-KEM-768 key exchange in fake STUN framing.
///
/// Protocol:
/// 1. Client generates ML-KEM-768 keypair, sends encapsulation key in ClientHello.
/// 2. Server reconstructs encapsulation key, encapsulates → shared secret + ciphertext.
/// 3. Server derives session keys and FlowID from shared secret.
/// 4. Server sends ciphertext + FlowID back in ServerHello.
/// 5. Client decapsulates → same shared secret → derives same keys.

use std::net::SocketAddr;

use kem::Encapsulate;
use ml_kem::{Encoded, EncodedSizeUser, KemCore, MlKem768};
use omega_core::crypto::{derive_flow_id, SessionKeys};
use omega_core::protocol::{
    ClientHello, FlowId, ServerHello, StunWrapper, HANDSHAKE_VERSION,
};

use crate::session::{SessionManager, SessionState};

/// Type aliases for ML-KEM-768 key types.
type Ek768 = <MlKem768 as KemCore>::EncapsulationKey;

/// Server-side handshake processing errors.
#[derive(Debug)]
pub enum HandshakeError {
    InvalidStun,
    VersionMismatch,
    MalformedClientHello,
    InvalidEncapsKey,
    KemEncapsulationFailed,
    KeyDerivation,
    SessionLimitExceeded,
}

impl std::fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidStun => write!(f, "invalid STUN framing"),
            Self::VersionMismatch => write!(f, "protocol version mismatch"),
            Self::MalformedClientHello => write!(f, "malformed ClientHello"),
            Self::InvalidEncapsKey => write!(f, "invalid ML-KEM encapsulation key"),
            Self::KemEncapsulationFailed => write!(f, "ML-KEM encapsulation failed"),
            Self::KeyDerivation => write!(f, "key derivation error"),
            Self::SessionLimitExceeded => write!(f, "max concurrent sessions exceeded"),
        }
    }
}

impl std::error::Error for HandshakeError {}

/// Result of processing a client handshake.
pub struct HandshakeResult {
    /// STUN-wrapped ServerHello response to send back.
    pub response: Vec<u8>,
    /// Allocated FlowId for the new session.
    pub flow_id: FlowId,
}

/// Process an incoming handshake packet from a client.
///
/// 1. Parse STUN Binding Request wrapper.
/// 2. Deserialize ClientHello (version, MTU, FEC support, ML-KEM-768 encapsulation key).
/// 3. Reconstruct typed EncapsulationKey from bytes.
/// 4. Encapsulate: generate ciphertext + shared secret.
/// 5. Derive session keys (HKDF) and FlowId.
/// 6. Create session state and insert into manager.
/// 7. Return STUN-wrapped ServerHello.
pub fn process_client_handshake(
    raw_packet: &[u8],
    client_addr: SocketAddr,
    session_manager: &SessionManager,
    server_mtu: u16,
) -> Result<HandshakeResult, HandshakeError> {
    // 1. Parse STUN
    let (is_request, txn_id, payload) =
        StunWrapper::parse(raw_packet).ok_or(HandshakeError::InvalidStun)?;
    if !is_request {
        return Err(HandshakeError::InvalidStun);
    }

    // 2. Deserialize ClientHello
    let client_hello =
        ClientHello::deserialize(payload).ok_or(HandshakeError::MalformedClientHello)?;
    if client_hello.version != HANDSHAKE_VERSION {
        return Err(HandshakeError::VersionMismatch);
    }

    // 3. Reconstruct encapsulation key from bytes
    let ek_encoded: &Encoded<Ek768> = client_hello
        .encaps_key
        .as_slice()
        .try_into()
        .map_err(|_| HandshakeError::InvalidEncapsKey)?;
    let ek = Ek768::from_bytes(ek_encoded);

    // 4. Encapsulate → (ciphertext, shared_secret)
    let mut rng = rand::thread_rng();
    let (ct, shared_secret) = ek
        .encapsulate(&mut rng)
        .map_err(|_| HandshakeError::KemEncapsulationFailed)?;

    // 5. Derive keys + FlowId
    let ss_bytes: &[u8] = shared_secret.as_ref();
    let session_keys = SessionKeys::from_shared_secret(ss_bytes, true)
        .map_err(|_| HandshakeError::KeyDerivation)?;
    let flow_id_bytes =
        derive_flow_id(ss_bytes).map_err(|_| HandshakeError::KeyDerivation)?;
    let flow_id = FlowId(flow_id_bytes);

    // Derive chaos seed and SSRC from shared secret
    let chaos_seed = u64::from_le_bytes(ss_bytes[0..8].try_into().unwrap());
    let ssrc = u32::from_be_bytes(flow_id_bytes[0..4].try_into().unwrap());

    // 6. Negotiate MTU and FEC, create session
    let negotiated_mtu = server_mtu.min(client_hello.client_mtu);
    let fec_enabled = client_hello.fec_support;
    
    // FORCE STATIC IP for single-user stability (matches Client's hardcoded 10.7.0.2)
    let tunnel_ip = std::net::Ipv4Addr::new(10, 7, 0, 2);
    
    // Cleanup any zombie session holding this IP
    session_manager.remove_by_tunnel_ip(tunnel_ip);

    // let tunnel_ip = session_manager.allocate_tunnel_ip(); // Disabled for now

    let session = SessionState::new(
        session_keys,
        client_addr,
        tunnel_ip,
        chaos_seed,
        fec_enabled,
        ssrc,
    );
    if !session_manager.insert(flow_id, session) {
        return Err(HandshakeError::SessionLimitExceeded);
    }

    tracing::info!(
        %client_addr,
        %tunnel_ip,
        mtu = negotiated_mtu,
        fec = fec_enabled,
        sessions = session_manager.count(),
        "new session established"
    );

    // 7. Build ServerHello response
    let ct_bytes: &[u8] = ct.as_ref();
    let server_hello = ServerHello {
        version: HANDSHAKE_VERSION,
        server_mtu: negotiated_mtu,
        fec_enabled,
        flow_id,
        ciphertext: ct_bytes.to_vec(),
    };
    let response = StunWrapper::wrap_response(&txn_id, &server_hello.serialize());

    Ok(HandshakeResult { response, flow_id })
}
