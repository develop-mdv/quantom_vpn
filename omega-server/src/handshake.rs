use std::net::SocketAddr;

use kem::Encapsulate;
use ml_kem::{Encoded, EncodedSizeUser, KemCore, MlKem768};

use omega_core::crypto::{derive_flow_id, SessionKeys};
use omega_core::protocol::{
    ClientHello, FlowId, HandshakeReject, HandshakeRejectReason, ServerHello, StunWrapper,
    HANDSHAKE_VERSION,
};

use crate::identity::limits::ensure_session_limit;
use crate::identity::IdentityStore;
use crate::metrics;
use crate::session::{SessionManager, SessionState};

/// Type aliases for ML-KEM-768 key types.
type Ek768 = <MlKem768 as KemCore>::EncapsulationKey;

#[derive(Debug)]
pub enum HandshakeError {
    InvalidStun,
    NotARequest,
}

impl std::fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidStun => write!(f, "invalid STUN framing"),
            Self::NotARequest => write!(f, "STUN packet is not a request"),
        }
    }
}

impl std::error::Error for HandshakeError {}

pub enum HandshakeOutcome {
    Accepted {
        response: Vec<u8>,
        flow_id: FlowId,
    },
    Rejected {
        response: Vec<u8>,
        reason: HandshakeRejectReason,
    },
}

pub fn process_client_handshake(
    raw_packet: &[u8],
    client_addr: SocketAddr,
    session_manager: &SessionManager,
    identity_store: &IdentityStore,
    server_mtu: u16,
    allow_legacy_v1: bool,
) -> Result<HandshakeOutcome, HandshakeError> {
    let (is_request, txn_id, payload) =
        StunWrapper::parse(raw_packet).ok_or(HandshakeError::InvalidStun)?;
    if !is_request {
        return Err(HandshakeError::NotARequest);
    }

    let client_hello = match ClientHello::deserialize(payload) {
        Some(v) => v,
        None => {
            return Ok(reject_handshake(&txn_id, HandshakeRejectReason::Malformed));
        }
    };

    if client_hello.version != HANDSHAKE_VERSION && !(allow_legacy_v1 && client_hello.version == 1)
    {
        return Ok(reject_handshake(
            &txn_id,
            HandshakeRejectReason::VersionMismatch,
        ));
    }

    let auth = match client_hello.auth {
        Some(auth) => auth,
        None => {
            metrics::record_handshake_failure(HandshakeRejectReason::AuthFailed);
            return Ok(reject_handshake(&txn_id, HandshakeRejectReason::AuthFailed));
        }
    };

    let auth_ctx = match identity_store.authenticate_device(
        auth.device_id,
        auth.device_token,
        auth.platform,
        &auth.device_name,
    ) {
        Ok(ctx) => ctx,
        Err(reason) => {
            let reject_reason = reason.as_reject_reason();
            metrics::record_handshake_failure(reject_reason);
            return Ok(reject_handshake(&txn_id, reject_reason));
        }
    };

    let replaced_sessions = session_manager.terminate_device_sessions(&auth_ctx.device.device_id);
    if replaced_sessions > 0 {
        metrics::record_device_reconnect(replaced_sessions);
        tracing::info!(
            %client_addr,
            user_id = %auth_ctx.user.user_id,
            device_id = %auth_ctx.device.device_id,
            replaced_sessions,
            "device reconnect: replaced stale active session(s)"
        );
    }

    if ensure_session_limit(
        &auth_ctx.user,
        session_manager.count_user_sessions(&auth_ctx.user.user_id),
    )
    .is_err()
    {
        metrics::record_handshake_failure(HandshakeRejectReason::LimitExceeded);
        return Ok(reject_handshake(
            &txn_id,
            HandshakeRejectReason::LimitExceeded,
        ));
    }

    let tunnel_ip = match session_manager.allocate_tunnel_ip(&auth_ctx.device.device_id) {
        Some(ip) => ip,
        None => {
            metrics::record_handshake_failure(HandshakeRejectReason::IpPoolExhausted);
            return Ok(reject_handshake(
                &txn_id,
                HandshakeRejectReason::IpPoolExhausted,
            ));
        }
    };

    let ek_encoded: &Encoded<Ek768> = match client_hello.encaps_key.as_slice().try_into() {
        Ok(v) => v,
        Err(_) => {
            metrics::record_handshake_failure(HandshakeRejectReason::Malformed);
            return Ok(reject_handshake(&txn_id, HandshakeRejectReason::Malformed));
        }
    };
    let ek = Ek768::from_bytes(ek_encoded);

    let mut rng = rand::thread_rng();
    let (ct, shared_secret) = match ek.encapsulate(&mut rng) {
        Ok(v) => v,
        Err(_) => {
            metrics::record_handshake_failure(HandshakeRejectReason::ServerBusy);
            return Ok(reject_handshake(&txn_id, HandshakeRejectReason::ServerBusy));
        }
    };

    let ss_bytes: &[u8] = shared_secret.as_ref();
    let session_keys = match SessionKeys::from_shared_secret(ss_bytes, true) {
        Ok(v) => v,
        Err(_) => {
            metrics::record_handshake_failure(HandshakeRejectReason::ServerBusy);
            return Ok(reject_handshake(&txn_id, HandshakeRejectReason::ServerBusy));
        }
    };
    let flow_id_bytes = match derive_flow_id(ss_bytes) {
        Ok(v) => v,
        Err(_) => {
            metrics::record_handshake_failure(HandshakeRejectReason::ServerBusy);
            return Ok(reject_handshake(&txn_id, HandshakeRejectReason::ServerBusy));
        }
    };
    let flow_id = FlowId(flow_id_bytes);

    let chaos_seed = u64::from_le_bytes(ss_bytes[0..8].try_into().unwrap_or_default());
    let ssrc = u32::from_be_bytes(flow_id_bytes[0..4].try_into().unwrap_or_default());

    let negotiated_mtu = server_mtu.min(client_hello.client_mtu);
    let fec_enabled = client_hello.fec_support;

    let session = SessionState::new(
        session_keys,
        client_addr,
        tunnel_ip,
        auth_ctx.user.user_id.clone(),
        auth_ctx.device.device_id.clone(),
        chaos_seed,
        fec_enabled,
        ssrc,
    );
    if !session_manager.insert(flow_id, session) {
        metrics::record_handshake_failure(HandshakeRejectReason::ServerBusy);
        return Ok(reject_handshake(&txn_id, HandshakeRejectReason::ServerBusy));
    }

    let user_id = auth_ctx.user.user_id.clone();
    metrics::record_handshake_success(user_id.clone(), auth_ctx.device.platform.as_str());

    tracing::info!(
        %client_addr,
        user_id = %user_id,
        device_id = %auth_ctx.device.device_id,
        %tunnel_ip,
        mtu = negotiated_mtu,
        fec = fec_enabled,
        replaced_sessions,
        sessions = session_manager.count(),
        "new session established"
    );

    let ct_bytes: &[u8] = ct.as_ref();
    let server_hello = ServerHello {
        version: HANDSHAKE_VERSION,
        server_mtu: negotiated_mtu,
        fec_enabled,
        flow_id,
        tunnel_ip,
        ciphertext: ct_bytes.to_vec(),
    };
    let response = StunWrapper::wrap_response(&txn_id, &server_hello.serialize());

    Ok(HandshakeOutcome::Accepted { response, flow_id })
}

fn reject_handshake(txn_id: &[u8; 12], reason: HandshakeRejectReason) -> HandshakeOutcome {
    let payload = HandshakeReject {
        version: HANDSHAKE_VERSION,
        reason,
    }
    .serialize();
    let response = StunWrapper::wrap_response(txn_id, &payload);
    HandshakeOutcome::Rejected { response, reason }
}
