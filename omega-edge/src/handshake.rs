use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use kem::Encapsulate;
use ml_kem::{Encoded, EncodedSizeUser, KemCore, MlKem768};
use rand::RngCore;

use omega_control::identity::auth::AuthContext;
use omega_control::identity::limits::ensure_session_limit;
use omega_control::identity::IdentityStore;
use omega_control::policy::SessionAdmission;
use omega_core_crypto::{
    derive_credential_key, derive_hybrid_handshake_secrets, derive_resumption_handshake_secrets,
    hash_transcript, open_with_key, seal_with_key, X25519Keypair,
};
use omega_core_wire::{
    ClientAuthV2, ClientCredentialPayload, ClientInitV2, ClientKemChunkV2, ClientResumeV2,
    ConnectionId, FlowId, HandshakeReject, HandshakeRejectReason, HandshakeV2Kind,
    ServerCompleteV2, ServerRetryV2, StunWrapper, CREDENTIAL_NONCE_LEN, HANDSHAKE_V2_VERSION,
    HANDSHAKE_VERSION, MLKEM768_EK_LEN,
};

use crate::abuse::{AbuseVerdict, HandshakeAbuseGuard};
use crate::fabric::SharedFabric;
use crate::session::{SessionManager, SessionState};
use crate::{metrics, observability};
use omega_stealth::{persona_spec, PersonaId, ProbeResponseClass};

const COOKIE_AAD: &[u8] = b"omega-v2-cookie";
const TICKET_AAD: &[u8] = b"omega-v2-ticket";
const COOKIE_TTL: Duration = Duration::from_secs(10);
const PENDING_TTL: Duration = Duration::from_secs(15);

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
    Response {
        response: Vec<u8>,
        flow_id: Option<FlowId>,
        reason: Option<HandshakeRejectReason>,
    },
    NoResponse,
}

#[derive(Clone)]
pub struct HandshakeService {
    inner: Arc<HandshakeInner>,
}

struct HandshakeInner {
    server_x25519: X25519Keypair,
    cookie_key: [u8; 32],
    ticket_key: [u8; 32],
    pending: DashMap<String, PendingHandshake>,
    abuse_guard: HandshakeAbuseGuard,
}

struct PendingHandshake {
    client_addr: SocketAddr,
    auth_ctx: AuthContext,
    connection_id: ConnectionId,
    client_mtu: u16,
    fec_enabled: bool,
    x25519_shared: [u8; 32],
    init_transcript: Vec<u8>,
    retry_transcript: Vec<u8>,
    auth_transcript: Vec<u8>,
    tunnel_ip: std::net::Ipv4Addr,
    created_at: Instant,
    kem_total_len: usize,
    kem_chunks: Vec<Option<Vec<u8>>>,
}

#[derive(Clone)]
struct CookiePayload {
    issued_at_secs: u64,
    connection_id: ConnectionId,
    client_mtu: u16,
    fec_support: bool,
    client_x25519_public: [u8; 32],
    client_addr: SocketAddr,
}

struct TicketPayload {
    expires_at_secs: u64,
    device_id: [u8; 16],
    resumption_secret: [u8; 32],
}

impl HandshakeService {
    pub fn new() -> Self {
        let mut cookie_key = [0u8; 32];
        let mut ticket_key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut cookie_key);
        rand::thread_rng().fill_bytes(&mut ticket_key);
        Self {
            inner: Arc::new(HandshakeInner {
                server_x25519: X25519Keypair::generate(),
                cookie_key,
                ticket_key,
                pending: DashMap::new(),
                abuse_guard: HandshakeAbuseGuard::new(),
            }),
        }
    }

    pub fn pending_count(&self) -> usize {
        self.inner.pending.len()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn process_client_handshake(
        &self,
        raw_packet: &[u8],
        client_addr: SocketAddr,
        session_manager: &SessionManager,
        identity_store: &IdentityStore,
        server_mtu: u16,
        _allow_legacy_v1: bool,
        morphing_policy: omega_stealth::MorphingPolicy,
        persona: PersonaId,
        admission: &SessionAdmission,
        fabric: &SharedFabric,
    ) -> Result<HandshakeOutcome, HandshakeError> {
        self.cleanup();

        let (is_request, txn_id, payload) =
            StunWrapper::parse(raw_packet).ok_or(HandshakeError::InvalidStun)?;
        if !is_request {
            return Err(HandshakeError::NotARequest);
        }
        match self.inner.abuse_guard.register_attempt(client_addr.ip()) {
            AbuseVerdict::Allowed => {}
            AbuseVerdict::RateLimited { retry_after_ms } => {
                metrics::record_handshake_rate_limited();
                observability::record_trace_event(
                    "handshake",
                    "warning",
                    format!("hs-rate-limit-{}", client_addr.ip()),
                    None,
                    "handshake attempt was rate limited",
                    serde_json::json!({
                        "client_ip": client_addr.ip().to_string(),
                        "retry_after_ms": retry_after_ms,
                    }),
                );
                return Ok(anti_probe_outcome(
                    persona,
                    &txn_id,
                    HandshakeRejectReason::ServerBusy,
                ));
            }
        }
        if payload.len() < 2 {
            return Ok(anti_probe_outcome(
                persona,
                &txn_id,
                HandshakeRejectReason::Malformed,
            ));
        }

        match HandshakeV2Kind::from_u8(payload[1]) {
            Some(HandshakeV2Kind::ClientInit) => {
                self.handle_client_init(&txn_id, payload, client_addr, server_mtu, persona)
            }
            Some(HandshakeV2Kind::ClientAuth) => self.handle_client_auth(
                &txn_id,
                payload,
                client_addr,
                session_manager,
                identity_store,
                server_mtu,
                persona,
            ),
            Some(HandshakeV2Kind::ClientKemChunk) => self.handle_client_kem_chunk(
                &txn_id,
                payload,
                client_addr,
                session_manager,
                identity_store,
                server_mtu,
                morphing_policy,
                persona,
                admission,
                fabric,
            ),
            Some(HandshakeV2Kind::ClientResume) => self.handle_client_resume(
                &txn_id,
                payload,
                client_addr,
                session_manager,
                identity_store,
                server_mtu,
                morphing_policy,
                persona,
                admission,
                fabric,
            ),
            _ if payload[0] == HANDSHAKE_VERSION || payload[0] == HANDSHAKE_V2_VERSION => Ok(
                anti_probe_outcome(persona, &txn_id, HandshakeRejectReason::Malformed),
            ),
            _ => Ok(anti_probe_outcome(
                persona,
                &txn_id,
                HandshakeRejectReason::VersionMismatch,
            )),
        }
    }

    fn handle_client_init(
        &self,
        txn_id: &[u8; 12],
        payload: &[u8],
        client_addr: SocketAddr,
        server_mtu: u16,
        persona: PersonaId,
    ) -> Result<HandshakeOutcome, HandshakeError> {
        let init = match ClientInitV2::deserialize(payload) {
            Some(v) => v,
            None => {
                return Ok(anti_probe_outcome(
                    persona,
                    txn_id,
                    HandshakeRejectReason::Malformed,
                ))
            }
        };

        let cookie_payload = CookiePayload {
            issued_at_secs: now_secs(),
            connection_id: init.connection_id,
            client_mtu: init.client_mtu,
            fec_support: init.fec_support,
            client_x25519_public: init.client_x25519_public,
            client_addr,
        };
        let cookie = self
            .seal_cookie(&cookie_payload)
            .map_err(|_| HandshakeError::InvalidStun)?;
        let negotiated_mtu = server_mtu.min(init.client_mtu);

        let base_retry = ServerRetryV2 {
            connection_id: init.connection_id,
            server_mtu_hint: negotiated_mtu,
            server_x25519_public: self.inner.server_x25519.public(),
            cookie,
            grease: Vec::new(),
        };
        let base_len = base_retry.serialize().len();
        let init_len = payload.len();
        let grease_len = persona_spec(persona)
            .handshake
            .server_retry_grease_len
            .max(init_len.saturating_sub(base_len).min(32));
        let retry = ServerRetryV2 {
            grease: vec![0u8; grease_len],
            ..base_retry
        };
        let response = StunWrapper::wrap_response(txn_id, &retry.serialize());
        observability::record_trace_event(
            "handshake",
            "info",
            observability::handshake_correlation_id(&init.connection_id, client_addr),
            None,
            "issued retry for client init",
            serde_json::json!({
                "client_mtu": init.client_mtu,
                "negotiated_mtu": negotiated_mtu,
                "fec_support": init.fec_support,
                "persona": persona.label(),
                "retry_grease_len": grease_len,
            }),
        );
        Ok(HandshakeOutcome::Response {
            response,
            flow_id: None,
            reason: None,
        })
    }

    fn handle_client_auth(
        &self,
        txn_id: &[u8; 12],
        payload: &[u8],
        client_addr: SocketAddr,
        session_manager: &SessionManager,
        identity_store: &IdentityStore,
        server_mtu: u16,
        persona: PersonaId,
    ) -> Result<HandshakeOutcome, HandshakeError> {
        let auth = match ClientAuthV2::deserialize(payload) {
            Some(v) => v,
            None => {
                return Ok(anti_probe_outcome(
                    persona,
                    txn_id,
                    HandshakeRejectReason::Malformed,
                ))
            }
        };

        let cookie = match self.open_cookie(&auth.cookie) {
            Ok(v) => v,
            Err(_) => {
                metrics::record_handshake_failure(HandshakeRejectReason::AuthFailed);
                return Ok(anti_probe_outcome(
                    persona,
                    txn_id,
                    HandshakeRejectReason::AuthFailed,
                ));
            }
        };
        if cookie.connection_id != auth.connection_id
            || cookie.client_x25519_public != auth.client_x25519_public
            || cookie.client_addr != client_addr
            || !self.cookie_is_fresh(cookie.issued_at_secs)
        {
            metrics::record_handshake_failure(HandshakeRejectReason::AuthFailed);
            return Ok(HandshakeOutcome::NoResponse);
        }

        let x25519_shared = self
            .inner
            .server_x25519
            .diffie_hellman(&auth.client_x25519_public);
        let credential_key = match derive_credential_key(
            &x25519_shared,
            &auth.cookie,
            auth.connection_id.as_bytes(),
        ) {
            Ok(v) => v,
            Err(_) => {
                metrics::record_handshake_failure(HandshakeRejectReason::AuthFailed);
                return Ok(anti_probe_outcome(
                    persona,
                    txn_id,
                    HandshakeRejectReason::AuthFailed,
                ));
            }
        };
        let credential_plaintext = match open_with_key(
            &credential_key,
            auth.credential_nonce,
            auth.connection_id.as_bytes(),
            &auth.credential_ciphertext,
        ) {
            Ok(v) => v,
            Err(_) => {
                metrics::record_handshake_failure(HandshakeRejectReason::AuthFailed);
                return Ok(anti_probe_outcome(
                    persona,
                    txn_id,
                    HandshakeRejectReason::AuthFailed,
                ));
            }
        };
        let credentials = match ClientCredentialPayload::deserialize(&credential_plaintext) {
            Some(v) => v,
            None => {
                metrics::record_handshake_failure(HandshakeRejectReason::Malformed);
                return Ok(anti_probe_outcome(
                    persona,
                    txn_id,
                    HandshakeRejectReason::AuthFailed,
                ));
            }
        };

        let auth_ctx = match identity_store.authenticate_device(
            credentials.device_id,
            credentials.device_token,
            credentials.platform,
            &credentials.device_name,
        ) {
            Ok(v) => v,
            Err(reason) => {
                metrics::record_handshake_failure(reason.as_reject_reason());
                return Ok(anti_probe_outcome(
                    persona,
                    txn_id,
                    HandshakeRejectReason::AuthFailed,
                ));
            }
        };

        let tunnel_ip = match session_manager.allocate_tunnel_ip(&auth_ctx.device.device_id) {
            Some(ip) => ip,
            None => {
                metrics::record_handshake_failure(HandshakeRejectReason::IpPoolExhausted);
                return Ok(anti_probe_outcome(
                    persona,
                    txn_id,
                    HandshakeRejectReason::AuthFailed,
                ));
            }
        };

        let key = pending_key(&auth.connection_id, &client_addr);
        self.inner.pending.insert(
            key,
            PendingHandshake {
                client_addr,
                auth_ctx: auth_ctx.clone(),
                connection_id: auth.connection_id,
                client_mtu: cookie.client_mtu,
                fec_enabled: cookie.fec_support,
                x25519_shared,
                init_transcript: canonical_init_bytes(&cookie),
                retry_transcript: canonical_retry_bytes(
                    &cookie,
                    self.inner.server_x25519.public(),
                    auth.cookie.clone(),
                    server_mtu.min(cookie.client_mtu),
                ),
                auth_transcript: auth.serialize(),
                tunnel_ip,
                created_at: Instant::now(),
                kem_total_len: MLKEM768_EK_LEN,
                kem_chunks: Vec::new(),
            },
        );

        observability::record_trace_event(
            "handshake",
            "info",
            observability::handshake_correlation_id(&auth.connection_id, client_addr),
            None,
            "client auth accepted and waiting for PQ chunk completion",
            serde_json::json!({
                "platform": auth_ctx.device.platform.as_str(),
                "client_mtu": cookie.client_mtu,
                "fec_support": cookie.fec_support,
                "server_mtu": server_mtu.min(cookie.client_mtu),
            }),
        );

        Ok(HandshakeOutcome::NoResponse)
    }

    fn handle_client_kem_chunk(
        &self,
        txn_id: &[u8; 12],
        payload: &[u8],
        client_addr: SocketAddr,
        session_manager: &SessionManager,
        identity_store: &IdentityStore,
        server_mtu: u16,
        morphing_policy: omega_stealth::MorphingPolicy,
        persona: PersonaId,
        admission: &SessionAdmission,
        fabric: &SharedFabric,
    ) -> Result<HandshakeOutcome, HandshakeError> {
        let chunk = match ClientKemChunkV2::deserialize(payload) {
            Some(v) => v,
            None => {
                return Ok(anti_probe_outcome(
                    persona,
                    txn_id,
                    HandshakeRejectReason::Malformed,
                ))
            }
        };
        let key = pending_key(&chunk.connection_id, &client_addr);
        let mut pending = match self.inner.pending.get_mut(&key) {
            Some(v) => v,
            None => {
                return Ok(anti_probe_outcome(
                    persona,
                    txn_id,
                    HandshakeRejectReason::Malformed,
                ))
            }
        };
        if pending.client_addr != client_addr {
            return Ok(HandshakeOutcome::NoResponse);
        }
        if pending.kem_chunks.is_empty() {
            pending.kem_total_len = chunk.total_len as usize;
            pending.kem_chunks = vec![None; chunk.chunk_count as usize];
        }
        let idx = chunk.chunk_index as usize;
        if idx >= pending.kem_chunks.len() {
            return Ok(HandshakeOutcome::NoResponse);
        }
        pending.kem_chunks[idx] = Some(chunk.chunk.clone());

        if pending.kem_chunks.iter().any(|part| part.is_none()) {
            return Ok(HandshakeOutcome::NoResponse);
        }

        let mut full_kem = Vec::with_capacity(pending.kem_total_len);
        for part in pending.kem_chunks.iter() {
            full_kem.extend_from_slice(part.as_ref().unwrap());
        }
        full_kem.truncate(pending.kem_total_len);
        if full_kem.len() != MLKEM768_EK_LEN {
            metrics::record_handshake_failure(HandshakeRejectReason::Malformed);
            self.inner.pending.remove(&key);
            return Ok(anti_probe_outcome(
                persona,
                txn_id,
                HandshakeRejectReason::Malformed,
            ));
        }

        let ek_encoded: &Encoded<Ek768> = match full_kem.as_slice().try_into() {
            Ok(v) => v,
            Err(_) => {
                metrics::record_handshake_failure(HandshakeRejectReason::Malformed);
                self.inner.pending.remove(&key);
                return Ok(anti_probe_outcome(
                    persona,
                    txn_id,
                    HandshakeRejectReason::Malformed,
                ));
            }
        };
        let ek = Ek768::from_bytes(ek_encoded);
        let mut rng = rand::thread_rng();
        let (ct, mlkem_shared) = match ek.encapsulate(&mut rng) {
            Ok(v) => v,
            Err(_) => {
                metrics::record_handshake_failure(HandshakeRejectReason::ServerBusy);
                self.inner.pending.remove(&key);
                return Ok(anti_probe_outcome(
                    persona,
                    txn_id,
                    HandshakeRejectReason::ServerBusy,
                ));
            }
        };

        let transcript_hash = hash_transcript(&[
            pending.init_transcript.as_slice(),
            pending.retry_transcript.as_slice(),
            pending.auth_transcript.as_slice(),
            full_kem.as_slice(),
        ]);
        let secrets = match derive_hybrid_handshake_secrets(
            &pending.x25519_shared,
            mlkem_shared.as_ref(),
            &transcript_hash,
            true,
        ) {
            Ok(v) => v,
            Err(_) => {
                metrics::record_handshake_failure(HandshakeRejectReason::ServerBusy);
                self.inner.pending.remove(&key);
                return Ok(anti_probe_outcome(
                    persona,
                    txn_id,
                    HandshakeRejectReason::ServerBusy,
                ));
            }
        };

        let response = self.finalize_session(
            txn_id,
            session_manager,
            identity_store,
            admission,
            fabric,
            pending.auth_ctx.clone(),
            pending.tunnel_ip,
            pending.client_addr,
            pending.client_mtu,
            pending.fec_enabled,
            server_mtu,
            morphing_policy,
            persona,
            pending.connection_id,
            secrets,
            {
                let ct_bytes: &[u8] = ct.as_ref();
                ct_bytes.to_vec()
            },
            false,
            None,
        );
        self.inner.pending.remove(&key);
        Ok(response)
    }

    fn handle_client_resume(
        &self,
        txn_id: &[u8; 12],
        payload: &[u8],
        client_addr: SocketAddr,
        session_manager: &SessionManager,
        identity_store: &IdentityStore,
        server_mtu: u16,
        morphing_policy: omega_stealth::MorphingPolicy,
        persona: PersonaId,
        admission: &SessionAdmission,
        fabric: &SharedFabric,
    ) -> Result<HandshakeOutcome, HandshakeError> {
        let resume = match ClientResumeV2::deserialize(payload) {
            Some(v) => v,
            None => {
                return Ok(anti_probe_outcome(
                    persona,
                    txn_id,
                    HandshakeRejectReason::Malformed,
                ))
            }
        };
        let cookie = match self.open_cookie(&resume.cookie) {
            Ok(v) => v,
            Err(_) => {
                metrics::record_handshake_failure(HandshakeRejectReason::AuthFailed);
                return Ok(anti_probe_outcome(
                    persona,
                    txn_id,
                    HandshakeRejectReason::AuthFailed,
                ));
            }
        };
        if cookie.connection_id != resume.connection_id
            || cookie.client_x25519_public != resume.client_x25519_public
            || cookie.client_addr != client_addr
            || !self.cookie_is_fresh(cookie.issued_at_secs)
        {
            metrics::record_handshake_failure(HandshakeRejectReason::AuthFailed);
            return Ok(HandshakeOutcome::NoResponse);
        }
        let ticket = match self.open_ticket(&resume.ticket) {
            Ok(v) => v,
            Err(_) => {
                metrics::record_handshake_failure(HandshakeRejectReason::AuthFailed);
                return Ok(anti_probe_outcome(
                    persona,
                    txn_id,
                    HandshakeRejectReason::AuthFailed,
                ));
            }
        };
        if ticket.expires_at_secs <= now_secs() {
            metrics::record_handshake_failure(HandshakeRejectReason::AuthFailed);
            return Ok(HandshakeOutcome::NoResponse);
        }
        let auth_ctx = match identity_store.authorize_resumption(ticket.device_id) {
            Ok(v) => v,
            Err(reason) => {
                metrics::record_handshake_failure(reason.as_reject_reason());
                return Ok(anti_probe_outcome(
                    persona,
                    txn_id,
                    HandshakeRejectReason::AuthFailed,
                ));
            }
        };
        if identity_store
            .authorize_ticket(&resume.ticket, &auth_ctx.device.device_id)
            .is_err()
        {
            metrics::record_handshake_failure(HandshakeRejectReason::AuthFailed);
            return Ok(anti_probe_outcome(
                persona,
                txn_id,
                HandshakeRejectReason::AuthFailed,
            ));
        }
        let tunnel_ip = match session_manager.allocate_tunnel_ip(&auth_ctx.device.device_id) {
            Some(ip) => ip,
            None => {
                metrics::record_handshake_failure(HandshakeRejectReason::IpPoolExhausted);
                return Ok(anti_probe_outcome(
                    persona,
                    txn_id,
                    HandshakeRejectReason::AuthFailed,
                ));
            }
        };
        observability::record_trace_event(
            "handshake",
            "info",
            observability::handshake_correlation_id(&resume.connection_id, client_addr),
            None,
            "resumption ticket authorized",
            serde_json::json!({
                "client_mtu": cookie.client_mtu,
                "fec_support": cookie.fec_support,
                "ticket_ttl_remaining_secs": ticket.expires_at_secs.saturating_sub(now_secs()),
            }),
        );
        let x25519_shared = self
            .inner
            .server_x25519
            .diffie_hellman(&resume.client_x25519_public);
        let transcript_hash = hash_transcript(&[
            canonical_init_bytes(&cookie).as_slice(),
            canonical_retry_bytes(
                &cookie,
                self.inner.server_x25519.public(),
                resume.cookie.clone(),
                server_mtu.min(cookie.client_mtu),
            )
            .as_slice(),
            resume.serialize().as_slice(),
        ]);
        let secrets = match derive_resumption_handshake_secrets(
            &x25519_shared,
            &ticket.resumption_secret,
            &transcript_hash,
            true,
        ) {
            Ok(v) => v,
            Err(_) => {
                metrics::record_handshake_failure(HandshakeRejectReason::ServerBusy);
                return Ok(anti_probe_outcome(
                    persona,
                    txn_id,
                    HandshakeRejectReason::ServerBusy,
                ));
            }
        };
        Ok(self.finalize_session(
            txn_id,
            session_manager,
            identity_store,
            admission,
            fabric,
            auth_ctx,
            tunnel_ip,
            client_addr,
            cookie.client_mtu,
            cookie.fec_support,
            server_mtu,
            morphing_policy,
            persona,
            resume.connection_id,
            secrets,
            Vec::new(),
            true,
            Some(resume.ticket.as_slice()),
        ))
    }

    #[allow(clippy::too_many_arguments)]
    fn finalize_session(
        &self,
        txn_id: &[u8; 12],
        session_manager: &SessionManager,
        identity_store: &IdentityStore,
        admission: &SessionAdmission,
        fabric: &SharedFabric,
        auth_ctx: AuthContext,
        tunnel_ip: std::net::Ipv4Addr,
        client_addr: SocketAddr,
        client_mtu: u16,
        fec_enabled: bool,
        server_mtu: u16,
        morphing_policy: omega_stealth::MorphingPolicy,
        persona: PersonaId,
        connection_id: ConnectionId,
        secrets: omega_core_crypto::HandshakeSecrets,
        ciphertext: Vec<u8>,
        resumed: bool,
        prior_ticket: Option<&[u8]>,
    ) -> HandshakeOutcome {
        let replaced_sessions =
            session_manager.terminate_device_sessions(&auth_ctx.device.device_id);
        if replaced_sessions > 0 {
            metrics::record_device_reconnect(replaced_sessions);
        }

        if ensure_session_limit(
            &auth_ctx.user,
            session_manager.count_user_sessions(&auth_ctx.user.user_id),
        )
        .is_err()
        {
            metrics::record_handshake_failure(HandshakeRejectReason::LimitExceeded);
            return anti_probe_outcome(persona, txn_id, HandshakeRejectReason::LimitExceeded);
        }

        let flow_id = FlowId(secrets.flow_id);
        let session_id = crate::session::flow_id_to_hex(&flow_id);
        let fabric_view = fabric.read().unwrap().runtime_view();
        let policy_decision = identity_store.evaluate_session_admission(
            &auth_ctx.user,
            &auth_ctx.device,
            admission.clone(),
            &fabric_view.region,
            &fabric_view.local_role,
        );
        identity_store.append_audit(
            "policy_decision",
            "handshake",
            serde_json::json!({
                "flow_id": session_id.clone(),
                "device_id": auth_ctx.device.device_id.clone(),
                "policy_id": policy_decision.admission.policy_id.clone(),
                "matched_rules": policy_decision.matched_rules.clone(),
                "explainability": policy_decision.explainability.clone(),
            }),
        );
        let effective_admission = policy_decision.admission.clone();
        let session_id = crate::session::flow_id_to_hex(&flow_id);
        let fabric_state = match fabric
            .read()
            .unwrap()
            .plan_session(&session_id, &effective_admission)
        {
            Some(route) => route,
            None => {
                metrics::record_handshake_failure(HandshakeRejectReason::ServerBusy);
                return anti_probe_outcome(persona, txn_id, HandshakeRejectReason::ServerBusy);
            }
        };
        let activation = omega_control::control_plane::SessionActivation {
            flow_id: session_id.clone(),
            user_id: auth_ctx.user.user_id.clone(),
            device_id: auth_ctx.device.device_id.clone(),
            tunnel_ip: tunnel_ip.to_string(),
            client_addr: client_addr.to_string(),
            policy_id: effective_admission.policy_id.clone(),
            mode: effective_admission.mode,
            relay_permitted: effective_admission.relay_permitted,
            privileged_boundary: effective_admission.privileged_boundary,
            active_route_id: fabric_state.active_route.route_id.clone(),
            backup_route_ids: fabric_state
                .backup_routes
                .iter()
                .map(|route| route.route_id.clone())
                .collect(),
            route_diversity_score: fabric_state.route_diversity_score,
            fabric_ticket_generation: fabric_state.handoff_ticket.generation,
        };
        let negotiated_mtu = server_mtu.min(client_mtu);
        let established_route_id = fabric_state.active_route.route_id.clone();
        let chaos_seed =
            u64::from_le_bytes(secrets.app_secret[0..8].try_into().unwrap_or_default());
        let ssrc = u32::from_be_bytes(secrets.flow_id[0..4].try_into().unwrap_or_default());
        let session = SessionState::with_transport(
            secrets.session_keys,
            client_addr,
            tunnel_ip,
            auth_ctx.user.user_id.clone(),
            auth_ctx.device.device_id.clone(),
            chaos_seed,
            fec_enabled,
            morphing_policy,
            fabric_state,
            persona,
            ssrc,
            connection_id,
            secrets.update_secret,
            secrets.app_secret,
            negotiated_mtu,
        );
        if !session_manager.insert(flow_id, session, activation) {
            metrics::record_handshake_failure(HandshakeRejectReason::ServerBusy);
            return anti_probe_outcome(persona, txn_id, HandshakeRejectReason::ServerBusy);
        }

        let ticket_expires_at = now_secs().saturating_add(effective_admission.resumption_ttl_secs);
        let ticket = match self.seal_ticket(&TicketPayload {
            expires_at_secs: ticket_expires_at,
            device_id: parse_uuid_bytes(&auth_ctx.device.device_id).unwrap_or([0u8; 16]),
            resumption_secret: secrets.resumption_secret,
        }) {
            Ok(v) => v,
            Err(_) => {
                metrics::record_handshake_failure(HandshakeRejectReason::ServerBusy);
                return anti_probe_outcome(persona, txn_id, HandshakeRejectReason::ServerBusy);
            }
        };
        if identity_store
            .issue_ticket(
                &ticket,
                &session_id,
                &auth_ctx.device.device_id,
                &effective_admission.policy_id,
                ticket_expires_at,
                "handshake",
            )
            .is_err()
        {
            session_manager.terminate_session_with_reason(&flow_id, "ticket_issue_failed");
            metrics::record_handshake_failure(HandshakeRejectReason::ServerBusy);
            return anti_probe_outcome(persona, txn_id, HandshakeRejectReason::ServerBusy);
        }
        if let Some(previous_ticket) = prior_ticket {
            if identity_store
                .consume_ticket(previous_ticket, "handshake")
                .is_err()
            {
                session_manager.terminate_session_with_reason(&flow_id, "ticket_consume_failed");
                metrics::record_handshake_failure(HandshakeRejectReason::ServerBusy);
                return anti_probe_outcome(persona, txn_id, HandshakeRejectReason::ServerBusy);
            }
        }

        observability::record_trace_event(
            "handshake",
            "info",
            observability::handshake_correlation_id(&connection_id, client_addr),
            Some(session_id.clone()),
            if resumed {
                "handshake resumed session"
            } else {
                "handshake established session"
            },
            serde_json::json!({
                "resumed": resumed,
                "policy_id": effective_admission.policy_id,
                "route_id": established_route_id,
                "negotiated_mtu": negotiated_mtu,
                "fec_enabled": fec_enabled,
                "persona": persona.label(),
                "replaced_sessions": replaced_sessions,
            }),
        );
        metrics::record_handshake_success(
            auth_ctx.user.user_id.clone(),
            auth_ctx.device.platform.as_str(),
        );
        let complete = ServerCompleteV2 {
            connection_id,
            resumed,
            fec_enabled,
            flow_id,
            tunnel_ip,
            server_mtu: negotiated_mtu,
            ciphertext,
            resumption_ticket: ticket,
        };
        let response = StunWrapper::wrap_response(txn_id, &complete.serialize());
        HandshakeOutcome::Response {
            response,
            flow_id: Some(flow_id),
            reason: None,
        }
    }

    fn cleanup(&self) {
        let now = Instant::now();
        self.inner.abuse_guard.cleanup();
        let stale = self
            .inner
            .pending
            .iter()
            .filter_map(|entry| {
                if now.duration_since(entry.value().created_at) > PENDING_TTL {
                    Some(entry.key().clone())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        if !stale.is_empty() {
            observability::record_trace_event(
                "handshake",
                "warning",
                "handshake-pending-cleanup",
                None,
                "removed stale pending handshakes",
                serde_json::json!({
                    "stale_entries": stale.len(),
                    "ttl_secs": PENDING_TTL.as_secs(),
                }),
            );
        }
        for key in stale {
            self.inner.pending.remove(&key);
        }
    }

    fn cookie_is_fresh(&self, issued_at_secs: u64) -> bool {
        now_secs().saturating_sub(issued_at_secs) <= COOKIE_TTL.as_secs()
    }

    fn seal_cookie(
        &self,
        payload: &CookiePayload,
    ) -> Result<Vec<u8>, omega_core_crypto::CryptoError> {
        let mut nonce = [0u8; CREDENTIAL_NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut nonce);
        let ciphertext = seal_with_key(
            &self.inner.cookie_key,
            nonce,
            COOKIE_AAD,
            &payload.serialize(),
        )?;
        let mut out = Vec::with_capacity(CREDENTIAL_NONCE_LEN + ciphertext.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    fn open_cookie(&self, raw: &[u8]) -> Result<CookiePayload, omega_core_crypto::CryptoError> {
        if raw.len() < CREDENTIAL_NONCE_LEN {
            return Err(omega_core_crypto::CryptoError::DecryptionFailed);
        }
        let mut nonce = [0u8; CREDENTIAL_NONCE_LEN];
        nonce.copy_from_slice(&raw[..CREDENTIAL_NONCE_LEN]);
        let plaintext = open_with_key(
            &self.inner.cookie_key,
            nonce,
            COOKIE_AAD,
            &raw[CREDENTIAL_NONCE_LEN..],
        )?;
        CookiePayload::deserialize(&plaintext)
            .ok_or(omega_core_crypto::CryptoError::DecryptionFailed)
    }

    fn seal_ticket(
        &self,
        payload: &TicketPayload,
    ) -> Result<Vec<u8>, omega_core_crypto::CryptoError> {
        let mut nonce = [0u8; CREDENTIAL_NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut nonce);
        let ciphertext = seal_with_key(
            &self.inner.ticket_key,
            nonce,
            TICKET_AAD,
            &payload.serialize(),
        )?;
        let mut out = Vec::with_capacity(CREDENTIAL_NONCE_LEN + ciphertext.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    fn open_ticket(&self, raw: &[u8]) -> Result<TicketPayload, omega_core_crypto::CryptoError> {
        if raw.len() < CREDENTIAL_NONCE_LEN {
            return Err(omega_core_crypto::CryptoError::DecryptionFailed);
        }
        let mut nonce = [0u8; CREDENTIAL_NONCE_LEN];
        nonce.copy_from_slice(&raw[..CREDENTIAL_NONCE_LEN]);
        let plaintext = open_with_key(
            &self.inner.ticket_key,
            nonce,
            TICKET_AAD,
            &raw[CREDENTIAL_NONCE_LEN..],
        )?;
        TicketPayload::deserialize(&plaintext)
            .ok_or(omega_core_crypto::CryptoError::DecryptionFailed)
    }
}

impl CookiePayload {
    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(8 + 8 + 2 + 1 + 32 + 1 + 18);
        buf.extend_from_slice(&self.issued_at_secs.to_be_bytes());
        buf.extend_from_slice(self.connection_id.as_bytes());
        buf.extend_from_slice(&self.client_mtu.to_be_bytes());
        buf.push(if self.fec_support { 1 } else { 0 });
        buf.extend_from_slice(&self.client_x25519_public);
        encode_socket_addr(&mut buf, self.client_addr);
        buf
    }

    fn deserialize(buf: &[u8]) -> Option<Self> {
        if buf.len() < 8 + 8 + 2 + 1 + 32 + 1 + 6 {
            return None;
        }
        let mut offset = 0usize;
        let issued_at_secs = u64::from_be_bytes(buf[offset..offset + 8].try_into().ok()?);
        offset += 8;
        let connection_id = ConnectionId::from_bytes(&buf[offset..offset + 8])?;
        offset += 8;
        let client_mtu = u16::from_be_bytes(buf[offset..offset + 2].try_into().ok()?);
        offset += 2;
        let fec_support = buf[offset] != 0;
        offset += 1;
        let mut client_x25519_public = [0u8; 32];
        client_x25519_public.copy_from_slice(&buf[offset..offset + 32]);
        offset += 32;
        let client_addr = decode_socket_addr(buf, &mut offset)?;
        Some(Self {
            issued_at_secs,
            connection_id,
            client_mtu,
            fec_support,
            client_x25519_public,
            client_addr,
        })
    }
}

impl TicketPayload {
    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(8 + 16 + 32);
        buf.extend_from_slice(&self.expires_at_secs.to_be_bytes());
        buf.extend_from_slice(&self.device_id);
        buf.extend_from_slice(&self.resumption_secret);
        buf
    }

    fn deserialize(buf: &[u8]) -> Option<Self> {
        if buf.len() < 56 {
            return None;
        }
        let expires_at_secs = u64::from_be_bytes(buf[0..8].try_into().ok()?);
        let mut device_id = [0u8; 16];
        device_id.copy_from_slice(&buf[8..24]);
        let mut resumption_secret = [0u8; 32];
        resumption_secret.copy_from_slice(&buf[24..56]);
        Some(Self {
            expires_at_secs,
            device_id,
            resumption_secret,
        })
    }
}

fn pending_key(connection_id: &ConnectionId, client_addr: &SocketAddr) -> String {
    let mut out = String::with_capacity(64);
    for byte in connection_id.as_bytes() {
        out.push(hex_nibble((byte >> 4) & 0x0f));
        out.push(hex_nibble(byte & 0x0f));
    }
    out.push('@');
    out.push_str(&client_addr.to_string());
    out
}

fn canonical_init_bytes(cookie: &CookiePayload) -> Vec<u8> {
    ClientInitV2 {
        connection_id: cookie.connection_id,
        client_mtu: cookie.client_mtu,
        fec_support: cookie.fec_support,
        client_x25519_public: cookie.client_x25519_public,
        grease: Vec::new(),
    }
    .serialize()
}

fn canonical_retry_bytes(
    cookie: &CookiePayload,
    server_public: [u8; 32],
    cookie_bytes: Vec<u8>,
    server_mtu_hint: u16,
) -> Vec<u8> {
    ServerRetryV2 {
        connection_id: cookie.connection_id,
        server_mtu_hint,
        server_x25519_public: server_public,
        cookie: cookie_bytes,
        grease: Vec::new(),
    }
    .serialize()
}

fn encode_socket_addr(buf: &mut Vec<u8>, addr: SocketAddr) {
    match addr.ip() {
        IpAddr::V4(ip) => {
            buf.push(4);
            buf.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            buf.push(16);
            buf.extend_from_slice(&ip.octets());
        }
    }
    buf.extend_from_slice(&addr.port().to_be_bytes());
}

fn decode_socket_addr(buf: &[u8], offset: &mut usize) -> Option<SocketAddr> {
    let ip_len = *buf.get(*offset)? as usize;
    *offset += 1;
    let ip_end = *offset + ip_len;
    let ip = match ip_len {
        4 => IpAddr::V4(std::net::Ipv4Addr::new(
            buf[*offset],
            buf[*offset + 1],
            buf[*offset + 2],
            buf[*offset + 3],
        )),
        16 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[*offset..ip_end]);
            IpAddr::V6(std::net::Ipv6Addr::from(octets))
        }
        _ => return None,
    };
    *offset = ip_end;
    let port = u16::from_be_bytes(buf[*offset..*offset + 2].try_into().ok()?);
    *offset += 2;
    Some(SocketAddr::new(ip, port))
}

fn anti_probe_outcome(
    persona: PersonaId,
    txn_id: &[u8; 12],
    reason: HandshakeRejectReason,
) -> HandshakeOutcome {
    match persona_spec(persona).handshake.invalid_probe_response {
        ProbeResponseClass::SilentDrop => HandshakeOutcome::NoResponse,
        ProbeResponseClass::UniformReject => {
            let mapped_reason = if matches!(persona, PersonaId::Off) {
                reason
            } else {
                HandshakeRejectReason::AuthFailed
            };
            reject_handshake(txn_id, mapped_reason)
        }
    }
}

fn reject_handshake(txn_id: &[u8; 12], reason: HandshakeRejectReason) -> HandshakeOutcome {
    let payload = HandshakeReject {
        version: HANDSHAKE_V2_VERSION,
        reason,
    }
    .serialize();
    let response = StunWrapper::wrap_response(txn_id, &payload);
    HandshakeOutcome::Response {
        response,
        flow_id: None,
        reason: Some(reason),
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn parse_uuid_bytes(value: &str) -> Option<[u8; 16]> {
    let hex = value.replace('-', "");
    if hex.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    let bytes = hex.as_bytes();
    for i in 0..16 {
        let hi = from_hex(bytes[i * 2])?;
        let lo = from_hex(bytes[i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

fn from_hex(ch: u8) -> Option<u8> {
    match ch {
        b'0'..=b'9' => Some(ch - b'0'),
        b'a'..=b'f' => Some(ch - b'a' + 10),
        b'A'..=b'F' => Some(ch - b'A' + 10),
        _ => None,
    }
}

fn hex_nibble(nibble: u8) -> char {
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        10..=15 => (b'a' + nibble - 10) as char,
        _ => '0',
    }
}
