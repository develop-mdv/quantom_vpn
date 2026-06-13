use crate::api::{HandshakeResponse, NativeResult};

#[cfg(target_os = "android")]
mod android {
    use super::*;
    use crate::config::AndroidProfile;
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use std::os::fd::{FromRawFd, RawFd};
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::{Arc, Mutex, OnceLock};
    use std::time::{Duration, Instant, SystemTime};

    use bytes::{Bytes, BytesMut};
    use kem::Decapsulate;
    use ml_kem::{EncodedSizeUser, KemCore, MlKem768};
    use omega_core::arq::{GapDetector, LossEstimator, RetransmitQueue};
    use omega_core::chaos::ChaosPrng;
    use omega_core::crypto::{derive_flow_id, SessionKeys};
    use omega_core::protocol::{
        ClientAuth, ClientHello, DevicePlatform, FlowId, HandshakeReject, NackMessage, OmegaHeader,
        PacketType, RtpHeader, ServerHello, StunWrapper, AEAD_TAG_LEN, HANDSHAKE_VERSION,
        RTP_HEADER_LEN, TOTAL_HEADER_LEN,
    };
    use omega_core::replay::ReplayFilter;
    use omega_reality::handshake_client::{client_handshake, ClientHandshakeInputs};
    use omega_reality::key_schedule::CipherSuiteParams;
    use omega_reality::record_layer::{RecordDecryptor, RecordEncryptor};
    use omega_reality::tls_messages::{
        parse_record_header, CT_APPLICATION_DATA, CT_CHANGE_CIPHER_SPEC, TLS_MAX_RECORD_CIPHERTEXT,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
    use tokio::net::{TcpStream, UdpSocket};
    use tokio::runtime::Runtime;
    use tokio::sync::{mpsc, Mutex as AsyncMutex};
    use x25519_dalek::PublicKey;

    const DEFAULT_CLIENT_MTU: u16 = 1280;
    const DEFAULT_INITIAL_ARQ_RTT_MS: u64 = 350;
    const DEFAULT_HANDSHAKE_ATTEMPTS: u32 = 5;
    const DEFAULT_HANDSHAKE_TIMEOUT_MS: u64 = 1500;
    const DEFAULT_HANDSHAKE_BACKOFF_MS: u64 = 500;
    const MAX_RETRANSMIT_BURST: usize = 24;
    const RETRANSMIT_PACING_US: u64 = 500;
    const REDUNDANCY_PACING_US: u64 = 200;
    const KEEPALIVE_SECS: u64 = 15;
    const PADDING_RECOVERY_STEP: usize = 24;
    const PADDING_RECOVERY_INTERVAL_SECS: u64 = 2;
    const REDUNDANCY_EXTRA_MAX: u8 = 2;
    const REDUNDANCY_DECAY_SECS: u64 = 8;
    /// Consecutive transport recv errors tolerated before we declare the
    /// datapath dead so the Android service can reconnect on a fresh socket.
    const MAX_DATAPATH_RECV_ERRORS: u32 = 5;

    static NEXT_HANDLE: AtomicU64 = AtomicU64::new(1);
    static SESSIONS: OnceLock<Mutex<HashMap<u64, NativeSession>>> = OnceLock::new();

    struct NativeSession {
        runtime: Runtime,
        pending: Option<Pending>,
        tasks: Vec<tokio::task::JoinHandle<()>>,
        /// `true` while the datapath is healthy; a tunnel loop flips it to
        /// `false` when its transport dies so the Android service watchdog can
        /// tear the session down and reconnect on a fresh socket.
        running: Arc<AtomicBool>,
    }

    enum Pending {
        Udp(PendingSession),
        Reality(PendingRealitySession),
    }

    struct PendingSession {
        transport: Arc<UdpSocket>,
        shared_secret: Vec<u8>,
        keys_send: SessionKeys,
        flow_id: FlowId,
        chaos_seed: u64,
        ssrc: u32,
        tunnel_ipv4: String,
        tunnel_ipv6: Option<String>,
        mtu: u16,
    }

    /// Pending REALITY tunnel: TLS 1.3 record layer already negotiated, Omega
    /// (STUN+ML-KEM) ClientHello already exchanged inside the TLS tunnel.
    /// Waiting for the Android `VpnService` to hand us its TUN fd so we can
    /// start pumping IP packets through the encrypted record stream.
    struct PendingRealitySession {
        reader: Arc<AsyncMutex<OwnedReadHalf>>,
        writer: Arc<AsyncMutex<OwnedWriteHalf>>,
        encryptor: Arc<AsyncMutex<RecordEncryptor>>,
        decryptor: Arc<AsyncMutex<RecordDecryptor>>,
        shared_secret: Vec<u8>,
        keys_send: SessionKeys,
        flow_id: FlowId,
        chaos_seed: u64,
        ssrc: u32,
        tunnel_ipv4: String,
        tunnel_ipv6: Option<String>,
        mtu: u16,
        #[allow(dead_code)]
        cipher_suite: u16,
        #[allow(dead_code)]
        params: CipherSuiteParams,
    }

    struct HandshakeResult {
        hello: ServerHello,
        rtt_ms: u64,
    }

    struct ClientState {
        retransmit_queue: RetransmitQueue,
        gap_detector: GapDetector,
        loss_estimator: LossEstimator,
        send_seq: u32,
        rtp_seq: u16,
        rtp_timestamp: u32,
        ssrc: u32,
        chaos: ChaosPrng,
        padding_budget: usize,
        last_padding_adjust: Instant,
        redundancy_extra: u8,
        last_redundancy_adjust: Instant,
        loss_est_seq: u32,
        loss_est_init: bool,
    }

    impl ClientState {
        fn new(ssrc: u32, chaos_seed: u64) -> Self {
            Self {
                retransmit_queue: RetransmitQueue::with_initial_rtt(DEFAULT_INITIAL_ARQ_RTT_MS),
                gap_detector: GapDetector::new(),
                loss_estimator: LossEstimator::new(),
                send_seq: 0,
                rtp_seq: 0,
                rtp_timestamp: 0,
                ssrc,
                chaos: ChaosPrng::new(chaos_seed),
                padding_budget: 96,
                last_padding_adjust: Instant::now(),
                redundancy_extra: 0,
                last_redundancy_adjust: Instant::now(),
                loss_est_seq: 0,
                loss_est_init: false,
            }
        }

        fn current_padding_budget(&mut self) -> usize {
            let elapsed = self.last_padding_adjust.elapsed().as_secs();
            let ticks = elapsed / PADDING_RECOVERY_INTERVAL_SECS;
            if ticks > 0 {
                let growth = (ticks as usize).saturating_mul(PADDING_RECOVERY_STEP);
                self.padding_budget = self.padding_budget.saturating_add(growth).min(96);
                self.last_padding_adjust = Instant::now();
            }
            self.padding_budget
        }

        fn on_remote_nack(&mut self, nack: &NackMessage) {
            let missing = nack.bitmap.count_ones() as usize;
            if missing == 0 {
                return;
            }
            let penalty = 16 + missing.saturating_mul(8);
            self.padding_budget = self.padding_budget.saturating_sub(penalty);
            self.last_padding_adjust = Instant::now();
            let bump = if missing >= 16 { 2 } else { 1 };
            self.redundancy_extra = self
                .redundancy_extra
                .saturating_add(bump)
                .min(REDUNDANCY_EXTRA_MAX);
            self.last_redundancy_adjust = Instant::now();
        }

        fn current_redundancy_extra(&mut self) -> usize {
            let elapsed = self.last_redundancy_adjust.elapsed().as_secs();
            let ticks = elapsed / REDUNDANCY_DECAY_SECS;
            if ticks > 0 {
                self.redundancy_extra = self.redundancy_extra.saturating_sub(ticks as u8);
                self.last_redundancy_adjust = Instant::now();
            }
            self.redundancy_extra as usize
        }

        fn observe_inbound_seq(&mut self, seq: u32) -> Option<NackMessage> {
            let nack = self.gap_detector.record_received(seq);
            self.update_loss_stats(seq);
            nack
        }

        fn update_loss_stats(&mut self, received_seq: u32) {
            if !self.loss_est_init {
                self.loss_est_seq = received_seq;
                self.loss_est_init = true;
                self.loss_estimator.record(true);
                return;
            }

            let diff = received_seq.wrapping_sub(self.loss_est_seq);
            if diff == 0 {
                return;
            }
            if diff < 0x8000_0000 {
                for _ in 0..diff.saturating_sub(1).min(256) {
                    self.loss_estimator.record(false);
                }
                self.loss_estimator.record(true);
                self.loss_est_seq = received_seq;
            }
        }
    }

    pub fn start_handshake(
        server: &str,
        device_id: &str,
        device_token: &str,
        device_name: &str,
        transport: &str,
        protected_udp_fd: i32,
    ) -> HandshakeResponse {
        let profile =
            match AndroidProfile::parse(server, device_id, device_token, "android", transport) {
                Ok(profile) => profile,
                Err(err) => {
                    close_raw_fd(protected_udp_fd);
                    return HandshakeResponse::err(err);
                }
            };

        if profile.transport == "tcp" {
            close_raw_fd(protected_udp_fd);
            return HandshakeResponse::err(
                "Android native bridge currently supports UDP transport; choose auto or udp.",
            );
        }
        if profile.transport == "reality" {
            close_raw_fd(protected_udp_fd);
            return HandshakeResponse::err(
                "REALITY transport uses a different entry point: call \
                 nativeStartRealityHandshake (with a protected TCP fd) instead of \
                 nativeStartHandshake.",
            );
        }

        let result = (|| -> Result<HandshakeResponse, String> {
            let server_addr: SocketAddr = profile
                .server
                .parse()
                .map_err(|_| "server must be a numeric host:port socket address".to_string())?;
            let runtime = Runtime::new().map_err(|err| format!("runtime init failed: {err}"))?;

            let std_socket = unsafe { std::net::UdpSocket::from_raw_fd(protected_udp_fd as RawFd) };
            std_socket
                .set_nonblocking(true)
                .map_err(|err| format!("udp nonblocking failed: {err}"))?;
            std_socket
                .connect(server_addr)
                .map_err(|err| format!("udp connect failed: {err}"))?;
            let udp = Arc::new(
                runtime
                    .block_on(async { UdpSocket::from_std(std_socket) })
                    .map_err(|err| format!("tokio udp init failed: {err}"))?,
            );

            let mut rng = rand::thread_rng();
            let (dk, ek) = MlKem768::generate(&mut rng);
            let client_hello = ClientHello {
                version: HANDSHAKE_VERSION,
                client_mtu: DEFAULT_CLIENT_MTU,
                fec_support: true,
                supports_tunnel_ipv6: true,
                encaps_key: ek.as_bytes().to_vec(),
                auth: Some(ClientAuth {
                    device_id: profile.device_id_bytes()?,
                    device_token: profile.device_token_bytes()?,
                    platform: DevicePlatform::Android,
                    device_name: device_name.trim().if_empty("android").to_string(),
                }),
            };

            let handshake = runtime.block_on(perform_handshake(&udp, &client_hello))?;
            let server_hello = handshake.hello;
            let ct_array: &ml_kem::Ciphertext<MlKem768> = server_hello
                .ciphertext
                .as_slice()
                .try_into()
                .map_err(|_| "invalid KEM ciphertext length".to_string())?;
            let shared_secret = dk
                .decapsulate(ct_array)
                .map_err(|_| "KEM decapsulation failed".to_string())?;
            let ss_bytes: &[u8] = shared_secret.as_ref();
            let shared_secret = ss_bytes.to_vec();
            let flow_id_bytes =
                derive_flow_id(&shared_secret).map_err(|err| format!("flow id failed: {err}"))?;
            let flow_id = FlowId(flow_id_bytes);
            let chaos_seed = u64::from_le_bytes(shared_secret[0..8].try_into().unwrap());
            let ssrc = u32::from_be_bytes(flow_id_bytes[0..4].try_into().unwrap());
            let keys_send = SessionKeys::from_shared_secret(&shared_secret, false)
                .map_err(|err| format!("key derivation failed: {err}"))?;

            let handle = NEXT_HANDLE.fetch_add(1, Ordering::Relaxed);
            let mtu = server_hello.server_mtu.clamp(1200, 1420);
            let tunnel_ipv4 = server_hello.tunnel_ip.to_string();
            let tunnel_ipv6 = server_hello.tunnel_ipv6.map(|value| value.to_string());

            sessions().lock().unwrap().insert(
                handle,
                NativeSession {
                    runtime,
                    pending: Some(Pending::Udp(PendingSession {
                        transport: udp,
                        shared_secret,
                        keys_send,
                        flow_id,
                        chaos_seed,
                        ssrc,
                        tunnel_ipv4: tunnel_ipv4.clone(),
                        tunnel_ipv6: tunnel_ipv6.clone(),
                        mtu,
                    })),
                    tasks: Vec::new(),
                    running: Arc::new(AtomicBool::new(true)),
                },
            );

            let _ = handshake.rtt_ms;
            Ok(HandshakeResponse::ok(
                handle,
                tunnel_ipv4,
                tunnel_ipv6,
                mtu,
                vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()],
            ))
        })();

        match result {
            Ok(response) => response,
            Err(err) => HandshakeResponse::err(err),
        }
    }

    pub fn continue_with_tun_fd(handle: u64, tun_fd: i32) -> NativeResult {
        let mut sessions = sessions().lock().unwrap();
        let Some(session) = sessions.get_mut(&handle) else {
            close_raw_fd(tun_fd);
            return NativeResult::err("unknown native session handle");
        };
        let Some(pending) = session.pending.take() else {
            close_raw_fd(tun_fd);
            return NativeResult::err("native session is already running");
        };

        let tun = match session
            .runtime
            .block_on(async { unsafe { tun_rs::AsyncDevice::from_fd(tun_fd as RawFd) } })
        {
            Ok(tun) => Arc::new(tun),
            Err(err) => {
                close_raw_fd(tun_fd);
                return NativeResult::err(format!("failed to attach Android TUN fd: {err}"));
            }
        };

        let running = session.running.clone();
        running.store(true, Ordering::Relaxed);
        match pending {
            Pending::Udp(mut pending) => {
                let state = Arc::new(Mutex::new(ClientState::new(
                    pending.ssrc,
                    pending.chaos_seed,
                )));
                {
                    let mut state = state.lock().unwrap();
                    state.send_seq = pending.keys_send.send_nonce() as u32;
                }

                let (nack_tx, nack_rx) = mpsc::channel::<NackMessage>(100);
                let send_task = session.runtime.spawn(tun_to_udp_loop(
                    tun.clone(),
                    pending.transport.clone(),
                    pending.flow_id,
                    pending.keys_send,
                    state.clone(),
                    nack_rx,
                ));
                let recv_task = session.runtime.spawn(udp_to_tun_loop(
                    tun,
                    pending.transport,
                    pending.flow_id,
                    pending.shared_secret,
                    state,
                    nack_tx,
                    running.clone(),
                ));
                session.tasks.push(send_task);
                session.tasks.push(recv_task);

                let _ = (pending.tunnel_ipv4, pending.tunnel_ipv6.take(), pending.mtu);
                NativeResult::ok("Omega datapath started")
            }
            Pending::Reality(mut pending) => {
                let state = Arc::new(Mutex::new(ClientState::new(
                    pending.ssrc,
                    pending.chaos_seed,
                )));
                {
                    let mut state = state.lock().unwrap();
                    state.send_seq = pending.keys_send.send_nonce() as u32;
                }

                let (nack_tx, nack_rx) = mpsc::channel::<NackMessage>(100);
                let send_task = session.runtime.spawn(tun_to_reality_loop(
                    tun.clone(),
                    pending.encryptor.clone(),
                    pending.writer.clone(),
                    pending.flow_id,
                    pending.keys_send,
                    state.clone(),
                    nack_rx,
                    running.clone(),
                ));
                let recv_task = session.runtime.spawn(reality_to_tun_loop(
                    tun,
                    pending.decryptor.clone(),
                    pending.reader.clone(),
                    pending.flow_id,
                    pending.shared_secret,
                    state,
                    nack_tx,
                    running.clone(),
                ));
                session.tasks.push(send_task);
                session.tasks.push(recv_task);

                let _ = (pending.tunnel_ipv4, pending.tunnel_ipv6.take(), pending.mtu);
                NativeResult::ok("Omega REALITY datapath started")
            }
        }
    }

    pub fn stop(handle: u64) -> NativeResult {
        let Some(session) = sessions().lock().unwrap().remove(&handle) else {
            return NativeResult::ok("No active native session.");
        };

        for task in session.tasks {
            task.abort();
        }
        NativeResult::ok("Stopped.")
    }

    /// Liveness probe for the Android service watchdog.
    /// Returns `1` if the datapath is healthy, `0` if a tunnel loop has died
    /// (transport broke and the session needs a reconnect), and `-1` if the
    /// handle is unknown (already stopped / never existed).
    pub fn session_alive(handle: u64) -> i32 {
        match sessions().lock().unwrap().get(&handle) {
            Some(session) => {
                if session.running.load(Ordering::Relaxed) {
                    1
                } else {
                    0
                }
            }
            None => -1,
        }
    }

    // -------------------------------------------------------------------------
    // REALITY handshake + tunnel loop
    // -------------------------------------------------------------------------

    #[allow(clippy::too_many_arguments)]
    pub fn start_reality_handshake(
        server: &str,
        device_id: &str,
        device_token: &str,
        device_name: &str,
        reality_sni: &str,
        reality_server_pubkey_b64: &str,
        reality_short_id: &str,
        reality_fingerprint: &str,
        protected_tcp_fd: i32,
    ) -> HandshakeResponse {
        let profile = match AndroidProfile::parse_extended(
            server,
            device_id,
            device_token,
            "android",
            "reality",
            reality_sni,
            reality_server_pubkey_b64,
            reality_short_id,
            reality_fingerprint,
        ) {
            Ok(profile) => profile,
            Err(err) => {
                close_raw_fd(protected_tcp_fd);
                return HandshakeResponse::err(err);
            }
        };

        let pubkey_bytes = match decode_b64_pubkey(&profile.reality_server_pubkey) {
            Some(bytes) => bytes,
            None => {
                close_raw_fd(protected_tcp_fd);
                return HandshakeResponse::err(
                    "reality_server_pubkey must decode to 32 bytes (base64)",
                );
            }
        };
        let server_pubkey = PublicKey::from(pubkey_bytes);
        let short_id = match parse_short_id_hex(&profile.reality_short_id) {
            Ok(value) => value,
            Err(err) => {
                close_raw_fd(protected_tcp_fd);
                return HandshakeResponse::err(err);
            }
        };

        let result = (|| -> Result<HandshakeResponse, String> {
            let runtime = Runtime::new().map_err(|err| format!("runtime init failed: {err}"))?;

            // Adopt protected TCP fd. The Kotlin side already called
            // `connect(server)` after `VpnService.protect()`, so the socket
            // is connected to the REALITY listener and excluded from the VPN.
            let std_socket =
                unsafe { std::net::TcpStream::from_raw_fd(protected_tcp_fd as RawFd) };
            std_socket
                .set_nonblocking(true)
                .map_err(|err| format!("tcp nonblocking failed: {err}"))?;
            let _ = std_socket.set_nodelay(true);

            let tcp = runtime
                .block_on(async { TcpStream::from_std(std_socket) })
                .map_err(|err| format!("tokio tcp init failed: {err}"))?;

            // Run the REALITY TLS handshake to completion.
            let alpn: [&[u8]; 1] = [b"http/1.1"];
            let inputs = ClientHandshakeInputs {
                server_name: &profile.reality_sni,
                server_long_term_pubkey: &server_pubkey,
                short_id,
                alpn_offer: Some(&alpn),
            };

            let (mut tcp, established) = runtime.block_on(async {
                let mut stream = tcp;
                let est = client_handshake(&mut stream, &inputs)
                    .await
                    .map_err(|err| format!("REALITY TLS handshake failed: {err}"))?;
                Ok::<_, String>((stream, est))
            })?;

            // Build encryptor/decryptor under the **application** keys.
            let params = established.params;
            let mut encryptor = RecordEncryptor::new(
                &params,
                &established
                    .application_secrets
                    .client_application_traffic_secret_0,
            )
            .map_err(|err| format!("record encryptor: {err}"))?;
            let mut decryptor = RecordDecryptor::new(
                &params,
                &established
                    .application_secrets
                    .server_application_traffic_secret_0,
            )
            .map_err(|err| format!("record decryptor: {err}"))?;

            // ---- Omega ClientHello (STUN + ML-KEM) inside the TLS tunnel ----
            let mut rng = rand::thread_rng();
            let (dk, ek) = MlKem768::generate(&mut rng);
            let client_hello = ClientHello {
                version: HANDSHAKE_VERSION,
                client_mtu: DEFAULT_CLIENT_MTU,
                fec_support: true,
                supports_tunnel_ipv6: true,
                encaps_key: ek.as_bytes().to_vec(),
                auth: Some(ClientAuth {
                    device_id: profile.device_id_bytes()?,
                    device_token: profile.device_token_bytes()?,
                    platform: DevicePlatform::Android,
                    device_name: device_name.trim().if_empty("android").to_string(),
                }),
            };
            let txn_id: [u8; 12] = rand::random();
            let request = StunWrapper::wrap_request(&txn_id, &client_hello.serialize());

            let server_hello = runtime.block_on(async {
                let record = encryptor
                    .seal_record(CT_APPLICATION_DATA, &request, 0)
                    .map_err(|err| format!("seal omega CHLO: {err}"))?;
                tcp.write_all(&record)
                    .await
                    .map_err(|err| format!("tcp write CHLO: {err}"))?;
                tcp.flush()
                    .await
                    .map_err(|err| format!("tcp flush CHLO: {err}"))?;

                let deadline =
                    Instant::now() + Duration::from_millis(DEFAULT_HANDSHAKE_TIMEOUT_MS * 4);
                loop {
                    if Instant::now() >= deadline {
                        return Err("Omega handshake (inside REALITY) timed out".to_string());
                    }
                    let payload = read_one_app_record(&mut tcp, &mut decryptor).await?;
                    let Some((is_request, resp_txn, resp_payload)) =
                        StunWrapper::parse(&payload)
                    else {
                        continue;
                    };
                    if is_request || resp_txn != txn_id {
                        continue;
                    }
                    if let Some(hello) = ServerHello::deserialize(resp_payload) {
                        return Ok::<ServerHello, String>(hello);
                    }
                    if let Some(reject) = HandshakeReject::deserialize(resp_payload) {
                        return Err(format!(
                            "REALITY/Omega handshake rejected by server: {:?}",
                            reject.reason
                        ));
                    }
                    return Err(
                        "malformed REALITY/Omega handshake response payload".to_string(),
                    );
                }
            })?;

            let ct_array: &ml_kem::Ciphertext<MlKem768> = server_hello
                .ciphertext
                .as_slice()
                .try_into()
                .map_err(|_| "invalid KEM ciphertext length".to_string())?;
            let shared_secret = dk
                .decapsulate(ct_array)
                .map_err(|_| "KEM decapsulation failed".to_string())?;
            let ss_bytes: &[u8] = shared_secret.as_ref();
            let shared_secret = ss_bytes.to_vec();
            let flow_id_bytes =
                derive_flow_id(&shared_secret).map_err(|err| format!("flow id failed: {err}"))?;
            let flow_id = FlowId(flow_id_bytes);
            let chaos_seed = u64::from_le_bytes(shared_secret[0..8].try_into().unwrap());
            let ssrc = u32::from_be_bytes(flow_id_bytes[0..4].try_into().unwrap());
            let keys_send = SessionKeys::from_shared_secret(&shared_secret, false)
                .map_err(|err| format!("key derivation failed: {err}"))?;

            // Split TCP stream into reader/writer halves for the tunnel loops.
            let (reader, writer) = tcp.into_split();

            let handle = NEXT_HANDLE.fetch_add(1, Ordering::Relaxed);
            let mtu = server_hello.server_mtu.clamp(1200, 1420);
            let tunnel_ipv4 = server_hello.tunnel_ip.to_string();
            let tunnel_ipv6 = server_hello.tunnel_ipv6.map(|value| value.to_string());

            sessions().lock().unwrap().insert(
                handle,
                NativeSession {
                    runtime,
                    pending: Some(Pending::Reality(PendingRealitySession {
                        reader: Arc::new(AsyncMutex::new(reader)),
                        writer: Arc::new(AsyncMutex::new(writer)),
                        encryptor: Arc::new(AsyncMutex::new(encryptor)),
                        decryptor: Arc::new(AsyncMutex::new(decryptor)),
                        shared_secret,
                        keys_send,
                        flow_id,
                        chaos_seed,
                        ssrc,
                        tunnel_ipv4: tunnel_ipv4.clone(),
                        tunnel_ipv6: tunnel_ipv6.clone(),
                        mtu,
                        cipher_suite: established.cipher_suite,
                        params,
                    })),
                    tasks: Vec::new(),
                    running: Arc::new(AtomicBool::new(true)),
                },
            );

            Ok(HandshakeResponse::ok(
                handle,
                tunnel_ipv4,
                tunnel_ipv6,
                mtu,
                vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()],
            ))
        })();

        match result {
            Ok(response) => response,
            Err(err) => HandshakeResponse::err(err),
        }
    }

    /// Read one TLS application_data record from `tcp`, decrypt, and return
    /// the inner payload bytes. Skips middlebox-compat ChangeCipherSpec
    /// records that some peers still emit after handshake.
    async fn read_one_app_record(
        tcp: &mut TcpStream,
        decryptor: &mut RecordDecryptor,
    ) -> Result<Vec<u8>, String> {
        loop {
            let mut header = [0u8; 5];
            tcp.read_exact(&mut header)
                .await
                .map_err(|err| format!("tcp read header: {err}"))?;
            let (content_type, length, _) =
                parse_record_header(&header).map_err(|err| err.to_string())?;
            if length == 0 || length as usize > TLS_MAX_RECORD_CIPHERTEXT {
                return Err(format!("invalid record length {length}"));
            }
            let mut body = vec![0u8; length as usize];
            tcp.read_exact(&mut body)
                .await
                .map_err(|err| format!("tcp read body: {err}"))?;
            match content_type {
                CT_APPLICATION_DATA => {
                    let opened = decryptor
                        .open_record(&header, &mut body)
                        .map_err(|err| format!("AEAD open: {err}"))?;
                    if opened.content_type == CT_APPLICATION_DATA {
                        return Ok(opened.content);
                    }
                    // handshake/alert inner types after handshake → ignore.
                    continue;
                }
                CT_CHANGE_CIPHER_SPEC => continue,
                _ => return Err(format!("unexpected content_type={content_type}")),
            }
        }
    }

    fn decode_b64_pubkey(raw: &str) -> Option<[u8; 32]> {
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine;
        let bytes = STANDARD.decode(raw.trim().as_bytes()).ok()?;
        if bytes.len() != 32 {
            return None;
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Some(out)
    }

    fn parse_short_id_hex(raw: &str) -> Result<[u8; 8], String> {
        let raw = raw.trim();
        if raw.is_empty() {
            return Ok([0u8; 8]);
        }
        if raw.len() != 16 {
            return Err("reality_short_id must be 16 hex chars".to_string());
        }
        let mut out = [0u8; 8];
        for (i, chunk) in raw.as_bytes().chunks_exact(2).enumerate() {
            let s = std::str::from_utf8(chunk)
                .map_err(|_| "invalid hex in reality_short_id".to_string())?;
            out[i] = u8::from_str_radix(s, 16)
                .map_err(|err| format!("invalid hex in reality_short_id: {err}"))?;
        }
        Ok(out)
    }

    #[allow(clippy::too_many_arguments)]
    async fn tun_to_reality_loop(
        tun: Arc<tun_rs::AsyncDevice>,
        encryptor: Arc<AsyncMutex<RecordEncryptor>>,
        writer: Arc<AsyncMutex<OwnedWriteHalf>>,
        flow_id: FlowId,
        keys_send: SessionKeys,
        state: Arc<Mutex<ClientState>>,
        nack_rx: mpsc::Receiver<NackMessage>,
        running: Arc<AtomicBool>,
    ) {
        tun_to_reality_inner(tun, encryptor, writer, flow_id, keys_send, state, nack_rx).await;
        // The loop only returns when the REALITY socket write failed → the
        // tunnel is dead; signal the Android watchdog to reconnect.
        running.store(false, Ordering::Relaxed);
    }

    #[allow(clippy::too_many_arguments)]
    async fn tun_to_reality_inner(
        tun: Arc<tun_rs::AsyncDevice>,
        encryptor: Arc<AsyncMutex<RecordEncryptor>>,
        writer: Arc<AsyncMutex<OwnedWriteHalf>>,
        flow_id: FlowId,
        mut keys_send: SessionKeys,
        state: Arc<Mutex<ClientState>>,
        mut nack_rx: mpsc::Receiver<NackMessage>,
    ) {
        let mut keepalive_interval = tokio::time::interval(Duration::from_secs(KEEPALIVE_SECS));
        keepalive_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut buf = vec![0u8; 1500];

        loop {
            tokio::select! {
                _ = keepalive_interval.tick() => {
                    let (seq, rtp_s, rtp_ts, ssrc) = next_header_state(&state, false);
                    let Some(packet) = build_packet(&mut keys_send, flow_id, seq, PacketType::KeepAlive, rtp_s, rtp_ts, ssrc, Vec::new(), true) else {
                        continue;
                    };
                    cache_packet(&state, seq, packet.clone());
                    if send_reality_packet(&encryptor, &writer, packet.as_ref()).await.is_err() {
                        return;
                    }
                }
                Some(nack) = nack_rx.recv() => {
                    let (seq, rtp_s, rtp_ts, ssrc) = next_header_state(&state, false);
                    let mut payload = vec![0u8; 12];
                    nack.write_to(&mut payload);
                    let Some(packet) = build_packet(&mut keys_send, flow_id, seq, PacketType::Nack, rtp_s, rtp_ts, ssrc, payload, true) else {
                        continue;
                    };
                    cache_packet(&state, seq, packet.clone());
                    if send_reality_packet(&encryptor, &writer, packet.as_ref()).await.is_err() {
                        return;
                    }
                }
                read = tun.recv(&mut buf) => {
                    let Ok(n) = read else { continue; };
                    let is_small = n < 500;
                    let (seq, rtp_s, rtp_ts, ssrc, target_size, padding_budget, redundancy_extra) = {
                        let mut state = state.lock().unwrap();
                        let seq = state.send_seq;
                        state.send_seq = state.send_seq.wrapping_add(1);
                        state.rtp_seq = state.rtp_seq.wrapping_add(1);
                        state.rtp_timestamp = state.rtp_timestamp.wrapping_add(if is_small { 960 } else { 3000 });
                        (
                            seq,
                            state.rtp_seq,
                            state.rtp_timestamp,
                            state.ssrc,
                            state.chaos.get_target_size() as usize,
                            state.current_padding_budget(),
                            state.current_redundancy_extra(),
                        )
                    };
                    let overhead = TOTAL_HEADER_LEN + AEAD_TAG_LEN;
                    let wire_size = n + overhead;
                    let padding_len = target_size.saturating_sub(wire_size).min(padding_budget);
                    let mut payload = buf[..n].to_vec();
                    if padding_len > 0 {
                        payload.extend(std::iter::repeat(0).take(padding_len));
                    }
                    let Some(packet) = build_packet(&mut keys_send, flow_id, seq, PacketType::Data, rtp_s, rtp_ts, ssrc, payload, is_small) else {
                        continue;
                    };
                    cache_packet(&state, seq, packet.clone());
                    if send_reality_packet(&encryptor, &writer, packet.as_ref()).await.is_ok() {
                        for _ in 0..redundancy_extra {
                            tokio::time::sleep(Duration::from_micros(REDUNDANCY_PACING_US)).await;
                            if send_reality_packet(&encryptor, &writer, packet.as_ref()).await.is_err() {
                                return;
                            }
                        }
                    } else {
                        return;
                    }
                }
            }
        }
    }

    /// Encrypt an Omega-wire packet as a single TLS application_data record
    /// and write it to the REALITY socket.
    async fn send_reality_packet(
        encryptor: &Arc<AsyncMutex<RecordEncryptor>>,
        writer: &Arc<AsyncMutex<OwnedWriteHalf>>,
        packet: &[u8],
    ) -> Result<(), ()> {
        let record = {
            let mut enc = encryptor.lock().await;
            enc.seal_record(CT_APPLICATION_DATA, packet, 0).map_err(|_| ())?
        };
        let mut w = writer.lock().await;
        w.write_all(&record).await.map_err(|_| ())?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn reality_to_tun_loop(
        tun: Arc<tun_rs::AsyncDevice>,
        decryptor: Arc<AsyncMutex<RecordDecryptor>>,
        reader: Arc<AsyncMutex<OwnedReadHalf>>,
        flow_id: FlowId,
        shared_secret: Vec<u8>,
        state: Arc<Mutex<ClientState>>,
        nack_tx: mpsc::Sender<NackMessage>,
        running: Arc<AtomicBool>,
    ) {
        reality_to_tun_inner(tun, decryptor, reader, flow_id, shared_secret, state, nack_tx).await;
        // Any return from the read loop means the REALITY socket broke or the
        // peer closed the session → mark dead so the watchdog reconnects.
        running.store(false, Ordering::Relaxed);
    }

    async fn reality_to_tun_inner(
        tun: Arc<tun_rs::AsyncDevice>,
        decryptor: Arc<AsyncMutex<RecordDecryptor>>,
        reader: Arc<AsyncMutex<OwnedReadHalf>>,
        flow_id: FlowId,
        shared_secret: Vec<u8>,
        state: Arc<Mutex<ClientState>>,
        nack_tx: mpsc::Sender<NackMessage>,
    ) {
        let mut keys_recv = match SessionKeys::from_shared_secret(&shared_secret, false) {
            Ok(keys) => keys,
            Err(_) => return,
        };
        let mut replay_filter = ReplayFilter::new();

        loop {
            // Read one encrypted TLS record from the socket.
            let payload = {
                let mut r = reader.lock().await;
                let mut header = [0u8; 5];
                if r.read_exact(&mut header).await.is_err() {
                    return;
                }
                let Ok((content_type, length, _)) = parse_record_header(&header) else {
                    return;
                };
                if length == 0 || length as usize > TLS_MAX_RECORD_CIPHERTEXT {
                    return;
                }
                let mut body = vec![0u8; length as usize];
                if r.read_exact(&mut body).await.is_err() {
                    return;
                }
                if content_type != CT_APPLICATION_DATA {
                    continue;
                }
                let mut dec = decryptor.lock().await;
                match dec.open_record(&header, &mut body) {
                    Ok(rec) if rec.content_type == CT_APPLICATION_DATA => rec.content,
                    _ => continue,
                }
            };

            let n = payload.len();
            if n < TOTAL_HEADER_LEN + AEAD_TAG_LEN {
                continue;
            }
            let Some(omega) = OmegaHeader::read_from(&payload[RTP_HEADER_LEN..TOTAL_HEADER_LEN])
            else {
                continue;
            };
            if omega.flow_id != flow_id {
                continue;
            }
            if !matches!(
                omega.packet_type,
                PacketType::Data | PacketType::Nack | PacketType::KeepAlive | PacketType::Close
            ) {
                continue;
            }
            if !replay_filter.check(omega.seq as u64) {
                continue;
            }

            let mut owned = payload;
            let (aad, ciphertext) = owned.split_at_mut(TOTAL_HEADER_LEN);
            let Ok(plaintext) = keys_recv.decrypt_in_place(ciphertext, omega.seq as u64, aad)
            else {
                continue;
            };
            replay_filter.update(omega.seq as u64);

            let inbound_nack = {
                let mut state = state.lock().unwrap();
                state.observe_inbound_seq(omega.seq)
            };
            if !matches!(omega.packet_type, PacketType::Close) {
                if let Some(nack) = inbound_nack {
                    let _ = nack_tx.send(nack).await;
                }
            }

            match omega.packet_type {
                PacketType::Data => {
                    let final_len = get_ip_packet_len(plaintext)
                        .map(|ip_len| plaintext.len().min(ip_len))
                        .unwrap_or(plaintext.len());
                    let _ = tun.send(&plaintext[..final_len]).await;
                }
                PacketType::Close => return,
                PacketType::KeepAlive | PacketType::Nack | _ => {}
            }
        }
    }

    async fn perform_handshake(
        udp: &UdpSocket,
        client_hello: &ClientHello,
    ) -> Result<HandshakeResult, String> {
        let txn_id: [u8; 12] = rand::random();
        let request = StunWrapper::wrap_request(&txn_id, &client_hello.serialize());
        let mut buf = vec![0u8; 4096];
        let mut last_error = String::from("timeout");

        for attempt in 1..=DEFAULT_HANDSHAKE_ATTEMPTS {
            let sent_at = Instant::now();
            udp.send(&request)
                .await
                .map_err(|err| format!("handshake send failed: {err}"))?;

            let deadline = Instant::now() + Duration::from_millis(DEFAULT_HANDSHAKE_TIMEOUT_MS);
            loop {
                let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                    break;
                };
                if remaining.is_zero() {
                    break;
                }

                match tokio::time::timeout(remaining, udp.recv(&mut buf)).await {
                    Ok(Ok(n)) => {
                        let Some((is_request, resp_txn, resp_payload)) =
                            StunWrapper::parse(&buf[..n])
                        else {
                            continue;
                        };
                        if is_request || resp_txn != txn_id {
                            continue;
                        }
                        if let Some(hello) = ServerHello::deserialize(resp_payload) {
                            return Ok(HandshakeResult {
                                hello,
                                rtt_ms: sent_at.elapsed().as_millis() as u64,
                            });
                        }
                        if let Some(reject) = HandshakeReject::deserialize(resp_payload) {
                            return Err(format!(
                                "handshake rejected by server: {:?}",
                                reject.reason
                            ));
                        }
                        last_error = "malformed handshake response payload".to_string();
                        break;
                    }
                    Ok(Err(err)) => return Err(format!("handshake recv failed: {err}")),
                    Err(_) => {
                        last_error = format!("timeout after {DEFAULT_HANDSHAKE_TIMEOUT_MS} ms");
                        break;
                    }
                }
            }

            if attempt < DEFAULT_HANDSHAKE_ATTEMPTS {
                let backoff = Duration::from_millis(DEFAULT_HANDSHAKE_BACKOFF_MS * attempt as u64);
                tokio::time::sleep(backoff).await;
            }
        }

        Err(format!(
            "handshake failed after {DEFAULT_HANDSHAKE_ATTEMPTS} attempts: {last_error}"
        ))
    }

    async fn tun_to_udp_loop(
        tun: Arc<tun_rs::AsyncDevice>,
        transport: Arc<UdpSocket>,
        flow_id: FlowId,
        mut keys_send: SessionKeys,
        state: Arc<Mutex<ClientState>>,
        mut nack_rx: mpsc::Receiver<NackMessage>,
    ) {
        let mut keepalive_interval = tokio::time::interval(Duration::from_secs(KEEPALIVE_SECS));
        keepalive_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut buf = vec![0u8; 1500];

        loop {
            tokio::select! {
                _ = keepalive_interval.tick() => {
                    let (seq, rtp_s, rtp_ts, ssrc) = next_header_state(&state, false);
                    let packet = match build_packet(&mut keys_send, flow_id, seq, PacketType::KeepAlive, rtp_s, rtp_ts, ssrc, Vec::new(), true) {
                        Some(packet) => packet,
                        None => continue,
                    };
                    cache_packet(&state, seq, packet.clone());
                    let _ = transport.send(packet.as_ref()).await;
                }
                Some(nack) = nack_rx.recv() => {
                    let (seq, rtp_s, rtp_ts, ssrc) = next_header_state(&state, false);
                    let mut payload = vec![0u8; 12];
                    nack.write_to(&mut payload);
                    let packet = match build_packet(&mut keys_send, flow_id, seq, PacketType::Nack, rtp_s, rtp_ts, ssrc, payload, true) {
                        Some(packet) => packet,
                        None => continue,
                    };
                    cache_packet(&state, seq, packet.clone());
                    let _ = transport.send(packet.as_ref()).await;
                }
                read = tun.recv(&mut buf) => {
                    let Ok(n) = read else {
                        continue;
                    };
                    let is_small = n < 500;
                    let (seq, rtp_s, rtp_ts, ssrc, target_size, padding_budget, redundancy_extra) = {
                        let mut state = state.lock().unwrap();
                        let seq = state.send_seq;
                        state.send_seq = state.send_seq.wrapping_add(1);
                        state.rtp_seq = state.rtp_seq.wrapping_add(1);
                        state.rtp_timestamp = state.rtp_timestamp.wrapping_add(if is_small { 960 } else { 3000 });
                        (
                            seq,
                            state.rtp_seq,
                            state.rtp_timestamp,
                            state.ssrc,
                            state.chaos.get_target_size() as usize,
                            state.current_padding_budget(),
                            state.current_redundancy_extra(),
                        )
                    };
                    let overhead = TOTAL_HEADER_LEN + AEAD_TAG_LEN;
                    let wire_size = n + overhead;
                    let padding_len = target_size.saturating_sub(wire_size).min(padding_budget);
                    let mut payload = buf[..n].to_vec();
                    if padding_len > 0 {
                        payload.extend(std::iter::repeat(0).take(padding_len));
                    }
                    let packet = match build_packet(&mut keys_send, flow_id, seq, PacketType::Data, rtp_s, rtp_ts, ssrc, payload, is_small) {
                        Some(packet) => packet,
                        None => continue,
                    };
                    cache_packet(&state, seq, packet.clone());
                    if transport.send(packet.as_ref()).await.is_ok() {
                        for _ in 0..redundancy_extra {
                            tokio::time::sleep(Duration::from_micros(REDUNDANCY_PACING_US)).await;
                            if transport.send(packet.as_ref()).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn udp_to_tun_loop(
        tun: Arc<tun_rs::AsyncDevice>,
        transport: Arc<UdpSocket>,
        flow_id: FlowId,
        shared_secret: Vec<u8>,
        state: Arc<Mutex<ClientState>>,
        nack_tx: mpsc::Sender<NackMessage>,
        running: Arc<AtomicBool>,
    ) {
        udp_to_tun_inner(tun, transport, flow_id, shared_secret, state, nack_tx).await;
        // Returns only after the UDP socket produced sustained recv errors
        // (underlying network gone) → mark dead so the watchdog reconnects.
        running.store(false, Ordering::Relaxed);
    }

    async fn udp_to_tun_inner(
        tun: Arc<tun_rs::AsyncDevice>,
        transport: Arc<UdpSocket>,
        flow_id: FlowId,
        shared_secret: Vec<u8>,
        state: Arc<Mutex<ClientState>>,
        nack_tx: mpsc::Sender<NackMessage>,
    ) {
        let mut keys_recv = match SessionKeys::from_shared_secret(&shared_secret, false) {
            Ok(keys) => keys,
            Err(_) => return,
        };
        let mut replay_filter = ReplayFilter::new();
        let mut buf = vec![0u8; 2048];
        let mut consecutive_errors: u32 = 0;

        loop {
            // Previously this busy-spun (`else { continue }`) on a dead socket,
            // pinning a CPU core and draining the battery after a network drop.
            // Now we back off briefly and bail once errors persist so the
            // Android service can rebuild the tunnel on the new network.
            let n = match transport.recv(&mut buf).await {
                Ok(n) => {
                    consecutive_errors = 0;
                    n
                }
                Err(_) => {
                    consecutive_errors += 1;
                    if consecutive_errors >= MAX_DATAPATH_RECV_ERRORS {
                        return;
                    }
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    continue;
                }
            };
            if n < TOTAL_HEADER_LEN + AEAD_TAG_LEN {
                continue;
            }
            let Some(omega) = OmegaHeader::read_from(&buf[RTP_HEADER_LEN..TOTAL_HEADER_LEN]) else {
                continue;
            };
            if omega.flow_id != flow_id {
                continue;
            }
            if !matches!(
                omega.packet_type,
                PacketType::Data | PacketType::Nack | PacketType::KeepAlive | PacketType::Close
            ) {
                continue;
            }
            if !replay_filter.check(omega.seq as u64) {
                continue;
            }

            let (aad, ciphertext) = buf[..n].split_at_mut(TOTAL_HEADER_LEN);
            let Ok(plaintext) = keys_recv.decrypt_in_place(ciphertext, omega.seq as u64, aad)
            else {
                continue;
            };
            replay_filter.update(omega.seq as u64);

            let inbound_nack = {
                let mut state = state.lock().unwrap();
                state.observe_inbound_seq(omega.seq)
            };
            if !matches!(omega.packet_type, PacketType::Close) {
                if let Some(nack) = inbound_nack {
                    let _ = nack_tx.send(nack).await;
                }
            }

            match omega.packet_type {
                PacketType::Data => {
                    let final_len = get_ip_packet_len(plaintext)
                        .map(|ip_len| plaintext.len().min(ip_len))
                        .unwrap_or(plaintext.len());
                    let _ = tun.send(&plaintext[..final_len]).await;
                }
                PacketType::Nack => {
                    if let Some(nack) = NackMessage::read_from(plaintext) {
                        let packets = {
                            let mut state = state.lock().unwrap();
                            state.on_remote_nack(&nack);
                            state.retransmit_queue.observe_nack(&nack, current_ms());
                            state
                                .retransmit_queue
                                .process_nack(&nack)
                                .into_iter()
                                .take(MAX_RETRANSMIT_BURST)
                                .map(|packet| packet.data.clone())
                                .collect::<Vec<_>>()
                        };
                        let packet_count = packets.len();
                        for (idx, packet) in packets.into_iter().enumerate() {
                            let _ = transport.send(packet.as_ref()).await;
                            if idx + 1 < packet_count {
                                tokio::time::sleep(Duration::from_micros(RETRANSMIT_PACING_US))
                                    .await;
                            }
                        }
                    }
                }
                PacketType::Close => return,
                PacketType::KeepAlive => {}
                _ => {}
            }
        }
    }

    fn build_packet(
        keys_send: &mut SessionKeys,
        flow_id: FlowId,
        seq: u32,
        packet_type: PacketType,
        rtp_s: u16,
        rtp_ts: u32,
        ssrc: u32,
        mut payload: Vec<u8>,
        is_small: bool,
    ) -> Option<Bytes> {
        let rtp = if is_small {
            RtpHeader::opus(rtp_s, rtp_ts, ssrc)
        } else {
            RtpHeader::vp8(rtp_s, rtp_ts, ssrc, true)
        };
        let omega = OmegaHeader {
            flow_id,
            seq,
            packet_type,
        };
        let mut out = BytesMut::with_capacity(TOTAL_HEADER_LEN + payload.len() + AEAD_TAG_LEN);
        out.resize(TOTAL_HEADER_LEN, 0);
        rtp.write_to(&mut out[..RTP_HEADER_LEN]);
        omega.write_to(&mut out[RTP_HEADER_LEN..TOTAL_HEADER_LEN]);
        let aad = &out[..TOTAL_HEADER_LEN];
        keys_send.encrypt_in_place(&mut payload, aad).ok()?;
        out.extend_from_slice(&payload);
        Some(out.freeze())
    }

    fn next_header_state(state: &Arc<Mutex<ClientState>>, is_small: bool) -> (u32, u16, u32, u32) {
        let mut state = state.lock().unwrap();
        let seq = state.send_seq;
        state.send_seq = state.send_seq.wrapping_add(1);
        state.rtp_seq = state.rtp_seq.wrapping_add(1);
        state.rtp_timestamp = state
            .rtp_timestamp
            .wrapping_add(if is_small { 960 } else { 3000 });
        (seq, state.rtp_seq, state.rtp_timestamp, state.ssrc)
    }

    fn cache_packet(state: &Arc<Mutex<ClientState>>, seq: u32, packet: Bytes) {
        let mut state = state.lock().unwrap();
        let now = current_ms();
        state.retransmit_queue.cache_packet(seq, packet, now);
        state.retransmit_queue.purge_expired(now);
    }

    fn get_ip_packet_len(buf: &[u8]) -> Option<usize> {
        if buf.is_empty() {
            return None;
        }
        match buf[0] >> 4 {
            4 => {
                if buf.len() < 4 {
                    None
                } else {
                    Some(u16::from_be_bytes([buf[2], buf[3]]) as usize)
                }
            }
            6 => {
                if buf.len() < 6 {
                    None
                } else {
                    Some(40 + u16::from_be_bytes([buf[4], buf[5]]) as usize)
                }
            }
            _ => None,
        }
    }

    fn current_ms() -> u64 {
        SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }

    fn sessions() -> &'static Mutex<HashMap<u64, NativeSession>> {
        SESSIONS.get_or_init(|| Mutex::new(HashMap::new()))
    }

    fn close_raw_fd(fd: i32) {
        if fd >= 0 {
            let _ = unsafe { std::fs::File::from_raw_fd(fd as RawFd) };
        }
    }

    trait IfEmpty {
        fn if_empty<'a>(&'a self, fallback: &'a str) -> &'a str;
    }

    impl IfEmpty for str {
        fn if_empty<'a>(&'a self, fallback: &'a str) -> &'a str {
            if self.is_empty() {
                fallback
            } else {
                self
            }
        }
    }
}

#[cfg(not(target_os = "android"))]
mod host {
    use super::*;

    pub fn start_handshake(
        _server: &str,
        _device_id: &str,
        _device_token: &str,
        _device_name: &str,
        _transport: &str,
        _protected_udp_fd: i32,
    ) -> HandshakeResponse {
        HandshakeResponse::err("Android native runtime can only run on Android.")
    }

    #[allow(clippy::too_many_arguments)]
    pub fn start_reality_handshake(
        _server: &str,
        _device_id: &str,
        _device_token: &str,
        _device_name: &str,
        _reality_sni: &str,
        _reality_server_pubkey_b64: &str,
        _reality_short_id: &str,
        _reality_fingerprint: &str,
        _protected_tcp_fd: i32,
    ) -> HandshakeResponse {
        HandshakeResponse::err("Android REALITY runtime can only run on Android.")
    }

    pub fn continue_with_tun_fd(_handle: u64, _tun_fd: i32) -> NativeResult {
        NativeResult::err("Android TUN fd can only be attached on Android.")
    }

    pub fn stop(_handle: u64) -> NativeResult {
        NativeResult::ok("No Android native session on this host.")
    }

    pub fn session_alive(_handle: u64) -> i32 {
        -1
    }
}

#[cfg(target_os = "android")]
pub use android::*;

#[cfg(not(target_os = "android"))]
pub use host::*;
