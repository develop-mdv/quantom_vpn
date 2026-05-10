use crate::api::{HandshakeResponse, NativeResult};

#[cfg(target_os = "android")]
mod android {
    use super::*;
    use crate::config::AndroidProfile;
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use std::os::fd::{FromRawFd, RawFd};
    use std::sync::atomic::{AtomicU64, Ordering};
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
    use tokio::net::UdpSocket;
    use tokio::runtime::Runtime;
    use tokio::sync::mpsc;

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

    static NEXT_HANDLE: AtomicU64 = AtomicU64::new(1);
    static SESSIONS: OnceLock<Mutex<HashMap<u64, NativeSession>>> = OnceLock::new();

    struct NativeSession {
        runtime: Runtime,
        pending: Option<PendingSession>,
        tasks: Vec<tokio::task::JoinHandle<()>>,
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
                    pending: Some(PendingSession {
                        transport: udp,
                        shared_secret,
                        keys_send,
                        flow_id,
                        chaos_seed,
                        ssrc,
                        tunnel_ipv4: tunnel_ipv4.clone(),
                        tunnel_ipv6: tunnel_ipv6.clone(),
                        mtu,
                    }),
                    tasks: Vec::new(),
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
        let Some(mut pending) = session.pending.take() else {
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
        ));
        session.tasks.push(send_task);
        session.tasks.push(recv_task);

        let _ = (pending.tunnel_ipv4, pending.tunnel_ipv6.take(), pending.mtu);
        NativeResult::ok("Omega datapath started")
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

    async fn udp_to_tun_loop(
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

        loop {
            let Ok(n) = transport.recv(&mut buf).await else {
                continue;
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

    pub fn continue_with_tun_fd(_handle: u64, _tun_fd: i32) -> NativeResult {
        NativeResult::err("Android TUN fd can only be attached on Android.")
    }

    pub fn stop(_handle: u64) -> NativeResult {
        NativeResult::ok("No Android native session on this host.")
    }
}

#[cfg(target_os = "android")]
pub use android::*;

#[cfg(not(target_os = "android"))]
pub use host::*;
