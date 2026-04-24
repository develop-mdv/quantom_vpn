mod config;
mod diagnostics;
mod network;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use anyhow::Context;
use bytes::{Bytes, BytesMut};
use kem::Decapsulate;
use ml_kem::{EncodedSizeUser, KemCore, MlKem768};
use omega_core::arq::{GapDetector, LossEstimator, RetransmitQueue};
use omega_core::chaos::ChaosPrng;
use omega_core::crypto::{derive_flow_id, SessionKeys};
use omega_core::protocol::*;
use omega_core::replay::ReplayFilter;
use tokio::net::UdpSocket;
use tracing_subscriber::EnvFilter;

use crate::config::{ClientConfig, DnsLeakGuardPolicy, MorphingPolicy, MtuPolicy};
use crate::diagnostics::{ClientDiagnostics, HealthCheckKind};

const DEFAULT_SERVER: &str = "127.0.0.1:51820";
const DEFAULT_TUN_PREFIX: u8 = 16;
const DEFAULT_TUN_PREFIX_V6: u8 = 64;
const DEFAULT_INITIAL_ARQ_RTT_MS: u64 = 350;
const MAX_RETRANSMIT_BURST: usize = 24;
const RETRANSMIT_PACING_US: u64 = 500;
const PADDING_BUDGET_MIN: usize = 0;
const PADDING_RECOVERY_STEP: usize = 24;
const PADDING_RECOVERY_INTERVAL_SECS: u64 = 2;
const REDUNDANCY_EXTRA_MAX: u8 = 2;
const REDUNDANCY_DECAY_SECS: u64 = 8;
const REDUNDANCY_PACING_US: u64 = 200;

struct ClientState {
    retransmit_queue: RetransmitQueue,
    gap_detector: GapDetector,
    loss_estimator: LossEstimator,
    send_seq: u32,
    rtp_seq: u16,
    rtp_timestamp: u32,
    ssrc: u32,
    chaos: ChaosPrng,
    morphing_policy: MorphingPolicy,
    padding_budget: usize,
    last_padding_adjust: Instant,
    redundancy_extra: u8,
    last_redundancy_adjust: Instant,
    loss_est_seq: u32,
    loss_est_init: bool,
}

impl ClientState {
    fn new(ssrc: u32, chaos_seed: u64, morphing_policy: MorphingPolicy) -> Self {
        Self {
            retransmit_queue: RetransmitQueue::with_initial_rtt(DEFAULT_INITIAL_ARQ_RTT_MS),
            gap_detector: GapDetector::new(),
            loss_estimator: LossEstimator::new(),
            send_seq: 0,
            rtp_seq: 0,
            rtp_timestamp: 0,
            ssrc,
            chaos: ChaosPrng::new(chaos_seed),
            morphing_policy,
            padding_budget: morphing_policy.padding_budget_cap(),
            last_padding_adjust: Instant::now(),
            redundancy_extra: 0,
            last_redundancy_adjust: Instant::now(),
            loss_est_seq: 0,
            loss_est_init: false,
        }
    }

    fn current_padding_budget(&mut self) -> usize {
        let padding_cap = self.morphing_policy.padding_budget_cap();
        if padding_cap == 0 {
            self.padding_budget = 0;
            return 0;
        }

        let elapsed = self.last_padding_adjust.elapsed().as_secs();
        let ticks = elapsed / PADDING_RECOVERY_INTERVAL_SECS;
        if ticks > 0 {
            let growth = (ticks as usize).saturating_mul(PADDING_RECOVERY_STEP);
            self.padding_budget = self.padding_budget.saturating_add(growth).min(padding_cap);
            self.last_padding_adjust = Instant::now();
        }
        self.padding_budget.min(padding_cap)
    }

    fn on_remote_nack(&mut self, nack: &NackMessage) {
        let missing = nack.bitmap.count_ones() as usize;
        if missing == 0 {
            return;
        }

        if matches!(self.morphing_policy, MorphingPolicy::Off) {
            self.padding_budget = 0;
            self.redundancy_extra = 0;
            self.last_padding_adjust = Instant::now();
            self.last_redundancy_adjust = Instant::now();
            return;
        }

        let penalty = 16 + missing.saturating_mul(8);
        self.padding_budget = self
            .padding_budget
            .saturating_sub(penalty)
            .max(PADDING_BUDGET_MIN);
        self.last_padding_adjust = Instant::now();

        let bump = if missing >= 16 { 2 } else { 1 };
        self.redundancy_extra = self
            .redundancy_extra
            .saturating_add(bump)
            .min(REDUNDANCY_EXTRA_MAX);
        self.last_redundancy_adjust = Instant::now();
    }

    fn current_redundancy_extra(&mut self) -> usize {
        if matches!(self.morphing_policy, MorphingPolicy::Off) {
            self.redundancy_extra = 0;
            return 0;
        }

        let elapsed = self.last_redundancy_adjust.elapsed().as_secs();
        let ticks = elapsed / REDUNDANCY_DECAY_SECS;
        if ticks > 0 {
            self.redundancy_extra = self.redundancy_extra.saturating_sub(ticks as u8);
            self.last_redundancy_adjust = Instant::now();
        }
        self.redundancy_extra as usize
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
            let lost_count = diff - 1;
            let to_record_lost = lost_count.min(256);

            for _ in 0..to_record_lost {
                self.loss_estimator.record(false);
            }
            self.loss_estimator.record(true);
            self.loss_est_seq = received_seq;
        }
    }

    fn loss_ratio(&self) -> f64 {
        self.loss_estimator.loss_ratio()
    }

    fn observe_inbound_seq(&mut self, seq: u32) -> Option<NackMessage> {
        let nack = self.gap_detector.record_received(seq);
        self.update_loss_stats(seq);
        nack
    }
}

fn current_ms() -> u64 {
    SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn get_ip_packet_len(buf: &[u8]) -> Option<usize> {
    if buf.is_empty() {
        return None;
    }
    let version = buf[0] >> 4;
    match version {
        4 => {
            if buf.len() < 4 {
                return None;
            }
            Some(u16::from_be_bytes([buf[2], buf[3]]) as usize)
        }
        6 => {
            if buf.len() < 6 {
                return None;
            }
            let payload_len = u16::from_be_bytes([buf[4], buf[5]]) as usize;
            Some(40 + payload_len)
        }
        _ => None,
    }
}

fn mtu_probe_candidates(requested_mtu: u16) -> Vec<u16> {
    let mut candidates = vec![requested_mtu.clamp(1200, 1420), 1360, 1320, 1280, 1200];
    candidates.sort_by(|a, b| b.cmp(a));
    candidates.dedup();
    candidates
        .into_iter()
        .filter(|candidate| *candidate <= requested_mtu && *candidate >= 1200)
        .collect()
}

fn build_encrypted_control_packet(
    keys: &mut SessionKeys,
    flow_id: FlowId,
    seq: u32,
    packet_type: PacketType,
    ssrc: u32,
    payload_len: usize,
) -> anyhow::Result<Bytes> {
    let rtp = RtpHeader::opus(seq as u16, seq.wrapping_mul(960), ssrc);
    let omega = OmegaHeader {
        flow_id,
        seq,
        packet_type,
    };

    let mut out = BytesMut::with_capacity(TOTAL_HEADER_LEN + payload_len + AEAD_TAG_LEN);
    out.resize(TOTAL_HEADER_LEN, 0);
    rtp.write_to(&mut out[..RTP_HEADER_LEN]);
    omega.write_to(&mut out[RTP_HEADER_LEN..TOTAL_HEADER_LEN]);

    let aad = &out[..TOTAL_HEADER_LEN];
    let mut payload = vec![0xA5; payload_len];
    keys.encrypt_in_place(&mut payload, aad)
        .map_err(|err| anyhow::anyhow!("failed to encrypt control packet: {err}"))?;
    out.extend_from_slice(&payload);
    Ok(out.freeze())
}

async fn run_path_mtu_probe(
    udp: &UdpSocket,
    server_addr: SocketAddr,
    flow_id: FlowId,
    shared_secret: &[u8],
    keys_send: &mut SessionKeys,
    ssrc: u32,
    requested_mtu: u16,
    timeout_ms: u64,
) -> anyhow::Result<(u16, Vec<u16>, usize)> {
    let candidates = mtu_probe_candidates(requested_mtu);
    let mut probes_sent = 0usize;
    let mut keys_recv = SessionKeys::from_shared_secret(shared_secret, false)
        .map_err(|err| anyhow::anyhow!("failed to derive MTU probe receive keys: {err}"))?;
    let mut buf = vec![0u8; 2048];

    for candidate in &candidates {
        let seq = keys_send.send_nonce() as u32;
        let packet = build_encrypted_control_packet(
            keys_send,
            flow_id,
            seq,
            PacketType::PathProbe,
            ssrc,
            *candidate as usize,
        )?;
        probes_sent += 1;
        udp.send_to(packet.as_ref(), server_addr).await?;

        let deadline = Instant::now() + Duration::from_millis(timeout_ms);
        loop {
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                break;
            };
            if remaining.is_zero() {
                break;
            }

            let recv = tokio::time::timeout(remaining, udp.recv_from(&mut buf)).await;
            let Ok(Ok((n, _src))) = recv else {
                break;
            };
            if n < TOTAL_HEADER_LEN + AEAD_TAG_LEN {
                continue;
            }
            let Some(omega) = OmegaHeader::read_from(&buf[RTP_HEADER_LEN..TOTAL_HEADER_LEN]) else {
                continue;
            };
            if omega.flow_id != flow_id || omega.packet_type != PacketType::PathProbeReply {
                continue;
            }

            let (aad, ciphertext) = buf[..n].split_at_mut(TOTAL_HEADER_LEN);
            let plaintext = match keys_recv.decrypt_in_place(ciphertext, omega.seq as u64, aad) {
                Ok(plaintext) => plaintext,
                Err(_) => continue,
            };
            if plaintext.len() == *candidate as usize {
                return Ok((*candidate, candidates, probes_sent));
            }
        }
    }

    Err(anyhow::anyhow!(
        "no MTU probe reply received for candidates {:?}",
        candidates
    ))
}

fn detect_platform() -> DevicePlatform {
    #[cfg(target_os = "windows")]
    {
        return DevicePlatform::Windows;
    }
    #[cfg(target_os = "linux")]
    {
        return DevicePlatform::Linux;
    }
    #[cfg(target_os = "macos")]
    {
        return DevicePlatform::Macos;
    }
    #[cfg(target_os = "android")]
    {
        return DevicePlatform::Android;
    }
    #[cfg(target_os = "ios")]
    {
        return DevicePlatform::Ios;
    }
    #[allow(unreachable_code)]
    DevicePlatform::Other
}

fn parse_uuid(value: &str) -> anyhow::Result<[u8; 16]> {
    let compact = value.replace('-', "");
    if compact.len() != 32 {
        return Err(anyhow::anyhow!("device_id must be UUID"));
    }

    let mut out = [0u8; 16];
    let bytes = compact.as_bytes();
    for i in 0..16 {
        let hi = hex_value(bytes[i * 2])
            .ok_or_else(|| anyhow::anyhow!("invalid device_id hex at pos {}", i * 2))?;
        let lo = hex_value(bytes[i * 2 + 1])
            .ok_or_else(|| anyhow::anyhow!("invalid device_id hex at pos {}", i * 2 + 1))?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn parse_token(value: &str) -> anyhow::Result<[u8; DEVICE_TOKEN_LEN]> {
    if value.len() != DEVICE_TOKEN_LEN * 2 {
        return Err(anyhow::anyhow!(
            "device token must be {} hex chars",
            DEVICE_TOKEN_LEN * 2
        ));
    }

    let mut out = [0u8; DEVICE_TOKEN_LEN];
    let bytes = value.as_bytes();
    for i in 0..DEVICE_TOKEN_LEN {
        let hi = hex_value(bytes[i * 2])
            .ok_or_else(|| anyhow::anyhow!("invalid token hex at pos {}", i * 2))?;
        let lo = hex_value(bytes[i * 2 + 1])
            .ok_or_else(|| anyhow::anyhow!("invalid token hex at pos {}", i * 2 + 1))?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_value(v: u8) -> Option<u8> {
    match v {
        b'0'..=b'9' => Some(v - b'0'),
        b'a'..=b'f' => Some(v - b'a' + 10),
        b'A'..=b'F' => Some(v - b'A' + 10),
        _ => None,
    }
}

fn build_dns_query(hostname: &str, txid: u16) -> Vec<u8> {
    let mut query = Vec::with_capacity(64);
    query.extend_from_slice(&txid.to_be_bytes());
    query.extend_from_slice(&0x0100u16.to_be_bytes());
    query.extend_from_slice(&1u16.to_be_bytes());
    query.extend_from_slice(&0u16.to_be_bytes());
    query.extend_from_slice(&0u16.to_be_bytes());
    query.extend_from_slice(&0u16.to_be_bytes());

    for label in hostname.split('.').filter(|part| !part.is_empty()) {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0);
    query.extend_from_slice(&1u16.to_be_bytes());
    query.extend_from_slice(&1u16.to_be_bytes());
    query
}

async fn udp_dns_probe(target: SocketAddr) -> anyhow::Result<SocketAddr> {
    let socket = match target {
        SocketAddr::V4(_) => UdpSocket::bind("0.0.0.0:0").await?,
        SocketAddr::V6(_) => UdpSocket::bind("[::]:0").await?,
    };
    let txid: u16 = rand::random();
    let query = build_dns_query("example.com", txid);
    let mut buf = [0u8; 1500];

    socket.send_to(&query, target).await?;
    let (n, src) = tokio::time::timeout(Duration::from_secs(3), socket.recv_from(&mut buf))
        .await
        .map_err(|_| anyhow::anyhow!("timed out waiting for UDP DNS response from {target}"))??;

    if n >= 4 && u16::from_be_bytes([buf[0], buf[1]]) == txid && (buf[2] & 0x80) != 0 {
        Ok(src)
    } else {
        Err(anyhow::anyhow!(
            "unexpected UDP DNS response from {src}; bytes={n}"
        ))
    }
}

async fn run_post_connect_health_checks(
    dns_servers: Vec<String>,
    enabled: bool,
    ipv6_required: bool,
    dns_leak_guard_policy: DnsLeakGuardPolicy,
    diagnostics: ClientDiagnostics,
) {
    if !enabled {
        diagnostics.health_check_skipped(HealthCheckKind::Ipv4Egress, "OMEGA_NETWORK_DIAG=0");
        diagnostics.health_check_skipped(HealthCheckKind::Ipv6Egress, "OMEGA_NETWORK_DIAG=0");
        diagnostics.health_check_skipped(HealthCheckKind::Dns, "OMEGA_NETWORK_DIAG=0");
        diagnostics.health_check_skipped(HealthCheckKind::DnsLeakGuard, "OMEGA_NETWORK_DIAG=0");
        diagnostics.refresh_connection_health(ipv6_required);
        return;
    }

    tokio::time::sleep(Duration::from_secs(2)).await;

    let targets = dns_servers
        .into_iter()
        .filter_map(|value| value.parse::<std::net::IpAddr>().ok())
        .collect::<Vec<_>>();
    if targets.is_empty() {
        tracing::warn!("UDP diagnostic skipped: no valid DNS servers");
        diagnostics.udp_check_failed("no valid DNS servers configured");
        diagnostics.health_check_failed(HealthCheckKind::Dns, "no valid DNS servers configured");
        diagnostics.health_check_failed(
            HealthCheckKind::DnsLeakGuard,
            "cannot verify tunnel DNS because no valid DNS servers are configured",
        );
        diagnostics.refresh_connection_health(ipv6_required);
        return;
    }

    let ipv4_target: SocketAddr = "1.1.1.1:53".parse().unwrap();
    match udp_dns_probe(ipv4_target).await {
        Ok(src) => diagnostics.health_check_passed(HealthCheckKind::Ipv4Egress, src.to_string()),
        Err(err) => {
            tracing::warn!(error = %err, %ipv4_target, "IPv4 egress health check failed");
            diagnostics.health_check_failed(HealthCheckKind::Ipv4Egress, err.to_string());
        }
    }

    let mut dns_passed = false;
    for dns_ip in targets {
        let target = SocketAddr::from((dns_ip, 53));
        match udp_dns_probe(target).await {
            Ok(src) => {
                tracing::info!(%src, dns_server = %target, "UDP DNS diagnostic passed");
                diagnostics.udp_check_passed(target, src);
                diagnostics.health_check_passed(HealthCheckKind::Dns, target.to_string());
                dns_passed = true;
                break;
            }
            Err(err) => tracing::warn!(error = %err, %target, "DNS health check failed"),
        }
    }
    if !dns_passed {
        diagnostics.udp_check_failed("all UDP DNS checks timed out or returned unexpected replies");
        diagnostics.health_check_failed(
            HealthCheckKind::Dns,
            "all UDP DNS checks timed out or returned unexpected replies",
        );
    }

    if ipv6_required {
        let ipv6_target: SocketAddr = "[2606:4700:4700::1111]:53".parse().unwrap();
        match udp_dns_probe(ipv6_target).await {
            Ok(src) => {
                diagnostics.health_check_passed(HealthCheckKind::Ipv6Egress, src.to_string())
            }
            Err(err) => {
                tracing::warn!(error = %err, %ipv6_target, "IPv6 egress health check failed");
                diagnostics.health_check_failed(HealthCheckKind::Ipv6Egress, err.to_string());
            }
        }
    } else {
        diagnostics.health_check_skipped(HealthCheckKind::Ipv6Egress, "IPv6 tunnel not requested");
    }

    match dns_leak_guard_policy {
        DnsLeakGuardPolicy::Off => {
            diagnostics.health_check_skipped(HealthCheckKind::DnsLeakGuard, "disabled");
        }
        DnsLeakGuardPolicy::Warn | DnsLeakGuardPolicy::Strict => {
            if dns_passed {
                diagnostics
                    .health_check_passed(HealthCheckKind::DnsLeakGuard, "tunnel DNS responded");
            } else {
                diagnostics.health_check_failed(
                    HealthCheckKind::DnsLeakGuard,
                    "tunnel DNS did not respond; DNS leak risk is elevated",
                );
            }
        }
    }

    diagnostics.refresh_connection_health(ipv6_required);
}

struct HandshakeResult {
    hello: ServerHello,
    rtt_ms: u64,
}

async fn perform_handshake(
    udp: &UdpSocket,
    server_addr: SocketAddr,
    client_hello: &ClientHello,
    config: &ClientConfig,
) -> anyhow::Result<HandshakeResult> {
    let attempts = config.handshake_attempts;
    let timeout_ms = config.handshake_timeout_ms;
    let backoff_ms = config.handshake_backoff_ms;

    let txn_id: [u8; 12] = rand::random();
    let request = StunWrapper::wrap_request(&txn_id, &client_hello.serialize());
    let mut buf = vec![0u8; 4096];
    let mut last_error = String::from("timeout");

    for attempt in 1..=attempts {
        let sent_at = Instant::now();
        udp.send_to(&request, server_addr).await?;
        tracing::info!(attempt, attempts, %server_addr, "handshake request sent");

        let deadline = Instant::now() + Duration::from_millis(timeout_ms);
        loop {
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                break;
            };
            if remaining.is_zero() {
                break;
            }

            match tokio::time::timeout(remaining, udp.recv_from(&mut buf)).await {
                Ok(Ok((n, _src))) => {
                    let parsed = StunWrapper::parse(&buf[..n]);
                    let Some((is_request, resp_txn, resp_payload)) = parsed else {
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
                        return Err(anyhow::anyhow!(
                            "handshake rejected by server: {:?}",
                            reject.reason
                        ));
                    }

                    last_error = "malformed handshake response payload".to_string();
                    break;
                }
                Ok(Err(err)) => {
                    return Err(err.into());
                }
                Err(_) => {
                    last_error = format!("timeout after {} ms", timeout_ms);
                    break;
                }
            }
        }

        if attempt < attempts {
            let backoff = Duration::from_millis(backoff_ms.saturating_mul(attempt as u64));
            tracing::warn!(
                attempt,
                attempts,
                wait_ms = backoff.as_millis(),
                "handshake attempt failed, retrying"
            );
            tokio::time::sleep(backoff).await;
        }
    }

    Err(anyhow::anyhow!(
        "handshake failed after {} attempts: {}",
        attempts,
        last_error
    ))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    tracing::info!("omega-client v{} starting", env!("CARGO_PKG_VERSION"));

    let client_config = ClientConfig::from_env();
    let server_addr: SocketAddr = std::env::var("OMEGA_SERVER")
        .unwrap_or_else(|_| DEFAULT_SERVER.to_string())
        .parse()?;

    let device_id = parse_uuid(
        &std::env::var("OMEGA_DEVICE_ID")
            .context("OMEGA_DEVICE_ID is required (UUID from admin register_device)")?,
    )?;
    let device_token = parse_token(
        &std::env::var("OMEGA_DEVICE_TOKEN")
            .context("OMEGA_DEVICE_TOKEN is required (token from admin register_device)")?,
    )?;
    let device_name =
        std::env::var("OMEGA_DEVICE_NAME").unwrap_or_else(|_| "omega-client".to_string());
    let platform = std::env::var("OMEGA_PLATFORM")
        .ok()
        .and_then(|value| {
            DevicePlatform::from_u8(match value.to_ascii_lowercase().as_str() {
                "windows" => 1,
                "linux" => 2,
                "macos" => 3,
                "android" => 4,
                "ios" => 5,
                _ => 255,
            })
        })
        .unwrap_or_else(detect_platform);
    let platform_label = match platform {
        DevicePlatform::Windows => "windows",
        DevicePlatform::Linux => "linux",
        DevicePlatform::Macos => "macos",
        DevicePlatform::Android => "android",
        DevicePlatform::Ios => "ios",
        DevicePlatform::Other => "other",
    };

    let diagnostics = ClientDiagnostics::new(
        client_config.diagnostics_path.clone(),
        &client_config,
        server_addr,
        &device_name,
        platform_label,
    );
    diagnostics.spawn_writer();

    use socket2::{Domain, Protocol, Socket, Type};

    let socket_domain = if server_addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(socket_domain, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_nonblocking(true)?;
    let _ = socket.set_recv_buffer_size(client_config.udp_rcvbuf);
    let _ = socket.set_send_buffer_size(client_config.udp_sndbuf);
    if server_addr.is_ipv6() {
        let _ = socket.set_only_v6(false);
    }

    let addr: SocketAddr = if server_addr.is_ipv4() {
        "0.0.0.0:0".parse()?
    } else {
        "[::]:0".parse()?
    };
    socket.bind(&addr.into())?;

    let std_socket: std::net::UdpSocket = socket.into();
    let udp = Arc::new(UdpSocket::from_std(std_socket)?);
    tracing::info!(local_addr = %udp.local_addr()?, "UDP socket bound");
    network::cleanup_stale(server_addr, &client_config);

    let mut rng = rand::thread_rng();
    let (dk, ek) = MlKem768::generate(&mut rng);

    let client_hello = ClientHello {
        version: HANDSHAKE_VERSION,
        client_mtu: client_config.requested_mtu,
        fec_support: true,
        supports_tunnel_ipv6: client_config.should_tunnel_ipv6(),
        encaps_key: ek.as_bytes().to_vec(),
        auth: Some(ClientAuth {
            device_id,
            device_token,
            platform,
            device_name: device_name.clone(),
        }),
    };

    let keepalive_secs = client_config.keepalive_secs;
    let handshake = match perform_handshake(&udp, server_addr, &client_hello, &client_config).await
    {
        Ok(handshake) => handshake,
        Err(err) => {
            diagnostics.set_status("handshake_failed");
            let _ = diagnostics.write_now();
            return Err(err);
        }
    };
    let server_hello = handshake.hello;

    let ct_array: &ml_kem::Ciphertext<MlKem768> = server_hello
        .ciphertext
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid ciphertext length"))?;
    let shared_secret = dk
        .decapsulate(ct_array)
        .map_err(|_| anyhow::anyhow!("decapsulation failed"))?;

    let ss_bytes: &[u8] = shared_secret.as_ref();
    let flow_id_bytes = derive_flow_id(ss_bytes)?;
    let flow_id = FlowId(flow_id_bytes);
    let chaos_seed = u64::from_le_bytes(ss_bytes[0..8].try_into().unwrap());
    let ssrc = u32::from_be_bytes(flow_id_bytes[0..4].try_into().unwrap());
    let mut keys_send = SessionKeys::from_shared_secret(ss_bytes, false)
        .map_err(|err| anyhow::anyhow!("key derivation failed: {err}"))?;

    let tun_ip = server_hello.tunnel_ip;
    let tun_ipv6 = server_hello.tunnel_ipv6;
    let effective_mtu = match client_config.mtu_policy {
        MtuPolicy::Fixed => {
            diagnostics.mtu_probe_fixed(server_hello.server_mtu);
            server_hello.server_mtu
        }
        MtuPolicy::Auto => match run_path_mtu_probe(
            &udp,
            server_addr,
            flow_id,
            ss_bytes,
            &mut keys_send,
            ssrc,
            server_hello.server_mtu,
            client_config.mtu_probe_timeout_ms,
        )
        .await
        {
            Ok((selected_mtu, candidates, probes_sent)) => {
                diagnostics.mtu_probe_selected(selected_mtu, candidates, probes_sent);
                tracing::info!(
                    selected_mtu,
                    probes_sent,
                    "path MTU probe selected tunnel MTU"
                );
                selected_mtu
            }
            Err(err) => {
                let fallback_mtu = server_hello.server_mtu.min(1280);
                let candidates = mtu_probe_candidates(server_hello.server_mtu);
                diagnostics.mtu_probe_failed(fallback_mtu, candidates, err.to_string());
                tracing::warn!(
                    error = %err,
                    fallback_mtu,
                    "path MTU probe failed; using conservative tunnel MTU"
                );
                fallback_mtu
            }
        },
    };
    let tun_ip_s = tun_ip.to_string();
    let mut tun_builder = tun_rs::DeviceBuilder::new()
        .ipv4(tun_ip_s.clone(), DEFAULT_TUN_PREFIX, None)
        .mtu(effective_mtu)
        .with(|builder| {
            #[cfg(target_os = "windows")]
            {
                let ring_capacity = client_config.udp_rcvbuf.clamp(0x2_0000, 0x400_0000) as u32;
                builder.ring_capacity(ring_capacity);
            }
        });
    if let Some(tun_ipv6_addr) = tun_ipv6 {
        tun_builder = tun_builder.ipv6(tun_ipv6_addr.to_string(), DEFAULT_TUN_PREFIX_V6);
    }
    let tun: Arc<tun_rs::AsyncDevice> = match tun_builder.build_async() {
        Ok(device) => Arc::new(device),
        Err(err) => {
            diagnostics.set_status("tun_failed");
            let _ = diagnostics.write_now();
            return Err(err.into());
        }
    };
    let interface_name = tun.name().ok();
    if let Some(interface_name) = interface_name.as_ref() {
        diagnostics.set_interface_name(interface_name.clone());
        tracing::info!(
            %interface_name,
            %tun_ip,
            tunnel_ipv6 = ?tun_ipv6,
            tun_mtu = effective_mtu,
            "handshake complete"
        );
    } else {
        tracing::info!(
            %tun_ip,
            tunnel_ipv6 = ?tun_ipv6,
            tun_mtu = effective_mtu,
            "handshake complete"
        );
    }
    diagnostics.set_handshake(tun_ip, tun_ipv6, effective_mtu, handshake.rtt_ms);
    diagnostics.update_path_metrics(
        0.0,
        DEFAULT_INITIAL_ARQ_RTT_MS,
        client_config.morphing_policy.padding_budget_cap(),
        0,
    );

    let network_state = match network::configure(
        server_addr,
        tun_ip,
        tun_ipv6,
        interface_name.as_deref(),
        effective_mtu,
        &client_config,
    ) {
        Ok(state) => state,
        Err(err) => {
            diagnostics.set_status("routing_failed");
            let _ = diagnostics.write_now();
            return Err(err);
        }
    };

    let diag_dns_servers = client_config.dns_servers.clone();
    let diag_enabled = client_config.network_diag;
    let diag_ipv6_required = client_config.should_tunnel_ipv6();
    let diag_dns_leak_guard_policy = client_config.dns_leak_guard_policy;
    let diag_handle = diagnostics.clone();
    tokio::spawn(async move {
        run_post_connect_health_checks(
            diag_dns_servers,
            diag_enabled,
            diag_ipv6_required,
            diag_dns_leak_guard_policy,
            diag_handle,
        )
        .await;
    });

    let mut initial_client_state =
        ClientState::new(ssrc, chaos_seed, client_config.morphing_policy);
    initial_client_state.send_seq = keys_send.send_nonce() as u32;
    let state = Arc::new(Mutex::new(initial_client_state));
    let ss_owned = ss_bytes.to_vec();

    let tun_r = tun.clone();
    let udp_r = udp.clone();
    let flow_id_copy = flow_id;
    let state_send = state.clone();
    let diagnostics_send = diagnostics.clone();

    let (nack_tx, mut nack_rx) = tokio::sync::mpsc::channel::<NackMessage>(100);

    let mut keepalive_interval = tokio::time::interval(Duration::from_secs(keepalive_secs));
    keepalive_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    tokio::spawn(async move {
        let mut keys_send = keys_send;

        let mut buf = vec![0u8; 1500];

        loop {
            tokio::select! {
                _ = keepalive_interval.tick() => {
                    let (seq, rtp_s, rtp_ts, ssrc) = {
                        let mut s = state_send.lock().unwrap();
                        let seq = s.send_seq;
                        s.send_seq = s.send_seq.wrapping_add(1);
                        s.rtp_seq = s.rtp_seq.wrapping_add(1);
                        (seq, s.rtp_seq, s.rtp_timestamp, s.ssrc)
                    };

                    let ka_omega = OmegaHeader {
                        flow_id: flow_id_copy,
                        seq,
                        packet_type: PacketType::KeepAlive,
                    };
                    let rtp = RtpHeader::opus(rtp_s, rtp_ts, ssrc);

                    let mut out = BytesMut::with_capacity(TOTAL_HEADER_LEN + AEAD_TAG_LEN);
                    out.resize(TOTAL_HEADER_LEN, 0);
                    rtp.write_to(&mut out[..RTP_HEADER_LEN]);
                    ka_omega.write_to(&mut out[RTP_HEADER_LEN..TOTAL_HEADER_LEN]);

                    let aad = &out[..TOTAL_HEADER_LEN];
                    let mut payload = Vec::new();
                    if keys_send.encrypt_in_place(&mut payload, &aad).is_ok() {
                        out.extend_from_slice(&payload);
                        let packet = out.freeze();
                        let now = current_ms();
                        {
                            let mut s = state_send.lock().unwrap();
                            s.retransmit_queue.cache_packet(seq, packet.clone(), now);
                            s.retransmit_queue.purge_expired(now);
                        }
                        let _ = udp_r.send_to(packet.as_ref(), server_addr).await;
                    }
                }
                Some(nack) = nack_rx.recv() => {
                    let (nack_seq, rtp_s, rtp_ts, ssrc) = {
                        let mut s = state_send.lock().unwrap();
                        let seq = s.send_seq;
                        s.send_seq = s.send_seq.wrapping_add(1);
                        s.rtp_seq = s.rtp_seq.wrapping_add(1);
                        (seq, s.rtp_seq, s.rtp_timestamp, s.ssrc)
                    };

                    let nack_omega = OmegaHeader {
                        flow_id: flow_id_copy,
                        seq: nack_seq,
                        packet_type: PacketType::Nack,
                    };
                    let rtp = RtpHeader::opus(rtp_s, rtp_ts, ssrc);

                    let mut out = BytesMut::with_capacity(TOTAL_HEADER_LEN + 12 + AEAD_TAG_LEN);
                    out.resize(TOTAL_HEADER_LEN + 12, 0);
                    rtp.write_to(&mut out[..RTP_HEADER_LEN]);
                    nack_omega.write_to(&mut out[RTP_HEADER_LEN..TOTAL_HEADER_LEN]);
                    nack.write_to(&mut out[TOTAL_HEADER_LEN..]);

                    let aad = &out[..TOTAL_HEADER_LEN];
                    let mut payload = out[TOTAL_HEADER_LEN..].to_vec();
                    if keys_send.encrypt_in_place(&mut payload, &aad).is_ok() {
                        out.truncate(TOTAL_HEADER_LEN);
                        out.extend_from_slice(&payload);
                        let packet = out.freeze();
                        let now = current_ms();
                        {
                            let mut s = state_send.lock().unwrap();
                            s.retransmit_queue.cache_packet(nack_seq, packet.clone(), now);
                            s.retransmit_queue.purge_expired(now);
                        }
                        diagnostics_send.record_nack_sent();
                        let _ = udp_r.send_to(packet.as_ref(), server_addr).await;
                    }
                }
                res = tun_r.recv(&mut buf) => {
                    let n = match res {
                        Ok(n) => n,
                        Err(e) => {
                            tracing::error!(error = %e, "TUN read failed");
                            continue;
                        }
                    };
                    diagnostics_send.note_tun_packet();

                    let is_small = n < 500;

                    let (seq, rtp_s, rtp_ts, ssrc, target_size, padding_budget, redundancy_extra) = {
                        let mut s = state_send.lock().unwrap();
                        let seq = s.send_seq;
                        s.send_seq = s.send_seq.wrapping_add(1);

                        s.rtp_seq = s.rtp_seq.wrapping_add(1);
                        s.rtp_timestamp = s.rtp_timestamp.wrapping_add(if is_small { 960 } else { 3000 });
                        let target_size = s.chaos.get_target_size() as usize;
                        let padding_budget = s.current_padding_budget();
                        let redundancy_extra = s.current_redundancy_extra();

                        (
                            seq,
                            s.rtp_seq,
                            s.rtp_timestamp,
                            s.ssrc,
                            target_size,
                            padding_budget,
                            redundancy_extra,
                        )
                    };

                    let rtp = if is_small {
                        RtpHeader::opus(rtp_s, rtp_ts, ssrc)
                    } else {
                        RtpHeader::vp8(rtp_s, rtp_ts, ssrc, true)
                    };

                    let omega = OmegaHeader {
                        flow_id: flow_id_copy,
                        seq,
                        packet_type: PacketType::Data,
                    };

                    let overhead = TOTAL_HEADER_LEN + AEAD_TAG_LEN;
                    let wire_size = n + overhead;
                    let desired_padding = target_size.saturating_sub(wire_size);
                    let padding_len = desired_padding.min(padding_budget);

                    let mut out = BytesMut::with_capacity(wire_size + padding_len);
                    out.resize(TOTAL_HEADER_LEN, 0);
                    rtp.write_to(&mut out[..RTP_HEADER_LEN]);
                    omega.write_to(&mut out[RTP_HEADER_LEN..TOTAL_HEADER_LEN]);

                    let aad = &out[..TOTAL_HEADER_LEN];
                    let mut payload = buf[..n].to_vec();
                    if padding_len > 0 {
                        payload.extend(std::iter::repeat(0).take(padding_len));
                    }

                    if let Err(e) = keys_send.encrypt_in_place(&mut payload, &aad) {
                        tracing::error!(error = %e, "encrypt failed");
                        continue;
                    }
                    out.extend_from_slice(&payload);
                    let packet = out.freeze();

                    {
                        let mut s = state_send.lock().unwrap();
                        let now = current_ms();
                        s.retransmit_queue.cache_packet(seq, packet.clone(), now);
                        s.retransmit_queue.purge_expired(now);
                    }

                    if let Err(e) = udp_r.send_to(packet.as_ref(), server_addr).await {
                        tracing::error!(error = %e, "UDP send failed");
                    } else {
                        for _ in 0..redundancy_extra {
                            tokio::time::sleep(Duration::from_micros(REDUNDANCY_PACING_US)).await;
                            if let Err(e) = udp_r.send_to(packet.as_ref(), server_addr).await {
                                tracing::trace!(error = %e, "UDP redundant send failed");
                                break;
                            }
                        }
                    }
                }
            }
        }
    });

    let tun_w = tun.clone();
    let udp_w = udp.clone();
    let ss_for_recv = ss_owned.clone();
    let state_recv = state.clone();
    let diagnostics_recv = diagnostics.clone();

    tokio::spawn(async move {
        let mut keys_recv = match SessionKeys::from_shared_secret(&ss_for_recv, false) {
            Ok(k) => k,
            Err(e) => {
                tracing::error!(error = %e, "key derivation failed");
                return;
            }
        };

        let mut replay_filter = ReplayFilter::new();
        let mut buf = vec![0u8; 2048];

        loop {
            let (n, _src) = match udp_w.recv_from(&mut buf).await {
                Ok(r) => r,
                Err(e) => {
                    tracing::error!(error = %e, "UDP recv failed");
                    continue;
                }
            };
            diagnostics_recv.note_server_packet();

            if n < TOTAL_HEADER_LEN + AEAD_TAG_LEN {
                continue;
            }

            let omega = match OmegaHeader::read_from(&buf[RTP_HEADER_LEN..TOTAL_HEADER_LEN]) {
                Some(h) => h,
                None => continue,
            };

            match omega.packet_type {
                PacketType::Data | PacketType::Nack | PacketType::KeepAlive | PacketType::Close => {
                    if !replay_filter.check(omega.seq as u64) {
                        continue;
                    }

                    let (aad, ciphertext) = buf[..n].split_at_mut(TOTAL_HEADER_LEN);

                    match keys_recv.decrypt_in_place(ciphertext, omega.seq as u64, aad) {
                        Ok(plaintext) => {
                            replay_filter.update(omega.seq as u64);

                            let (
                                inbound_nack,
                                loss_ratio,
                                arq_rtt_ms,
                                padding_budget,
                                redundancy_extra,
                            ) = {
                                let mut s = state_recv.lock().unwrap();
                                let inbound_nack = s.observe_inbound_seq(omega.seq);
                                (
                                    inbound_nack,
                                    s.loss_ratio(),
                                    s.retransmit_queue.rtt_ms(),
                                    s.padding_budget,
                                    s.redundancy_extra as usize,
                                )
                            };
                            diagnostics_recv.update_path_metrics(
                                loss_ratio,
                                arq_rtt_ms,
                                padding_budget,
                                redundancy_extra,
                            );
                            if !matches!(omega.packet_type, PacketType::Close) {
                                if let Some(nack) = inbound_nack {
                                    let _ = nack_tx.send(nack).await;
                                }
                            }

                            match omega.packet_type {
                                PacketType::Data => {
                                    let final_len =
                                        if let Some(ip_len) = get_ip_packet_len(plaintext) {
                                            plaintext.len().min(ip_len)
                                        } else {
                                            plaintext.len()
                                        };

                                    if let Err(e) = tun_w.send(&plaintext[..final_len]).await {
                                        tracing::error!(error = %e, "TUN write failed");
                                    }
                                }
                                PacketType::Nack => {
                                    if let Some(nack) = NackMessage::read_from(plaintext) {
                                        diagnostics_recv.record_nack_received();
                                        let (
                                            packets,
                                            loss_ratio,
                                            arq_rtt_ms,
                                            padding_budget,
                                            redundancy_extra,
                                        ) = {
                                            let mut s = state_recv.lock().unwrap();
                                            s.on_remote_nack(&nack);
                                            s.retransmit_queue.observe_nack(&nack, current_ms());
                                            let packets: Vec<Bytes> = s
                                                .retransmit_queue
                                                .process_nack(&nack)
                                                .into_iter()
                                                .take(MAX_RETRANSMIT_BURST)
                                                .map(|p| p.data.clone())
                                                .collect::<Vec<_>>();
                                            (
                                                packets,
                                                s.loss_ratio(),
                                                s.retransmit_queue.rtt_ms(),
                                                s.padding_budget,
                                                s.redundancy_extra as usize,
                                            )
                                        };
                                        diagnostics_recv.update_path_metrics(
                                            loss_ratio,
                                            arq_rtt_ms,
                                            padding_budget,
                                            redundancy_extra,
                                        );

                                        let packets_len = packets.len();
                                        diagnostics_recv.record_retransmits(packets_len);
                                        for (idx, pkt) in packets.into_iter().enumerate() {
                                            let _ = udp_w.send_to(pkt.as_ref(), server_addr).await;
                                            if idx + 1 < packets_len {
                                                tokio::time::sleep(Duration::from_micros(
                                                    RETRANSMIT_PACING_US,
                                                ))
                                                .await;
                                            }
                                        }
                                    }
                                }
                                PacketType::Close => {
                                    diagnostics_recv.set_status("server_closed");
                                    tracing::warn!("session closed by server");
                                }
                                PacketType::KeepAlive => {}
                                _ => {}
                            }
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, seq = omega.seq, "auth failed");
                        }
                    }
                }
                _ => {}
            }
        }
    });

    tracing::info!("data path running, press Ctrl+C to stop");
    tokio::signal::ctrl_c().await?;
    diagnostics.set_status("stopping");
    tracing::info!("shutting down");

    network::cleanup(server_addr, network_state.as_ref());

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observed_control_seq_does_not_create_false_gap() {
        let mut state = ClientState::new(0xDEADBEEF, 7, MorphingPolicy::Balanced);

        assert!(state.observe_inbound_seq(100).is_none());
        assert!(state.observe_inbound_seq(101).is_none()); // keepalive/nack seq
        assert!(state.observe_inbound_seq(102).is_none());
        assert_eq!(state.loss_ratio(), 0.0);
    }

    #[test]
    fn missing_seq_is_still_reported_after_control_packet() {
        let mut state = ClientState::new(0xDEADBEEF, 7, MorphingPolicy::Balanced);

        assert!(state.observe_inbound_seq(10).is_none());
        assert!(state.observe_inbound_seq(11).is_none()); // observed control seq
        assert!(state.observe_inbound_seq(13).is_none());
        let mut emitted_nack = false;
        for seq in 14..30 {
            if state.observe_inbound_seq(seq).is_some() {
                emitted_nack = true;
                break;
            }
        }
        assert!(emitted_nack, "gap should eventually trigger a nack");
        assert!(state.loss_ratio() > 0.0);
    }

    #[test]
    fn mtu_probe_candidates_are_descending_unique_and_safe() {
        let candidates = mtu_probe_candidates(1380);

        assert_eq!(candidates, vec![1380, 1360, 1320, 1280, 1200]);
    }
}
