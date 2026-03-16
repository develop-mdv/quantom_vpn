use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use anyhow::Context;
use bytes::BytesMut;
use kem::Decapsulate;
use ml_kem::{EncodedSizeUser, KemCore, MlKem768};
use omega_core::arq::{GapDetector, RetransmitQueue};
use omega_core::chaos::ChaosPrng;
use omega_core::crypto::{derive_flow_id, SessionKeys};
use omega_core::protocol::*;
use omega_core::replay::ReplayFilter;
use tokio::net::UdpSocket;
use tracing_subscriber::EnvFilter;

const DEFAULT_SERVER: &str = "127.0.0.1:51820";
const DEFAULT_TUN_PREFIX: u8 = 16;
const DEFAULT_MTU: u16 = 1200;
const DEFAULT_KEEPALIVE_SECS: u64 = 15;
const DEFAULT_HANDSHAKE_ATTEMPTS: u32 = 5;
const DEFAULT_HANDSHAKE_TIMEOUT_MS: u64 = 1500;
const DEFAULT_HANDSHAKE_BACKOFF_MS: u64 = 500;
const DEFAULT_INITIAL_ARQ_RTT_MS: u64 = 350;
const MAX_RETRANSMIT_BURST: usize = 24;
const RETRANSMIT_PACING_US: u64 = 500;
const PADDING_BUDGET_MIN: usize = 0;
const PADDING_BUDGET_MAX: usize = 256;
const PADDING_RECOVERY_STEP: usize = 24;
const PADDING_RECOVERY_INTERVAL_SECS: u64 = 2;
const REDUNDANCY_EXTRA_MAX: u8 = 2;
const REDUNDANCY_DECAY_SECS: u64 = 8;
const REDUNDANCY_PACING_US: u64 = 200;

struct ClientState {
    retransmit_queue: RetransmitQueue,
    gap_detector: GapDetector,
    send_seq: u32,
    rtp_seq: u16,
    rtp_timestamp: u32,
    ssrc: u32,
    chaos: ChaosPrng,
    padding_budget: usize,
    last_padding_adjust: Instant,
    redundancy_extra: u8,
    last_redundancy_adjust: Instant,
}

impl ClientState {
    fn new(ssrc: u32, chaos_seed: u64) -> Self {
        Self {
            retransmit_queue: RetransmitQueue::with_initial_rtt(DEFAULT_INITIAL_ARQ_RTT_MS),
            gap_detector: GapDetector::new(),
            send_seq: 0,
            rtp_seq: 0,
            rtp_timestamp: 0,
            ssrc,
            chaos: ChaosPrng::new(chaos_seed),
            padding_budget: PADDING_BUDGET_MAX,
            last_padding_adjust: Instant::now(),
            redundancy_extra: 0,
            last_redundancy_adjust: Instant::now(),
        }
    }

    fn current_padding_budget(&mut self) -> usize {
        let elapsed = self.last_padding_adjust.elapsed().as_secs();
        let ticks = elapsed / PADDING_RECOVERY_INTERVAL_SECS;
        if ticks > 0 {
            let growth = (ticks as usize).saturating_mul(PADDING_RECOVERY_STEP);
            self.padding_budget = self
                .padding_budget
                .saturating_add(growth)
                .min(PADDING_BUDGET_MAX);
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
        let elapsed = self.last_redundancy_adjust.elapsed().as_secs();
        let ticks = elapsed / REDUNDANCY_DECAY_SECS;
        if ticks > 0 {
            self.redundancy_extra = self.redundancy_extra.saturating_sub(ticks as u8);
            self.last_redundancy_adjust = Instant::now();
        }
        self.redundancy_extra as usize
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

#[cfg(target_os = "windows")]
fn configure_windows_routing(server_ip: std::net::Ipv4Addr, tunnel_ip: std::net::Ipv4Addr) {
    use std::process::Command;
    use std::time::Duration;

    tracing::info!(%tunnel_ip, "configuring Windows routing tables");

    let tunnel_ip_s = tunnel_ip.to_string();
    let mut if_index = String::new();
    let mut if_alias = String::new();

    for _ in 0..15 {
        let output_idx = Command::new("powershell")
            .args([
                "-Command",
                &format!(
                    "Get-NetIPAddress -IPAddress '{}' | Select-Object -ExpandProperty InterfaceIndex",
                    tunnel_ip_s
                ),
            ])
            .output();

        let output_alias = Command::new("powershell")
            .args([
                "-Command",
                &format!(
                    "Get-NetIPAddress -IPAddress '{}' | Select-Object -ExpandProperty InterfaceAlias",
                    tunnel_ip_s
                ),
            ])
            .output();

        if let (Ok(o_idx), Ok(o_alias)) = (output_idx, output_alias) {
            let idx_str = String::from_utf8_lossy(&o_idx.stdout).trim().to_string();
            let alias_str = String::from_utf8_lossy(&o_alias.stdout).trim().to_string();

            if !idx_str.is_empty() && !alias_str.is_empty() {
                if_index = idx_str;
                if_alias = alias_str;
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(500));
    }

    if if_index.is_empty() || if_alias.is_empty() {
        tracing::error!("could not find Wintun interface");
        return;
    }

    let _ = Command::new("netsh")
        .args([
            "interface",
            "ipv4",
            "set",
            "subinterface",
            &if_alias,
            &format!("mtu={}", DEFAULT_MTU),
            "store=active",
        ])
        .status();

    let dns_servers = windows_dns_servers();
    if !dns_servers.is_empty() {
        let dns_ps = dns_servers
            .iter()
            .map(|v| format!("'{}'", v))
            .collect::<Vec<_>>()
            .join(",");
        let alias_ps = powershell_quote(&if_alias);
        let set_dns_cmd = format!(
            "Set-DnsClientServerAddress -InterfaceAlias '{}' -ServerAddresses @({})",
            alias_ps, dns_ps
        );
        let _ = Command::new("powershell")
            .args(["-Command", &set_dns_cmd])
            .status();
        tracing::info!(
            interface = %if_alias,
            dns = %dns_servers.join(","),
            "configured DNS on Wintun interface"
        );
    }

    let ps_cmd = format!(
        "(Get-NetRoute -DestinationPrefix 0.0.0.0/0 | Where-Object {{ $_.InterfaceIndex -ne {} }} | Sort-Object RouteMetric | Select-Object -First 1).NextHop",
        if_index
    );

    if let Ok(output) = Command::new("powershell")
        .args(["-Command", &ps_cmd])
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if let Some(gateway) = stdout
            .lines()
            .next()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
        {
            let _ = Command::new("route")
                .args([
                    "add",
                    &server_ip.to_string(),
                    "mask",
                    "255.255.255.255",
                    gateway,
                    "metric",
                    "1",
                ])
                .status();
        }
    }

    let _ = Command::new("route")
        .args([
            "add",
            "0.0.0.0",
            "mask",
            "128.0.0.0",
            "0.0.0.0",
            "IF",
            &if_index,
            "metric",
            "1",
        ])
        .status();

    let _ = Command::new("route")
        .args([
            "add",
            "128.0.0.0",
            "mask",
            "128.0.0.0",
            "0.0.0.0",
            "IF",
            &if_index,
            "metric",
            "1",
        ])
        .status();
}

#[cfg(target_os = "windows")]
fn cleanup_windows_routing(server_ip: std::net::Ipv4Addr, tunnel_ip: std::net::Ipv4Addr) {
    use std::process::Command;

    let tunnel_ip_s = tunnel_ip.to_string();
    let alias_cmd = format!(
        "Get-NetIPAddress -IPAddress '{}' | Select-Object -ExpandProperty InterfaceAlias",
        tunnel_ip_s
    );
    if let Ok(output) = Command::new("powershell")
        .args(["-Command", &alias_cmd])
        .output()
    {
        let alias = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !alias.is_empty() {
            let reset_dns = format!(
                "Set-DnsClientServerAddress -InterfaceAlias '{}' -ResetServerAddresses",
                powershell_quote(&alias)
            );
            let _ = Command::new("powershell")
                .args(["-Command", &reset_dns])
                .status();
        }
    }

    let _ = Command::new("route")
        .args(["delete", &server_ip.to_string()])
        .status();
    let _ = Command::new("route")
        .args(["delete", "0.0.0.0", "mask", "128.0.0.0"])
        .status();
    let _ = Command::new("route")
        .args(["delete", "128.0.0.0", "mask", "128.0.0.0"])
        .status();
}

#[cfg(not(target_os = "windows"))]
fn configure_windows_routing(_: std::net::Ipv4Addr, _: std::net::Ipv4Addr) {}
#[cfg(not(target_os = "windows"))]
fn cleanup_windows_routing(_: std::net::Ipv4Addr, _: std::net::Ipv4Addr) {}

#[cfg(target_os = "windows")]
fn windows_dns_servers() -> Vec<String> {
    let configured =
        std::env::var("OMEGA_DNS_SERVERS").unwrap_or_else(|_| "1.1.1.1,8.8.8.8".to_string());
    let mut servers = Vec::new();

    for item in configured
        .split(',')
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
    {
        if item.parse::<std::net::Ipv4Addr>().is_ok() {
            servers.push(item.to_string());
        } else {
            tracing::warn!(value = %item, "ignoring invalid OMEGA_DNS_SERVERS entry");
        }
    }

    if servers.is_empty() {
        vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()]
    } else {
        servers
    }
}

#[cfg(target_os = "windows")]
fn powershell_quote(value: &str) -> String {
    value.replace('\'', "''")
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

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(default)
}

fn env_u32(name: &str, default: u32) -> u32 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(default)
}

async fn perform_handshake(
    udp: &UdpSocket,
    server_addr: SocketAddr,
    client_hello: &ClientHello,
) -> anyhow::Result<ServerHello> {
    let attempts = env_u32("OMEGA_HANDSHAKE_ATTEMPTS", DEFAULT_HANDSHAKE_ATTEMPTS).max(1);
    let timeout_ms = env_u64("OMEGA_HANDSHAKE_TIMEOUT_MS", DEFAULT_HANDSHAKE_TIMEOUT_MS).max(250);
    let backoff_ms = env_u64("OMEGA_HANDSHAKE_BACKOFF_MS", DEFAULT_HANDSHAKE_BACKOFF_MS).max(100);

    let txn_id: [u8; 12] = rand::random();
    let request = StunWrapper::wrap_request(&txn_id, &client_hello.serialize());
    let mut buf = vec![0u8; 4096];
    let mut last_error = String::from("timeout");

    for attempt in 1..=attempts {
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
                        return Ok(hello);
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

    use socket2::{Domain, Protocol, Socket, Type};

    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_nonblocking(true)?;
    let _ = socket.set_recv_buffer_size(1024 * 1024);
    let _ = socket.set_send_buffer_size(1024 * 1024);

    let addr: SocketAddr = "0.0.0.0:0".parse()?;
    socket.bind(&addr.into())?;

    let std_socket: std::net::UdpSocket = socket.into();
    let udp = Arc::new(UdpSocket::from_std(std_socket)?);
    tracing::info!(local_addr = %udp.local_addr()?, "UDP socket bound");

    let mut rng = rand::thread_rng();
    let (dk, ek) = MlKem768::generate(&mut rng);

    let client_hello = ClientHello {
        version: HANDSHAKE_VERSION,
        client_mtu: DEFAULT_MTU,
        fec_support: true,
        encaps_key: ek.as_bytes().to_vec(),
        auth: Some(ClientAuth {
            device_id,
            device_token,
            platform,
            device_name: device_name.clone(),
        }),
    };

    let keepalive_secs = env_u64("OMEGA_KEEPALIVE_SECS", DEFAULT_KEEPALIVE_SECS).max(5);
    let server_hello = perform_handshake(&udp, server_addr, &client_hello).await?;

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

    let tun_ip = server_hello.tunnel_ip;
    let tun_ip_s = tun_ip.to_string();
    let tun: Arc<tun_rs::AsyncDevice> = Arc::new(
        tun_rs::DeviceBuilder::new()
            .ipv4(tun_ip_s.clone(), DEFAULT_TUN_PREFIX, None)
            .build_async()?,
    );
    tracing::info!(%tun_ip, server_mtu = server_hello.server_mtu, "handshake complete");

    #[cfg(target_os = "windows")]
    {
        if let std::net::SocketAddr::V4(v4) = server_addr {
            configure_windows_routing(*v4.ip(), tun_ip);
        }
    }

    let state = Arc::new(Mutex::new(ClientState::new(ssrc, chaos_seed)));
    let ss_owned = ss_bytes.to_vec();

    let tun_r = tun.clone();
    let udp_r = udp.clone();
    let flow_id_copy = flow_id;
    let ss_for_send = ss_owned.clone();
    let state_send = state.clone();

    let (nack_tx, mut nack_rx) = tokio::sync::mpsc::channel::<NackMessage>(100);

    let mut keepalive_interval = tokio::time::interval(Duration::from_secs(keepalive_secs));
    keepalive_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    tokio::spawn(async move {
        let mut keys_send = match SessionKeys::from_shared_secret(&ss_for_send, false) {
            Ok(k) => k,
            Err(e) => {
                tracing::error!(error = %e, "key derivation failed");
                return;
            }
        };

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

                    let aad = out[..TOTAL_HEADER_LEN].to_vec();
                    let mut payload = Vec::new();
                    if keys_send.encrypt_in_place(&mut payload, &aad).is_ok() {
                        out.extend_from_slice(&payload);
                        let _ = udp_r.send_to(&out, server_addr).await;
                    }
                }
                Some(nack) = nack_rx.recv() => {
                    let (nack_seq, rtp_s, rtp_ts, ssrc) = {
                        let mut s = state_send.lock().unwrap();
                        s.on_remote_nack(&nack);
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

                    let aad = out[..TOTAL_HEADER_LEN].to_vec();
                    let mut payload = out[TOTAL_HEADER_LEN..].to_vec();
                    if keys_send.encrypt_in_place(&mut payload, &aad).is_ok() {
                        out.truncate(TOTAL_HEADER_LEN);
                        out.extend_from_slice(&payload);
                        let _ = udp_r.send_to(&out, server_addr).await;
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

                    let aad = out[..TOTAL_HEADER_LEN].to_vec();
                    let mut payload = buf[..n].to_vec();
                    if padding_len > 0 {
                        payload.extend(std::iter::repeat(0).take(padding_len));
                    }

                    if let Err(e) = keys_send.encrypt_in_place(&mut payload, &aad) {
                        tracing::error!(error = %e, "encrypt failed");
                        continue;
                    }
                    out.extend_from_slice(&payload);

                    {
                        let mut s = state_send.lock().unwrap();
                        let now = current_ms();
                        s.retransmit_queue.cache_packet(seq, out.to_vec(), now);
                        s.retransmit_queue.purge_expired(now);
                    }

                    if let Err(e) = udp_r.send_to(&out, server_addr).await {
                        tracing::error!(error = %e, "UDP send failed");
                    } else {
                        for _ in 0..redundancy_extra {
                            tokio::time::sleep(Duration::from_micros(REDUNDANCY_PACING_US)).await;
                            if let Err(e) = udp_r.send_to(&out, server_addr).await {
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

                    let aad = buf[..TOTAL_HEADER_LEN].to_vec();
                    let mut ciphertext = buf[TOTAL_HEADER_LEN..n].to_vec();

                    match keys_recv.decrypt_in_place(&mut ciphertext, omega.seq as u64, &aad) {
                        Ok(plaintext) => {
                            replay_filter.update(omega.seq as u64);

                            match omega.packet_type {
                                PacketType::Data => {
                                    let nack_opt = {
                                        let mut s = state_recv.lock().unwrap();
                                        s.gap_detector.record_received(omega.seq)
                                    };
                                    if let Some(nack) = nack_opt {
                                        let _ = nack_tx.send(nack).await;
                                    }

                                    let final_len =
                                        if let Some(ip_len) = get_ip_packet_len(plaintext) {
                                            plaintext.len().min(ip_len)
                                        } else {
                                            plaintext.len()
                                        };

                                    let plain_owned = plaintext[..final_len].to_vec();
                                    if let Err(e) = tun_w.send(&plain_owned).await {
                                        tracing::error!(error = %e, "TUN write failed");
                                    }
                                }
                                PacketType::Nack => {
                                    if let Some(nack) = NackMessage::read_from(plaintext) {
                                        let packets = {
                                            let mut s = state_recv.lock().unwrap();
                                            s.on_remote_nack(&nack);
                                            s.retransmit_queue.observe_nack(&nack, current_ms());
                                            s.retransmit_queue
                                                .process_nack(&nack)
                                                .into_iter()
                                                .take(MAX_RETRANSMIT_BURST)
                                                .map(|p| p.data.clone())
                                                .collect::<Vec<_>>()
                                        };

                                        let packets_len = packets.len();
                                        for (idx, pkt) in packets.into_iter().enumerate() {
                                            let _ = udp_w.send_to(&pkt, server_addr).await;
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
    tracing::info!("shutting down");

    #[cfg(target_os = "windows")]
    {
        if let std::net::SocketAddr::V4(v4) = server_addr {
            cleanup_windows_routing(*v4.ip(), tun_ip);
        }
    }

    Ok(())
}
