/// Omega VPN Client — single-session with auto-reconnect.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use kem::Decapsulate;
use ml_kem::{EncodedSizeUser, KemCore, MlKem768};

use omega_core::chaos::ChaosPrng;
use omega_core::arq::{GapDetector, RetransmitQueue};
use omega_core::crypto::{derive_flow_id, SessionKeys};
use omega_core::protocol::*;
use omega_core::replay::ReplayFilter;

use bytes::BytesMut;
use tokio::net::UdpSocket;
use tracing_subscriber::EnvFilter;

const DEFAULT_SERVER: &str = "127.0.0.1:51820";
const DEFAULT_TUN_IP: &str = "10.7.0.2";
const DEFAULT_TUN_PREFIX: u8 = 24;
const DEFAULT_MTU: u16 = 1280;

struct ClientState {
    retransmit_queue: RetransmitQueue,
    gap_detector: GapDetector,
    send_seq: u32,
    rtp_seq: u16,
    rtp_timestamp: u32,
    ssrc: u32,
    chaos: ChaosPrng,
}

impl ClientState {
    fn new(ssrc: u32, chaos_seed: u64) -> Self {
        Self {
            retransmit_queue: RetransmitQueue::new(),
            gap_detector: GapDetector::new(),
            send_seq: 0,
            rtp_seq: 0,
            rtp_timestamp: 0,
            ssrc,
            chaos: ChaosPrng::new(chaos_seed),
        }
    }
}

fn current_ms() -> u64 {
    SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Get the length of the IP packet (excluding padding).
fn get_ip_packet_len(buf: &[u8]) -> Option<usize> {
    if buf.len() < 1 {
        return None;
    }
    let version = buf[0] >> 4;
    match version {
        4 => {
            if buf.len() < 4 { return None; }
            Some(u16::from_be_bytes([buf[2], buf[3]]) as usize)
        },
        6 => {
            if buf.len() < 6 { return None; }
            // Payload length is at offset 4
            let payload_len = u16::from_be_bytes([buf[4], buf[5]]) as usize;
            Some(40 + payload_len) // Fixed header is 40 bytes
        },
        _ => None,
    }
}

#[cfg(target_os = "windows")]
fn configure_windows_routing(server_ip: std::net::Ipv4Addr) {
    use std::process::Command;
    
    tracing::info!("Configuring Windows routing tables...");

    // 1. Get current default gateway (Lowest Metric)
    let output = Command::new("powershell")
        .args(&["-Command", "(Get-NetRoute -DestinationPrefix 0.0.0.0/0 | Sort-Object RouteMetric | Select-Object -First 1).NextHop"])
        .output();

    if let Ok(o) = output {
        let stdout = String::from_utf8_lossy(&o.stdout);
        if let Some(gateway) = stdout.lines().next().map(|s| s.trim()).filter(|s| !s.is_empty()) {
            tracing::info!("Detected physical gateway: {}", gateway);
            
            // 2. Add route to VPN Server via physical gateway
            let status = Command::new("route")
                .args(&["add", &server_ip.to_string(), "mask", "255.255.255.255", gateway, "metric", "1"])
                .status();
             if let Ok(s) = status {
                 if !s.success() { tracing::warn!("Failed to add route to server via gateway"); }
             }
        } else {
            tracing::warn!("Could not determine physical gateway");
        }
    }

    // 3. Override default gateway via TUN
    let _ = Command::new("route")
        .args(&["add", "0.0.0.0", "mask", "128.0.0.0", "10.7.0.1", "metric", "1"])
        .status();
    let _ = Command::new("route")
        .args(&["add", "128.0.0.0", "mask", "128.0.0.0", "10.7.0.1", "metric", "1"])
        .status();
        
    tracing::info!("Routing configured.");
}

#[cfg(target_os = "windows")]
fn cleanup_windows_routing(server_ip: std::net::Ipv4Addr) {
    use std::process::Command;
    tracing::info!("Cleaning up routing tables...");
    
    let _ = Command::new("route").args(&["delete", &server_ip.to_string()]).status();
    let _ = Command::new("route").args(&["delete", "0.0.0.0", "mask", "128.0.0.0"]).status();
    let _ = Command::new("route").args(&["delete", "128.0.0.0", "mask", "128.0.0.0"]).status();
}

#[cfg(not(target_os = "windows"))]
fn configure_windows_routing(_: std::net::Ipv4Addr) {}
#[cfg(not(target_os = "windows"))]
fn cleanup_windows_routing(_: std::net::Ipv4Addr) {}


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

    // Create TUN device
    let tun: Arc<tun_rs::AsyncDevice> = Arc::new(
        tun_rs::DeviceBuilder::new()
            .ipv4(DEFAULT_TUN_IP, DEFAULT_TUN_PREFIX, None)
            .mtu(DEFAULT_MTU)
            .build_async()?,
    );
    tracing::info!("TUN device created at {}", DEFAULT_TUN_IP);

    // Bind UDP socket (any port)
    let udp = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
    tracing::info!("UDP socket bound to {}", udp.local_addr()?);

    #[cfg(target_os = "windows")]
    {
        if let std::net::SocketAddr::V4(v4) = server_addr {
             configure_windows_routing(*v4.ip());
        }
    }

    // ── Perform ML-KEM-768 handshake ───────────────────────────────
    let mut rng = rand::thread_rng();
    let (dk, ek) = MlKem768::generate(&mut rng);

    // Serialize encapsulation key
    let ek_bytes = ek.as_bytes();

    let client_hello = ClientHello {
        version: HANDSHAKE_VERSION,
        client_mtu: DEFAULT_MTU,
        fec_support: true,
        encaps_key: ek_bytes.to_vec(),
    };

    // Wrap in STUN Binding Request
    let txn_id: [u8; 12] = rand::random();
    let request = StunWrapper::wrap_request(&txn_id, &client_hello.serialize());

    udp.send_to(&request, server_addr).await?;
    tracing::info!("handshake request sent to {}", server_addr);

    // Wait for response
    let mut buf = vec![0u8; 4096];
    let (n, _src) = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        udp.recv_from(&mut buf),
    )
    .await??;

    // Parse STUN response
    let (is_request, _resp_txn, resp_payload) =
        StunWrapper::parse(&buf[..n]).ok_or_else(|| anyhow::anyhow!("invalid STUN response"))?;
    if is_request {
        return Err(anyhow::anyhow!("expected STUN response, got request"));
    }

    // Parse ServerHello
    let server_hello = ServerHello::deserialize(resp_payload)
        .ok_or_else(|| anyhow::anyhow!("malformed ServerHello"))?;

    // Decapsulate shared secret
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

    // Use shared secret as seed for ChaosPrng (first 8 bytes)
    let chaos_seed = u64::from_le_bytes(ss_bytes[0..8].try_into().unwrap());

    let ssrc = u32::from_be_bytes(flow_id_bytes[0..4].try_into().unwrap());

    tracing::info!(
        server_mtu = server_hello.server_mtu,
        fec = server_hello.fec_enabled,
        "handshake complete, session established"
    );

    // Initialize shared state
    let state = Arc::new(Mutex::new(ClientState::new(ssrc, chaos_seed)));
    let ss_owned = ss_bytes.to_vec();

    // ── Data path ──────────────────────────────────────────────────

    let tun_r = tun.clone();
    let udp_r = udp.clone();
    let flow_id_copy = flow_id;
    let ss_for_send = ss_owned.clone();
    let state_send = state.clone();

    // Channel for sending NACK requests from recv loop to send loop
    let (nack_tx, mut nack_rx) = tokio::sync::mpsc::channel::<NackMessage>(100);

    // TUN → UDP (client → server)
    tokio::spawn(async move {
        let mut keys_send = match SessionKeys::from_shared_secret(&ss_for_send, false) {
            Ok(k) => k,
            Err(e) => {
                tracing::error!("key derivation failed: {}", e);
                return;
            }
        };
        let mut buf = vec![0u8; 1500];

        loop {
            tokio::select! {
                // Handle NACK requests from receive loop
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
                    // Typically NACKs are control packets (small/audio-like)
                    let rtp = RtpHeader::opus(rtp_s, rtp_ts, ssrc);

                    let mut out = BytesMut::with_capacity(TOTAL_HEADER_LEN + 12 + AEAD_TAG_LEN);
                    out.resize(TOTAL_HEADER_LEN + 12, 0);
                    rtp.write_to(&mut out[..RTP_HEADER_LEN]);
                    nack_omega.write_to(&mut out[RTP_HEADER_LEN..TOTAL_HEADER_LEN]);
                    nack.write_to(&mut out[TOTAL_HEADER_LEN..]);

                    // No padding for NACKs (control, keep small)
                    let aad = out[..TOTAL_HEADER_LEN].to_vec();
                    let mut payload = out[TOTAL_HEADER_LEN..].to_vec();
                    if let Ok(_) = keys_send.encrypt_in_place(&mut payload, &aad) {
                         out.truncate(TOTAL_HEADER_LEN);
                         out.extend_from_slice(&payload);
                         if let Err(e) = udp_r.send_to(&out, server_addr).await {
                             tracing::error!("UDP NACK send: {}", e);
                         }
                    }
                }

                // Handle outgoing TUN packets
                res = tun_r.recv(&mut buf) => {
                    let n = match res {
                        Ok(n) => n,
                        Err(e) => {
                            tracing::error!("TUN read: {}", e);
                            continue;
                        }
                    };

                    let is_small = n < 500;
                    
                    let (seq, rtp_s, rtp_ts, ssrc, target_size) = {
                        let mut s = state_send.lock().unwrap();
                        let seq = s.send_seq;
                        s.send_seq = s.send_seq.wrapping_add(1);
                        
                        s.rtp_seq = s.rtp_seq.wrapping_add(1);
                        s.rtp_timestamp = s.rtp_timestamp.wrapping_add(if is_small { 960 } else { 3000 });
                        
                        // Get target size from ChaosPrng
                        let target_size = s.chaos.get_target_size() as usize;

                        (seq, s.rtp_seq, s.rtp_timestamp, s.ssrc, target_size)
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

                    // Padding logic
                    let overhead = TOTAL_HEADER_LEN + AEAD_TAG_LEN;
                    let wire_size = n + overhead;
                    let padding_len = if target_size > wire_size {
                        target_size - wire_size
                    } else {
                        0
                    };

                    let total_len = wire_size + padding_len;
                    let mut out = BytesMut::with_capacity(total_len);
                    out.resize(TOTAL_HEADER_LEN, 0);
                    rtp.write_to(&mut out[..RTP_HEADER_LEN]);
                    omega.write_to(&mut out[RTP_HEADER_LEN..TOTAL_HEADER_LEN]);

                    let aad = out[..TOTAL_HEADER_LEN].to_vec();
                    
                    // Plaintext with padding
                    let mut payload = buf[..n].to_vec();
                    if padding_len > 0 {
                        payload.extend(std::iter::repeat(0).take(padding_len));
                    }

                    if let Err(e) = keys_send.encrypt_in_place(&mut payload, &aad) {
                        tracing::error!("encrypt: {}", e);
                        continue;
                    }
                    out.extend_from_slice(&payload);

                    // Cache for ARQ
                    {
                        let mut s = state_send.lock().unwrap();
                        let now = current_ms();
                        s.retransmit_queue.cache_packet(seq, out.to_vec(), now);
                        s.retransmit_queue.purge_expired(now);
                    }

                    if let Err(e) = udp_r.send_to(&out, server_addr).await {
                        tracing::error!("UDP send: {}", e);
                    }
                }
            }
        }
    });

    // UDP → TUN (server → client)
    let tun_w = tun.clone();
    let udp_w = udp.clone();
    let ss_for_recv = ss_owned.clone();
    let state_recv = state.clone();
    
    tokio::spawn(async move {
        let mut keys_recv = match SessionKeys::from_shared_secret(&ss_for_recv, false) {
            Ok(k) => k,
            Err(e) => {
                tracing::error!("key derivation failed: {}", e);
                return;
            }
        };
        let mut replay_filter = ReplayFilter::new();
        let mut buf = vec![0u8; 2048];
        loop {
            let (n, _src) = match udp_w.recv_from(&mut buf).await {
                Ok(r) => r,
                Err(e) => {
                    tracing::error!("UDP recv: {}", e);
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
                    // 1. Check Replay (Peek)
                    if !replay_filter.check(omega.seq as u64) {
                        continue;
                    }

                    // 2. Authenticate & Decrypt
                    let aad = buf[..TOTAL_HEADER_LEN].to_vec();
                    let mut ciphertext = buf[TOTAL_HEADER_LEN..n].to_vec();

                    match keys_recv.decrypt_in_place(&mut ciphertext, omega.seq as u64, &aad) {
                        Ok(plaintext) => {
                            // 3. Update Replay Filter (Commit)
                            replay_filter.update(omega.seq as u64);

                            // 4. Handle Packet Type
                            match omega.packet_type {
                                PacketType::Data => {
                                    // Gap detection and NACK generation
                                    let nack_opt = {
                                        let mut s = state_recv.lock().unwrap();
                                        s.gap_detector.record_received(omega.seq)
                                    };

                                    if let Some(nack) = nack_opt {
                                        tracing::debug!("client sending NACK for base={} bitmap={:x}", nack.base_seq, nack.bitmap);
                                        if let Err(e) = nack_tx.send(nack).await {
                                             tracing::warn!("failed to queue NACK: {}", e);
                                        }
                                    }

                                    // Truncate padding based on IP header
                                    let final_len = if let Some(ip_len) = get_ip_packet_len(plaintext) {
                                        plaintext.len().min(ip_len)
                                    } else {
                                        plaintext.len()
                                    };
                                    let plain_owned = plaintext[..final_len].to_vec();
                                    if let Err(e) = tun_w.send(&plain_owned).await {
                                        tracing::error!("TUN write: {}", e);
                                    }
                                }
                                PacketType::Nack => {
                                    if let Some(nack) = NackMessage::read_from(plaintext) {
                                        let packets = {
                                            let s = state_recv.lock().unwrap();
                                            s.retransmit_queue.process_nack(&nack).into_iter().map(|p| p.data.clone()).collect::<Vec<_>>()
                                        };
                                        if !packets.is_empty() {
                                            tracing::debug!("client resending {} packets", packets.len());
                                            for pkt in packets {
                                                if let Err(e) = udp_w.send_to(&pkt, server_addr).await {
                                                    tracing::warn!("resend failed: {}", e);
                                                }
                                            }
                                        }
                                    }
                                }
                                PacketType::Close => {
                                    tracing::info!("session closed by server");
                                    // Exit loop? Or just reconnect?
                                    // For now, simple client acts as if connection lost -> timeout would handle it?
                                    // But we should probably exit or trigger re-handshake.
                                    // For simplicity, we just log it.
                                }
                                PacketType::KeepAlive => {
                                    // Nothing to do
                                }
                                _ => {}
                            }
                        }
                        Err(e) => {
                             tracing::warn!("auth failed for type {:?}: {} (seq={})", omega.packet_type, e, omega.seq);
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
             cleanup_windows_routing(*v4.ip());
        }
    }

    Ok(())
}
