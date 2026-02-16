/// Data path — async TUN ↔ UDP forwarding with encryption.
///
/// Two main loops:
/// - `tun_to_udp`: Read IP packets from TUN → find session by dst IP → encrypt → send UDP
/// - `udp_to_tun`: Recv UDP → parse headers → find session by FlowId → decrypt → write TUN

use std::net::Ipv4Addr;
use std::sync::Arc;

use bytes::BytesMut;
use dashmap::DashMap;
use tokio::net::UdpSocket;

use omega_core::protocol::{
    FlowId, OmegaHeader, PacketType, RtpHeader, StunWrapper, NackMessage,
    RTP_HEADER_LEN, AEAD_TAG_LEN, TOTAL_HEADER_LEN,
};

use crate::handshake;
use crate::session::{SessionManager, SessionState};

/// Maximum UDP receive buffer size.
const UDP_BUF_SIZE: usize = 2048;

/// Maximum TUN read buffer size.
const TUN_BUF_SIZE: usize = 1500;

/// Run the TUN → UDP forwarding loop.
///
/// Reads packets from the TUN device, looks up the session by destination IP,
/// encrypts the payload, wraps in RTP + Omega headers, and sends via UDP.
pub async fn tun_to_udp_loop(
    tun: Arc<tun_rs::AsyncDevice>,
    udp: Arc<UdpSocket>,
    sessions: Arc<DashMap<FlowId, SessionState>>,
) {
    let mut buf = vec![0u8; TUN_BUF_SIZE];
    loop {
        // Read a packet from TUN
        let n = match tun.recv(&mut buf).await {
            Ok(n) => n,
            Err(e) => {
                tracing::error!("TUN read error: {}", e);
                continue;
            }
        };

        if n < 20 {
            continue; // Too short to be a valid IP packet
        }

        // Extract destination IP from IPv4 header
        let dst_ip = Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]);

        // Find session by tunnel IP
        let flow_id = {
            let mut found = None;
            for entry in sessions.iter() {
                if entry.value().tunnel_ip == dst_ip {
                    found = Some(*entry.key());
                    break;
                }
            }
            match found {
                Some(fid) => fid,
                None => {
                    tracing::trace!("no session for dst IP {}", dst_ip);
                    continue;
                }
            }
        };

        // Get mutable session reference
        let mut session = match sessions.get_mut(&flow_id) {
            Some(s) => s,
            None => continue,
        };

        // Get target size from ChaosPrng (bimodal distribution)
        let target_size = session.chaos.get_target_size() as usize;
        
        // Build RTP cover header
        let is_small = n < 500;
        let rtp_seq = session.next_rtp_seq();
        session.advance_rtp_timestamp(is_small);
        let rtp = if is_small {
            RtpHeader::opus(rtp_seq, session.rtp_timestamp, session.ssrc)
        } else {
            RtpHeader::vp8(rtp_seq, session.rtp_timestamp, session.ssrc, true)
        };

        // Build Omega header
        let omega_seq = session.next_send_seq();
        let omega = OmegaHeader {
            flow_id,
            seq: omega_seq,
            packet_type: PacketType::Data,
        };

        // Construct the outgoing packet:
        // [RTP:12][OmegaHdr:21][encrypted payload (IP + padding)][tag:16]
        // Target wire size includes everything.
        // Current overhead = 12 + 21 + 16 = 49 bytes.
        // Plaintext size = n.
        // Wire size = n + 49.
        // Padding needed = target_size.saturating_sub(n + 49).
        
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

        // Write RTP header
        rtp.write_to(&mut out[..RTP_HEADER_LEN]);

        // Write Omega header
        omega.write_to(&mut out[RTP_HEADER_LEN..TOTAL_HEADER_LEN]);

        // AAD = RTP + Omega headers (bound to ciphertext)
        let aad = out[..TOTAL_HEADER_LEN].to_vec();

        // Prepare plaintext: IP packet + padding
        let mut payload = buf[..n].to_vec();
        if padding_len > 0 {
            payload.extend(std::iter::repeat(0).take(padding_len));
        }

        // Encrypt payload in-place
        match session.keys.encrypt_in_place(&mut payload, &aad) {
            Ok(_nonce) => {}
            Err(e) => {
                tracing::error!("encrypt error: {}", e);
                continue;
            }
        }

        // Append encrypted payload + tag
        out.extend_from_slice(&payload);

        let client_addr = session.client_addr;
        
        // ARQ: Cache packet for retransmission
        // We need to clone the packet as we're sending it
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        session.retransmit_queue.cache_packet(omega_seq, out.to_vec(), now_ms);
        session.retransmit_queue.purge_expired(now_ms);

        drop(session); // Release lock before async send

        // Send via UDP
        if let Err(e) = udp.send_to(&out, client_addr).await {
            tracing::error!("UDP send error: {}", e);
        }
    }
}

/// Run the UDP → TUN forwarding loop.
///
/// Receives UDP packets, parses RTP + Omega headers, handles handshake vs data,
/// decrypts data packets, and writes plaintext to TUN.
pub async fn udp_to_tun_loop(
    tun: Arc<tun_rs::AsyncDevice>,
    udp: Arc<UdpSocket>,
    sessions: Arc<DashMap<FlowId, SessionState>>,
    session_manager: Arc<SessionManager>,
    server_mtu: u16,
) {
    let mut buf = vec![0u8; UDP_BUF_SIZE];
    loop {
        let (n, src_addr) = match udp.recv_from(&mut buf).await {
            Ok((n, addr)) => (n, addr),
            Err(e) => {
                tracing::error!("UDP recv error: {}", e);
                continue;
            }
        };

        if n < 4 {
            continue;
        }

        // Check if this is a STUN handshake packet
        if is_stun_packet(&buf[..n]) {
            handle_handshake(&buf[..n], src_addr, &session_manager, &udp, server_mtu).await;
            continue;
        }

        // Parse as data packet: [RTP:12][OmegaHdr:21][encrypted_payload+tag]
        if n < TOTAL_HEADER_LEN + AEAD_TAG_LEN {
            tracing::trace!("packet too short: {} bytes", n);
            continue;
        }

        // Parse Omega header (after RTP)
        let omega = match OmegaHeader::read_from(&buf[RTP_HEADER_LEN..TOTAL_HEADER_LEN]) {
            Some(h) => h,
            None => {
                tracing::trace!("invalid Omega header");
                continue;
            }
        };

        // Look up session
        let mut session = match sessions.get_mut(&omega.flow_id) {
            Some(s) => s,
            None => {
                tracing::trace!("unknown FlowId");
                continue;
            }
        };

        match omega.packet_type {
            PacketType::Data | PacketType::Nack | PacketType::KeepAlive | PacketType::Close => {
                // 1. Check Replay (Peek)
                if !session.replay_filter.check(omega.seq as u64) {
                    tracing::trace!("replay detected: seq={}", omega.seq);
                    continue;
                }

                // 2. Authenticate & Decrypt
                // All packet types must be authenticated.
                // AAD = RTP + Omega headers
                let aad = buf[..TOTAL_HEADER_LEN].to_vec();
                let mut ciphertext = buf[TOTAL_HEADER_LEN..n].to_vec();

                match session.keys.decrypt_in_place(&mut ciphertext, omega.seq as u64, &aad) {
                    Ok(plaintext) => {
                        // 3. Update Replay Filter (Commit)
                        session.replay_filter.update(omega.seq as u64);
                        session.touch();

                        // 4. Handle Packet Type
                        match omega.packet_type {
                            PacketType::Data => {
                                // ARQ: Update gap detector
                                if let Some(nack) = session.gap_detector.record_received(omega.seq) {
                                    tracing::debug!("sending NACK for seqs base={} bitmap={:x}", nack.base_seq, nack.bitmap);
                                    // Send NACK back
                                    let nack_seq = session.next_send_seq();
                                    let nack_omega = OmegaHeader {
                                        flow_id: omega.flow_id,
                                        seq: nack_seq,
                                        packet_type: PacketType::Nack,
                                    };
                                    let rtp_seq = session.next_rtp_seq();
                                    let rtp_ts = session.rtp_timestamp;
                                    let rtp = RtpHeader::opus(rtp_seq, rtp_ts, session.ssrc);
                                    
                                    let mut out = BytesMut::with_capacity(TOTAL_HEADER_LEN + 12 + AEAD_TAG_LEN);
                                    out.resize(TOTAL_HEADER_LEN + 12, 0); 
                                    rtp.write_to(&mut out[..RTP_HEADER_LEN]);
                                    nack_omega.write_to(&mut out[RTP_HEADER_LEN..TOTAL_HEADER_LEN]);
                                    nack.write_to(&mut out[TOTAL_HEADER_LEN..]);
                                    
                                    let aad = out[..TOTAL_HEADER_LEN].to_vec();
                                    let mut payload = out[TOTAL_HEADER_LEN..].to_vec();
                                    if let Ok(_) = session.keys.encrypt_in_place(&mut payload, &aad) {
                                        out.truncate(TOTAL_HEADER_LEN);
                                        out.extend_from_slice(&payload);
                                        let addr = session.client_addr;
                                        let data = out.clone();
                                        let udp_clone = udp.clone();
                                        tokio::spawn(async move {
                                            let _ = udp_clone.send_to(&data, addr).await;
                                        });
                                    }
                                }
                
                                // Update loss stats
                                session.update_loss_stats(omega.seq);

                                // Truncate padding based on IP header
                                let final_len = if let Some(ip_len) = get_ip_packet_len(plaintext) {
                                    plaintext.len().min(ip_len)
                                } else {
                                    plaintext.len()
                                };
                                
                                let plain_owned = plaintext[..final_len].to_vec();
                                drop(session); // Release lock before TUN write
                                if let Err(e) = tun.send(&plain_owned).await {
                                    tracing::error!("TUN write error: {}", e);
                                }
                            }
                            PacketType::Nack => {
                                // Parse NACK from plaintext
                                if let Some(nack) = NackMessage::read_from(plaintext) {
                                     let packets = session.retransmit_queue.process_nack(&nack);
                                     if !packets.is_empty() {
                                         tracing::debug!("resending {} packets for NACK", packets.len());
                                         let addr = session.client_addr;
                                         let udp_clone = udp.clone();
                                         let to_send: Vec<Vec<u8>> = packets.iter().map(|p| p.data.clone()).collect();
                                         tokio::spawn(async move {
                                             for pkt in to_send {
                                                 let _ = udp_clone.send_to(&pkt, addr).await;
                                             }
                                         });
                                     }
                                }
                            }
                            PacketType::Close => {
                                let fid = omega.flow_id;
                                drop(session);
                                sessions.remove(&fid);
                                tracing::info!("session closed by client");
                            }
                            PacketType::KeepAlive => {
                                // Nothing to do, touched above
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
}

/// Check if a UDP payload looks like a STUN message.
fn is_stun_packet(buf: &[u8]) -> bool {
    StunWrapper::parse(buf).is_some()
}

/// Handle an incoming STUN handshake packet.
async fn handle_handshake(
    buf: &[u8],
    src_addr: std::net::SocketAddr,
    session_manager: &SessionManager,
    udp: &UdpSocket,
    server_mtu: u16,
) {
    match handshake::process_client_handshake(buf, src_addr, session_manager, server_mtu) {
        Ok(result) => {
            if let Err(e) = udp.send_to(&result.response, src_addr).await {
                tracing::error!("failed to send handshake response: {}", e);
            }
        }
        Err(e) => {
            tracing::warn!("handshake error from {}: {}", src_addr, e);
        }
    }
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
