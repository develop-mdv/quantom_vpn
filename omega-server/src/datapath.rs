use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc;

use omega_core::protocol::{
    NackMessage, OmegaHeader, PacketType, RtpHeader, StunWrapper, AEAD_TAG_LEN, RTP_HEADER_LEN,
    TOTAL_HEADER_LEN,
};

use crate::handshake::{self, HandshakeOutcome};
use crate::identity::IdentityStore;
use crate::metrics;
use crate::session::{SessionManager, SessionState};

const UDP_BUF_SIZE: usize = 2048;
const TUN_BUF_SIZE: usize = 1500;
const MAX_RETRANSMIT_BURST: usize = 24;
const RETRANSMIT_PACING_US: u64 = 500;
const REDUNDANCY_PACING_US: u64 = 200;
const TCP_FRAME_MAX: usize = 4096;

#[derive(Clone)]
enum ServerEgress {
    Udp(std::net::SocketAddr),
    Tcp(mpsc::Sender<Bytes>),
}

fn session_egress(session: &SessionState) -> ServerEgress {
    if let Some(tx) = session.tcp_egress.as_ref() {
        ServerEgress::Tcp(tx.clone())
    } else {
        ServerEgress::Udp(session.client_addr)
    }
}

async fn send_to_egress(udp: &Arc<UdpSocket>, egress: ServerEgress, packet: Bytes) -> bool {
    match egress {
        ServerEgress::Udp(addr) => udp.send_to(packet.as_ref(), addr).await.is_ok(),
        ServerEgress::Tcp(tx) => tx.send(packet).await.is_ok(),
    }
}

async fn write_tcp_frame<W>(writer: &mut W, packet: &[u8]) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    if packet.len() > u16::MAX as usize {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "TCP frame too large",
        ));
    }
    writer
        .write_all(&(packet.len() as u16).to_be_bytes())
        .await?;
    writer.write_all(packet).await
}

async fn read_tcp_frame<R>(reader: &mut R, buf: &mut Vec<u8>) -> std::io::Result<usize>
where
    R: AsyncRead + Unpin,
{
    let mut len_buf = [0u8; 2];
    reader.read_exact(&mut len_buf).await?;
    let len = u16::from_be_bytes(len_buf) as usize;
    if len == 0 || len > TCP_FRAME_MAX {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid TCP frame length",
        ));
    }
    if buf.len() < len {
        buf.resize(len, 0);
    }
    reader.read_exact(&mut buf[..len]).await?;
    Ok(len)
}

fn path_probe_reply_type(packet_type: PacketType) -> Option<PacketType> {
    match packet_type {
        PacketType::PathProbe => Some(PacketType::PathProbeReply),
        _ => None,
    }
}

pub async fn tun_to_udp_loop(
    tun: Arc<tun_rs::AsyncDevice>,
    udp: Arc<UdpSocket>,
    session_manager: Arc<SessionManager>,
) {
    let mut buf = vec![0u8; TUN_BUF_SIZE];
    loop {
        let n = match tun.recv(&mut buf).await {
            Ok(n) => n,
            Err(e) => {
                tracing::error!(error = %e, "TUN read error");
                continue;
            }
        };

        let dst_addr = match extract_tunnel_destination(&buf[..n]) {
            Some(addr) => addr,
            None => continue,
        };
        let flow_id = match session_manager.flow_by_tunnel_addr(dst_addr) {
            Some(fid) => fid,
            None => {
                tracing::trace!(%dst_addr, "no session for destination tunnel address");
                continue;
            }
        };

        let mut session = match session_manager.get(&flow_id) {
            Some(s) => s,
            None => continue,
        };

        let target_size = session.chaos.get_target_size() as usize;
        let padding_budget = session.current_padding_budget();
        let redundancy_extra = session.current_redundancy_extra();

        let is_small = n < 500;
        let rtp_seq = session.next_rtp_seq();
        session.advance_rtp_timestamp(is_small);
        let rtp = if is_small {
            RtpHeader::opus(rtp_seq, session.rtp_timestamp, session.ssrc)
        } else {
            RtpHeader::vp8(rtp_seq, session.rtp_timestamp, session.ssrc, true)
        };

        let omega_seq = session.next_send_seq();
        let omega = OmegaHeader {
            flow_id,
            seq: omega_seq,
            packet_type: PacketType::Data,
        };

        let overhead = TOTAL_HEADER_LEN + AEAD_TAG_LEN;
        let wire_size = n + overhead;
        let desired_padding = target_size.saturating_sub(wire_size);
        let padding_len = desired_padding.min(padding_budget);

        let total_len = wire_size + padding_len;
        let mut out = BytesMut::with_capacity(total_len);
        out.resize(TOTAL_HEADER_LEN, 0);

        rtp.write_to(&mut out[..RTP_HEADER_LEN]);
        omega.write_to(&mut out[RTP_HEADER_LEN..TOTAL_HEADER_LEN]);

        let aad = &out[..TOTAL_HEADER_LEN];

        let mut payload = buf[..n].to_vec();
        if padding_len > 0 {
            payload.extend(std::iter::repeat(0).take(padding_len));
        }

        if let Err(e) = session.keys.encrypt_in_place(&mut payload, &aad) {
            tracing::error!(error = %e, "encrypt error");
            continue;
        }

        out.extend_from_slice(&payload);
        let packet = out.freeze();

        let egress = session_egress(&session);
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        session
            .retransmit_queue
            .cache_packet(omega_seq, packet.clone(), now_ms);
        session.retransmit_queue.purge_expired(now_ms);

        drop(session);

        if !send_to_egress(&udp, egress.clone(), packet.clone()).await {
            tracing::error!("server egress send error");
            continue;
        } else {
            metrics::record_packet_out(packet.len());
            let redundancy_extra = if matches!(egress, ServerEgress::Tcp(_)) {
                0
            } else {
                redundancy_extra
            };
            for _ in 0..redundancy_extra {
                tokio::time::sleep(Duration::from_micros(REDUNDANCY_PACING_US)).await;
                if !send_to_egress(&udp, egress.clone(), packet.clone()).await {
                    tracing::trace!("server redundant egress send error");
                    break;
                }
                metrics::record_packet_out(packet.len());
            }
        }
    }
}

pub async fn udp_to_tun_loop(
    tun: Arc<tun_rs::AsyncDevice>,
    udp: Arc<UdpSocket>,
    session_manager: Arc<SessionManager>,
    identity_store: Arc<IdentityStore>,
    server_mtu: u16,
    allow_legacy_v1: bool,
    morphing_policy: crate::runtime::MorphingPolicy,
) {
    let mut buf = vec![0u8; UDP_BUF_SIZE];
    loop {
        let (n, src_addr) = match udp.recv_from(&mut buf).await {
            Ok((n, addr)) => (n, addr),
            Err(e) => {
                tracing::error!(error = %e, "UDP recv error");
                continue;
            }
        };

        if n < 4 {
            continue;
        }

        if is_stun_packet(&buf[..n]) {
            handle_handshake(
                &buf[..n],
                src_addr,
                &session_manager,
                &identity_store,
                &udp,
                server_mtu,
                allow_legacy_v1,
                morphing_policy,
            )
            .await;
            continue;
        }

        if n < TOTAL_HEADER_LEN + AEAD_TAG_LEN {
            tracing::trace!(len = n, "packet too short");
            continue;
        }

        let omega = match OmegaHeader::read_from(&buf[RTP_HEADER_LEN..TOTAL_HEADER_LEN]) {
            Some(h) => h,
            None => {
                tracing::trace!("invalid Omega header");
                continue;
            }
        };

        let mut session = match session_manager.get(&omega.flow_id) {
            Some(s) => s,
            None => {
                tracing::trace!("unknown FlowId");
                continue;
            }
        };

        match omega.packet_type {
            PacketType::Data
            | PacketType::Nack
            | PacketType::KeepAlive
            | PacketType::Close
            | PacketType::PathProbe
            | PacketType::PathProbeReply => {
                if !session.replay_filter.check(omega.seq as u64) {
                    tracing::trace!(seq = omega.seq, "replay detected");
                    continue;
                }

                let (aad, ciphertext) = buf[..n].split_at_mut(TOTAL_HEADER_LEN);

                match session
                    .keys
                    .decrypt_in_place(ciphertext, omega.seq as u64, aad)
                {
                    Ok(plaintext) => {
                        session.replay_filter.update(omega.seq as u64);
                        session.touch();

                        if session.client_addr != src_addr {
                            tracing::info!(
                                from = %session.client_addr,
                                to = %src_addr,
                                "client roamed"
                            );
                            session.client_addr = src_addr;
                        }

                        let inbound_nack = session.observe_inbound_seq(omega.seq);
                        if !matches!(omega.packet_type, PacketType::Close) {
                            if let Some(nack) = inbound_nack {
                                metrics::record_nack_sent(nack.bitmap.count_ones());
                                let nack_seq = session.next_send_seq();
                                let nack_omega = OmegaHeader {
                                    flow_id: omega.flow_id,
                                    seq: nack_seq,
                                    packet_type: PacketType::Nack,
                                };
                                let rtp_seq = session.next_rtp_seq();
                                let rtp_ts = session.rtp_timestamp;
                                let rtp = RtpHeader::opus(rtp_seq, rtp_ts, session.ssrc);

                                let mut out =
                                    BytesMut::with_capacity(TOTAL_HEADER_LEN + 12 + AEAD_TAG_LEN);
                                out.resize(TOTAL_HEADER_LEN + 12, 0);
                                rtp.write_to(&mut out[..RTP_HEADER_LEN]);
                                nack_omega.write_to(&mut out[RTP_HEADER_LEN..TOTAL_HEADER_LEN]);
                                nack.write_to(&mut out[TOTAL_HEADER_LEN..]);

                                let nack_aad = &out[..TOTAL_HEADER_LEN];
                                let mut nack_payload = out[TOTAL_HEADER_LEN..].to_vec();
                                if session
                                    .keys
                                    .encrypt_in_place(&mut nack_payload, &nack_aad)
                                    .is_ok()
                                {
                                    out.truncate(TOTAL_HEADER_LEN);
                                    out.extend_from_slice(&nack_payload);
                                    let egress = session_egress(&session);
                                    let data = out.freeze();
                                    let now_ms = now_ms();
                                    session.retransmit_queue.cache_packet(
                                        nack_seq,
                                        data.clone(),
                                        now_ms,
                                    );
                                    session.retransmit_queue.purge_expired(now_ms);
                                    let udp_clone = udp.clone();
                                    tokio::spawn(async move {
                                        let _ = send_to_egress(&udp_clone, egress, data).await;
                                    });
                                }
                            }
                        }

                        match omega.packet_type {
                            PacketType::Data => {
                                let final_len = if let Some(ip_len) = get_ip_packet_len(plaintext) {
                                    plaintext.len().min(ip_len)
                                } else {
                                    plaintext.len()
                                };
                                drop(session);

                                if let Err(e) = tun.send(&plaintext[..final_len]).await {
                                    tracing::error!(error = %e, "TUN write error");
                                } else {
                                    metrics::record_packet_in(final_len);
                                }
                            }
                            PacketType::Nack => {
                                if let Some(nack) = NackMessage::read_from(plaintext) {
                                    metrics::record_nack_received(nack.bitmap.count_ones());
                                    session.on_remote_nack(&nack);
                                    let now_ms = std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .unwrap_or_default()
                                        .as_millis()
                                        as u64;
                                    session.retransmit_queue.observe_nack(&nack, now_ms);
                                    let packets = session.retransmit_queue.process_nack(&nack);
                                    if !packets.is_empty() {
                                        let egress = session_egress(&session);
                                        let udp_clone = udp.clone();
                                        let to_send: Vec<Bytes> = packets
                                            .iter()
                                            .take(MAX_RETRANSMIT_BURST)
                                            .map(|p| p.data.clone())
                                            .collect();
                                        let dropped = packets.len().saturating_sub(to_send.len());
                                        metrics::record_retransmit_sent(to_send.len(), dropped);
                                        tokio::spawn(async move {
                                            let total = to_send.len();
                                            for (idx, pkt) in to_send.into_iter().enumerate() {
                                                let _ =
                                                    send_to_egress(&udp_clone, egress.clone(), pkt)
                                                        .await;
                                                if idx + 1 < total {
                                                    tokio::time::sleep(Duration::from_micros(
                                                        RETRANSMIT_PACING_US,
                                                    ))
                                                    .await;
                                                }
                                            }
                                        });
                                    }
                                }
                            }
                            PacketType::Close => {
                                let fid = omega.flow_id;
                                drop(session);
                                session_manager.terminate_session(&fid);
                                tracing::info!("session closed by client");
                            }
                            PacketType::PathProbe => {
                                let probe_payload = plaintext.to_vec();
                                let reply_type = path_probe_reply_type(omega.packet_type);
                                if let Some(packet_type) = reply_type {
                                    let reply_seq = session.next_send_seq();
                                    let reply_omega = OmegaHeader {
                                        flow_id: omega.flow_id,
                                        seq: reply_seq,
                                        packet_type,
                                    };
                                    let rtp_seq = session.next_rtp_seq();
                                    let rtp_ts = session.rtp_timestamp;
                                    let rtp = RtpHeader::opus(rtp_seq, rtp_ts, session.ssrc);
                                    let mut out = BytesMut::with_capacity(
                                        TOTAL_HEADER_LEN + probe_payload.len() + AEAD_TAG_LEN,
                                    );
                                    out.resize(TOTAL_HEADER_LEN, 0);
                                    rtp.write_to(&mut out[..RTP_HEADER_LEN]);
                                    reply_omega
                                        .write_to(&mut out[RTP_HEADER_LEN..TOTAL_HEADER_LEN]);
                                    let aad = &out[..TOTAL_HEADER_LEN];
                                    let mut payload = probe_payload;
                                    if session.keys.encrypt_in_place(&mut payload, aad).is_ok() {
                                        out.extend_from_slice(&payload);
                                        let egress = session_egress(&session);
                                        let data = out.freeze();
                                        let udp_clone = udp.clone();
                                        tokio::spawn(async move {
                                            let _ = send_to_egress(&udp_clone, egress, data).await;
                                        });
                                    }
                                }
                            }
                            PacketType::PathProbeReply => {}
                            PacketType::KeepAlive => {}
                            _ => {}
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            packet_type = ?omega.packet_type,
                            seq = omega.seq,
                            "auth failed"
                        );
                    }
                }
            }
            _ => {}
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn tcp_listener_loop(
    bind_addr: String,
    tun: Arc<tun_rs::AsyncDevice>,
    udp: Arc<UdpSocket>,
    session_manager: Arc<SessionManager>,
    identity_store: Arc<IdentityStore>,
    server_mtu: u16,
    allow_legacy_v1: bool,
    morphing_policy: crate::runtime::MorphingPolicy,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(&bind_addr).await?;
    tracing::info!(%bind_addr, "listening on framed TCP fallback");

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let tun = tun.clone();
        let udp = udp.clone();
        let sessions = session_manager.clone();
        let identity = identity_store.clone();
        tokio::spawn(async move {
            if let Err(err) = tcp_connection_loop(
                stream,
                peer_addr,
                tun,
                udp,
                sessions,
                identity,
                server_mtu,
                allow_legacy_v1,
                morphing_policy,
            )
            .await
            {
                tracing::warn!(%peer_addr, error = %err, "TCP fallback connection stopped");
            }
        });
    }
}

#[allow(clippy::too_many_arguments)]
async fn tcp_connection_loop(
    stream: TcpStream,
    peer_addr: SocketAddr,
    tun: Arc<tun_rs::AsyncDevice>,
    udp: Arc<UdpSocket>,
    session_manager: Arc<SessionManager>,
    identity_store: Arc<IdentityStore>,
    server_mtu: u16,
    allow_legacy_v1: bool,
    morphing_policy: crate::runtime::MorphingPolicy,
) -> anyhow::Result<()> {
    let (mut reader, mut writer) = stream.into_split();
    let (tx, mut rx) = mpsc::channel::<Bytes>(512);
    let writer_task = tokio::spawn(async move {
        while let Some(packet) = rx.recv().await {
            if write_tcp_frame(&mut writer, packet.as_ref()).await.is_err() {
                break;
            }
        }
    });

    let mut buf = vec![0u8; TCP_FRAME_MAX];
    let n = read_tcp_frame(&mut reader, &mut buf).await?;
    if !is_stun_packet(&buf[..n]) {
        writer_task.abort();
        anyhow::bail!("first TCP frame was not a STUN handshake");
    }

    let flow_id = match handshake::process_client_handshake(
        &buf[..n],
        peer_addr,
        &session_manager,
        &identity_store,
        server_mtu,
        allow_legacy_v1,
        morphing_policy,
    ) {
        Ok(HandshakeOutcome::Accepted { response, flow_id }) => {
            if let Some(mut session) = session_manager.get(&flow_id) {
                session.set_tcp_egress(tx.clone());
            }
            tx.send(Bytes::from(response)).await.ok();
            flow_id
        }
        Ok(HandshakeOutcome::Rejected { response, reason }) => {
            tracing::warn!(%peer_addr, ?reason, "TCP handshake rejected");
            tx.send(Bytes::from(response)).await.ok();
            writer_task.abort();
            return Ok(());
        }
        Err(err) => {
            writer_task.abort();
            return Err(err.into());
        }
    };

    loop {
        let n = match read_tcp_frame(&mut reader, &mut buf).await {
            Ok(n) => n,
            Err(err) => {
                if let Some(mut session) = session_manager.get(&flow_id) {
                    session.clear_tcp_egress();
                }
                writer_task.abort();
                return Err(err.into());
            }
        };
        handle_client_frame(&buf[..n], peer_addr, &tun, &udp, &session_manager, true).await;
    }
}

async fn handle_client_frame(
    frame: &[u8],
    src_addr: SocketAddr,
    tun: &Arc<tun_rs::AsyncDevice>,
    udp: &Arc<UdpSocket>,
    session_manager: &Arc<SessionManager>,
    from_tcp: bool,
) {
    if frame.len() < TOTAL_HEADER_LEN + AEAD_TAG_LEN {
        return;
    }

    let omega = match OmegaHeader::read_from(&frame[RTP_HEADER_LEN..TOTAL_HEADER_LEN]) {
        Some(h) => h,
        None => return,
    };

    let mut owned = frame.to_vec();
    let mut session = match session_manager.get(&omega.flow_id) {
        Some(s) => s,
        None => return,
    };

    if !session.replay_filter.check(omega.seq as u64) {
        return;
    }

    let (aad, ciphertext) = owned.split_at_mut(TOTAL_HEADER_LEN);
    let plaintext = match session
        .keys
        .decrypt_in_place(ciphertext, omega.seq as u64, aad)
    {
        Ok(value) => value,
        Err(err) => {
            tracing::warn!(error = %err, seq = omega.seq, "auth failed");
            return;
        }
    };

    session.replay_filter.update(omega.seq as u64);
    session.touch();
    if !from_tcp && session.client_addr != src_addr {
        tracing::info!(from = %session.client_addr, to = %src_addr, "client roamed");
        session.client_addr = src_addr;
    }

    let inbound_nack = session.observe_inbound_seq(omega.seq);
    if !matches!(omega.packet_type, PacketType::Close) {
        if let Some(nack) = inbound_nack {
            metrics::record_nack_sent(nack.bitmap.count_ones());
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

            let nack_aad = &out[..TOTAL_HEADER_LEN];
            let mut nack_payload = out[TOTAL_HEADER_LEN..].to_vec();
            if session
                .keys
                .encrypt_in_place(&mut nack_payload, &nack_aad)
                .is_ok()
            {
                out.truncate(TOTAL_HEADER_LEN);
                out.extend_from_slice(&nack_payload);
                let egress = session_egress(&session);
                let data = out.freeze();
                let now_ms = now_ms();
                session
                    .retransmit_queue
                    .cache_packet(nack_seq, data.clone(), now_ms);
                session.retransmit_queue.purge_expired(now_ms);
                let udp = udp.clone();
                tokio::spawn(async move {
                    let _ = send_to_egress(&udp, egress, data).await;
                });
            }
        }
    }

    match omega.packet_type {
        PacketType::Data => {
            let final_len = if let Some(ip_len) = get_ip_packet_len(plaintext) {
                plaintext.len().min(ip_len)
            } else {
                plaintext.len()
            };
            let packet = plaintext[..final_len].to_vec();
            drop(session);
            if tun.send(&packet).await.is_ok() {
                metrics::record_packet_in(final_len);
            }
        }
        PacketType::Nack => {
            if let Some(nack) = NackMessage::read_from(plaintext) {
                metrics::record_nack_received(nack.bitmap.count_ones());
                session.on_remote_nack(&nack);
                let now_ms = now_ms();
                session.retransmit_queue.observe_nack(&nack, now_ms);
                let packets = session.retransmit_queue.process_nack(&nack);
                if !packets.is_empty() {
                    let egress = session_egress(&session);
                    let udp = udp.clone();
                    let to_send: Vec<Bytes> = packets
                        .iter()
                        .take(MAX_RETRANSMIT_BURST)
                        .map(|p| p.data.clone())
                        .collect();
                    let dropped = packets.len().saturating_sub(to_send.len());
                    metrics::record_retransmit_sent(to_send.len(), dropped);
                    tokio::spawn(async move {
                        let total = to_send.len();
                        for (idx, pkt) in to_send.into_iter().enumerate() {
                            let _ = send_to_egress(&udp, egress.clone(), pkt).await;
                            if idx + 1 < total {
                                tokio::time::sleep(Duration::from_micros(RETRANSMIT_PACING_US))
                                    .await;
                            }
                        }
                    });
                }
            }
        }
        PacketType::Close => {
            let fid = omega.flow_id;
            drop(session);
            session_manager.terminate_session(&fid);
            tracing::info!("session closed by client");
        }
        PacketType::PathProbe => {
            let probe_payload = plaintext.to_vec();
            if let Some(packet_type) = path_probe_reply_type(omega.packet_type) {
                let reply_seq = session.next_send_seq();
                let reply_omega = OmegaHeader {
                    flow_id: omega.flow_id,
                    seq: reply_seq,
                    packet_type,
                };
                let rtp_seq = session.next_rtp_seq();
                let rtp_ts = session.rtp_timestamp;
                let rtp = RtpHeader::opus(rtp_seq, rtp_ts, session.ssrc);
                let mut out =
                    BytesMut::with_capacity(TOTAL_HEADER_LEN + probe_payload.len() + AEAD_TAG_LEN);
                out.resize(TOTAL_HEADER_LEN, 0);
                rtp.write_to(&mut out[..RTP_HEADER_LEN]);
                reply_omega.write_to(&mut out[RTP_HEADER_LEN..TOTAL_HEADER_LEN]);
                let aad = &out[..TOTAL_HEADER_LEN];
                let mut payload = probe_payload;
                if session.keys.encrypt_in_place(&mut payload, aad).is_ok() {
                    out.extend_from_slice(&payload);
                    let egress = session_egress(&session);
                    let data = out.freeze();
                    let udp = udp.clone();
                    tokio::spawn(async move {
                        let _ = send_to_egress(&udp, egress, data).await;
                    });
                }
            }
        }
        PacketType::PathProbeReply | PacketType::KeepAlive => {}
        _ => {}
    }
}

fn is_stun_packet(buf: &[u8]) -> bool {
    StunWrapper::parse(buf).is_some()
}

async fn handle_handshake(
    buf: &[u8],
    src_addr: std::net::SocketAddr,
    session_manager: &SessionManager,
    identity_store: &IdentityStore,
    udp: &UdpSocket,
    server_mtu: u16,
    allow_legacy_v1: bool,
    morphing_policy: crate::runtime::MorphingPolicy,
) {
    match handshake::process_client_handshake(
        buf,
        src_addr,
        session_manager,
        identity_store,
        server_mtu,
        allow_legacy_v1,
        morphing_policy,
    ) {
        Ok(HandshakeOutcome::Accepted { response, flow_id }) => {
            if let Err(e) = udp.send_to(&response, src_addr).await {
                tracing::error!(error = %e, "failed to send handshake response");
            } else {
                tracing::debug!(flow_id = %crate::session::flow_id_to_hex(&flow_id), "handshake accepted");
            }
        }
        Ok(HandshakeOutcome::Rejected { response, reason }) => {
            if let Err(e) = udp.send_to(&response, src_addr).await {
                tracing::error!(error = %e, "failed to send handshake reject");
            }
            tracing::warn!(%src_addr, reason = ?reason, "handshake rejected");
        }
        Err(e) => {
            tracing::warn!(%src_addr, error = %e, "handshake parsing error");
        }
    }
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

fn extract_tunnel_destination(buf: &[u8]) -> Option<IpAddr> {
    if buf.is_empty() {
        return None;
    }

    match buf[0] >> 4 {
        4 => {
            if buf.len() < 20 {
                return None;
            }
            Some(IpAddr::V4(std::net::Ipv4Addr::new(
                buf[16], buf[17], buf[18], buf[19],
            )))
        }
        6 => {
            if buf.len() < 40 {
                return None;
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[24..40]);
            Some(IpAddr::V6(std::net::Ipv6Addr::from(octets)))
        }
        _ => None,
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::{
        extract_tunnel_destination, path_probe_reply_type, read_tcp_frame, write_tcp_frame,
    };
    use omega_core::protocol::PacketType;

    #[test]
    fn extracts_ipv4_destination_from_inner_packet() {
        let packet = [
            0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 10, 7, 0, 1, 10, 7, 0, 2,
        ];
        assert_eq!(
            extract_tunnel_destination(&packet),
            Some(IpAddr::V4(Ipv4Addr::new(10, 7, 0, 2)))
        );
    }

    #[test]
    fn extracts_ipv6_destination_from_inner_packet() {
        let mut packet = [0u8; 40];
        packet[0] = 0x60;
        packet[24..40].copy_from_slice(&Ipv6Addr::new(0xfd70, 0x0007, 0, 0, 0, 0, 0, 2).octets());
        assert_eq!(
            extract_tunnel_destination(&packet),
            Some(IpAddr::V6(Ipv6Addr::new(0xfd70, 0x0007, 0, 0, 0, 0, 0, 2)))
        );
    }

    #[test]
    fn path_probe_echoes_only_as_probe_reply() {
        assert_eq!(
            path_probe_reply_type(PacketType::PathProbe),
            Some(PacketType::PathProbeReply)
        );
        assert_eq!(path_probe_reply_type(PacketType::Data), None);
        assert_eq!(path_probe_reply_type(PacketType::KeepAlive), None);
    }

    #[tokio::test]
    async fn tcp_frame_helpers_round_trip_packet_bytes() {
        let (mut client, mut server) = tokio::io::duplex(64);
        let packet = vec![9, 8, 7, 6];

        write_tcp_frame(&mut client, &packet).await.unwrap();

        let mut out = vec![0u8; 16];
        let n = read_tcp_frame(&mut server, &mut out).await.unwrap();
        assert_eq!(n, packet.len());
        assert_eq!(&out[..n], packet.as_slice());
    }
}
