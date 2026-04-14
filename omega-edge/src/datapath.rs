use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Instant;

use bytes::{Bytes, BytesMut};
use tokio::net::UdpSocket;

use omega_core_wire::TransportFrame;
use omega_core_wire::{
    control_packet_type, decode_transport_frames, encode_transport_frames,
    read_protected_omega_header, write_protected_omega_header, OmegaHeader, PacketType, RtpHeader,
    StunWrapper, TrafficClass, AEAD_TAG_LEN, RTP_HEADER_LEN, TOTAL_HEADER_LEN,
};

use crate::fabric::SharedFabric;
use crate::handshake::{HandshakeOutcome, HandshakeService};
use crate::metrics;
use crate::session::SessionManager;
use omega_control::identity::IdentityStore;
use omega_control::policy::SessionAdmission;
use omega_stealth::PersonaId;

const UDP_BUF_SIZE: usize = 2048;
const TUN_BUF_SIZE: usize = 1500;
const MAX_DRAIN_DATAGRAMS: usize = 24;

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
        if n < 20 {
            continue;
        }

        let dst_ip = Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]);
        let flow_id = match session_manager.flow_by_tunnel_ip(dst_ip) {
            Some(fid) => fid,
            None => continue,
        };

        if let Some(mut session) = session_manager.get(&flow_id) {
            session.queue_protected_message(classify_ip_packet(&buf[..n]), buf[..n].to_vec());
        }
        drain_session_outbound(flow_id, &session_manager, &udp).await;
    }
}

pub async fn udp_to_tun_loop(
    tun: Arc<tun_rs::AsyncDevice>,
    udp: Arc<UdpSocket>,
    session_manager: Arc<SessionManager>,
    identity_store: Arc<IdentityStore>,
    handshake_service: Arc<HandshakeService>,
    server_mtu: u16,
    allow_legacy_v1: bool,
    morphing_policy: omega_stealth::MorphingPolicy,
    persona: PersonaId,
    admission: &SessionAdmission,
    fabric: &SharedFabric,
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
                &handshake_service,
                &udp,
                server_mtu,
                allow_legacy_v1,
                morphing_policy,
                persona,
                &admission,
                &fabric,
            )
            .await;
            continue;
        }

        if n < TOTAL_HEADER_LEN + AEAD_TAG_LEN {
            continue;
        }

        let Some(rtp) = RtpHeader::read_from(&buf[..RTP_HEADER_LEN]) else {
            continue;
        };
        let Some(flow_id) =
            omega_core_wire::FlowId::from_bytes(&buf[RTP_HEADER_LEN..RTP_HEADER_LEN + 16])
        else {
            continue;
        };

        let mut session = match session_manager.get(&flow_id) {
            Some(session) => session,
            None => continue,
        };

        let Some(omega) = read_protected_omega_header(
            &rtp,
            &session.header_protection,
            &buf[RTP_HEADER_LEN..TOTAL_HEADER_LEN],
        ) else {
            continue;
        };
        if !matches!(omega.packet_type, PacketType::Data | PacketType::Close) {
            continue;
        }
        if !session.replay_filter.check(omega.seq as u64) {
            continue;
        }

        let (aad, ciphertext) = buf[..n].split_at_mut(TOTAL_HEADER_LEN);
        let plaintext = match session
            .keys
            .decrypt_in_place(ciphertext, omega.seq as u64, aad)
        {
            Ok(plaintext) => plaintext.to_vec(),
            Err(e) => {
                tracing::warn!(error = %e, seq = omega.seq, "auth failed");
                continue;
            }
        };
        session.replay_filter.update(omega.seq as u64);
        session.touch();
        if session.client_addr != src_addr {
            session.transport.note_peer_roam(Instant::now());
            metrics::record_path_roam();
            session.client_addr = src_addr;
        }

        let Some(frames) = decode_transport_frames(&plaintext) else {
            continue;
        };
        let should_close = omega.packet_type == PacketType::Close
            || frames.iter().any(|frame| matches!(frame, omega_core_wire::TransportFrame::Control(control) if matches!(control.kind, omega_core_wire::ControlKind::Close)));
        let now = Instant::now();
        let messages = session
            .transport
            .on_datagram_received(now, omega.seq, &frames);
        let mut messages = session.accept_transport_messages(now, messages);
        let recovered = session.recover_fec_messages(now, &frames);
        if !recovered.is_empty() {
            metrics::record_fec_recovery(recovered.len());
        }
        messages.extend(recovered);
        let snapshot = session.transport.snapshot();
        session.observe_transport_snapshot(&snapshot);
        drop(session);

        for message in messages {
            let final_len = if let Some(ip_len) = get_ip_packet_len(&message.payload) {
                message.payload.len().min(ip_len)
            } else {
                message.payload.len()
            };
            if let Err(e) = tun.send(&message.payload[..final_len]).await {
                tracing::error!(error = %e, "TUN write error");
            } else {
                metrics::record_packet_in(final_len);
            }
        }

        if should_close {
            session_manager.terminate_session_with_reason(&flow_id, "peer_close");
            continue;
        }
        drain_session_outbound(flow_id, &session_manager, &udp).await;
    }
}

async fn drain_session_outbound(
    flow_id: omega_core_wire::FlowId,
    session_manager: &SessionManager,
    udp: &UdpSocket,
) {
    for _ in 0..MAX_DRAIN_DATAGRAMS {
        let prepared = {
            let mut session = match session_manager.get(&flow_id) {
                Some(session) => session,
                None => return,
            };
            if !session.transport.has_pending_work() {
                return;
            }
            if let Some(deadline) = session.transport.next_send_deadline() {
                if deadline > Instant::now() {
                    return;
                }
            }

            let payload_budget = session.transport_payload_budget;
            let padding_budget = session.current_padding_budget();
            let mut datagram = match session
                .transport
                .poll_datagram(Instant::now(), payload_budget)
            {
                Some(datagram) => datagram,
                None => return,
            };
            if let Some(target_floor) =
                session.stealth_padding_floor(datagram.encoded_len, payload_budget, padding_budget)
            {
                if target_floor > datagram.encoded_len + 3 {
                    datagram.frames.push(TransportFrame::Padding(
                        target_floor - datagram.encoded_len - 3,
                    ));
                    datagram.encoded_len = encode_transport_frames(&datagram.frames).len();
                }
            }
            let addr = session.client_addr;
            let packet_number = datagram.packet_number;
            let packet = match build_wire_packet(flow_id, &mut session, datagram) {
                Some(packet) => packet,
                None => {
                    session.transport.abort_sent(packet_number);
                    return;
                }
            };
            (packet_number, addr, packet)
        };

        let (packet_number, addr, packet) = prepared;
        if let Err(e) = udp.send_to(packet.as_ref(), addr).await {
            tracing::error!(error = %e, "UDP send error");
            if let Some(mut session) = session_manager.get(&flow_id) {
                session.transport.abort_sent(packet_number);
            }
            return;
        }
        metrics::record_packet_out(packet.len());
    }
}

fn build_wire_packet(
    flow_id: omega_core_wire::FlowId,
    session: &mut crate::session::SessionState,
    datagram: omega_transport::transport_v2::OutboundDatagram,
) -> Option<Bytes> {
    let payload_bytes = encode_transport_frames(&datagram.frames);
    let is_small = payload_bytes.len() < 500;
    let rtp_seq = session.next_rtp_seq();
    session.advance_rtp_timestamp(is_small);
    let rtp = if is_small {
        RtpHeader::opus(rtp_seq, session.rtp_timestamp, session.ssrc)
    } else {
        RtpHeader::vp8(rtp_seq, session.rtp_timestamp, session.ssrc, true)
    };
    let omega = OmegaHeader {
        flow_id,
        seq: datagram.packet_number,
        packet_type: control_packet_type(&datagram.frames),
    };

    let mut out = BytesMut::with_capacity(TOTAL_HEADER_LEN + payload_bytes.len() + AEAD_TAG_LEN);
    out.resize(TOTAL_HEADER_LEN, 0);
    rtp.write_to(&mut out[..RTP_HEADER_LEN]);
    write_protected_omega_header(
        &omega,
        &rtp,
        &session.header_protection,
        &mut out[RTP_HEADER_LEN..TOTAL_HEADER_LEN],
    );

    let aad = &out[..TOTAL_HEADER_LEN];
    let mut payload = payload_bytes;
    let nonce = session.keys.encrypt_in_place(&mut payload, aad).ok()?;
    if nonce != datagram.packet_number as u64 {
        tracing::warn!(
            expected = datagram.packet_number,
            actual = nonce,
            "transport packet number drifted from AEAD nonce"
        );
        return None;
    }
    out.extend_from_slice(&payload);
    Some(out.freeze())
}

fn classify_ip_packet(buf: &[u8]) -> TrafficClass {
    if buf.len() < 20 {
        return TrafficClass::Interactive;
    }
    match buf[0] >> 4 {
        4 => match buf[9] {
            1 | 17 => TrafficClass::Interactive,
            _ if buf.len() <= 700 => TrafficClass::Interactive,
            _ => TrafficClass::Bulk,
        },
        6 => match buf.get(6).copied().unwrap_or_default() {
            58 | 17 => TrafficClass::Interactive,
            _ if buf.len() <= 700 => TrafficClass::Interactive,
            _ => TrafficClass::Bulk,
        },
        _ if buf.len() <= 700 => TrafficClass::Interactive,
        _ => TrafficClass::Bulk,
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
    handshake_service: &HandshakeService,
    udp: &UdpSocket,
    server_mtu: u16,
    allow_legacy_v1: bool,
    morphing_policy: omega_stealth::MorphingPolicy,
    persona: PersonaId,
    admission: &SessionAdmission,
    fabric: &SharedFabric,
) {
    match handshake_service.process_client_handshake(
        buf,
        src_addr,
        session_manager,
        identity_store,
        server_mtu,
        allow_legacy_v1,
        morphing_policy,
        persona,
        admission,
        fabric,
    ) {
        Ok(HandshakeOutcome::Response {
            response,
            flow_id: Some(flow_id),
            reason: None,
        }) => {
            if let Err(e) = udp.send_to(&response, src_addr).await {
                tracing::error!(error = %e, "failed to send handshake response");
            } else {
                tracing::debug!(flow_id = %crate::session::flow_id_to_hex(&flow_id), "handshake accepted");
            }
        }
        Ok(HandshakeOutcome::Response {
            response,
            flow_id: None,
            reason: Some(reason),
        }) => {
            if let Err(e) = udp.send_to(&response, src_addr).await {
                tracing::error!(error = %e, "failed to send handshake reject");
            }
            tracing::warn!(%src_addr, reason = ?reason, "handshake rejected");
        }
        Ok(HandshakeOutcome::Response { response, .. }) => {
            if let Err(e) = udp.send_to(&response, src_addr).await {
                tracing::error!(error = %e, "failed to send handshake response");
            }
        }
        Ok(HandshakeOutcome::NoResponse) => {}
        Err(e) => {
            tracing::warn!(%src_addr, error = %e, "handshake parsing error");
        }
    }
}

fn get_ip_packet_len(buf: &[u8]) -> Option<usize> {
    if buf.is_empty() {
        return None;
    }
    match buf[0] >> 4 {
        4 if buf.len() >= 4 => Some(u16::from_be_bytes([buf[2], buf[3]]) as usize),
        6 if buf.len() >= 6 => Some(40 + u16::from_be_bytes([buf[4], buf[5]]) as usize),
        _ => None,
    }
}
