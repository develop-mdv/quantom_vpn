//! VPN data pipe through an established REALITY TLS 1.3 record layer.
//!
//! After `handshake_server::server_handshake` returns `Authentic`, this
//! module is responsible for what `datapath::tcp_connection_loop` does for
//! the plain framed-TCP transport: read the first STUN-wrapped ML-KEM
//! ClientHello from the client (now arriving inside an encrypted TLS
//! application-data record), drive `omega::handshake::process_client_handshake`,
//! plug the resulting session into the session manager, and then loop over
//! incoming records calling `datapath::handle_client_frame`.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use omega_reality::handshake_server::EstablishedTunnel;
use omega_reality::record_layer::{RecordDecryptor, RecordEncryptor};
use omega_reality::tls_messages::{
    parse_record_header, CT_APPLICATION_DATA, CT_CHANGE_CIPHER_SPEC, TLS_MAX_RECORD_CIPHERTEXT,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;

use crate::handshake::{self, HandshakeOutcome};
use crate::identity::IdentityStore;
use crate::session::SessionManager;

/// Run the VPN payload pipe over an already-established REALITY tunnel.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    stream: TcpStream,
    peer_addr: SocketAddr,
    established: EstablishedTunnel,
    tun: Arc<tun_rs::AsyncDevice>,
    udp: Arc<UdpSocket>,
    session_manager: Arc<SessionManager>,
    identity_store: Arc<IdentityStore>,
    server_mtu: u16,
    allow_legacy_v1: bool,
    morphing_policy: crate::runtime::MorphingPolicy,
) -> Result<()> {
    let params = established.params;
    let mut encryptor = RecordEncryptor::new(
        &params,
        &established
            .application_secrets
            .server_application_traffic_secret_0,
    )?;
    let mut decryptor = RecordDecryptor::new(
        &params,
        &established
            .application_secrets
            .client_application_traffic_secret_0,
    )?;

    let (mut reader, mut writer) = stream.into_split();

    // Egress channel: anything our datapath wants to send back to the client
    // arrives here; the writer task wraps it in an encrypted record.
    let (tx, mut rx) = mpsc::channel::<Bytes>(512);
    let writer_task = tokio::spawn(async move {
        while let Some(packet) = rx.recv().await {
            let wire = match encryptor.seal_record(CT_APPLICATION_DATA, packet.as_ref(), 0) {
                Ok(w) => w,
                Err(err) => {
                    tracing::warn!(error = %err, "REALITY: failed to seal egress record");
                    break;
                }
            };
            if let Err(err) = writer.write_all(&wire).await {
                tracing::debug!(error = %err, "REALITY: writer closed");
                break;
            }
        }
    });

    // ---- 1. First encrypted record == STUN-wrapped ML-KEM ClientHello ----
    let first = match read_one_record(&mut reader, &mut decryptor).await? {
        Some(payload) => payload,
        None => {
            writer_task.abort();
            bail!("REALITY tunnel closed before sending Omega ClientHello");
        }
    };
    if !crate::datapath::is_stun_packet(&first) {
        writer_task.abort();
        bail!("first REALITY application-data record was not a STUN handshake");
    }

    let flow_id = match handshake::process_client_handshake(
        &first,
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
            let _ = tx.send(Bytes::from(response)).await;
            flow_id
        }
        Ok(HandshakeOutcome::Rejected { response, reason }) => {
            tracing::warn!(%peer_addr, ?reason, "REALITY: Omega handshake rejected");
            let _ = tx.send(Bytes::from(response)).await;
            // Give the writer a chance to flush the rejection record.
            drop(tx);
            let _ = writer_task.await;
            return Ok(());
        }
        Err(err) => {
            writer_task.abort();
            return Err(err.into());
        }
    };

    // ---- 2. Data loop ----
    loop {
        let payload = match read_one_record(&mut reader, &mut decryptor).await {
            Ok(Some(p)) => p,
            Ok(None) => break,
            Err(err) => {
                tracing::debug!(%peer_addr, error = %err, "REALITY: read error, closing");
                break;
            }
        };
        crate::datapath::handle_client_frame(
            &payload,
            peer_addr,
            &tun,
            &udp,
            &session_manager,
            true,
        )
        .await;
    }

    if let Some(mut session) = session_manager.get(&flow_id) {
        session.clear_tcp_egress();
    }
    writer_task.abort();
    Ok(())
}

/// Read one TLS application-data record from `reader`, decrypt it, and return
/// the inner payload. Returns `Ok(None)` if the stream closed cleanly.
async fn read_one_record<R>(
    reader: &mut R,
    decryptor: &mut RecordDecryptor,
) -> Result<Option<Vec<u8>>>
where
    R: AsyncReadExt + Unpin,
{
    loop {
        let mut header = [0u8; 5];
        match reader.read_exact(&mut header).await {
            Ok(_) => {}
            Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(err) => return Err(err).context("read record header"),
        }
        let (content_type, length, _) = parse_record_header(&header)?;
        if length == 0 || length as usize > TLS_MAX_RECORD_CIPHERTEXT {
            bail!("invalid record length {}", length);
        }
        let mut body = vec![0u8; length as usize];
        reader
            .read_exact(&mut body)
            .await
            .context("read record body")?;
        match content_type {
            CT_APPLICATION_DATA => {
                let opened = decryptor.open_record(&header, &mut body)?;
                // After handshake the only legitimate inner type is
                // application_data; ignore anything else (Alert handling is
                // out of scope for Phase 4).
                if opened.content_type == CT_APPLICATION_DATA {
                    return Ok(Some(opened.content));
                }
            }
            CT_CHANGE_CIPHER_SPEC => {
                // Middlebox-compat CCS that might still trail in; skip.
                continue;
            }
            _ => bail!("unexpected record content_type={}", content_type),
        }
    }
}
