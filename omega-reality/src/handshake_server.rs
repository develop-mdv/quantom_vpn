//! REALITY server-side TLS 1.3 handshake state machine.
//!
//! Moved from `omega-server/src/reality/handshake.rs` so that `omega-client`
//! can drive the *same* code in integration tests and so the higher-level
//! crates only own the orchestration (cert sniffing, session manager
//! plumbing, etc.).
//!
//! Flight written on the wire on success:
//!     ServerHello                  (plaintext record)
//!     ChangeCipherSpec             (middlebox compat, RFC 8446 §D.4)
//!     EncryptedExtensions          (encrypted with server_handshake_traffic_secret)
//!     Certificate                  (caller-supplied leaf + chain DER)
//!     CertificateVerify            (REALITY non-standard MAC via auth_key)
//!     Finished                     (HMAC of transcript hash)

use anyhow::{anyhow, bail, Context, Result};
use rand::rngs::OsRng;
use rand::RngCore;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

use crate::auth::{
    self, derive_cv_signature_key, AuthVerdict, SESSION_ID_LEN, SHORT_ID_LEN,
};
use crate::key_schedule::{
    compute_finished_verify_data, derive_finished_key, ApplicationSecrets, CipherSuiteParams,
    EarlySecrets, HandshakeSecrets, TranscriptHashSha256,
};
use crate::record_layer::{RecordDecryptor, RecordEncryptor};
use subtle::ConstantTimeEq;
use crate::tls_messages::{
    build_certificate, build_certificate_verify, build_encrypted_extensions, build_finished,
    parse_record_header, wrap_handshake, wrap_record, ClientHelloView, ServerHelloBuilder,
    CT_CHANGE_CIPHER_SPEC, CT_HANDSHAKE, HS_CERTIFICATE, HS_CERTIFICATE_VERIFY, HS_CLIENT_HELLO,
    HS_ENCRYPTED_EXTENSIONS, HS_FINISHED, HS_SERVER_HELLO, NG_X25519, SS_ED25519,
    TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256, TLS_MAX_RECORD_CIPHERTEXT, TLS_RANDOM_LEN,
    TLS_VERSION_13, TLS_VERSION_LEGACY,
};

#[derive(Debug)]
pub enum HandshakeOutcome {
    /// Authentic Omega client; TLS server flight has been sent on the wire.
    Authentic(EstablishedTunnel),
    /// Stranger / DPI probe. Nothing has been written; caller runs proxy
    /// fallback with `captured_chlo_record` replayed verbatim upstream.
    Foreign {
        captured_chlo_record: Vec<u8>,
    },
}

#[derive(Debug)]
pub struct EstablishedTunnel {
    pub cipher_suite: u16,
    pub negotiated_sni: String,
    pub short_id: [u8; SHORT_ID_LEN],
    pub alpn: Vec<u8>,
    pub application_secrets: ApplicationSecrets,
    pub transcript_after_server_finished: [u8; 32],
    pub client_handshake_traffic_secret: [u8; 32],
    pub params: CipherSuiteParams,
}

pub struct ServerHandshakeInputs<'a> {
    pub leaf_der: &'a [u8],
    pub chain_der: &'a [Vec<u8>],
    pub fallback_sni: &'a str,
    pub server_long_term_secret: &'a StaticSecret,
    pub allowed_short_ids: &'a [[u8; SHORT_ID_LEN]],
}

pub async fn server_handshake<IO>(
    io: &mut IO,
    inputs: &ServerHandshakeInputs<'_>,
) -> Result<HandshakeOutcome>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    // ---------- 1. read ClientHello (capturing raw record bytes for proxy) ----------
    let mut header = [0u8; 5];
    io.read_exact(&mut header).await.context("read record header")?;
    let (content_type, length, _) = parse_record_header(&header)?;
    if content_type != CT_HANDSHAKE {
        bail!(
            "expected handshake record (22), got content_type={}",
            content_type
        );
    }
    if length == 0 {
        bail!("empty handshake record");
    }
    if length as usize > TLS_MAX_RECORD_CIPHERTEXT {
        bail!("handshake record too large: {}", length);
    }
    let mut chlo_hs_bytes = vec![0u8; length as usize];
    io.read_exact(&mut chlo_hs_bytes).await.context("read record body")?;
    let mut captured = Vec::with_capacity(5 + chlo_hs_bytes.len());
    captured.extend_from_slice(&header);
    captured.extend_from_slice(&chlo_hs_bytes);

    let chlo_body = strip_handshake_header(&chlo_hs_bytes, HS_CLIENT_HELLO)
        .context("decode CHLO handshake header")?;
    let chlo = ClientHelloView::parse(chlo_body).context("parse CHLO body")?;

    let foreign = || HandshakeOutcome::Foreign {
        captured_chlo_record: captured.clone(),
    };
    if !chlo.offers_tls13() || chlo.has_pre_shared_key {
        return Ok(foreign());
    }
    let client_share = match chlo.pick_x25519_key_share() {
        Some(ks) if ks.key_exchange.len() == 32 => ks,
        _ => return Ok(foreign()),
    };
    let mut client_pub = [0u8; 32];
    client_pub.copy_from_slice(client_share.key_exchange);
    let client_pubkey = PublicKey::from(client_pub);

    // ---------- 2. REALITY auth ----------
    if chlo.session_id.len() != SESSION_ID_LEN {
        return Ok(foreign());
    }
    let verdict = auth::verify_session_id(
        chlo.session_id,
        inputs.server_long_term_secret,
        &client_pubkey,
        inputs.allowed_short_ids,
    );
    let (short_id, auth_key) = match verdict {
        AuthVerdict::Authentic { short_id, auth_key } => (short_id, auth_key),
        AuthVerdict::Foreign => return Ok(foreign()),
    };

    // ---------- 3. cipher suite ----------
    let cipher_suite = match pick_cipher_suite(&chlo) {
        Ok(s) => s,
        Err(_) => return Ok(foreign()),
    };
    let params = CipherSuiteParams::for_suite(cipher_suite)?;

    // ---------- 4. server ephemeral X25519 + ECDHE ----------
    let server_eph_secret = EphemeralSecret::random_from_rng(&mut OsRng);
    let server_eph_public = PublicKey::from(&server_eph_secret);
    let ecdhe_shared = server_eph_secret.diffie_hellman(&client_pubkey);

    // ---------- 5. ServerHello ----------
    let mut server_random = [0u8; TLS_RANDOM_LEN];
    OsRng.fill_bytes(&mut server_random);
    let shlo_body = ServerHelloBuilder {
        legacy_version: TLS_VERSION_LEGACY,
        random: server_random,
        legacy_session_id_echo: chlo.session_id,
        cipher_suite,
        legacy_compression_method: 0,
        selected_group: NG_X25519,
        key_share: server_eph_public.as_bytes(),
        negotiated_version: TLS_VERSION_13,
    }
    .encode()?;
    let shlo_hs = wrap_handshake(HS_SERVER_HELLO, &shlo_body)?;

    // ---------- 6. transcript + handshake secrets ----------
    let mut transcript = TranscriptHashSha256::new();
    transcript.update(&chlo_hs_bytes);
    transcript.update(&shlo_hs);
    let transcript_after_shlo = transcript.digest();

    let early = EarlySecrets::from_psk_zero()?;
    let hs_secrets =
        HandshakeSecrets::derive(&early, ecdhe_shared.as_bytes(), &transcript_after_shlo)?;

    let mut enc = RecordEncryptor::new(&params, &hs_secrets.server_handshake_traffic_secret)?;

    // ---------- 7. ServerHello + CCS (plaintext) ----------
    let shlo_record = wrap_record(CT_HANDSHAKE, &shlo_hs)?;
    io.write_all(&shlo_record).await?;
    let ccs_record = wrap_record(CT_CHANGE_CIPHER_SPEC, &[0x01])?;
    io.write_all(&ccs_record).await?;

    // ---------- 8. EncryptedExtensions ----------
    let alpn = pick_alpn(&chlo);
    let ee_body = build_encrypted_extensions(Some(&alpn))?;
    let ee_hs = wrap_handshake(HS_ENCRYPTED_EXTENSIONS, &ee_body)?;
    transcript.update(&ee_hs);
    let ee_record = enc.seal_record(CT_HANDSHAKE, &ee_hs, 0)?;
    io.write_all(&ee_record).await?;

    // ---------- 9. Certificate ----------
    let cert_body = build_certificate(inputs.leaf_der, inputs.chain_der)?;
    let cert_hs = wrap_handshake(HS_CERTIFICATE, &cert_body)?;
    transcript.update(&cert_hs);
    let cert_record = enc.seal_record(CT_HANDSHAKE, &cert_hs, 0)?;
    io.write_all(&cert_record).await?;

    // ---------- 10. CertificateVerify (REALITY MAC) ----------
    let transcript_before_cv = transcript.digest();
    let cv_key = derive_cv_signature_key(&auth_key);
    let cv_signature = auth::compute_reality_cv_signature(&cv_key, &transcript_before_cv);
    let cv_body = build_certificate_verify(SS_ED25519, &cv_signature)?;
    let cv_hs = wrap_handshake(HS_CERTIFICATE_VERIFY, &cv_body)?;
    transcript.update(&cv_hs);
    let cv_record = enc.seal_record(CT_HANDSHAKE, &cv_hs, 0)?;
    io.write_all(&cv_record).await?;

    // ---------- 11. Finished ----------
    let transcript_before_finished = transcript.digest();
    let finished_key = derive_finished_key(&hs_secrets.server_handshake_traffic_secret)?;
    let verify_data = compute_finished_verify_data(&finished_key, &transcript_before_finished);
    let fin_body = build_finished(&verify_data);
    let fin_hs = wrap_handshake(HS_FINISHED, &fin_body)?;
    transcript.update(&fin_hs);
    let fin_record = enc.seal_record(CT_HANDSHAKE, &fin_hs, 0)?;
    io.write_all(&fin_record).await?;
    io.flush().await?;

    let transcript_after_server_finished = transcript.digest();
    let application_secrets =
        ApplicationSecrets::derive(&hs_secrets, &transcript_after_server_finished)?;

    // ---------- 12. read client CCS + client Finished, verify MAC ----------
    let mut client_dec =
        RecordDecryptor::new(&params, &hs_secrets.client_handshake_traffic_secret)?;
    // The client sends a single ChangeCipherSpec plaintext record for
    // middlebox compatibility (RFC 8446 §D.4). Skip it.
    let mut ccs_header = [0u8; 5];
    io.read_exact(&mut ccs_header).await.context("client CCS header")?;
    let (ccs_ct, ccs_len, _) = parse_record_header(&ccs_header)?;
    if ccs_ct != CT_CHANGE_CIPHER_SPEC {
        bail!(
            "expected client ChangeCipherSpec, got content_type={}",
            ccs_ct
        );
    }
    let mut ccs_body = vec![0u8; ccs_len as usize];
    io.read_exact(&mut ccs_body).await.context("client CCS body")?;

    // Encrypted handshake record containing the client Finished.
    let mut fin_header = [0u8; 5];
    io.read_exact(&mut fin_header)
        .await
        .context("client Finished record header")?;
    let (fin_ct, fin_len, _) = parse_record_header(&fin_header)?;
    if fin_ct != crate::tls_messages::CT_APPLICATION_DATA {
        bail!(
            "expected encrypted client Finished, got content_type={}",
            fin_ct
        );
    }
    if fin_len == 0 || fin_len as usize > TLS_MAX_RECORD_CIPHERTEXT {
        bail!("invalid client Finished record length {}", fin_len);
    }
    let mut fin_cipher = vec![0u8; fin_len as usize];
    io.read_exact(&mut fin_cipher)
        .await
        .context("client Finished record body")?;
    let opened = client_dec.open_record(&fin_header, &mut fin_cipher)?;
    if opened.content_type != CT_HANDSHAKE {
        bail!(
            "client Finished inner type was {} (expected handshake)",
            opened.content_type
        );
    }
    if opened.content.first().copied() != Some(HS_FINISHED) {
        bail!("expected client Finished handshake message");
    }
    if opened.content.len() < 4 {
        bail!("client Finished message too short");
    }
    let body_len = u32::from_be_bytes([0, opened.content[1], opened.content[2], opened.content[3]])
        as usize;
    if 4 + body_len != opened.content.len() {
        bail!(
            "client Finished length mismatch ({} vs {} payload)",
            body_len,
            opened.content.len() - 4
        );
    }
    let client_verify_data = &opened.content[4..];
    let client_finished_key = derive_finished_key(&hs_secrets.client_handshake_traffic_secret)?;
    let expected_client_verify_data =
        compute_finished_verify_data(&client_finished_key, &transcript_after_server_finished);
    if !bool::from(expected_client_verify_data.ct_eq(client_verify_data)) {
        bail!("client Finished verify_data mismatch — REALITY auth was valid but session is corrupted");
    }

    let sni = chlo
        .sni
        .clone()
        .unwrap_or_else(|| inputs.fallback_sni.to_string());

    Ok(HandshakeOutcome::Authentic(EstablishedTunnel {
        cipher_suite,
        negotiated_sni: sni,
        short_id,
        alpn,
        application_secrets,
        transcript_after_server_finished,
        client_handshake_traffic_secret: hs_secrets.client_handshake_traffic_secret,
        params,
    }))
}

fn strip_handshake_header(bytes: &[u8], expected_type: u8) -> Result<&[u8]> {
    if bytes.len() < 4 {
        bail!("handshake message too short ({})", bytes.len());
    }
    if bytes[0] != expected_type {
        bail!(
            "unexpected handshake type: got {}, want {}",
            bytes[0],
            expected_type
        );
    }
    let body_len = u32::from_be_bytes([0, bytes[1], bytes[2], bytes[3]]) as usize;
    if 4 + body_len > bytes.len() {
        bail!(
            "handshake message length {} > available {}",
            body_len,
            bytes.len() - 4
        );
    }
    Ok(&bytes[4..4 + body_len])
}

fn pick_cipher_suite(chlo: &ClientHelloView<'_>) -> Result<u16> {
    for &offered in &chlo.cipher_suites {
        if offered == TLS_AES_128_GCM_SHA256 || offered == TLS_CHACHA20_POLY1305_SHA256 {
            return Ok(offered);
        }
    }
    Err(anyhow!(
        "no mutually supported cipher suite (client offered: {:?})",
        chlo.cipher_suites
    ))
}

fn pick_alpn(chlo: &ClientHelloView<'_>) -> Vec<u8> {
    for offered in &chlo.alpn {
        if **offered == b"http/1.1"[..] {
            return offered.to_vec();
        }
    }
    b"http/1.1".to_vec()
}
