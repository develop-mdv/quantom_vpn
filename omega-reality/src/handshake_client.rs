//! Client-side REALITY TLS 1.3 handshake.
//!
//! Mirrors `omega_server::reality::handshake::server_handshake`:
//!   1. Build a Chrome-shaped ClientHello with a REALITY auth tag in
//!      `session_id` and an X25519 key_share, send it.
//!   2. Read the server flight: ServerHello (plaintext), the throwaway
//!      ChangeCipherSpec record, then EncryptedExtensions, Certificate,
//!      CertificateVerify, Finished — all under the server handshake
//!      traffic key.
//!   3. Verify the REALITY CertificateVerify signature using the long-term
//!      X25519 server pubkey we know out-of-band.
//!   4. Verify the server `Finished` MAC.
//!   5. Send our own `Finished` under the client handshake traffic key.
//!   6. Derive application traffic secrets and hand them to the caller.

use anyhow::{anyhow, bail, Context, Result};
use crate::auth::{
    self, derive_cv_signature_key, encode_session_id, verify_reality_cv_signature,
    SESSION_ID_LEN, SHORT_ID_LEN,
};
use crate::key_schedule::{
    compute_finished_verify_data, derive_finished_key, ApplicationSecrets, CipherSuiteParams,
    EarlySecrets, HandshakeSecrets, TranscriptHashSha256,
};
use crate::record_layer::{RecordDecryptor, RecordEncryptor};
use crate::tls_messages::{
    build_finished, parse_record_header, wrap_handshake, wrap_record, Reader,
    CT_APPLICATION_DATA, CT_CHANGE_CIPHER_SPEC, CT_HANDSHAKE, HS_CERTIFICATE,
    HS_CERTIFICATE_VERIFY, HS_ENCRYPTED_EXTENSIONS, HS_FINISHED, HS_SERVER_HELLO,
    NG_X25519, TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256,
    TLS_MAX_RECORD_CIPHERTEXT, TLS_RANDOM_LEN, TLS_VERSION_13,
};
use rand::rngs::OsRng;
use rand::RngCore;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::utls::{build_client_hello, ClientHelloPlan};

/// Inputs that the caller must provide to drive the client handshake.
pub struct ClientHandshakeInputs<'a> {
    pub server_name: &'a str,
    pub server_long_term_pubkey: &'a PublicKey,
    pub short_id: [u8; SHORT_ID_LEN],
    /// Optional ALPN offer list — Phase 4 always uses `["http/1.1"]`.
    pub alpn_offer: Option<&'a [&'a [u8]]>,
}

/// Output of [`client_handshake`]: everything needed by the caller to keep
/// sending VPN payload under the established application keys.
#[derive(Debug)]
pub struct ClientEstablished {
    pub cipher_suite: u16,
    pub params: CipherSuiteParams,
    pub application_secrets: ApplicationSecrets,
    pub transcript_after_client_finished: [u8; 32],
    pub server_leaf_cert_der: Option<Vec<u8>>,
}

/// Drive the full client-side TLS 1.3 + REALITY handshake on `io`. On
/// success the connection is in the "application data" phase: the caller
/// constructs a [`RecordEncryptor`] / [`RecordDecryptor`] from the
/// application secrets and starts pumping VPN frames.
pub async fn client_handshake<IO>(
    io: &mut IO,
    inputs: &ClientHandshakeInputs<'_>,
) -> Result<ClientEstablished>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    // ---------- 1. client key pair + auth ----------
    let client_secret = StaticSecret::random_from_rng(&mut OsRng);
    let client_pub = PublicKey::from(&client_secret);
    let auth_key = auth::derive_auth_key(&client_secret, inputs.server_long_term_pubkey);
    let session_id = encode_session_id(&inputs.short_id, &auth_key);

    let mut client_random = [0u8; TLS_RANDOM_LEN];
    OsRng.fill_bytes(&mut client_random);

    // ---------- 2. build & send ClientHello ----------
    let chlo = build_client_hello(&ClientHelloPlan {
        server_name: inputs.server_name,
        session_id: &session_id,
        client_random: &client_random,
        client_x25519_public: client_pub.as_bytes(),
        alpn_offer: inputs.alpn_offer,
    })?;
    io.write_all(&chlo.record_wire).await?;
    io.flush().await?;

    let mut transcript = TranscriptHashSha256::new();
    transcript.update(&chlo.handshake_message);

    // ---------- 3. read ServerHello (plaintext handshake record) ----------
    let (shlo_ct, shlo_body) = read_plain_record(io).await.context("read ServerHello")?;
    if shlo_ct != CT_HANDSHAKE {
        bail!(
            "expected ServerHello in handshake record, got content_type={}",
            shlo_ct
        );
    }
    let shlo_hs_type = shlo_body
        .first()
        .copied()
        .ok_or_else(|| anyhow!("empty SHLO record"))?;
    if shlo_hs_type != HS_SERVER_HELLO {
        bail!("expected SERVER_HELLO, got handshake type {}", shlo_hs_type);
    }
    transcript.update(&shlo_body);

    let shlo_view = parse_server_hello(&shlo_body[4..]).context("parse SHLO")?;
    if shlo_view.cipher_suite != TLS_AES_128_GCM_SHA256
        && shlo_view.cipher_suite != TLS_CHACHA20_POLY1305_SHA256
    {
        bail!(
            "server picked unsupported cipher suite 0x{:04x}",
            shlo_view.cipher_suite
        );
    }
    if shlo_view.selected_group != NG_X25519 {
        bail!(
            "server picked unsupported key_share group 0x{:04x}",
            shlo_view.selected_group
        );
    }
    if shlo_view.server_pubkey.len() != 32 {
        bail!(
            "server key_share has wrong length: {}",
            shlo_view.server_pubkey.len()
        );
    }
    let mut server_eph_pub_bytes = [0u8; 32];
    server_eph_pub_bytes.copy_from_slice(&shlo_view.server_pubkey);
    let server_eph_pub = PublicKey::from(server_eph_pub_bytes);
    let ecdhe_shared = client_secret.diffie_hellman(&server_eph_pub);

    let params = CipherSuiteParams::for_suite(shlo_view.cipher_suite)?;
    let transcript_after_shlo = transcript.digest();
    let early = EarlySecrets::from_psk_zero()?;
    let hs_secrets =
        HandshakeSecrets::derive(&early, ecdhe_shared.as_bytes(), &transcript_after_shlo)?;

    // ---------- 4. read & discard CCS (middlebox compat) ----------
    let (ccs_ct, _) = read_plain_record(io).await.context("read CCS")?;
    if ccs_ct != CT_CHANGE_CIPHER_SPEC {
        // Some servers omit the CCS; treat unexpected content_type as an
        // encrypted record we should re-feed to the decryptor below. We
        // can't easily put bytes back, so we require CCS here.
        bail!("expected ChangeCipherSpec, got content_type={}", ccs_ct);
    }

    // ---------- 5. set up encrypted decryptor ----------
    let mut server_dec =
        RecordDecryptor::new(&params, &hs_secrets.server_handshake_traffic_secret)?;

    // EncryptedExtensions
    let ee_hs = read_encrypted_handshake(io, &mut server_dec)
        .await
        .context("read EncryptedExtensions")?;
    if ee_hs.first().copied() != Some(HS_ENCRYPTED_EXTENSIONS) {
        bail!("expected EncryptedExtensions");
    }
    transcript.update(&ee_hs);

    // Certificate
    let cert_hs = read_encrypted_handshake(io, &mut server_dec)
        .await
        .context("read Certificate")?;
    if cert_hs.first().copied() != Some(HS_CERTIFICATE) {
        bail!("expected Certificate");
    }
    transcript.update(&cert_hs);
    let server_leaf_cert_der = extract_leaf_cert(&cert_hs[4..]);

    // CertificateVerify
    let transcript_before_cv = transcript.digest();
    let cv_hs = read_encrypted_handshake(io, &mut server_dec)
        .await
        .context("read CertificateVerify")?;
    if cv_hs.first().copied() != Some(HS_CERTIFICATE_VERIFY) {
        bail!("expected CertificateVerify");
    }
    let cv_signature =
        extract_cv_signature(&cv_hs[4..]).context("parse CertificateVerify body")?;
    let cv_key = derive_cv_signature_key(&auth_key);
    if !verify_reality_cv_signature(&cv_key, &transcript_before_cv, &cv_signature) {
        bail!(
            "REALITY CertificateVerify signature failed — server is not in possession of \
             the expected long-term X25519 key (or transcript drift)"
        );
    }
    transcript.update(&cv_hs);

    // Server Finished
    let transcript_before_server_fin = transcript.digest();
    let fin_hs = read_encrypted_handshake(io, &mut server_dec)
        .await
        .context("read server Finished")?;
    if fin_hs.first().copied() != Some(HS_FINISHED) {
        bail!("expected Finished");
    }
    let server_finished_key =
        derive_finished_key(&hs_secrets.server_handshake_traffic_secret)?;
    let expected_server_verify_data =
        compute_finished_verify_data(&server_finished_key, &transcript_before_server_fin);
    let presented_server_verify_data = &fin_hs[4..];
    if presented_server_verify_data != expected_server_verify_data {
        bail!("server Finished verify_data mismatch");
    }
    transcript.update(&fin_hs);

    // ---------- 6. derive application secrets ----------
    let transcript_after_server_finished = transcript.digest();
    let application_secrets =
        ApplicationSecrets::derive(&hs_secrets, &transcript_after_server_finished)?;

    // ---------- 7. send client Finished ----------
    let mut client_enc =
        RecordEncryptor::new(&params, &hs_secrets.client_handshake_traffic_secret)?;
    // RFC 8446 §D.4 — clients also send a dummy CCS for compatibility.
    let ccs_out = wrap_record(CT_CHANGE_CIPHER_SPEC, &[0x01])?;
    io.write_all(&ccs_out).await?;
    let client_finished_key =
        derive_finished_key(&hs_secrets.client_handshake_traffic_secret)?;
    let client_verify_data =
        compute_finished_verify_data(&client_finished_key, &transcript_after_server_finished);
    let client_fin_hs = wrap_handshake(HS_FINISHED, &build_finished(&client_verify_data))?;
    transcript.update(&client_fin_hs);
    let client_fin_record = client_enc.seal_record(CT_HANDSHAKE, &client_fin_hs, 0)?;
    io.write_all(&client_fin_record).await?;
    io.flush().await?;

    let transcript_after_client_finished = transcript.digest();

    Ok(ClientEstablished {
        cipher_suite: shlo_view.cipher_suite,
        params,
        application_secrets,
        transcript_after_client_finished,
        server_leaf_cert_der,
    })
}

// -----------------------------------------------------------------------------
// helpers
// -----------------------------------------------------------------------------

async fn read_plain_record<IO>(io: &mut IO) -> Result<(u8, Vec<u8>)>
where
    IO: AsyncRead + Unpin,
{
    let mut header = [0u8; 5];
    io.read_exact(&mut header).await.context("record header")?;
    let (content_type, length, _) = parse_record_header(&header)?;
    if length == 0 || length as usize > TLS_MAX_RECORD_CIPHERTEXT {
        bail!("invalid record length {}", length);
    }
    let mut body = vec![0u8; length as usize];
    io.read_exact(&mut body).await.context("record body")?;
    Ok((content_type, body))
}

/// Read one encrypted record from `io` and decrypt it; expect a single
/// handshake message inside.
async fn read_encrypted_handshake<IO>(
    io: &mut IO,
    decryptor: &mut RecordDecryptor,
) -> Result<Vec<u8>>
where
    IO: AsyncRead + Unpin,
{
    let mut header = [0u8; 5];
    io.read_exact(&mut header).await.context("record header")?;
    let (content_type, length, _) = parse_record_header(&header)?;
    if content_type != CT_APPLICATION_DATA {
        bail!(
            "expected application_data (encrypted handshake), got content_type={}",
            content_type
        );
    }
    if length == 0 || length as usize > TLS_MAX_RECORD_CIPHERTEXT {
        bail!("invalid encrypted record length {}", length);
    }
    let mut cipher = vec![0u8; length as usize];
    io.read_exact(&mut cipher).await.context("record body")?;
    let plaintext = decryptor.open_record(&header, &mut cipher)?;
    if plaintext.content_type != CT_HANDSHAKE {
        bail!(
            "encrypted record inner type was {} (expected handshake)",
            plaintext.content_type
        );
    }
    Ok(plaintext.content)
}

#[derive(Debug)]
struct ServerHelloView<'a> {
    cipher_suite: u16,
    selected_group: u16,
    server_pubkey: &'a [u8],
}

fn parse_server_hello(body: &[u8]) -> Result<ServerHelloView<'_>> {
    let mut r = Reader::new(body);
    let _legacy_version = r.u16()?;
    let _random = r.take(32)?;
    let _session_id = r.vec_u8()?;
    let cipher_suite = r.u16()?;
    let _legacy_compression = r.u8()?;
    let ext_blob = r.vec_u16()?;
    let mut er = Reader::new(ext_blob);
    let mut selected_group = 0u16;
    let mut server_pubkey: &[u8] = &[];
    let mut supported_versions_ok = false;
    while !er.is_empty() {
        let ext_type = er.u16()?;
        let ext_data = er.vec_u16()?;
        match ext_type {
            0x002b /* supported_versions */ => {
                if ext_data.len() == 2 {
                    let v = u16::from_be_bytes([ext_data[0], ext_data[1]]);
                    if v == TLS_VERSION_13 {
                        supported_versions_ok = true;
                    }
                }
            }
            0x0033 /* key_share — server variant: single entry, no list */ => {
                let mut kr = Reader::new(ext_data);
                selected_group = kr.u16()?;
                server_pubkey = kr.vec_u16()?;
            }
            _ => {}
        }
    }
    if !supported_versions_ok {
        bail!("server did not negotiate TLS 1.3");
    }
    if selected_group == 0 {
        bail!("server did not include key_share extension");
    }
    Ok(ServerHelloView {
        cipher_suite,
        selected_group,
        server_pubkey,
    })
}

fn extract_leaf_cert(body: &[u8]) -> Option<Vec<u8>> {
    let mut r = Reader::new(body);
    // certificate_request_context (u8 length, server: empty)
    let _ = r.vec_u8().ok()?;
    let list = r.vec_u24().ok()?;
    let mut lr = Reader::new(list);
    let leaf = lr.vec_u24().ok()?;
    Some(leaf.to_vec())
}

fn extract_cv_signature(body: &[u8]) -> Result<Vec<u8>> {
    let mut r = Reader::new(body);
    let _algorithm = r.u16()?;
    let sig = r.vec_u16()?;
    Ok(sig.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls_messages::{
        build_certificate_verify, record_header, wrap_handshake, Writer, EXT_KEY_SHARE,
        EXT_SUPPORTED_VERSIONS, HS_SERVER_HELLO, SS_ED25519, TLS_RANDOM_LEN, TLS_VERSION_13,
        TLS_VERSION_LEGACY,
    };

    #[test]
    fn parse_minimal_server_hello() {
        // Build a SHLO body with supported_versions+key_share extensions.
        let mut body = Writer::new();
        body.push_u16(TLS_VERSION_LEGACY);
        body.push_slice(&[0u8; TLS_RANDOM_LEN]);
        body.vec_u8(|w| w.push_slice(&[0u8; 32])).unwrap();
        body.push_u16(TLS_AES_128_GCM_SHA256);
        body.push_u8(0);
        body.vec_u16(|w| {
            w.push_u16(EXT_SUPPORTED_VERSIONS);
            w.vec_u16(|w| w.push_u16(TLS_VERSION_13)).unwrap();
            w.push_u16(EXT_KEY_SHARE);
            w.vec_u16(|w| {
                w.push_u16(NG_X25519);
                w.vec_u16(|w| w.push_slice(&[0x42u8; 32])).unwrap();
            })
            .unwrap();
        })
        .unwrap();
        let bytes = body.into_bytes();
        let view = parse_server_hello(&bytes).unwrap();
        assert_eq!(view.cipher_suite, TLS_AES_128_GCM_SHA256);
        assert_eq!(view.selected_group, NG_X25519);
        assert_eq!(view.server_pubkey, &[0x42u8; 32]);
    }

    #[test]
    fn extract_cv_signature_parses_64_byte_body() {
        let sig = [0xABu8; 64];
        let body = build_certificate_verify(SS_ED25519, &sig).unwrap();
        let parsed = extract_cv_signature(&body).unwrap();
        assert_eq!(parsed, sig);
    }
}
