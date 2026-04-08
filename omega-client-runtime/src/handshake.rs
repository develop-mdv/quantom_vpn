use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::Context;
use kem::Decapsulate;
use ml_kem::{EncodedSizeUser, KemCore, MlKem768};
use rand::RngCore;
use tokio::net::UdpSocket;

use omega_core_crypto::{
    derive_credential_key, derive_hybrid_handshake_secrets, derive_resumption_handshake_secrets,
    hash_transcript, seal_with_key, HandshakeSecrets, X25519Keypair,
};
use omega_core_wire::{
    ClientAuthV2, ClientCredentialPayload, ClientInitV2, ClientKemChunkV2, ClientResumeV2,
    ConnectionId, HandshakeReject, HandshakeRejectReason, ServerCompleteV2, ServerRetryV2,
    StunWrapper, CREDENTIAL_NONCE_LEN, DEFAULT_KEM_CHUNK_LEN,
};

use crate::config::ClientConfig;
use omega_stealth::StealthEngine;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

const DEFAULT_RESUMPTION_TICKET_PATH: &str = "omega-client/state/resumption_ticket.hex";
const MAX_STORED_RESUMPTION_BYTES: usize = 4096;
const MAX_RESUMPTION_TICKET_BYTES: usize = 2048;

type DecapKey768 = <MlKem768 as KemCore>::DecapsulationKey;

pub struct HandshakeV2Result {
    pub complete: ServerCompleteV2,
    pub secrets: HandshakeSecrets,
    pub rtt_ms: u64,
}

pub async fn perform_handshake_v2(
    udp: &UdpSocket,
    server_addr: SocketAddr,
    credentials: &ClientCredentialPayload,
    config: &ClientConfig,
) -> anyhow::Result<HandshakeV2Result> {
    let attempts = config.handshake_attempts;
    let timeout_ms = config.handshake_timeout_ms;
    let backoff_ms = config.handshake_backoff_ms;
    let stored_ticket = load_resumption_ticket();
    let mut buf = vec![0u8; 4096];
    let mut last_error = String::from("timeout");

    for attempt in 1..=attempts {
        let started_at = Instant::now();
        let connection_id = random_connection_id();
        let x25519 = X25519Keypair::generate();
        let init_grease_len = StealthEngine::new(config.persona).client_init_grease_len();
        let init = ClientInitV2 {
            connection_id,
            client_mtu: config.requested_mtu,
            fec_support: true,
            client_x25519_public: x25519.public(),
            grease: random_grease(init_grease_len),
        };
        let retry = match send_and_wait_retry(udp, server_addr, &init, &mut buf, timeout_ms).await {
            Ok(v) => v,
            Err(err) => {
                last_error = err.to_string();
                if attempt < attempts {
                    tokio::time::sleep(Duration::from_millis(
                        backoff_ms.saturating_mul(attempt as u64),
                    ))
                    .await;
                    continue;
                }
                break;
            }
        };

        if let Some(stored) = stored_ticket.as_ref() {
            match try_resume(
                udp,
                server_addr,
                &init,
                &retry,
                stored,
                &x25519,
                &mut buf,
                timeout_ms,
                started_at,
            )
            .await
            {
                Ok(Some(result)) => {
                    save_resumption_ticket(
                        &result.complete.resumption_ticket,
                        &result.secrets.resumption_secret,
                    )?;
                    return Ok(result);
                }
                Ok(None) => {}
                Err(err) => {
                    tracing::debug!(error = %err, "resumption attempt fell back to full handshake");
                }
            }
        }

        match complete_full_handshake(
            udp,
            server_addr,
            credentials,
            &init,
            &retry,
            &x25519,
            &mut buf,
            timeout_ms,
            started_at,
        )
        .await
        {
            Ok(result) => {
                save_resumption_ticket(
                    &result.complete.resumption_ticket,
                    &result.secrets.resumption_secret,
                )?;
                return Ok(result);
            }
            Err(err) => {
                last_error = err.to_string();
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
        "handshake v2 failed after {} attempts: {}",
        attempts,
        last_error
    ))
}

async fn send_and_wait_retry(
    udp: &UdpSocket,
    server_addr: SocketAddr,
    init: &ClientInitV2,
    buf: &mut [u8],
    timeout_ms: u64,
) -> anyhow::Result<ServerRetryV2> {
    let txn_id: [u8; 12] = rand::random();
    let request = StunWrapper::wrap_request(&txn_id, &init.serialize());
    udp.send_to(&request, server_addr).await?;

    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    loop {
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            break;
        };
        match tokio::time::timeout(remaining, udp.recv_from(buf)).await {
            Ok(Ok((n, _))) => {
                let Some((is_request, resp_txn, payload)) = StunWrapper::parse(&buf[..n]) else {
                    continue;
                };
                if is_request || resp_txn != txn_id {
                    continue;
                }
                if let Some(retry) = ServerRetryV2::deserialize(payload) {
                    return Ok(retry);
                }
                if let Some(reject) = HandshakeReject::deserialize(payload) {
                    return Err(anyhow::anyhow!(
                        "handshake retry rejected: {:?}",
                        reject.reason
                    ));
                }
            }
            Ok(Err(err)) => return Err(err.into()),
            Err(_) => break,
        }
    }
    Err(anyhow::anyhow!("retry timeout after {} ms", timeout_ms))
}

async fn try_resume(
    udp: &UdpSocket,
    server_addr: SocketAddr,
    init: &ClientInitV2,
    retry: &ServerRetryV2,
    stored: &StoredResumption,
    x25519: &X25519Keypair,
    buf: &mut [u8],
    timeout_ms: u64,
    started_at: Instant,
) -> anyhow::Result<Option<HandshakeV2Result>> {
    let resume = ClientResumeV2 {
        connection_id: init.connection_id,
        client_x25519_public: x25519.public(),
        cookie: retry.cookie.clone(),
        ticket: stored.ticket.clone(),
    };
    let txn_id: [u8; 12] = rand::random();
    let request = StunWrapper::wrap_request(&txn_id, &resume.serialize());
    udp.send_to(&request, server_addr).await?;

    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    loop {
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            break;
        };
        match tokio::time::timeout(remaining, udp.recv_from(buf)).await {
            Ok(Ok((n, _))) => {
                let Some((is_request, resp_txn, payload)) = StunWrapper::parse(&buf[..n]) else {
                    continue;
                };
                if is_request || resp_txn != txn_id {
                    continue;
                }
                if let Some(complete) = ServerCompleteV2::deserialize(payload) {
                    if !complete.resumed {
                        return Ok(None);
                    }
                    let x25519_shared = x25519.diffie_hellman(&retry.server_x25519_public);
                    let transcript_hash = hash_transcript(&[
                        canonical_init(init).as_slice(),
                        canonical_retry(retry).as_slice(),
                        resume.serialize().as_slice(),
                    ]);

                    let secrets = derive_resumption_handshake_secrets(
                        &x25519_shared,
                        &stored.secret,
                        &transcript_hash,
                        false,
                    )
                    .map_err(|err| anyhow::anyhow!(err.to_string()))?;
                    return Ok(Some(HandshakeV2Result {
                        complete,
                        secrets,
                        rtt_ms: started_at.elapsed().as_millis() as u64,
                    }));
                }
                if let Some(reject) = HandshakeReject::deserialize(payload) {
                    return match reject.reason {
                        HandshakeRejectReason::AuthFailed
                        | HandshakeRejectReason::Malformed
                        | HandshakeRejectReason::VersionMismatch => Ok(None),
                        reason => Err(anyhow::anyhow!("resume rejected: {:?}", reason)),
                    };
                }
            }
            Ok(Err(err)) => return Err(err.into()),
            Err(_) => break,
        }
    }

    Ok(None)
}

async fn complete_full_handshake(
    udp: &UdpSocket,
    server_addr: SocketAddr,
    credentials: &ClientCredentialPayload,
    init: &ClientInitV2,
    retry: &ServerRetryV2,
    x25519: &X25519Keypair,
    buf: &mut [u8],
    timeout_ms: u64,
    started_at: Instant,
) -> anyhow::Result<HandshakeV2Result> {
    let mut rng = rand::thread_rng();
    let (decap_key, encap_key) = MlKem768::generate(&mut rng);
    let x25519_shared = x25519.diffie_hellman(&retry.server_x25519_public);
    let credential_key =
        derive_credential_key(&x25519_shared, &retry.cookie, init.connection_id.as_bytes())
            .map_err(|err| anyhow::anyhow!(err.to_string()))?;
    let credential_nonce = random_nonce();
    let credential_ciphertext = seal_with_key(
        &credential_key,
        credential_nonce,
        init.connection_id.as_bytes(),
        &credentials.serialize(),
    )
    .map_err(|err| anyhow::anyhow!(err.to_string()))?;
    let auth = ClientAuthV2 {
        connection_id: init.connection_id,
        client_x25519_public: x25519.public(),
        cookie: retry.cookie.clone(),
        credential_nonce,
        credential_ciphertext,
    };

    let auth_request = StunWrapper::wrap_request(&rand::random(), &auth.serialize());
    udp.send_to(&auth_request, server_addr).await?;

    let kem_bytes = encap_key.as_bytes().to_vec();
    let chunks = ClientKemChunkV2::split(init.connection_id, &kem_bytes, DEFAULT_KEM_CHUNK_LEN);
    for (idx, chunk) in chunks.iter().enumerate() {
        let txn_id: [u8; 12] = rand::random();
        let request = StunWrapper::wrap_request(&txn_id, &chunk.serialize());
        udp.send_to(&request, server_addr).await?;
        if idx + 1 == chunks.len() {
            let complete = wait_for_complete(udp, buf, txn_id, timeout_ms).await?;
            let ct_array: &ml_kem::Ciphertext<MlKem768> = complete
                .ciphertext
                .as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid ML-KEM ciphertext length"))?;
            let mlkem_shared = decapsulate(&decap_key, ct_array)?;
            let transcript_hash = hash_transcript(&[
                canonical_init(init).as_slice(),
                canonical_retry(retry).as_slice(),
                auth.serialize().as_slice(),
                kem_bytes.as_slice(),
            ]);
            let secrets = derive_hybrid_handshake_secrets(
                &x25519_shared,
                &mlkem_shared,
                &transcript_hash,
                false,
            )
            .map_err(|err| anyhow::anyhow!(err.to_string()))?;
            return Ok(HandshakeV2Result {
                complete,
                secrets,
                rtt_ms: started_at.elapsed().as_millis() as u64,
            });
        }
    }

    Err(anyhow::anyhow!("no final KEM chunk sent"))
}

async fn wait_for_complete(
    udp: &UdpSocket,
    buf: &mut [u8],
    txn_id: [u8; 12],
    timeout_ms: u64,
) -> anyhow::Result<ServerCompleteV2> {
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    loop {
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            break;
        };
        match tokio::time::timeout(remaining, udp.recv_from(buf)).await {
            Ok(Ok((n, _))) => {
                let Some((is_request, resp_txn, payload)) = StunWrapper::parse(&buf[..n]) else {
                    continue;
                };
                if is_request || resp_txn != txn_id {
                    continue;
                }
                if let Some(complete) = ServerCompleteV2::deserialize(payload) {
                    return Ok(complete);
                }
                if let Some(reject) = HandshakeReject::deserialize(payload) {
                    return Err(anyhow::anyhow!(
                        "server rejected handshake: {:?}",
                        reject.reason
                    ));
                }
                return Err(anyhow::anyhow!("malformed handshake completion payload"));
            }
            Ok(Err(err)) => return Err(err.into()),
            Err(_) => break,
        }
    }
    Err(anyhow::anyhow!(
        "server did not complete handshake within {} ms",
        timeout_ms
    ))
}

fn decapsulate(
    decap_key: &DecapKey768,
    ciphertext: &ml_kem::Ciphertext<MlKem768>,
) -> anyhow::Result<Vec<u8>> {
    let shared = decap_key
        .decapsulate(ciphertext)
        .map_err(|_| anyhow::anyhow!("ML-KEM decapsulation failed"))?;
    let bytes: &[u8] = shared.as_ref();
    Ok(bytes.to_vec())
}

fn canonical_init(init: &ClientInitV2) -> Vec<u8> {
    let mut canonical = init.clone();
    canonical.grease.clear();
    canonical.serialize()
}

fn canonical_retry(retry: &ServerRetryV2) -> Vec<u8> {
    let mut canonical = retry.clone();
    canonical.grease.clear();
    canonical.serialize()
}

fn random_connection_id() -> ConnectionId {
    let mut out = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut out);
    ConnectionId(out)
}

fn random_grease(len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    rand::thread_rng().fill_bytes(&mut out);
    out
}

fn random_nonce() -> [u8; CREDENTIAL_NONCE_LEN] {
    let mut out = [0u8; CREDENTIAL_NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut out);
    out
}

fn ticket_path() -> PathBuf {
    std::env::var("OMEGA_RESUME_TICKET_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_RESUMPTION_TICKET_PATH))
}

fn load_resumption_ticket() -> Option<StoredResumption> {
    let path = ticket_path();
    let raw = fs::read(&path).ok()?;
    if raw.len() > MAX_STORED_RESUMPTION_BYTES {
        return None;
    }
    let text = std::str::from_utf8(&raw).ok()?;
    parse_stored_resumption(text)
}

fn save_resumption_ticket(ticket: &[u8], secret: &[u8; 32]) -> anyhow::Result<()> {
    let path = ticket_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let payload = format!(
        "ticket={}\nsecret={}\n",
        hex_encode(ticket),
        hex_encode(secret)
    );
    write_private_file(&path, payload.as_bytes())
}

fn write_private_file(path: &Path, payload: &[u8]) -> anyhow::Result<()> {
    let temp_path = temporary_ticket_path(path);
    let mut file = open_private_file(&temp_path)?;
    file.write_all(payload)
        .with_context(|| format!("failed to write {}", temp_path.display()))?;
    file.flush()
        .with_context(|| format!("failed to flush {}", temp_path.display()))?;
    file.sync_all()
        .with_context(|| format!("failed to sync {}", temp_path.display()))?;

    if path.exists() {
        fs::remove_file(path).with_context(|| format!("failed to replace {}", path.display()))?;
    }
    fs::rename(&temp_path, path)
        .with_context(|| format!("failed to move {} into place", path.display()))?;
    Ok(())
}

fn open_private_file(path: &Path) -> anyhow::Result<fs::File> {
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        options.mode(0o600);
    }
    options
        .open(path)
        .with_context(|| format!("failed to open {}", path.display()))
}

fn temporary_ticket_path(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("resumption_ticket.hex");
    path.with_file_name(format!(
        "{}.tmp-{}-{:016x}",
        file_name,
        std::process::id(),
        rand::random::<u64>()
    ))
}

struct StoredResumption {
    ticket: Vec<u8>,
    secret: [u8; 32],
}

fn parse_stored_resumption(raw: &str) -> Option<StoredResumption> {
    let mut ticket = None;
    let mut secret = None;
    for line in raw.lines() {
        if let Some(value) = line.strip_prefix("ticket=") {
            let bytes = hex_decode(value.trim())?;
            if bytes.is_empty() || bytes.len() > MAX_RESUMPTION_TICKET_BYTES {
                return None;
            }
            ticket = Some(bytes);
        } else if let Some(value) = line.strip_prefix("secret=") {
            let bytes = hex_decode(value.trim())?;
            if bytes.len() != 32 {
                return None;
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            secret = Some(arr);
        }
    }
    Some(StoredResumption {
        ticket: ticket?,
        secret: secret?,
    })
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(nibble((b >> 4) & 0x0f));
        out.push(nibble(b & 0x0f));
    }
    out
}

fn hex_decode(value: &str) -> Option<Vec<u8>> {
    if value.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(value.len() / 2);
    let bytes = value.as_bytes();
    for idx in (0..bytes.len()).step_by(2) {
        let hi = from_hex(bytes[idx])?;
        let lo = from_hex(bytes[idx + 1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

fn nibble(value: u8) -> char {
    match value {
        0..=9 => (b'0' + value) as char,
        10..=15 => (b'a' + value - 10) as char,
        _ => '0',
    }
}

fn from_hex(ch: u8) -> Option<u8> {
    match ch {
        b'0'..=b'9' => Some(ch - b'0'),
        b'a'..=b'f' => Some(ch - b'a' + 10),
        b'A'..=b'F' => Some(ch - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_stored_resumption_rejects_invalid_secret_len() {
        let raw = "ticket=abcd\nsecret=00\n";
        assert!(parse_stored_resumption(raw).is_none());
    }

    #[test]
    fn parse_stored_resumption_roundtrip() {
        let ticket = vec![0xde, 0xad, 0xbe, 0xef];
        let secret = [0x11u8; 32];
        let raw = format!(
            "ticket={}\nsecret={}\n",
            hex_encode(&ticket),
            hex_encode(&secret)
        );

        let parsed = parse_stored_resumption(&raw).expect("stored resumption should parse");
        assert_eq!(parsed.ticket, ticket);
        assert_eq!(parsed.secret, secret);
    }

    #[test]
    fn write_private_file_roundtrip() {
        let dir = temp_test_dir("write_private_file_roundtrip");
        let path = dir.join("resumption_ticket.hex");
        let payload = b"ticket=abcd\nsecret=0011\n";

        write_private_file(&path, payload).expect("private write should succeed");
        assert_eq!(fs::read(&path).unwrap(), payload);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    fn temp_test_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "omega-client-runtime-tests-{}-{}-{:016x}",
            name,
            std::process::id(),
            rand::random::<u64>()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }
}
