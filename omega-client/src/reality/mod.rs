//! Client-side REALITY transport: configuration, handshake driver, and a
//! `RealityClientTransport` wrapper that carries application data through
//! the established TLS 1.3 record layer.
//!
//! Public entry points:
//!   * [`RealityClientConfig::from_env`] — parse `OMEGA_REALITY_*` env vars.
//!   * [`perform_reality_handshake`] — connect, handshake, return transport.
//!   * [`RealityClientTransport`] — async-capable record-layer wrapper.

pub use omega_reality::{handshake_client as handshake, utls};

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use omega_reality::auth::SHORT_ID_LEN;
use omega_reality::key_schedule::CipherSuiteParams;
use omega_reality::record_layer::{DecryptedRecord, RecordDecryptor, RecordEncryptor};
use omega_reality::tls_messages::{
    parse_record_header, CT_APPLICATION_DATA, TLS_MAX_RECORD_CIPHERTEXT,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use x25519_dalek::PublicKey;

use self::handshake::{ClientEstablished, ClientHandshakeInputs};

const ENV_SERVER: &str = "OMEGA_REALITY_SERVER";
const ENV_SNI: &str = "OMEGA_REALITY_SNI";
const ENV_PUBKEY: &str = "OMEGA_REALITY_SERVER_PUBKEY";
const ENV_SHORT_ID: &str = "OMEGA_REALITY_SHORT_ID";
const ENV_FINGERPRINT: &str = "OMEGA_REALITY_FINGERPRINT";
const ENV_HANDSHAKE_TIMEOUT: &str = "OMEGA_REALITY_HANDSHAKE_TIMEOUT_MS";

const DEFAULT_FINGERPRINT: &str = "chrome_131";
const DEFAULT_HANDSHAKE_TIMEOUT_MS: u64 = 10_000;

#[derive(Debug, Clone)]
pub struct RealityClientConfig {
    pub server: SocketAddr,
    pub sni: String,
    pub server_pubkey: PublicKey,
    pub short_id: [u8; SHORT_ID_LEN],
    pub fingerprint_profile: String,
    pub handshake_timeout: Duration,
}

impl RealityClientConfig {
    pub fn from_env() -> Result<Self> {
        let server_raw = std::env::var(ENV_SERVER)
            .map_err(|_| anyhow!("{ENV_SERVER} must be set for REALITY transport"))?;
        let server: SocketAddr = server_raw
            .parse()
            .with_context(|| format!("parse {ENV_SERVER}={server_raw}"))?;

        let sni = std::env::var(ENV_SNI)
            .map_err(|_| anyhow!("{ENV_SNI} must be set for REALITY transport"))?
            .to_ascii_lowercase();

        let pubkey_raw = std::env::var(ENV_PUBKEY)
            .map_err(|_| anyhow!("{ENV_PUBKEY} must be set for REALITY transport"))?;
        let pubkey_bytes = B64
            .decode(pubkey_raw.trim().as_bytes())
            .context("decode OMEGA_REALITY_SERVER_PUBKEY (base64)")?;
        if pubkey_bytes.len() != 32 {
            bail!(
                "{ENV_PUBKEY} must decode to 32 bytes (got {})",
                pubkey_bytes.len()
            );
        }
        let mut pubkey_arr = [0u8; 32];
        pubkey_arr.copy_from_slice(&pubkey_bytes);
        let server_pubkey = PublicKey::from(pubkey_arr);

        let short_id = match std::env::var(ENV_SHORT_ID) {
            Ok(v) => parse_short_id(&v)?,
            Err(_) => [0u8; SHORT_ID_LEN],
        };

        let fingerprint_profile = std::env::var(ENV_FINGERPRINT)
            .unwrap_or_else(|_| DEFAULT_FINGERPRINT.to_string());

        let handshake_timeout = Duration::from_millis(
            std::env::var(ENV_HANDSHAKE_TIMEOUT)
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(DEFAULT_HANDSHAKE_TIMEOUT_MS),
        );

        Ok(Self {
            server,
            sni,
            server_pubkey,
            short_id,
            fingerprint_profile,
            handshake_timeout,
        })
    }
}

fn parse_short_id(raw: &str) -> Result<[u8; SHORT_ID_LEN]> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok([0u8; SHORT_ID_LEN]);
    }
    if raw.len() != SHORT_ID_LEN * 2 {
        bail!(
            "{ENV_SHORT_ID} must be {} hex chars (got {})",
            SHORT_ID_LEN * 2,
            raw.len()
        );
    }
    let mut out = [0u8; SHORT_ID_LEN];
    for (i, chunk) in raw.as_bytes().chunks_exact(2).enumerate() {
        let s = std::str::from_utf8(chunk).map_err(|_| anyhow!("invalid short_id hex"))?;
        out[i] = u8::from_str_radix(s, 16)
            .with_context(|| format!("parse short_id hex byte {i} ({s:?})"))?;
    }
    Ok(out)
}

/// Connect to the REALITY server, run the handshake, and return a transport
/// you can use to send/receive application data.
pub async fn perform_reality_handshake(
    config: &RealityClientConfig,
) -> Result<RealityClientTransport> {
    let tcp = tokio::time::timeout(config.handshake_timeout, TcpStream::connect(config.server))
        .await
        .map_err(|_| {
            anyhow!(
                "REALITY connect to {} timed out after {:?}",
                config.server,
                config.handshake_timeout
            )
        })?
        .with_context(|| format!("REALITY tcp connect to {}", config.server))?;
    // Reduce small-payload latency for the handshake flight.
    let _ = tcp.set_nodelay(true);

    let mut io = tcp;
    let alpn_offer: [&[u8]; 1] = [b"http/1.1"];
    let inputs = ClientHandshakeInputs {
        server_name: &config.sni,
        server_long_term_pubkey: &config.server_pubkey,
        short_id: config.short_id,
        alpn_offer: Some(&alpn_offer),
    };
    let established = tokio::time::timeout(
        config.handshake_timeout,
        handshake::client_handshake(&mut io, &inputs),
    )
    .await
    .map_err(|_| {
        anyhow!(
            "REALITY handshake stalled (timeout {:?})",
            config.handshake_timeout
        )
    })??;

    RealityClientTransport::from_handshake(io, established)
}

/// Connected REALITY tunnel: TLS 1.3 application records over a single TCP
/// stream, encrypted under the negotiated cipher suite (AES-128-GCM or
/// ChaCha20-Poly1305).
pub struct RealityClientTransport {
    inner: Arc<Mutex<TransportInner>>,
    peer_addr: SocketAddr,
}

struct TransportInner {
    stream: TcpStream,
    encryptor: RecordEncryptor,
    decryptor: RecordDecryptor,
    cipher_suite: u16,
    params: CipherSuiteParams,
}

impl RealityClientTransport {
    fn from_handshake(stream: TcpStream, established: ClientEstablished) -> Result<Self> {
        let peer_addr = stream
            .peer_addr()
            .context("REALITY transport: peer_addr() failed")?;
        let encryptor = RecordEncryptor::new(
            &established.params,
            &established
                .application_secrets
                .client_application_traffic_secret_0,
        )?;
        let decryptor = RecordDecryptor::new(
            &established.params,
            &established
                .application_secrets
                .server_application_traffic_secret_0,
        )?;
        Ok(Self {
            inner: Arc::new(Mutex::new(TransportInner {
                stream,
                encryptor,
                decryptor,
                cipher_suite: established.cipher_suite,
                params: established.params,
            })),
            peer_addr,
        })
    }

    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    pub async fn cipher_suite(&self) -> u16 {
        self.inner.lock().await.cipher_suite
    }

    pub async fn params(&self) -> CipherSuiteParams {
        self.inner.lock().await.params
    }

    /// Send a single record carrying `payload` as application_data.
    pub async fn send(&self, payload: &[u8]) -> Result<()> {
        let mut guard = self.inner.lock().await;
        let wire = guard
            .encryptor
            .seal_record(CT_APPLICATION_DATA, payload, 0)?;
        guard.stream.write_all(&wire).await?;
        guard.stream.flush().await?;
        Ok(())
    }

    /// Read one record from the underlying socket and return the decrypted
    /// inner content.
    pub async fn recv(&self) -> Result<DecryptedRecord> {
        let mut guard = self.inner.lock().await;
        let mut header = [0u8; 5];
        guard
            .stream
            .read_exact(&mut header)
            .await
            .context("read record header")?;
        let (content_type, length, _) = parse_record_header(&header)?;
        if content_type != CT_APPLICATION_DATA {
            bail!(
                "REALITY transport: unexpected record content_type={}",
                content_type
            );
        }
        if length == 0 || length as usize > TLS_MAX_RECORD_CIPHERTEXT {
            bail!("invalid record length {}", length);
        }
        let mut cipher = vec![0u8; length as usize];
        guard
            .stream
            .read_exact(&mut cipher)
            .await
            .context("read record body")?;
        let plaintext = guard.decryptor.open_record(&header, &mut cipher)?;
        Ok(plaintext)
    }

    /// Same as [`recv`], but copies the inner payload into `out` and returns
    /// the number of bytes written. Errors if the record is larger than
    /// `out`. Convenient for plugging REALITY into the existing
    /// `ClientTransport::recv(&mut [u8]) -> (usize, SocketAddr)` shape.
    pub async fn recv_into(&self, out: &mut [u8]) -> Result<usize> {
        let plaintext = self.recv().await?;
        if plaintext.content.len() > out.len() {
            bail!(
                "REALITY transport: record ({}) larger than caller buffer ({})",
                plaintext.content.len(),
                out.len()
            );
        }
        out[..plaintext.content.len()].copy_from_slice(&plaintext.content);
        Ok(plaintext.content.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_short_id_accepts_hex() {
        let id = parse_short_id("0102030405060708").unwrap();
        assert_eq!(id, [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
    }

    #[test]
    fn parse_short_id_accepts_empty_as_wildcard() {
        let id = parse_short_id("").unwrap();
        assert_eq!(id, [0u8; SHORT_ID_LEN]);
    }

    #[test]
    fn parse_short_id_rejects_wrong_length() {
        assert!(parse_short_id("01").is_err());
        assert!(parse_short_id("010203").is_err());
    }
}
