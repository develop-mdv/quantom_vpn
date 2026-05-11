use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use anyhow::{anyhow, bail, Context};
use ring::digest;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

#[derive(Debug, Clone)]
pub struct CertSnapshot {
    pub sni: String,
    pub leaf_der: Vec<u8>,
    pub chain_der: Vec<Vec<u8>>,
    pub leaf_sha256: [u8; 32],
    pub captured_at: SystemTime,
}

impl CertSnapshot {
    pub fn leaf_sha256_hex(&self) -> String {
        hex_lower(&self.leaf_sha256)
    }
}

#[derive(Serialize, Deserialize)]
struct StoredMeta {
    version: u32,
    sni: String,
    leaf_sha256_hex: String,
    captured_at_unix: u64,
    chain_files: Vec<String>,
}

const META_VERSION: u32 = 1;
const SNIFF_TIMEOUT: Duration = Duration::from_secs(15);

pub async fn sniff(
    dest_host: &str,
    dest_port: u16,
    sni: &str,
) -> anyhow::Result<CertSnapshot> {
    let captured = Arc::new(Mutex::new(None::<CapturedChain>));
    let verifier = Arc::new(CapturingVerifier {
        captured: captured.clone(),
    });

    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .context("rustls: configure safe default TLS protocol versions")?
        .with_root_certificates(roots)
        .with_no_client_auth();
    // Dangerous: replace verifier with one that records the chain unconditionally.
    config.dangerous().set_certificate_verifier(verifier);
    let connector = TlsConnector::from(Arc::new(config));

    let server_name: ServerName<'static> = ServerName::try_from(sni.to_string())
        .map_err(|err| anyhow!("invalid SNI {sni}: {err}"))?;
    let target = format!("{dest_host}:{dest_port}");

    let snapshot = timeout(SNIFF_TIMEOUT, async {
        let tcp = TcpStream::connect(&target)
            .await
            .with_context(|| format!("tcp connect to {target}"))?;
        let mut tls = connector
            .connect(server_name, tcp)
            .await
            .with_context(|| format!("tls handshake with {target} (sni={sni})"))?;
        // We don't need to send any application data; the chain has already been captured
        // during the handshake. Best-effort close.
        let _ = tls.shutdown().await;
        anyhow::Ok(())
    })
    .await
    .context("sniff handshake timed out")??;
    let _ = snapshot;

    let captured = captured
        .lock()
        .unwrap()
        .take()
        .ok_or_else(|| anyhow!("certificate verifier was not invoked during handshake"))?;
    let leaf_sha256 = sha256(&captured.leaf);
    Ok(CertSnapshot {
        sni: sni.to_string(),
        leaf_der: captured.leaf,
        chain_der: captured.chain,
        leaf_sha256,
        captured_at: SystemTime::now(),
    })
}

pub fn save_snapshot(dir: &Path, snapshot: &CertSnapshot) -> anyhow::Result<()> {
    fs::create_dir_all(dir)
        .with_context(|| format!("create reality cert dir {}", dir.display()))?;
    let safe_sni = sanitize_sni(&snapshot.sni);
    let leaf_path = dir.join(format!("{safe_sni}.leaf.der"));
    fs::write(&leaf_path, &snapshot.leaf_der)
        .with_context(|| format!("write leaf cert {}", leaf_path.display()))?;

    let mut chain_files = Vec::with_capacity(snapshot.chain_der.len());
    for (idx, der) in snapshot.chain_der.iter().enumerate() {
        let chain_path = dir.join(format!("{safe_sni}.chain.{idx}.der"));
        fs::write(&chain_path, der)
            .with_context(|| format!("write chain cert {}", chain_path.display()))?;
        chain_files.push(
            chain_path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default(),
        );
    }

    let meta = StoredMeta {
        version: META_VERSION,
        sni: snapshot.sni.clone(),
        leaf_sha256_hex: snapshot.leaf_sha256_hex(),
        captured_at_unix: snapshot
            .captured_at
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or_default(),
        chain_files,
    };
    let meta_path = dir.join(format!("{safe_sni}.meta.json"));
    let json = serde_json::to_string_pretty(&meta).context("serialize cert meta")?;
    fs::write(&meta_path, json)
        .with_context(|| format!("write cert meta {}", meta_path.display()))?;
    Ok(())
}

pub fn load_snapshot(dir: &Path, sni: &str) -> anyhow::Result<CertSnapshot> {
    let safe_sni = sanitize_sni(sni);
    let meta_path = dir.join(format!("{safe_sni}.meta.json"));
    let raw = fs::read_to_string(&meta_path)
        .with_context(|| format!("read cert meta {}", meta_path.display()))?;
    let meta: StoredMeta = serde_json::from_str(&raw).context("parse cert meta")?;
    if meta.version != META_VERSION {
        bail!(
            "unsupported reality cert meta version: {} (expected {})",
            meta.version,
            META_VERSION
        );
    }
    let leaf_path = dir.join(format!("{safe_sni}.leaf.der"));
    let leaf_der = fs::read(&leaf_path)
        .with_context(|| format!("read leaf cert {}", leaf_path.display()))?;
    let leaf_sha256 = sha256(&leaf_der);
    if hex_lower(&leaf_sha256) != meta.leaf_sha256_hex {
        bail!("reality cert cache: leaf sha256 mismatch (cache corrupt?)");
    }
    let mut chain_der = Vec::with_capacity(meta.chain_files.len());
    for name in &meta.chain_files {
        let p: PathBuf = dir.join(name);
        let bytes = fs::read(&p)
            .with_context(|| format!("read chain cert {}", p.display()))?;
        chain_der.push(bytes);
    }
    Ok(CertSnapshot {
        sni: meta.sni,
        leaf_der,
        chain_der,
        leaf_sha256,
        captured_at: SystemTime::UNIX_EPOCH + Duration::from_secs(meta.captured_at_unix),
    })
}

fn sanitize_sni(sni: &str) -> String {
    sni.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let d = digest::digest(&digest::SHA256, bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    out
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

#[derive(Debug)]
struct CapturedChain {
    leaf: Vec<u8>,
    chain: Vec<Vec<u8>>,
}

#[derive(Debug)]
struct CapturingVerifier {
    captured: Arc<Mutex<Option<CapturedChain>>>,
}

impl ServerCertVerifier for CapturingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let leaf = end_entity.as_ref().to_vec();
        let chain = intermediates
            .iter()
            .map(|c| c.as_ref().to_vec())
            .collect();
        *self.captured.lock().unwrap() = Some(CapturedChain { leaf, chain });
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitizes_unsafe_sni() {
        assert_eq!(sanitize_sni("gosuslugi.ru"), "gosuslugi.ru");
        assert_eq!(sanitize_sni("evil/../path"), "evil_.._path");
        assert_eq!(sanitize_sni("a b\tc"), "a_b_c");
    }

    #[test]
    fn save_and_load_snapshot_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let snap = CertSnapshot {
            sni: "example.com".to_string(),
            leaf_der: vec![1, 2, 3, 4, 5],
            chain_der: vec![vec![6, 7], vec![8, 9, 10]],
            leaf_sha256: sha256(&[1, 2, 3, 4, 5]),
            captured_at: SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000),
        };
        save_snapshot(dir.path(), &snap).unwrap();
        let loaded = load_snapshot(dir.path(), "example.com").unwrap();
        assert_eq!(loaded.leaf_der, snap.leaf_der);
        assert_eq!(loaded.chain_der, snap.chain_der);
        assert_eq!(loaded.leaf_sha256, snap.leaf_sha256);
    }
}
