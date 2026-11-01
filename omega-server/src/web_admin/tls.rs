use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use anyhow::Context;
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use tokio_rustls::TlsAcceptor;

type Stamp = ((SystemTime, u64), (SystemTime, u64));

pub(super) fn load(cert_path: &Path, key_path: &Path) -> anyhow::Result<(TlsAcceptor, usize)> {
    let certificate = std::fs::read(cert_path).context("read admin TLS certificate")?;
    let private_key = std::fs::read(key_path).context("read admin TLS private key")?;
    let chain = if certificate.starts_with(b"-----BEGIN") {
        CertificateDer::pem_slice_iter(&certificate).collect::<Result<Vec<_>, _>>()?
    } else {
        vec![CertificateDer::from(certificate)]
    };
    anyhow::ensure!(!chain.is_empty(), "Admin TLS certificate chain is empty");
    let key = if private_key.starts_with(b"-----BEGIN") {
        PrivateKeyDer::from_pem_slice(&private_key)?
    } else {
        PrivateKeyDer::try_from(private_key).map_err(|error| anyhow::anyhow!(error))?
    };
    let count = chain.len();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_no_client_auth()
    .with_single_cert(chain, key)?;
    Ok((TlsAcceptor::from(Arc::new(config)), count))
}

pub(super) struct Reloader {
    cert: PathBuf,
    key: PathBuf,
    stamp: Stamp,
    current: TlsAcceptor,
}

impl Reloader {
    pub fn new(cert: PathBuf, key: PathBuf) -> anyhow::Result<Self> {
        let stamp = stamp(&cert, &key)?;
        let (current, _) = load(&cert, &key)?;
        Ok(Self {
            cert,
            key,
            stamp,
            current,
        })
    }

    pub fn refresh(&mut self) -> anyhow::Result<bool> {
        let next_stamp = stamp(&self.cert, &self.key)?;
        if next_stamp == self.stamp {
            return Ok(false);
        }
        // Keep the last valid pair if files are incomplete during replacement.
        let (next, _) = load(&self.cert, &self.key)?;
        self.current = next;
        self.stamp = next_stamp;
        Ok(true)
    }

    pub fn acceptor(&self) -> TlsAcceptor {
        self.current.clone()
    }
}

fn stamp(cert: &Path, key: &Path) -> anyhow::Result<Stamp> {
    let cert = std::fs::metadata(cert)?;
    let key = std::fs::metadata(key)?;
    Ok(((cert.modified()?, cert.len()), (key.modified()?, key.len())))
}
