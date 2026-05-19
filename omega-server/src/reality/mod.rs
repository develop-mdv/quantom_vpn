//! XTLS REALITY transport for Omega VPN.
//!
//! This module gives Omega a third transport (alongside UDP and framed TCP):
//! incoming connections look indistinguishable from TLS 1.3 to a trusted public
//! site (e.g. `gosuslugi.ru`). "Authentic" Omega clients embed a short-lived
//! authentication tag in the TLS `session_id` of the ClientHello, so the server
//! can decide whether to terminate the TLS handshake itself (using its own
//! X25519 key + a leaf certificate sniffed from the real site) or to fall back
//! to a transparent proxy of the same connection to that real site (so that
//! active DPI probes see the indistinguishable behaviour of the real site).
//!
//! This file ties everything together: configuration, key management, cert
//! cache, and the listener entry point. Sub-modules implement the building
//! blocks. During Phase 1 the listener is a stub that simply accepts and
//! closes connections after sniffing the leaf certificate; later phases plug
//! in the full TLS handshake state machine.

// Shared protocol primitives live in the omega-reality crate so the
// omega-client side can use the exact same codec / key schedule.
pub use omega_reality::{
    auth, handshake_server as handshake, key_schedule, record_layer, tls_messages,
};

pub mod cert_cache;
pub mod config_store;
pub mod controller;
pub mod keys;
pub mod proxy;
pub mod tunnel;

pub use controller::{RealityController, RealityStatus, SharedController};

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context};
use tokio::net::TcpListener;

pub use cert_cache::CertSnapshot;
pub use keys::RealityKeyPair;

const ENV_ENABLE: &str = "OMEGA_REALITY_ENABLE";
const ENV_BIND: &str = "OMEGA_REALITY_BIND";
const ENV_DEST: &str = "OMEGA_REALITY_DEST";
const ENV_SERVER_NAMES: &str = "OMEGA_REALITY_SERVER_NAMES";
const ENV_KEY_FILE: &str = "OMEGA_REALITY_PRIVATE_KEY_FILE";
const ENV_CERT_DIR: &str = "OMEGA_REALITY_CERT_DIR";
const ENV_SHORT_IDS: &str = "OMEGA_REALITY_SHORT_IDS";
const ENV_FP_PROFILE: &str = "OMEGA_REALITY_FINGERPRINT_PROFILE";
const ENV_HANDSHAKE_TIMEOUT: &str = "OMEGA_REALITY_HANDSHAKE_TIMEOUT_MS";

pub(crate) const DEFAULT_BIND: &str = "0.0.0.0:443";
pub(crate) const DEFAULT_KEY_FILE: &str = "state/reality_x25519.key";
pub(crate) const DEFAULT_CERT_DIR: &str = "state/reality_certs";
pub(crate) const DEFAULT_FINGERPRINT: &str = "chrome_131";
pub(crate) const DEFAULT_HANDSHAKE_TIMEOUT_MS: u64 = 10_000;
pub(crate) const SHORT_ID_LEN: usize = 8;
const CERT_REFRESH_INTERVAL: Duration = Duration::from_secs(12 * 3600);

#[derive(Debug, Clone)]
pub struct RealityConfig {
    pub bind: SocketAddr,
    pub dest_host: String,
    pub dest_port: u16,
    pub server_names: Vec<String>,
    pub key_file: PathBuf,
    pub cert_dir: PathBuf,
    pub short_ids: Vec<[u8; SHORT_ID_LEN]>,
    pub fingerprint_profile: String,
    pub handshake_timeout: Duration,
}

impl RealityConfig {
    /// Parse all `OMEGA_REALITY_*` environment variables.
    ///
    /// Returns `Ok(None)` when REALITY is disabled (the env flag is unset or
    /// "0"/"false"). Returns `Ok(Some(_))` on success, or an error if REALITY
    /// is enabled but mandatory variables are missing or malformed.
    pub fn from_env() -> anyhow::Result<Option<Self>> {
        if !env_flag(ENV_ENABLE) {
            return Ok(None);
        }

        let bind: SocketAddr = std::env::var(ENV_BIND)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or_else(|| {
                DEFAULT_BIND
                    .parse()
                    .expect("DEFAULT_BIND is a valid SocketAddr")
            });

        let raw_dest = std::env::var(ENV_DEST)
            .map_err(|_| anyhow!("{ENV_DEST} must be set when REALITY is enabled (e.g. \"gosuslugi.ru:443\")"))?;
        let (dest_host, dest_port) = parse_host_port(&raw_dest)
            .with_context(|| format!("parse {ENV_DEST}={raw_dest}"))?;

        let server_names = match std::env::var(ENV_SERVER_NAMES) {
            Ok(v) => parse_server_names(&v),
            Err(_) => vec![dest_host.clone()],
        };
        if server_names.is_empty() {
            bail!("{ENV_SERVER_NAMES} resolves to an empty list");
        }

        let key_file = std::env::var(ENV_KEY_FILE)
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(DEFAULT_KEY_FILE));
        let cert_dir = std::env::var(ENV_CERT_DIR)
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(DEFAULT_CERT_DIR));

        let short_ids = match std::env::var(ENV_SHORT_IDS) {
            Ok(v) => parse_short_ids(&v)
                .with_context(|| format!("parse {ENV_SHORT_IDS}={v}"))?,
            Err(_) => Vec::new(),
        };

        let fingerprint_profile = std::env::var(ENV_FP_PROFILE)
            .unwrap_or_else(|_| DEFAULT_FINGERPRINT.to_string());

        let handshake_timeout_ms = std::env::var(ENV_HANDSHAKE_TIMEOUT)
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(DEFAULT_HANDSHAKE_TIMEOUT_MS);
        let handshake_timeout = Duration::from_millis(handshake_timeout_ms);

        Ok(Some(Self {
            bind,
            dest_host,
            dest_port,
            server_names,
            key_file,
            cert_dir,
            short_ids,
            fingerprint_profile,
            handshake_timeout,
        }))
    }

    pub fn primary_sni(&self) -> &str {
        self.server_names
            .first()
            .map(String::as_str)
            .unwrap_or(self.dest_host.as_str())
    }

    pub fn matches_sni(&self, sni: &str) -> bool {
        let sni = sni.to_ascii_lowercase();
        self.server_names.iter().any(|s| s == &sni)
    }
}

/// Everything the REALITY listener needs to hand off an authenticated
/// connection to the existing Omega data path. Built once at server boot
/// and shared across all connection tasks via `Arc`.
#[derive(Clone)]
pub struct RealityDataPath {
    pub tun: Arc<tun_rs::AsyncDevice>,
    pub udp: Arc<tokio::net::UdpSocket>,
    pub session_manager: Arc<crate::session::SessionManager>,
    pub identity_store: Arc<crate::identity::IdentityStore>,
    pub server_mtu: u16,
    pub allow_legacy_v1: bool,
    pub morphing_policy: crate::runtime::MorphingPolicy,
}

/// Live REALITY runtime: configuration, server identity, and cached leaf certs
/// for every advertised SNI. Built once during server bootstrap and shared
/// across the listener task and the cert-refresh task via `Arc`.
#[derive(Clone)]
pub struct RealityRuntime {
    pub config: Arc<RealityConfig>,
    pub keys: Arc<RealityKeyPair>,
    pub snapshots: Arc<tokio::sync::RwLock<HashMap<String, CertSnapshot>>>,
    pub datapath: RealityDataPath,
}

impl RealityRuntime {
    /// Load (or generate) the server keypair and ensure we have a leaf
    /// certificate snapshot for every advertised SNI. Cached snapshots are
    /// reused if present; otherwise the destination site is contacted once
    /// and the leaf cert is captured & saved.
    pub async fn bootstrap(config: RealityConfig, datapath: RealityDataPath) -> anyhow::Result<Self> {
        let (keys, created) = RealityKeyPair::load_or_generate(&config.key_file)
            .with_context(|| {
                format!(
                    "load or generate REALITY keypair at {}",
                    config.key_file.display()
                )
            })?;
        if created {
            tracing::warn!(
                public_key = %keys.public_base64(),
                path = %config.key_file.display(),
                "reality: generated new server X25519 keypair — distribute the public key to clients"
            );
        } else {
            tracing::info!(
                public_key = %keys.public_base64(),
                "reality: loaded existing server X25519 keypair"
            );
        }

        let mut snapshots = HashMap::with_capacity(config.server_names.len());
        for sni in &config.server_names {
            let snap = ensure_snapshot(&config, sni).await?;
            tracing::info!(
                %sni,
                leaf_sha256 = %snap.leaf_sha256_hex(),
                chain_len = snap.chain_der.len(),
                "reality: cert snapshot ready"
            );
            snapshots.insert(sni.clone(), snap);
        }

        Ok(Self {
            config: Arc::new(config),
            keys: Arc::new(keys),
            snapshots: Arc::new(tokio::sync::RwLock::new(snapshots)),
            datapath,
        })
    }

    /// Accept loop: TLS 1.3 server flight → REALITY auth → either VPN payload
    /// pipe (`Authentic`) or transparent proxy to the upstream site (`Foreign`).
    /// Also spawns a background task that periodically re-sniffs leaf certs
    /// from the masquerade target and updates the cache on rotation.
    pub async fn run_listener(self) -> anyhow::Result<()> {
        // Background cert refresh task — owns clones of config + snapshots.
        {
            let cfg = self.config.clone();
            let snapshots = self.snapshots.clone();
            tokio::spawn(async move {
                cert_refresh_loop(cfg, snapshots, CERT_REFRESH_INTERVAL).await;
            });
        }

        let listener = TcpListener::bind(self.config.bind)
            .await
            .with_context(|| format!("bind reality listener on {}", self.config.bind))?;
        tracing::info!(
            addr = %self.config.bind,
            primary_sni = %self.config.primary_sni(),
            "reality: listener accepting connections"
        );
        loop {
            let (stream, peer) = match listener.accept().await {
                Ok(pair) => pair,
                Err(err) => {
                    tracing::warn!(error = %err, "reality: accept error");
                    continue;
                }
            };
            let runtime = self.clone();
            tokio::spawn(async move {
                if let Err(err) = handle_connection(runtime, stream, peer).await {
                    tracing::warn!(%peer, error = %err, "reality: connection failed");
                }
            });
        }
    }
}

async fn cert_refresh_loop(
    config: Arc<RealityConfig>,
    snapshots: Arc<tokio::sync::RwLock<HashMap<String, CertSnapshot>>>,
    interval: Duration,
) {
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // First tick fires immediately — skip it, snapshots are already fresh
    // from bootstrap.
    ticker.tick().await;
    loop {
        ticker.tick().await;
        for sni in config.server_names.iter() {
            match cert_cache::sniff(&config.dest_host, config.dest_port, sni).await {
                Ok(fresh) => {
                    let rotated = {
                        let guard = snapshots.read().await;
                        guard
                            .get(sni)
                            .map(|prev| prev.leaf_sha256 != fresh.leaf_sha256)
                            .unwrap_or(true)
                    };
                    if rotated {
                        tracing::info!(
                            %sni,
                            new_sha = %fresh.leaf_sha256_hex(),
                            "reality: leaf cert rotated; updating cache"
                        );
                        if let Err(err) = cert_cache::save_snapshot(&config.cert_dir, &fresh) {
                            tracing::warn!(%sni, error = %err, "reality: persist refreshed cert failed");
                        }
                    } else {
                        tracing::debug!(%sni, "reality: cert unchanged");
                    }
                    snapshots.write().await.insert(sni.clone(), fresh);
                    crate::metrics::record_reality_cert_refresh(sni, rotated);
                }
                Err(err) => {
                    tracing::warn!(
                        %sni,
                        error = %err,
                        "reality: cert refresh failed; keeping existing snapshot"
                    );
                }
            }
        }
    }
}

async fn handle_connection(
    runtime: RealityRuntime,
    mut stream: tokio::net::TcpStream,
    peer: std::net::SocketAddr,
) -> anyhow::Result<()> {
    let timeout = runtime.config.handshake_timeout;

    let snapshot = {
        let guard = runtime.snapshots.read().await;
        guard
            .get(runtime.config.primary_sni())
            .cloned()
            .ok_or_else(|| anyhow!("no cert snapshot for primary SNI"))?
    };
    let inputs = handshake::ServerHandshakeInputs {
        leaf_der: &snapshot.leaf_der,
        chain_der: &snapshot.chain_der,
        fallback_sni: &snapshot.sni,
        server_long_term_secret: runtime.keys.secret(),
        allowed_short_ids: &runtime.config.short_ids,
    };

    let outcome = match tokio::time::timeout(
        timeout,
        handshake::server_handshake(&mut stream, &inputs),
    )
    .await
    {
        Ok(Ok(outcome)) => outcome,
        Ok(Err(err)) => {
            crate::metrics::record_reality_handshake_error("handshake_error");
            return Err(err);
        }
        Err(_) => {
            crate::metrics::record_reality_handshake_error("timeout");
            return Err(anyhow!("REALITY handshake timed out after {:?}", timeout));
        }
    };

    match outcome {
        handshake::HandshakeOutcome::Authentic(established) => {
            let short_id_hex = established
                .short_id
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>();
            tracing::info!(
                %peer,
                cipher = format!("0x{:04x}", established.cipher_suite),
                sni = %established.negotiated_sni,
                alpn = %String::from_utf8_lossy(&established.alpn),
                short_id = %short_id_hex,
                "reality: authentic client — entering VPN payload pipe"
            );
            crate::metrics::record_reality_handshake_authentic(short_id_hex);
            crate::metrics::reality_active_tunnels_inc();
            let dp = runtime.datapath.clone();
            let result = tunnel::run(
                stream,
                peer,
                established,
                dp.tun,
                dp.udp,
                dp.session_manager,
                dp.identity_store,
                dp.server_mtu,
                dp.allow_legacy_v1,
                dp.morphing_policy,
            )
            .await;
            crate::metrics::reality_active_tunnels_dec();
            result
        }
        handshake::HandshakeOutcome::Foreign {
            captured_chlo_record,
        } => {
            tracing::debug!(
                %peer,
                chlo_len = captured_chlo_record.len(),
                "reality: foreign client — routing to proxy fallback"
            );
            crate::metrics::record_reality_handshake_foreign();
            proxy::splice_to_upstream(
                stream,
                &runtime.config.dest_host,
                runtime.config.dest_port,
                captured_chlo_record,
            )
            .await
        }
    }
}

async fn ensure_snapshot(config: &RealityConfig, sni: &str) -> anyhow::Result<CertSnapshot> {
    if let Ok(cached) = cert_cache::load_snapshot(&config.cert_dir, sni) {
        return Ok(cached);
    }
    let fresh = cert_cache::sniff(&config.dest_host, config.dest_port, sni)
        .await
        .with_context(|| {
            format!(
                "sniff leaf certificate from {}:{} (sni={})",
                config.dest_host, config.dest_port, sni
            )
        })?;
    cert_cache::save_snapshot(&config.cert_dir, &fresh)
        .with_context(|| format!("persist sniffed cert for sni={sni}"))?;
    Ok(fresh)
}

fn env_flag(name: &str) -> bool {
    match std::env::var(name) {
        Ok(v) => matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => false,
    }
}

fn parse_host_port(raw: &str) -> anyhow::Result<(String, u16)> {
    let raw = raw.trim();
    if raw.is_empty() {
        bail!("empty host:port");
    }
    // Support bare host (default 443) for ergonomics.
    let (host, port) = match raw.rsplit_once(':') {
        Some((h, p)) => {
            let port: u16 = p.parse().with_context(|| format!("invalid port: {p}"))?;
            (h.trim().to_string(), port)
        }
        None => (raw.to_string(), 443u16),
    };
    if host.is_empty() {
        bail!("empty host");
    }
    Ok((host.to_ascii_lowercase(), port))
}

fn parse_server_names(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(|v| v.to_ascii_lowercase())
        .collect()
}

fn parse_short_ids(raw: &str) -> anyhow::Result<Vec<[u8; SHORT_ID_LEN]>> {
    let mut out = Vec::new();
    for token in raw.split(',').map(str::trim).filter(|v| !v.is_empty()) {
        let bytes = decode_hex(token)
            .with_context(|| format!("decode short_id {token} as hex"))?;
        if bytes.len() != SHORT_ID_LEN {
            bail!(
                "short_id {token} must decode to {SHORT_ID_LEN} bytes (got {})",
                bytes.len()
            );
        }
        let mut id = [0u8; SHORT_ID_LEN];
        id.copy_from_slice(&bytes);
        out.push(id);
    }
    Ok(out)
}

fn decode_hex(s: &str) -> anyhow::Result<Vec<u8>> {
    if s.len() % 2 != 0 {
        bail!("hex string must have even length");
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for chunk in bytes.chunks(2) {
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_nibble(c: u8) -> anyhow::Result<u8> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(anyhow!("invalid hex char: 0x{:02x}", c)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_host_port_with_explicit_port() {
        let (h, p) = parse_host_port("Gosuslugi.ru:443").unwrap();
        assert_eq!(h, "gosuslugi.ru");
        assert_eq!(p, 443);
    }

    #[test]
    fn parse_host_port_default_port() {
        let (h, p) = parse_host_port("vk.com").unwrap();
        assert_eq!(h, "vk.com");
        assert_eq!(p, 443);
    }

    #[test]
    fn parse_server_names_csv_lowercase_trim() {
        let names = parse_server_names("Gosuslugi.ru, www.gosuslugi.ru ,VK.com");
        assert_eq!(
            names,
            vec![
                "gosuslugi.ru".to_string(),
                "www.gosuslugi.ru".to_string(),
                "vk.com".to_string(),
            ]
        );
    }

    #[test]
    fn parse_short_ids_accepts_8byte_hex() {
        let ids = parse_short_ids("0102030405060708, abcdef0011223344").unwrap();
        assert_eq!(ids.len(), 2);
        assert_eq!(
            ids[0],
            [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        );
        assert_eq!(
            ids[1],
            [0xab, 0xcd, 0xef, 0x00, 0x11, 0x22, 0x33, 0x44]
        );
    }

    #[test]
    fn parse_short_ids_rejects_wrong_length() {
        assert!(parse_short_ids("0102").is_err());
    }
}
