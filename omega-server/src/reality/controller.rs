//! REALITY runtime controller.
//!
//! Wraps a `RealityRuntime` JoinHandle and exposes hot-reload semantics to
//! the admin web UI. The operator never edits env-vars by hand: they tick a
//! checkbox in the admin, hit "Apply", and this controller atomically
//! swaps the listener task.
//!
//! Source of truth on disk: `state/reality_config.json`. The X25519 server
//! key lives in a *separate* file (`state/reality_x25519.key`) so the
//! configuration JSON can be safely shown to logged-in admins without
//! leaking the private key.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::Serialize;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

use super::config_store::{self, StoredConfig};
use super::{cert_cache::CertSnapshot, keys::RealityKeyPair, RealityConfig, RealityDataPath, RealityRuntime};

pub struct RealityController {
    state_dir: PathBuf,
    datapath: RealityDataPath,
    inner: Mutex<Inner>,
}

struct Inner {
    stored: StoredConfig,
    active: Option<ActiveSession>,
}

struct ActiveSession {
    config: RealityConfig,
    public_key_b64: String,
    listener_task: JoinHandle<()>,
    started_at: std::time::SystemTime,
    cert_snapshots: Vec<CertSummary>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CertSummary {
    pub sni: String,
    pub leaf_sha256_hex: String,
    pub captured_at_unix: u64,
}

#[derive(Debug, Serialize)]
pub struct RealityStatus {
    pub running: bool,
    pub stored: StoredConfig,
    pub public_key_b64: Option<String>,
    pub bind: Option<String>,
    pub primary_sni: Option<String>,
    pub uptime_seconds: Option<u64>,
    pub cert_snapshots: Vec<CertSummary>,
    pub key_file_exists: bool,
}

impl RealityController {
    pub fn new(state_dir: PathBuf, datapath: RealityDataPath) -> Self {
        Self {
            state_dir,
            datapath,
            inner: Mutex::new(Inner {
                stored: StoredConfig::default(),
                active: None,
            }),
        }
    }

    /// Load the persisted config from disk (or bootstrap defaults). If
    /// `enabled = true` after loading, start the listener.
    pub async fn bootstrap(&self) -> Result<()> {
        let stored = config_store::load_or_default(&self.state_dir)
            .context("load reality config from disk")?;
        {
            let mut guard = self.inner.lock().await;
            guard.stored = stored.clone();
        }
        if stored.enabled {
            self.apply(stored).await?;
        }
        Ok(())
    }

    /// Fallback bootstrap: if `state/reality_config.json` is missing and the
    /// caller has parsed env-vars into a `StoredConfig`, persist them as the
    /// initial admin-managed state.
    pub async fn seed_from_env(&self, stored: StoredConfig) -> Result<()> {
        let path = config_store::config_file_path(&self.state_dir);
        if path.exists() {
            return Ok(());
        }
        config_store::save(&self.state_dir, &stored)?;
        {
            let mut guard = self.inner.lock().await;
            guard.stored = stored.clone();
        }
        if stored.enabled {
            self.apply(stored).await?;
        }
        Ok(())
    }

    pub async fn status(&self) -> RealityStatus {
        let guard = self.inner.lock().await;
        let key_file_exists = std::path::Path::new(&guard.stored.key_file).exists();
        if let Some(active) = guard.active.as_ref() {
            RealityStatus {
                running: true,
                stored: guard.stored.clone(),
                public_key_b64: Some(active.public_key_b64.clone()),
                bind: Some(active.config.bind.to_string()),
                primary_sni: Some(active.config.primary_sni().to_string()),
                uptime_seconds: active
                    .started_at
                    .elapsed()
                    .ok()
                    .map(|d| d.as_secs()),
                cert_snapshots: active.cert_snapshots.clone(),
                key_file_exists,
            }
        } else {
            RealityStatus {
                running: false,
                stored: guard.stored.clone(),
                public_key_b64: load_public_key_if_present(&guard.stored.key_file),
                bind: None,
                primary_sni: None,
                uptime_seconds: None,
                cert_snapshots: Vec::new(),
                key_file_exists,
            }
        }
    }

    /// Persist `new_stored` to disk and (re)start or stop the listener
    /// accordingly. Idempotent — calling with the same config is fine.
    pub async fn apply(&self, new_stored: StoredConfig) -> Result<RealityStatus> {
        // 1. Persist FIRST so a crash mid-restart leaves a consistent file.
        config_store::save(&self.state_dir, &new_stored)?;

        // 2. Tear down any active listener.
        {
            let mut guard = self.inner.lock().await;
            if let Some(prev) = guard.active.take() {
                prev.listener_task.abort();
            }
            guard.stored = new_stored.clone();
        }

        if !new_stored.enabled {
            tracing::info!("reality: disabled by admin");
            return Ok(self.status().await);
        }

        // 3. Build runtime config, bootstrap RealityRuntime, spawn listener.
        let config = new_stored.to_runtime().context("translate stored → runtime config")?;
        let datapath = self.datapath.clone();
        let runtime = RealityRuntime::bootstrap(config.clone(), datapath)
            .await
            .context("REALITY bootstrap failed")?;
        let public_key_b64 = runtime.keys.public_base64();
        let cert_snapshots = {
            let snapshots = runtime.snapshots.read().await;
            snapshots
                .values()
                .map(|s: &CertSnapshot| CertSummary {
                    sni: s.sni.clone(),
                    leaf_sha256_hex: s.leaf_sha256_hex(),
                    captured_at_unix: s
                        .captured_at
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or_default(),
                })
                .collect()
        };

        let runtime_for_task = runtime.clone();
        let listener_task = tokio::spawn(async move {
            if let Err(err) = runtime_for_task.run_listener().await {
                tracing::warn!(error = %err, "reality: listener stopped");
            }
        });

        let active = ActiveSession {
            config,
            public_key_b64,
            listener_task,
            started_at: std::time::SystemTime::now(),
            cert_snapshots,
        };
        {
            let mut guard = self.inner.lock().await;
            guard.active = Some(active);
        }

        tracing::info!("reality: applied admin config, listener running");
        Ok(self.status().await)
    }

    /// Generate a fresh X25519 keypair, write it to disk, and return the
    /// new base64-encoded public key. If the listener was running, restart
    /// it so the new key takes effect immediately.
    /// Build a self-contained REALITY connection code that the admin can
    /// paste to clients (Windows / Android). Format:
    ///
    ///     omega-reality://<base64url-no-padding>
    ///
    /// where the payload is JSON {"server","sni","pubkey","short_id","fp"}.
    /// `public_host` is the externally-reachable hostname or IP that clients
    /// should connect to (the local `bind` only knows about `0.0.0.0` etc.).
    pub async fn connection_code(&self, public_host: &str) -> Option<String> {
        let guard = self.inner.lock().await;
        let active = guard.active.as_ref()?;
        let port = active.config.bind.port();
        let sni = active.config.primary_sni().to_string();
        let short_id = active
            .config
            .short_ids
            .first()
            .map(|id| {
                id.iter().map(|b| format!("{:02x}", b)).collect::<String>()
            })
            .unwrap_or_default();
        let payload = serde_json::json!({
            "server": format!("{}:{}", public_host, port),
            "sni": sni,
            "pubkey": active.public_key_b64,
            "short_id": short_id,
            "fp": active.config.fingerprint_profile,
        })
        .to_string();
        Some(format!(
            "omega-reality://{}",
            base64_url_no_pad(payload.as_bytes())
        ))
    }

    pub async fn regenerate_keys(&self) -> Result<String> {
        let stored = { self.inner.lock().await.stored.clone() };
        let path = PathBuf::from(&stored.key_file);
        let pair = RealityKeyPair::generate();
        pair.save(&path)?;
        let pubkey = pair.public_base64();
        tracing::warn!(
            public_key = %pubkey,
            path = %path.display(),
            "reality: admin regenerated server X25519 keypair (clients must update)"
        );
        if stored.enabled {
            self.apply(stored).await?;
        }
        Ok(pubkey)
    }

    pub async fn shutdown(&self) {
        let mut guard = self.inner.lock().await;
        if let Some(prev) = guard.active.take() {
            prev.listener_task.abort();
        }
    }
}

fn load_public_key_if_present(path: &str) -> Option<String> {
    let path = std::path::Path::new(path);
    if !path.exists() {
        return None;
    }
    let raw = std::fs::read_to_string(path).ok()?;
    let v: serde_json::Value = serde_json::from_str(&raw).ok()?;
    let key = v.get("public_key")?.as_str()?.to_string();
    // Validate it really decodes to 32 bytes (so we don't show garbage in UI).
    let bytes = B64.decode(key.as_bytes()).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    Some(key)
}

/// Used by `main.rs` to map legacy `OMEGA_REALITY_*` env-vars into a
/// `StoredConfig` for the first-boot seed. Returns `None` if env-vars do
/// not request REALITY.
pub fn stored_from_env() -> Option<StoredConfig> {
    use std::env;
    let enabled = matches!(
        env::var("OMEGA_REALITY_ENABLE")
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str(),
        "1" | "true" | "yes" | "on"
    );
    if !enabled {
        return None;
    }
    let dest = env::var("OMEGA_REALITY_DEST").ok()?;
    let (dest_host, dest_port) = parse_host_port(&dest)?;
    let bind = env::var("OMEGA_REALITY_BIND").unwrap_or_else(|_| super::DEFAULT_BIND.to_string());
    let server_names: Vec<String> = env::var("OMEGA_REALITY_SERVER_NAMES")
        .ok()
        .map(|v| {
            v.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_else(|| vec![dest_host.clone()]);
    let key_file = env::var("OMEGA_REALITY_PRIVATE_KEY_FILE")
        .unwrap_or_else(|_| super::DEFAULT_KEY_FILE.to_string());
    let cert_dir = env::var("OMEGA_REALITY_CERT_DIR")
        .unwrap_or_else(|_| super::DEFAULT_CERT_DIR.to_string());
    let short_ids_hex: Vec<String> = env::var("OMEGA_REALITY_SHORT_IDS")
        .ok()
        .map(|v| {
            v.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default();
    let fingerprint_profile = env::var("OMEGA_REALITY_FINGERPRINT_PROFILE")
        .unwrap_or_else(|_| super::DEFAULT_FINGERPRINT.to_string());
    let handshake_timeout_ms = env::var("OMEGA_REALITY_HANDSHAKE_TIMEOUT_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(super::DEFAULT_HANDSHAKE_TIMEOUT_MS);

    Some(StoredConfig {
        version: 1,
        enabled: true,
        bind,
        dest_host,
        dest_port,
        server_names,
        key_file,
        cert_dir,
        short_ids_hex,
        fingerprint_profile,
        handshake_timeout_ms,
    })
}

fn base64_url_no_pad(bytes: &[u8]) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    URL_SAFE_NO_PAD.encode(bytes)
}

fn parse_host_port(raw: &str) -> Option<(String, u16)> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    let (host, port) = match raw.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse::<u16>().ok()?),
        None => (raw.to_string(), 443),
    };
    if host.is_empty() {
        return None;
    }
    Some((host.to_ascii_lowercase(), port))
}

/// Type alias for the shared handle propagated through the server.
pub type SharedController = Arc<RealityController>;
