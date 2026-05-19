//! Persisted REALITY runtime configuration.
//!
//! Lives at `state/reality_config.json`. Contains *no* secret material — the
//! X25519 private key is in `state/reality_x25519.key` (separately gitignored
//! and managed by the keygen entry point in the web admin).
//!
//! This file is the source of truth at runtime: the admin web UI rewrites it
//! atomically when the operator clicks "Apply", and the REALITY controller
//! reloads on every change. Environment variables (`OMEGA_REALITY_*`) are
//! treated as a one-shot bootstrap when the file does not exist yet, so
//! existing systemd deployments keep working through their first restart.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};

use super::{
    RealityConfig, DEFAULT_CERT_DIR, DEFAULT_FINGERPRINT, DEFAULT_HANDSHAKE_TIMEOUT_MS,
    DEFAULT_KEY_FILE, SHORT_ID_LEN,
};

const STORE_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredConfig {
    pub version: u32,
    pub enabled: bool,
    pub bind: String,
    pub dest_host: String,
    pub dest_port: u16,
    pub server_names: Vec<String>,
    pub key_file: String,
    pub cert_dir: String,
    /// Hex-encoded `short_id` whitelist (each entry is 16 hex chars).
    pub short_ids_hex: Vec<String>,
    pub fingerprint_profile: String,
    pub handshake_timeout_ms: u64,
}

impl Default for StoredConfig {
    fn default() -> Self {
        Self {
            version: STORE_VERSION,
            enabled: false,
            bind: "0.0.0.0:443".to_string(),
            dest_host: "gosuslugi.ru".to_string(),
            dest_port: 443,
            server_names: vec!["gosuslugi.ru".to_string()],
            key_file: DEFAULT_KEY_FILE.to_string(),
            cert_dir: DEFAULT_CERT_DIR.to_string(),
            short_ids_hex: Vec::new(),
            fingerprint_profile: DEFAULT_FINGERPRINT.to_string(),
            handshake_timeout_ms: DEFAULT_HANDSHAKE_TIMEOUT_MS,
        }
    }
}

impl StoredConfig {
    pub fn from_runtime(config: &RealityConfig, enabled: bool) -> Self {
        Self {
            version: STORE_VERSION,
            enabled,
            bind: config.bind.to_string(),
            dest_host: config.dest_host.clone(),
            dest_port: config.dest_port,
            server_names: config.server_names.clone(),
            key_file: config.key_file.to_string_lossy().into_owned(),
            cert_dir: config.cert_dir.to_string_lossy().into_owned(),
            short_ids_hex: config
                .short_ids
                .iter()
                .map(|id| hex_lower(id))
                .collect(),
            fingerprint_profile: config.fingerprint_profile.clone(),
            handshake_timeout_ms: config.handshake_timeout.as_millis() as u64,
        }
    }

    pub fn to_runtime(&self) -> Result<RealityConfig> {
        if self.version != STORE_VERSION {
            bail!(
                "unsupported reality config version {} (expected {})",
                self.version,
                STORE_VERSION
            );
        }
        let bind = self
            .bind
            .parse()
            .with_context(|| format!("parse bind {}", self.bind))?;
        if self.dest_host.trim().is_empty() {
            bail!("dest_host is required");
        }
        if self.server_names.is_empty() {
            bail!("server_names must not be empty");
        }
        let mut short_ids = Vec::new();
        for raw in &self.short_ids_hex {
            let raw = raw.trim();
            if raw.is_empty() {
                continue;
            }
            short_ids.push(parse_short_id_hex(raw)?);
        }
        Ok(RealityConfig {
            bind,
            dest_host: self.dest_host.trim().to_ascii_lowercase(),
            dest_port: self.dest_port,
            server_names: self
                .server_names
                .iter()
                .map(|s| s.trim().to_ascii_lowercase())
                .filter(|s| !s.is_empty())
                .collect(),
            key_file: PathBuf::from(&self.key_file),
            cert_dir: PathBuf::from(&self.cert_dir),
            short_ids,
            fingerprint_profile: if self.fingerprint_profile.trim().is_empty() {
                DEFAULT_FINGERPRINT.to_string()
            } else {
                self.fingerprint_profile.trim().to_string()
            },
            handshake_timeout: Duration::from_millis(self.handshake_timeout_ms),
        })
    }
}

pub fn config_file_path(state_dir: &Path) -> PathBuf {
    state_dir.join("reality_config.json")
}

pub fn load_or_default(state_dir: &Path) -> Result<StoredConfig> {
    let path = config_file_path(state_dir);
    if !path.exists() {
        return Ok(StoredConfig::default());
    }
    let raw = fs::read_to_string(&path)
        .with_context(|| format!("read {}", path.display()))?;
    let stored: StoredConfig =
        serde_json::from_str(&raw).with_context(|| format!("parse {}", path.display()))?;
    if stored.version != STORE_VERSION {
        bail!(
            "{} version mismatch: got {}, expected {}",
            path.display(),
            stored.version,
            STORE_VERSION
        );
    }
    Ok(stored)
}

pub fn save(state_dir: &Path, stored: &StoredConfig) -> Result<()> {
    fs::create_dir_all(state_dir)
        .with_context(|| format!("create {}", state_dir.display()))?;
    let path = config_file_path(state_dir);
    let json = serde_json::to_string_pretty(stored).context("serialize reality config")?;
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, json).with_context(|| format!("write {}", tmp.display()))?;
    fs::rename(&tmp, &path).with_context(|| format!("rename into {}", path.display()))?;
    Ok(())
}

fn parse_short_id_hex(raw: &str) -> Result<[u8; SHORT_ID_LEN]> {
    if raw.len() != SHORT_ID_LEN * 2 {
        bail!(
            "short_id {raw} must be {} hex chars",
            SHORT_ID_LEN * 2
        );
    }
    let mut out = [0u8; SHORT_ID_LEN];
    for (i, chunk) in raw.as_bytes().chunks_exact(2).enumerate() {
        let s = std::str::from_utf8(chunk).map_err(|_| anyhow!("invalid hex in {raw}"))?;
        out[i] = u8::from_str_radix(s, 16)
            .with_context(|| format!("parse hex {s} in short_id {raw}"))?;
    }
    Ok(out)
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_disabled() {
        let cfg = StoredConfig::default();
        assert!(!cfg.enabled);
        assert_eq!(cfg.dest_host, "gosuslugi.ru");
    }

    #[test]
    fn round_trip_via_runtime_config() {
        let mut stored = StoredConfig::default();
        stored.enabled = true;
        stored.dest_host = "vk.com".to_string();
        stored.dest_port = 443;
        stored.server_names = vec!["vk.com".to_string(), "www.vk.com".to_string()];
        stored.short_ids_hex = vec!["0102030405060708".to_string()];
        let runtime = stored.to_runtime().unwrap();
        assert_eq!(runtime.dest_host, "vk.com");
        assert_eq!(runtime.short_ids.len(), 1);
        assert_eq!(runtime.short_ids[0], [1, 2, 3, 4, 5, 6, 7, 8]);
        let round = StoredConfig::from_runtime(&runtime, true);
        assert_eq!(round.short_ids_hex, stored.short_ids_hex);
        assert_eq!(round.server_names, vec!["vk.com", "www.vk.com"]);
    }
}
