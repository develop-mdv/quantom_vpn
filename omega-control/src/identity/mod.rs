use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context};
use rand::RngCore;
use serde::{Deserialize, Serialize};

pub mod auth;
pub mod devices;
pub mod limits;
pub mod users;

pub use crate::control_plane::ControlPlaneStore as IdentityStore;

use devices::{DeviceRecord, Platform};

pub const DEFAULT_DB_PATH: &str = "state/control_plane.json";
pub const DEFAULT_LEGACY_DB_PATH: &str = "state/identity.json";
pub const DEFAULT_TOKEN_PEPPER: &str = "omega-change-this-token-pepper";
pub const AUDIT_CAPACITY: usize = 10_000;
pub const DEFAULT_MAX_DEVICES: u32 = 5;
pub const DEFAULT_MAX_CONCURRENT_SESSIONS: u32 = 3;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AuditEvent {
    pub ts: u64,
    #[serde(default)]
    pub revision: u64,
    pub action: String,
    pub actor: String,
    #[serde(default)]
    pub entity: String,
    #[serde(default)]
    pub consistency: String,
    pub details: serde_json::Value,
    #[serde(default)]
    pub prev_hash: String,
    #[serde(default)]
    pub event_hash: String,
}

#[derive(Debug, Clone)]
pub struct RegisteredDevice {
    pub device: DeviceRecord,
    pub device_token: String,
}

pub fn now_ts() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn generate_uuid_v4() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    uuid_bytes_to_string(&bytes)
}

pub fn uuid_bytes_to_string(bytes: &[u8; 16]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15],
    )
}

pub fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(hex_char((b >> 4) & 0x0f));
        out.push(hex_char(b & 0x0f));
    }
    out
}

fn hex_char(v: u8) -> char {
    match v {
        0..=9 => (b'0' + v) as char,
        10..=15 => (b'a' + (v - 10)) as char,
        _ => '0',
    }
}

pub fn parse_platform(value: &str) -> anyhow::Result<Platform> {
    Platform::from_str(value).ok_or_else(|| {
        anyhow!(
            "invalid platform '{}', expected windows|linux|macos|android|ios|other",
            value
        )
    })
}

pub fn ensure_identity_file(path: &Path) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }

    if path.exists() {
        return Ok(());
    }

    if let Some(legacy_path) = legacy_identity_path(path) {
        if legacy_path.exists() {
            return Ok(());
        }
    }

    fs::write(path, empty_control_plane_json())
        .with_context(|| format!("failed to initialize {}", path.display()))?;
    Ok(())
}

pub fn legacy_identity_path(path: &Path) -> Option<PathBuf> {
    let file_name = path.file_name()?.to_string_lossy().to_string();
    if file_name.eq_ignore_ascii_case("identity.json") {
        None
    } else {
        Some(path.with_file_name("identity.json"))
    }
}

fn empty_control_plane_json() -> &'static str {
    r#"{"meta":{"revision":0,"term":1,"last_updated_at":0,"last_actor":"bootstrap","last_event_hash":"","consistency":{"identity":"strong","session_lifecycle":"strong","ticket_lifecycle":"strong","policy_distribution":"strong","fabric_membership":"eventual","fabric_health":"eventual"}},"users":[],"devices":[],"sessions":[],"tickets":[],"fabric_nodes":[],"policies":[],"audit_events":[]}"#
}
