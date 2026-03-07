use std::collections::{HashMap, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

use omega_core::protocol::{DevicePlatform, DEVICE_TOKEN_LEN};

pub mod auth;
pub mod devices;
pub mod limits;
pub mod users;

use auth::{user_status_failure, AuthContext, AuthFailure};
use devices::{DeviceRecord, Platform};
use limits::ensure_device_limit;
use users::{UserRecord, UserStatus};

const DEFAULT_DB_PATH: &str = "state/identity.json";
const DEFAULT_TOKEN_PEPPER: &str = "omega-change-this-token-pepper";
const AUDIT_CAPACITY: usize = 10_000;

pub const DEFAULT_MAX_DEVICES: u32 = 5;
pub const DEFAULT_MAX_CONCURRENT_SESSIONS: u32 = 3;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub ts: u64,
    pub action: String,
    pub actor: String,
    pub details: serde_json::Value,
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct IdentitySnapshot {
    users: Vec<UserRecord>,
    devices: Vec<DeviceRecord>,
    audit_events: Vec<AuditEvent>,
}

#[derive(Default)]
struct IdentityInner {
    users: HashMap<String, UserRecord>,
    devices: HashMap<String, DeviceRecord>,
    audit_events: VecDeque<AuditEvent>,
}

#[derive(Debug, Clone)]
pub struct RegisteredDevice {
    pub device: DeviceRecord,
    pub device_token: String,
}

#[derive(Clone)]
pub struct IdentityStore {
    inner: Arc<RwLock<IdentityInner>>,
    db_path: PathBuf,
    pepper: Arc<Vec<u8>>,
}

impl IdentityStore {
    pub fn default_path() -> PathBuf {
        std::env::var("OMEGA_IDENTITY_DB")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(DEFAULT_DB_PATH))
    }

    pub fn load(db_path: PathBuf) -> anyhow::Result<Self> {
        let pepper = std::env::var("OMEGA_TOKEN_PEPPER")
            .unwrap_or_else(|_| DEFAULT_TOKEN_PEPPER.to_string())
            .into_bytes();

        let inner = if db_path.exists() {
            let raw = fs::read_to_string(&db_path)
                .with_context(|| format!("failed to read identity store {}", db_path.display()))?;
            let snapshot: IdentitySnapshot = serde_json::from_str(&raw)
                .with_context(|| format!("invalid identity JSON in {}", db_path.display()))?;

            let users = snapshot
                .users
                .into_iter()
                .map(|user| (user.user_id.clone(), user))
                .collect::<HashMap<_, _>>();
            let devices = snapshot
                .devices
                .into_iter()
                .map(|device| (device.device_id.clone(), device))
                .collect::<HashMap<_, _>>();
            let audit_events = snapshot.audit_events.into_iter().collect::<VecDeque<_>>();

            IdentityInner {
                users,
                devices,
                audit_events,
            }
        } else {
            IdentityInner::default()
        };

        Ok(Self {
            inner: Arc::new(RwLock::new(inner)),
            db_path,
            pepper: Arc::new(pepper),
        })
    }

    pub fn create_user(
        &self,
        max_devices: u32,
        max_concurrent_sessions: u32,
        actor: &str,
    ) -> anyhow::Result<UserRecord> {
        let now = now_ts();
        let user = UserRecord {
            user_id: generate_uuid_v4(),
            status: UserStatus::Active,
            max_devices,
            max_concurrent_sessions,
            created_at: now,
            updated_at: now,
        };

        {
            let mut inner = self.inner.write().unwrap();
            inner.users.insert(user.user_id.clone(), user.clone());
            push_audit(
                &mut inner,
                "create_user",
                actor,
                json!({
                    "user_id": user.user_id,
                    "max_devices": user.max_devices,
                    "max_concurrent_sessions": user.max_concurrent_sessions,
                }),
            );
        }

        self.save()?;
        Ok(user)
    }

    pub fn block_user(&self, user_id: &str, actor: &str) -> anyhow::Result<UserRecord> {
        self.set_user_status(user_id, UserStatus::Blocked, "block_user", actor)
    }

    pub fn unblock_user(&self, user_id: &str, actor: &str) -> anyhow::Result<UserRecord> {
        self.set_user_status(user_id, UserStatus::Active, "unblock_user", actor)
    }

    pub fn delete_user(&self, user_id: &str, actor: &str) -> anyhow::Result<UserRecord> {
        self.set_user_status(user_id, UserStatus::Deleted, "delete_user", actor)
    }

    fn set_user_status(
        &self,
        user_id: &str,
        status: UserStatus,
        action: &str,
        actor: &str,
    ) -> anyhow::Result<UserRecord> {
        let updated = {
            let mut inner = self.inner.write().unwrap();
            let (updated, status_text) = {
                let user = inner
                    .users
                    .get_mut(user_id)
                    .ok_or_else(|| anyhow!("user {} not found", user_id))?;
                user.status = status;
                user.updated_at = now_ts();
                (
                    user.clone(),
                    format!("{:?}", user.status).to_ascii_lowercase(),
                )
            };
            push_audit(
                &mut inner,
                action,
                actor,
                json!({ "user_id": user_id, "status": status_text }),
            );
            updated
        };

        self.save()?;
        Ok(updated)
    }

    pub fn list_users(&self) -> Vec<UserRecord> {
        let inner = self.inner.read().unwrap();
        let mut users = inner.users.values().cloned().collect::<Vec<_>>();
        users.sort_by(|a, b| a.user_id.cmp(&b.user_id));
        users
    }

    pub fn register_device(
        &self,
        user_id: &str,
        device_name: &str,
        platform: Platform,
        public_key_fingerprint: &str,
        actor: &str,
    ) -> anyhow::Result<RegisteredDevice> {
        let now = now_ts();
        let mut token = [0u8; DEVICE_TOKEN_LEN];
        rand::thread_rng().fill_bytes(&mut token);
        let token_hex = hex_encode(&token);
        let token_hash = self.hash_token(&token);

        let device = {
            let mut inner = self.inner.write().unwrap();
            let user = inner
                .users
                .get(user_id)
                .ok_or_else(|| anyhow!("user {} not found", user_id))?
                .clone();
            if !user.is_active() {
                return Err(anyhow!("user {} is not active", user_id));
            }

            let active_devices = inner
                .devices
                .values()
                .filter(|d| d.user_id == user_id && !d.revoked)
                .count();
            ensure_device_limit(&user, active_devices).map_err(|_| {
                anyhow!(
                    "max_devices limit exceeded for user {} (limit {})",
                    user_id,
                    user.max_devices
                )
            })?;

            let device = DeviceRecord {
                device_id: generate_uuid_v4(),
                user_id: user_id.to_string(),
                device_name: device_name.to_string(),
                platform,
                public_key_fingerprint: public_key_fingerprint.to_string(),
                token_hash,
                revoked: false,
                last_seen_at: None,
                created_at: now,
                updated_at: now,
            };

            inner
                .devices
                .insert(device.device_id.clone(), device.clone());
            push_audit(
                &mut inner,
                "register_device",
                actor,
                json!({
                    "user_id": user_id,
                    "device_id": device.device_id,
                    "device_name": device.device_name,
                    "platform": device.platform.as_str(),
                }),
            );
            device
        };

        self.save()?;
        Ok(RegisteredDevice {
            device,
            device_token: token_hex,
        })
    }

    pub fn revoke_device(&self, device_id: &str, actor: &str) -> anyhow::Result<DeviceRecord> {
        let updated = {
            let mut inner = self.inner.write().unwrap();
            let (updated, user_id) = {
                let device = inner
                    .devices
                    .get_mut(device_id)
                    .ok_or_else(|| anyhow!("device {} not found", device_id))?;
                device.revoked = true;
                device.updated_at = now_ts();
                (device.clone(), device.user_id.clone())
            };
            push_audit(
                &mut inner,
                "revoke_device",
                actor,
                json!({ "device_id": device_id, "user_id": user_id }),
            );
            updated
        };

        self.save()?;
        Ok(updated)
    }

    pub fn list_user_devices(&self, user_id: &str) -> Vec<DeviceRecord> {
        let inner = self.inner.read().unwrap();
        let mut devices = inner
            .devices
            .values()
            .filter(|d| d.user_id == user_id)
            .cloned()
            .collect::<Vec<_>>();
        devices.sort_by(|a, b| a.device_id.cmp(&b.device_id));
        devices
    }

    pub fn authenticate_device(
        &self,
        device_id_bytes: [u8; 16],
        device_token: [u8; DEVICE_TOKEN_LEN],
        platform: DevicePlatform,
        device_name: &str,
    ) -> Result<AuthContext, AuthFailure> {
        let device_id = uuid_bytes_to_string(&device_id_bytes);
        let token_hash = self.hash_token(&device_token);

        let auth_ctx = {
            let mut inner = self.inner.write().unwrap();

            let device_snapshot = match inner.devices.get(&device_id) {
                Some(device) => device.clone(),
                None => {
                    push_audit(
                        &mut inner,
                        "auth_failed",
                        "handshake",
                        json!({"device_id": device_id, "reason": "unknown_device"}),
                    );
                    return Err(AuthFailure::AuthFailed);
                }
            };

            if token_hash != device_snapshot.token_hash {
                push_audit(
                    &mut inner,
                    "auth_failed",
                    "handshake",
                    json!({"device_id": device_id, "reason": "invalid_token"}),
                );
                return Err(AuthFailure::AuthFailed);
            }

            if device_snapshot.revoked {
                push_audit(
                    &mut inner,
                    "auth_failed",
                    "handshake",
                    json!({"device_id": device_id, "reason": "device_revoked"}),
                );
                return Err(AuthFailure::DeviceRevoked);
            }

            let user = match inner.users.get(&device_snapshot.user_id) {
                Some(user) => user.clone(),
                None => {
                    push_audit(
                        &mut inner,
                        "auth_failed",
                        "handshake",
                        json!({"device_id": device_id, "reason": "user_not_found"}),
                    );
                    return Err(AuthFailure::AuthFailed);
                }
            };

            if let Some(reason) = user_status_failure(&user.status) {
                push_audit(
                    &mut inner,
                    "auth_failed",
                    "handshake",
                    json!({
                        "device_id": device_id,
                        "user_id": user.user_id,
                        "reason": format!("{:?}", reason).to_ascii_lowercase(),
                    }),
                );
                return Err(reason);
            }

            let updated_device = {
                let device = inner
                    .devices
                    .get_mut(&device_id)
                    .ok_or(AuthFailure::AuthFailed)?;
                if !device_name.is_empty() {
                    device.device_name = device_name.to_string();
                }
                device.platform = Platform::from_protocol(platform);
                device.last_seen_at = Some(now_ts());
                device.updated_at = now_ts();
                device.clone()
            };

            push_audit(
                &mut inner,
                "auth_success",
                "handshake",
                json!({"device_id": updated_device.device_id, "user_id": user.user_id}),
            );

            AuthContext {
                user,
                device: updated_device,
            }
        };

        if let Err(err) = self.save() {
            tracing::warn!(error = %err, "failed to persist auth update");
        }

        Ok(auth_ctx)
    }

    pub fn append_audit(&self, action: &str, actor: &str, details: serde_json::Value) {
        {
            let mut inner = self.inner.write().unwrap();
            push_audit(&mut inner, action, actor, details);
        }

        if let Err(err) = self.save() {
            tracing::warn!(error = %err, "failed to persist audit event");
        }
    }

    pub fn recent_audit(&self, limit: usize) -> Vec<AuditEvent> {
        let inner = self.inner.read().unwrap();
        inner
            .audit_events
            .iter()
            .rev()
            .take(limit)
            .cloned()
            .collect::<Vec<_>>()
    }

    pub fn save(&self) -> anyhow::Result<()> {
        let inner = self.inner.read().unwrap();
        let snapshot = IdentitySnapshot {
            users: inner.users.values().cloned().collect(),
            devices: inner.devices.values().cloned().collect(),
            audit_events: inner.audit_events.iter().cloned().collect(),
        };

        if let Some(parent) = self.db_path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }

        let serialized = serde_json::to_string_pretty(&snapshot)?;
        fs::write(&self.db_path, serialized)
            .with_context(|| format!("failed to write {}", self.db_path.display()))
    }

    fn hash_token(&self, token: &[u8; DEVICE_TOKEN_LEN]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.pepper.as_slice());
        hasher.update(token);
        hex_encode(&hasher.finalize())
    }
}

fn push_audit(inner: &mut IdentityInner, action: &str, actor: &str, details: serde_json::Value) {
    inner.audit_events.push_back(AuditEvent {
        ts: now_ts(),
        action: action.to_string(),
        actor: actor.to_string(),
        details,
    });
    while inner.audit_events.len() > AUDIT_CAPACITY {
        inner.audit_events.pop_front();
    }
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

    if !path.exists() {
        fs::write(path, "{\"users\":[],\"devices\":[],\"audit_events\":[]}")
            .with_context(|| format!("failed to initialize {}", path.display()))?;
    }
    Ok(())
}

