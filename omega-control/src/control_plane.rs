use std::collections::{HashMap, VecDeque};
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use anyhow::{anyhow, Context};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

use omega_core_wire::{DevicePlatform, DEVICE_TOKEN_LEN};
use omega_stealth::ProductMode;

use crate::identity::auth::{user_status_failure, AuthContext, AuthFailure};
use crate::identity::devices::{DeviceRecord, Platform};
use crate::identity::limits::ensure_device_limit;
use crate::identity::users::{UserRecord, UserStatus};
use crate::identity::{
    generate_uuid_v4, hex_encode, legacy_identity_path, now_ts, uuid_bytes_to_string, AuditEvent,
    RegisteredDevice, AUDIT_CAPACITY, DEFAULT_DB_PATH, DEFAULT_LEGACY_DB_PATH,
    DEFAULT_TOKEN_PEPPER,
};
use crate::policy::{
    default_bootstrap_policy, detect_conflicts, evaluate_policies, validate_policy_object,
    PolicyConflict, PolicyContext, PolicyDecision, PolicyObject, PrivilegeBoundary,
    SessionAdmission,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsistencyLevel {
    Strong,
    Eventual,
}

impl ConsistencyLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Strong => "strong",
            Self::Eventual => "eventual",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsistencyModel {
    pub identity: ConsistencyLevel,
    pub session_lifecycle: ConsistencyLevel,
    pub ticket_lifecycle: ConsistencyLevel,
    pub policy_distribution: ConsistencyLevel,
    pub fabric_membership: ConsistencyLevel,
    pub fabric_health: ConsistencyLevel,
}

impl Default for ConsistencyModel {
    fn default() -> Self {
        Self {
            identity: ConsistencyLevel::Strong,
            session_lifecycle: ConsistencyLevel::Strong,
            ticket_lifecycle: ConsistencyLevel::Strong,
            policy_distribution: ConsistencyLevel::Strong,
            fabric_membership: ConsistencyLevel::Eventual,
            fabric_health: ConsistencyLevel::Eventual,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlPlaneMeta {
    pub revision: u64,
    pub term: u64,
    pub last_updated_at: u64,
    pub last_actor: String,
    pub last_event_hash: String,
    #[serde(default)]
    pub consistency: ConsistencyModel,
}

impl Default for ControlPlaneMeta {
    fn default() -> Self {
        Self {
            revision: 0,
            term: 1,
            last_updated_at: 0,
            last_actor: "bootstrap".to_string(),
            last_event_hash: String::new(),
            consistency: ConsistencyModel::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionStatus {
    Active,
    Terminated,
    Revoked,
    Expired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TicketStatus {
    Issued,
    Consumed,
    Revoked,
    Expired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FabricNodeRole {
    Edge,
    Relay,
    Exit,
}

impl FabricNodeRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Edge => "edge",
            Self::Relay => "relay",
            Self::Exit => "exit",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionRecord {
    pub flow_id: String,
    pub user_id: String,
    pub device_id: String,
    pub tunnel_ip: String,
    pub client_addr: String,
    pub policy_id: String,
    pub mode: ProductMode,
    pub relay_permitted: bool,
    pub privileged_boundary: PrivilegeBoundary,
    #[serde(default)]
    pub active_route_id: String,
    #[serde(default)]
    pub backup_route_ids: Vec<String>,
    #[serde(default)]
    pub route_diversity_score: f64,
    #[serde(default)]
    pub fabric_ticket_generation: u32,
    pub status: SessionStatus,
    #[serde(default = "default_strong_consistency")]
    pub consistency: ConsistencyLevel,
    pub created_at: u64,
    pub updated_at: u64,
    pub last_seen_at: u64,
    pub terminated_at: Option<u64>,
    #[serde(default)]
    pub termination_reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TicketRecord {
    pub ticket_id: String,
    pub ticket_hash: String,
    pub flow_id: String,
    pub device_id: String,
    pub policy_id: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub consumed_at: Option<u64>,
    pub revoked_at: Option<u64>,
    pub status: TicketStatus,
    #[serde(default = "default_strong_consistency")]
    pub consistency: ConsistencyLevel,
    #[serde(default)]
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FabricNodeRecord {
    pub node_id: String,
    pub role: FabricNodeRole,
    pub region: String,
    pub operator: String,
    pub graph_revision: u64,
    pub healthy: bool,
    pub operational_percent: u8,
    pub trust_label: String,
    pub last_seen_at: u64,
    #[serde(default = "default_eventual_consistency")]
    pub consistency: ConsistencyLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlPlaneSummary {
    pub revision: u64,
    pub users: usize,
    pub blocked_users: usize,
    pub active_devices: usize,
    pub revoked_devices: usize,
    pub active_sessions: usize,
    pub issued_tickets: usize,
    pub policies: usize,
    pub fabric_nodes: usize,
}

#[derive(Debug, Clone)]
pub struct SessionActivation {
    pub flow_id: String,
    pub user_id: String,
    pub device_id: String,
    pub tunnel_ip: String,
    pub client_addr: String,
    pub policy_id: String,
    pub mode: ProductMode,
    pub relay_permitted: bool,
    pub privileged_boundary: PrivilegeBoundary,
    pub active_route_id: String,
    pub backup_route_ids: Vec<String>,
    pub route_diversity_score: f64,
    pub fabric_ticket_generation: u32,
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct ControlPlaneSnapshot {
    #[serde(default)]
    meta: ControlPlaneMeta,
    #[serde(default)]
    users: Vec<UserRecord>,
    #[serde(default)]
    devices: Vec<DeviceRecord>,
    #[serde(default)]
    sessions: Vec<SessionRecord>,
    #[serde(default)]
    tickets: Vec<TicketRecord>,
    #[serde(default)]
    fabric_nodes: Vec<FabricNodeRecord>,
    #[serde(default)]
    policies: Vec<PolicyObject>,
    #[serde(default)]
    audit_events: Vec<AuditEvent>,
}

#[derive(Default)]
struct ControlPlaneInner {
    meta: ControlPlaneMeta,
    users: HashMap<String, UserRecord>,
    devices: HashMap<String, DeviceRecord>,
    sessions: HashMap<String, SessionRecord>,
    tickets: HashMap<String, TicketRecord>,
    fabric_nodes: HashMap<String, FabricNodeRecord>,
    policies: HashMap<String, PolicyObject>,
    audit_events: VecDeque<AuditEvent>,
}

#[derive(Clone)]
pub struct ControlPlaneStore {
    inner: Arc<RwLock<ControlPlaneInner>>,
    db_path: PathBuf,
    pepper: Arc<Vec<u8>>,
}
impl ControlPlaneStore {
    pub fn default_path() -> PathBuf {
        std::env::var("OMEGA_CONTROL_PLANE_DB")
            .map(PathBuf::from)
            .or_else(|_| std::env::var("OMEGA_IDENTITY_DB").map(PathBuf::from))
            .unwrap_or_else(|_| PathBuf::from(DEFAULT_DB_PATH))
    }

    pub fn load(db_path: PathBuf) -> anyhow::Result<Self> {
        let pepper = std::env::var("OMEGA_TOKEN_PEPPER")
            .unwrap_or_else(|_| DEFAULT_TOKEN_PEPPER.to_string())
            .into_bytes();
        let store = Self {
            inner: Arc::new(RwLock::new(ControlPlaneInner::default())),
            db_path,
            pepper: Arc::new(pepper),
        };
        if let Some(snapshot) = store.read_snapshot_from_disk()? {
            let mut inner = store.inner.write().unwrap();
            *inner = ControlPlaneInner::from_snapshot(snapshot);
        }
        Ok(store)
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

        self.mutate(|inner| {
            inner.users.insert(user.user_id.clone(), user.clone());
            push_audit(
                inner,
                "create_user",
                actor,
                "user",
                ConsistencyLevel::Strong,
                json!({
                    "user_id": user.user_id,
                    "max_devices": user.max_devices,
                    "max_concurrent_sessions": user.max_concurrent_sessions,
                }),
            );
            Ok(user.clone())
        })
    }

    pub fn block_user(&self, user_id: &str, actor: &str) -> anyhow::Result<UserRecord> {
        self.set_user_status(user_id, UserStatus::Blocked, "block_user", actor, true)
    }

    pub fn unblock_user(&self, user_id: &str, actor: &str) -> anyhow::Result<UserRecord> {
        self.set_user_status(user_id, UserStatus::Active, "unblock_user", actor, false)
    }

    pub fn delete_user(&self, user_id: &str, actor: &str) -> anyhow::Result<UserRecord> {
        self.mutate(|inner| {
            let user = inner
                .users
                .get_mut(user_id)
                .ok_or_else(|| anyhow!("user {} not found", user_id))?;
            user.status = UserStatus::Deleted;
            user.updated_at = now_ts();
            let user_clone = user.clone();

            let affected_devices = inner
                .devices
                .values_mut()
                .filter(|device| device.user_id == user_id && !device.revoked)
                .map(|device| {
                    device.revoked = true;
                    device.updated_at = now_ts();
                    device.device_id.clone()
                })
                .collect::<Vec<_>>();
            revoke_tickets_for_devices(inner, &affected_devices, "user_deleted");
            terminate_sessions_for_user(inner, user_id, SessionStatus::Revoked, "user_deleted");

            push_audit(
                inner,
                "delete_user",
                actor,
                "user",
                ConsistencyLevel::Strong,
                json!({
                    "user_id": user_id,
                    "revoked_devices": affected_devices.len(),
                }),
            );
            Ok(user_clone)
        })
    }

    pub fn list_users(&self) -> Vec<UserRecord> {
        let _ = self.refresh_from_disk();
        let inner = self.inner.read().unwrap();
        let mut users = inner
            .users
            .values()
            .filter(|user| !matches!(user.status, UserStatus::Deleted))
            .cloned()
            .collect::<Vec<_>>();
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

        self.mutate(|inner| {
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
                .filter(|device| device.user_id == user_id && !device.revoked)
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
                inner,
                "register_device",
                actor,
                "device",
                ConsistencyLevel::Strong,
                json!({
                    "user_id": user_id,
                    "device_id": device.device_id,
                    "device_name": device.device_name,
                    "platform": device.platform.as_str(),
                }),
            );
            Ok(RegisteredDevice {
                device,
                device_token: token_hex,
            })
        })
    }

    pub fn revoke_device(&self, device_id: &str, actor: &str) -> anyhow::Result<DeviceRecord> {
        self.mutate(|inner| {
            let device = inner
                .devices
                .get_mut(device_id)
                .ok_or_else(|| anyhow!("device {} not found", device_id))?;
            device.revoked = true;
            device.updated_at = now_ts();
            let device_clone = device.clone();
            revoke_tickets_for_devices(inner, &[device_id.to_string()], "device_revoked");
            terminate_sessions_for_device(
                inner,
                device_id,
                SessionStatus::Revoked,
                "device_revoked",
            );
            push_audit(
                inner,
                "revoke_device",
                actor,
                "device",
                ConsistencyLevel::Strong,
                json!({
                    "device_id": device_id,
                    "user_id": device_clone.user_id,
                }),
            );
            Ok(device_clone)
        })
    }

    pub fn rotate_device_token(
        &self,
        device_id: &str,
        actor: &str,
    ) -> anyhow::Result<RegisteredDevice> {
        let mut token = [0u8; DEVICE_TOKEN_LEN];
        rand::thread_rng().fill_bytes(&mut token);
        let token_hex = hex_encode(&token);
        let token_hash = self.hash_token(&token);

        self.mutate(|inner| {
            let device = inner
                .devices
                .get_mut(device_id)
                .ok_or_else(|| anyhow!("device {} not found", device_id))?;
            if device.revoked {
                return Err(anyhow!("device {} is revoked", device_id));
            }
            device.token_hash = token_hash;
            device.updated_at = now_ts();
            let device_clone = device.clone();
            revoke_tickets_for_devices(inner, &[device_id.to_string()], "token_rotated");
            terminate_sessions_for_device(
                inner,
                device_id,
                SessionStatus::Revoked,
                "token_rotated",
            );
            push_audit(
                inner,
                "rotate_device_token",
                actor,
                "device",
                ConsistencyLevel::Strong,
                json!({ "device_id": device_id }),
            );
            Ok(RegisteredDevice {
                device: device_clone,
                device_token: token_hex,
            })
        })
    }
    pub fn list_user_devices(&self, user_id: &str) -> Vec<DeviceRecord> {
        let _ = self.refresh_from_disk();
        let inner = self.inner.read().unwrap();
        let mut devices = inner
            .devices
            .values()
            .filter(|device| device.user_id == user_id && !device.revoked)
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
        if let Err(err) = self.refresh_from_disk() {
            tracing::warn!(error = %err, "failed to refresh control plane before auth");
        }
        let device_id = uuid_bytes_to_string(&device_id_bytes);
        let token_hash = self.hash_token(&device_token);

        let auth_ctx = {
            let mut inner = self.inner.write().unwrap();
            expire_tickets(&mut inner);
            let device_snapshot = match inner.devices.get(&device_id) {
                Some(device) => device.clone(),
                None => {
                    push_audit(
                        &mut inner,
                        "auth_failed",
                        "handshake",
                        "device",
                        ConsistencyLevel::Strong,
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
                    "device",
                    ConsistencyLevel::Strong,
                    json!({"device_id": device_id, "reason": "invalid_token"}),
                );
                return Err(AuthFailure::AuthFailed);
            }
            if device_snapshot.revoked {
                push_audit(
                    &mut inner,
                    "auth_failed",
                    "handshake",
                    "device",
                    ConsistencyLevel::Strong,
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
                        "user",
                        ConsistencyLevel::Strong,
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
                    "user",
                    ConsistencyLevel::Strong,
                    json!({"device_id": device_id, "user_id": user.user_id, "reason": format!("{:?}", reason).to_ascii_lowercase()}),
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
                "device",
                ConsistencyLevel::Strong,
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

    pub fn authorize_resumption(
        &self,
        device_id_bytes: [u8; 16],
    ) -> Result<AuthContext, AuthFailure> {
        if let Err(err) = self.refresh_from_disk() {
            tracing::warn!(error = %err, "failed to refresh control plane before resume");
        }
        let device_id = uuid_bytes_to_string(&device_id_bytes);

        let auth_ctx = {
            let mut inner = self.inner.write().unwrap();
            expire_tickets(&mut inner);
            let device_snapshot = match inner.devices.get(&device_id) {
                Some(device) => device.clone(),
                None => {
                    push_audit(
                        &mut inner,
                        "resume_failed",
                        "handshake",
                        "device",
                        ConsistencyLevel::Strong,
                        json!({"device_id": device_id, "reason": "unknown_device"}),
                    );
                    return Err(AuthFailure::AuthFailed);
                }
            };
            if device_snapshot.revoked {
                push_audit(
                    &mut inner,
                    "resume_failed",
                    "handshake",
                    "device",
                    ConsistencyLevel::Strong,
                    json!({"device_id": device_id, "reason": "device_revoked"}),
                );
                return Err(AuthFailure::DeviceRevoked);
            }
            let user = match inner.users.get(&device_snapshot.user_id) {
                Some(user) => user.clone(),
                None => {
                    push_audit(
                        &mut inner,
                        "resume_failed",
                        "handshake",
                        "user",
                        ConsistencyLevel::Strong,
                        json!({"device_id": device_id, "reason": "user_not_found"}),
                    );
                    return Err(AuthFailure::AuthFailed);
                }
            };
            if let Some(reason) = user_status_failure(&user.status) {
                push_audit(
                    &mut inner,
                    "resume_failed",
                    "handshake",
                    "user",
                    ConsistencyLevel::Strong,
                    json!({"device_id": device_id, "user_id": user.user_id, "reason": format!("{:?}", reason).to_ascii_lowercase()}),
                );
                return Err(reason);
            }
            let updated_device = {
                let device = inner
                    .devices
                    .get_mut(&device_id)
                    .ok_or(AuthFailure::AuthFailed)?;
                device.last_seen_at = Some(now_ts());
                device.updated_at = now_ts();
                device.clone()
            };
            push_audit(
                &mut inner,
                "resume_success",
                "handshake",
                "device",
                ConsistencyLevel::Strong,
                json!({"device_id": updated_device.device_id, "user_id": user.user_id}),
            );
            AuthContext {
                user,
                device: updated_device,
            }
        };

        if let Err(err) = self.save() {
            tracing::warn!(error = %err, "failed to persist resume update");
        }
        Ok(auth_ctx)
    }

    pub fn ensure_bootstrap_policy(
        &self,
        admission: SessionAdmission,
        actor: &str,
    ) -> anyhow::Result<PolicyObject> {
        let bootstrap = default_bootstrap_policy(&admission);
        self.put_policy(bootstrap, actor)
    }

    pub fn put_policy(
        &self,
        mut policy: PolicyObject,
        actor: &str,
    ) -> anyhow::Result<PolicyObject> {
        validate_policy_object(&policy)?;
        self.mutate(|inner| {
            let mut candidate = inner.policies.values().cloned().collect::<Vec<_>>();
            let next_version = inner
                .policies
                .get(&policy.policy_id)
                .map(|existing| existing.version.saturating_add(1))
                .unwrap_or(policy.version.max(1));
            policy.version = next_version;
            policy.updated_at = now_ts();

            candidate.retain(|existing| existing.policy_id != policy.policy_id);
            candidate.push(policy.clone());
            let conflicts = detect_conflicts(&candidate);
            if !conflicts.is_empty() {
                return Err(anyhow!("policy conflicts detected"));
            }

            inner.policies.insert(policy.policy_id.clone(), policy.clone());
            push_audit(&mut *inner, "put_policy", actor, "policy", ConsistencyLevel::Strong, json!({"policy_id": policy.policy_id, "version": policy.version, "rules": policy.rules.len()}));
            Ok(policy.clone())
        })
    }

    pub fn list_policies(&self) -> Vec<PolicyObject> {
        let _ = self.refresh_from_disk();
        let inner = self.inner.read().unwrap();
        let mut policies = inner.policies.values().cloned().collect::<Vec<_>>();
        policies.sort_by(|a, b| a.policy_id.cmp(&b.policy_id));
        policies
    }

    pub fn policy_conflicts(&self) -> Vec<PolicyConflict> {
        let policies = self.list_policies();
        detect_conflicts(&policies)
    }

    pub fn evaluate_session_admission(
        &self,
        user: &UserRecord,
        device: &DeviceRecord,
        requested: SessionAdmission,
        region: &str,
        node_role: &str,
    ) -> PolicyDecision {
        let _ = self.refresh_from_disk();
        let inner = self.inner.read().unwrap();
        let policies = inner.policies.values().cloned().collect::<Vec<_>>();
        let context = PolicyContext {
            user_id: user.user_id.clone(),
            user_status: user.status.clone(),
            device_id: device.device_id.clone(),
            platform: device.platform.clone(),
            requested,
            region: region.to_string(),
            node_role: node_role.to_string(),
        };
        evaluate_policies(&policies, &context)
    }
    pub fn activate_session(
        &self,
        activation: SessionActivation,
        actor: &str,
    ) -> anyhow::Result<()> {
        self.mutate(|inner| {
            let now = now_ts();
            let record = SessionRecord {
                flow_id: activation.flow_id.clone(),
                user_id: activation.user_id,
                device_id: activation.device_id,
                tunnel_ip: activation.tunnel_ip,
                client_addr: activation.client_addr,
                policy_id: activation.policy_id,
                mode: activation.mode,
                relay_permitted: activation.relay_permitted,
                privileged_boundary: activation.privileged_boundary,
                active_route_id: activation.active_route_id,
                backup_route_ids: activation.backup_route_ids,
                route_diversity_score: activation.route_diversity_score,
                fabric_ticket_generation: activation.fabric_ticket_generation,
                status: SessionStatus::Active,
                consistency: ConsistencyLevel::Strong,
                created_at: inner.sessions.get(&activation.flow_id).map(|existing| existing.created_at).unwrap_or(now),
                updated_at: now,
                last_seen_at: now,
                terminated_at: None,
                termination_reason: String::new(),
            };
            inner.sessions.insert(record.flow_id.clone(), record.clone());
            push_audit(inner, "activate_session", actor, "session", ConsistencyLevel::Strong, json!({"flow_id": record.flow_id, "device_id": record.device_id, "policy_id": record.policy_id, "route_id": record.active_route_id}));
            Ok(())
        })
    }

    pub fn update_session_route(
        &self,
        flow_id: &str,
        active_route_id: &str,
        backup_route_ids: Vec<String>,
        route_diversity_score: f64,
        fabric_ticket_generation: u32,
        actor: &str,
    ) -> anyhow::Result<()> {
        self.mutate(|inner| {
            let session = inner.sessions.get_mut(flow_id).ok_or_else(|| anyhow!("session {} not found", flow_id))?;
            session.active_route_id = active_route_id.to_string();
            session.backup_route_ids = backup_route_ids.clone();
            session.route_diversity_score = route_diversity_score;
            session.fabric_ticket_generation = fabric_ticket_generation;
            session.updated_at = now_ts();
            session.last_seen_at = now_ts();
            push_audit(inner, "update_session_route", actor, "session", ConsistencyLevel::Eventual, json!({"flow_id": flow_id, "active_route_id": active_route_id, "backup_route_ids": backup_route_ids, "fabric_ticket_generation": fabric_ticket_generation}));
            Ok(())
        })
    }

    pub fn terminate_session_record(
        &self,
        flow_id: &str,
        reason: &str,
        actor: &str,
    ) -> anyhow::Result<Option<SessionRecord>> {
        self.mutate(|inner| {
            let Some(session) = inner.sessions.get_mut(flow_id) else {
                return Ok(None);
            };
            if !matches!(session.status, SessionStatus::Active) {
                return Ok(Some(session.clone()));
            }
            session.status = SessionStatus::Terminated;
            session.updated_at = now_ts();
            session.last_seen_at = now_ts();
            session.terminated_at = Some(now_ts());
            session.termination_reason = reason.to_string();
            let session_clone = session.clone();
            push_audit(
                inner,
                "terminate_session",
                actor,
                "session",
                ConsistencyLevel::Strong,
                json!({"flow_id": flow_id, "reason": reason}),
            );
            Ok(Some(session_clone))
        })
    }

    pub fn list_sessions(&self) -> Vec<SessionRecord> {
        let _ = self.refresh_from_disk();
        let inner = self.inner.read().unwrap();
        let mut sessions = inner.sessions.values().cloned().collect::<Vec<_>>();
        sessions.sort_by(|a, b| a.flow_id.cmp(&b.flow_id));
        sessions
    }

    pub fn list_active_sessions(&self) -> Vec<SessionRecord> {
        let mut sessions = self.list_sessions();
        sessions.retain(|session| matches!(session.status, SessionStatus::Active));
        sessions
    }

    pub fn should_terminate_session(&self, flow_id: &str) -> Option<String> {
        let _ = self.refresh_from_disk();
        let inner = self.inner.read().unwrap();
        let session = inner.sessions.get(flow_id)?;
        if !matches!(session.status, SessionStatus::Active) {
            return Some(if session.termination_reason.is_empty() {
                "control_plane_state".to_string()
            } else {
                session.termination_reason.clone()
            });
        }
        if let Some(device) = inner.devices.get(&session.device_id) {
            if device.revoked {
                return Some("device_revoked".to_string());
            }
        }
        if let Some(user) = inner.users.get(&session.user_id) {
            if !matches!(user.status, UserStatus::Active) {
                return Some(format!("user_{:?}", user.status).to_ascii_lowercase());
            }
        }
        None
    }

    pub fn issue_ticket(
        &self,
        raw_ticket: &[u8],
        flow_id: &str,
        device_id: &str,
        policy_id: &str,
        expires_at: u64,
        actor: &str,
    ) -> anyhow::Result<TicketRecord> {
        let ticket_hash = hash_ticket(raw_ticket);
        self.mutate(|inner| {
            expire_tickets(inner);
            let record = TicketRecord {
                ticket_id: ticket_hash.clone(),
                ticket_hash: ticket_hash.clone(),
                flow_id: flow_id.to_string(),
                device_id: device_id.to_string(),
                policy_id: policy_id.to_string(),
                issued_at: now_ts(),
                expires_at,
                consumed_at: None,
                revoked_at: None,
                status: TicketStatus::Issued,
                consistency: ConsistencyLevel::Strong,
                reason: String::new(),
            };
            inner.tickets.insert(ticket_hash.clone(), record.clone());
            push_audit(inner, "issue_ticket", actor, "ticket", ConsistencyLevel::Strong, json!({"ticket_id": record.ticket_id, "flow_id": record.flow_id, "device_id": record.device_id, "expires_at": record.expires_at}));
            Ok(record)
        })
    }

    pub fn authorize_ticket(
        &self,
        raw_ticket: &[u8],
        expected_device_id: &str,
    ) -> Result<TicketRecord, AuthFailure> {
        if let Err(err) = self.refresh_from_disk() {
            tracing::warn!(error = %err, "failed to refresh control plane before ticket auth");
        }
        let ticket_hash = hash_ticket(raw_ticket);
        let mut inner = self.inner.write().unwrap();
        expire_tickets(&mut inner);
        let record = match inner.tickets.get(&ticket_hash) {
            Some(record) => record.clone(),
            None => return Err(AuthFailure::AuthFailed),
        };
        if record.device_id != expected_device_id
            || !matches!(record.status, TicketStatus::Issued)
            || record.expires_at <= now_ts()
        {
            return Err(AuthFailure::AuthFailed);
        }
        Ok(record)
    }

    pub fn consume_ticket(&self, raw_ticket: &[u8], actor: &str) -> anyhow::Result<TicketRecord> {
        let ticket_hash = hash_ticket(raw_ticket);
        self.mutate(|inner| {
            expire_tickets(inner);
            let record = inner
                .tickets
                .get_mut(&ticket_hash)
                .ok_or_else(|| anyhow!("ticket {} not found", ticket_hash))?;
            if !matches!(record.status, TicketStatus::Issued) {
                return Err(anyhow!("ticket {} is not in issued state", ticket_hash));
            }
            record.status = TicketStatus::Consumed;
            record.consumed_at = Some(now_ts());
            let updated = record.clone();
            push_audit(
                inner,
                "consume_ticket",
                actor,
                "ticket",
                ConsistencyLevel::Strong,
                json!({"ticket_id": updated.ticket_id}),
            );
            Ok(updated)
        })
    }

    pub fn upsert_fabric_node(
        &self,
        record: FabricNodeRecord,
        actor: &str,
    ) -> anyhow::Result<FabricNodeRecord> {
        self.mutate(|inner| {
            inner.fabric_nodes.insert(record.node_id.clone(), record.clone());
            push_audit(inner, "upsert_fabric_node", actor, "fabric_node", ConsistencyLevel::Eventual, json!({"node_id": record.node_id, "role": record.role.as_str(), "healthy": record.healthy, "graph_revision": record.graph_revision}));
            Ok(record.clone())
        })
    }

    pub fn mark_fabric_node(
        &self,
        node_id: &str,
        healthy: bool,
        actor: &str,
    ) -> anyhow::Result<Option<FabricNodeRecord>> {
        self.mutate(|inner| {
            let Some(node) = inner.fabric_nodes.get_mut(node_id) else {
                return Ok(None);
            };
            node.healthy = healthy;
            node.last_seen_at = now_ts();
            if !healthy {
                node.operational_percent = 0;
            } else if node.operational_percent == 0 {
                node.operational_percent = 80;
            }
            let clone = node.clone();
            push_audit(
                inner,
                "mark_fabric_node",
                actor,
                "fabric_node",
                ConsistencyLevel::Eventual,
                json!({"node_id": node_id, "healthy": healthy}),
            );
            Ok(Some(clone))
        })
    }

    pub fn list_fabric_nodes(&self) -> Vec<FabricNodeRecord> {
        let _ = self.refresh_from_disk();
        let inner = self.inner.read().unwrap();
        let mut nodes = inner.fabric_nodes.values().cloned().collect::<Vec<_>>();
        nodes.sort_by(|a, b| a.node_id.cmp(&b.node_id));
        nodes
    }

    pub fn append_audit(&self, action: &str, actor: &str, details: serde_json::Value) {
        let result = self.mutate(|inner| {
            push_audit(
                inner,
                action,
                actor,
                "system",
                ConsistencyLevel::Eventual,
                details,
            );
            Ok(())
        });
        if let Err(err) = result {
            tracing::warn!(error = %err, "failed to append control plane audit event");
        }
    }

    pub fn recent_audit(&self, limit: usize) -> Vec<AuditEvent> {
        let _ = self.refresh_from_disk();
        let inner = self.inner.read().unwrap();
        inner
            .audit_events
            .iter()
            .rev()
            .take(limit)
            .cloned()
            .collect::<Vec<_>>()
    }

    pub fn summary(&self) -> ControlPlaneSummary {
        let _ = self.refresh_from_disk();
        let inner = self.inner.read().unwrap();
        ControlPlaneSummary {
            revision: inner.meta.revision,
            users: inner
                .users
                .values()
                .filter(|user| !matches!(user.status, UserStatus::Deleted))
                .count(),
            blocked_users: inner
                .users
                .values()
                .filter(|user| matches!(user.status, UserStatus::Blocked))
                .count(),
            active_devices: inner
                .devices
                .values()
                .filter(|device| !device.revoked)
                .count(),
            revoked_devices: inner
                .devices
                .values()
                .filter(|device| device.revoked)
                .count(),
            active_sessions: inner
                .sessions
                .values()
                .filter(|session| matches!(session.status, SessionStatus::Active))
                .count(),
            issued_tickets: inner
                .tickets
                .values()
                .filter(|ticket| matches!(ticket.status, TicketStatus::Issued))
                .count(),
            policies: inner.policies.len(),
            fabric_nodes: inner.fabric_nodes.len(),
        }
    }

    pub fn save(&self) -> anyhow::Result<()> {
        let inner = self.inner.read().unwrap();
        let snapshot = inner.to_snapshot();
        if let Some(parent) = self.db_path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        let serialized = serde_json::to_string_pretty(&snapshot)?;
        fs::write(&self.db_path, serialized)
            .with_context(|| format!("failed to write {}", self.db_path.display()))
    }
    fn set_user_status(
        &self,
        user_id: &str,
        status: UserStatus,
        action: &str,
        actor: &str,
        revoke_sessions: bool,
    ) -> anyhow::Result<UserRecord> {
        self.mutate(|inner| {
            let user = inner
                .users
                .get_mut(user_id)
                .ok_or_else(|| anyhow!("user {} not found", user_id))?;
            user.status = status.clone();
            user.updated_at = now_ts();
            let updated = user.clone();
            if revoke_sessions && !matches!(status, UserStatus::Active) {
                terminate_sessions_for_user(
                    inner,
                    user_id,
                    SessionStatus::Revoked,
                    &format!("user_{:?}", status).to_ascii_lowercase(),
                );
                let device_ids = inner
                    .devices
                    .values()
                    .filter(|device| device.user_id == user_id)
                    .map(|device| device.device_id.clone())
                    .collect::<Vec<_>>();
                revoke_tickets_for_devices(
                    inner,
                    &device_ids,
                    &format!("user_{:?}", status).to_ascii_lowercase(),
                );
            }
            push_audit(
                inner,
                action,
                actor,
                "user",
                ConsistencyLevel::Strong,
                json!({"user_id": user_id, "status": format!("{:?}", status).to_ascii_lowercase()}),
            );
            Ok(updated)
        })
    }

    fn hash_token(&self, token: &[u8; DEVICE_TOKEN_LEN]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.pepper.as_slice());
        hasher.update(token);
        hex_encode(&hasher.finalize())
    }

    fn refresh_from_disk(&self) -> anyhow::Result<()> {
        if let Some(snapshot) = self.read_snapshot_from_disk()? {
            let mut inner = self.inner.write().unwrap();
            *inner = ControlPlaneInner::from_snapshot(snapshot);
        }
        Ok(())
    }

    fn read_snapshot_from_disk(&self) -> anyhow::Result<Option<ControlPlaneSnapshot>> {
        let readable_path = if self.db_path.exists() {
            Some(self.db_path.clone())
        } else {
            legacy_identity_path(&self.db_path)
                .filter(|path| path.exists())
                .or_else(|| {
                    let legacy = PathBuf::from(DEFAULT_LEGACY_DB_PATH);
                    legacy.exists().then_some(legacy)
                })
        };
        let Some(path) = readable_path else {
            return Ok(None);
        };
        let raw = fs::read_to_string(&path)
            .with_context(|| format!("failed to read control plane store {}", path.display()))?;
        let snapshot: ControlPlaneSnapshot = serde_json::from_str(&raw)
            .with_context(|| format!("invalid control plane JSON in {}", path.display()))?;
        Ok(Some(snapshot))
    }

    fn mutate<T, F>(&self, f: F) -> anyhow::Result<T>
    where
        F: FnOnce(&mut ControlPlaneInner) -> anyhow::Result<T>,
    {
        self.refresh_from_disk()?;
        let result = {
            let mut inner = self.inner.write().unwrap();
            expire_tickets(&mut inner);
            f(&mut inner)
        }?;
        self.save()?;
        Ok(result)
    }
}

impl ControlPlaneInner {
    fn from_snapshot(snapshot: ControlPlaneSnapshot) -> Self {
        let mut inner = Self {
            meta: snapshot.meta,
            users: snapshot
                .users
                .into_iter()
                .map(|user| (user.user_id.clone(), user))
                .collect(),
            devices: snapshot
                .devices
                .into_iter()
                .map(|device| (device.device_id.clone(), device))
                .collect(),
            sessions: snapshot
                .sessions
                .into_iter()
                .map(|session| (session.flow_id.clone(), session))
                .collect(),
            tickets: snapshot
                .tickets
                .into_iter()
                .map(|ticket| (ticket.ticket_hash.clone(), ticket))
                .collect(),
            fabric_nodes: snapshot
                .fabric_nodes
                .into_iter()
                .map(|node| (node.node_id.clone(), node))
                .collect(),
            policies: snapshot
                .policies
                .into_iter()
                .map(|policy| (policy.policy_id.clone(), policy))
                .collect(),
            audit_events: snapshot.audit_events.into_iter().collect(),
        };
        if inner.meta.last_actor.is_empty() {
            inner.meta = ControlPlaneMeta::default();
        }
        expire_tickets(&mut inner);
        inner
    }

    fn to_snapshot(&self) -> ControlPlaneSnapshot {
        ControlPlaneSnapshot {
            meta: self.meta.clone(),
            users: self.users.values().cloned().collect(),
            devices: self.devices.values().cloned().collect(),
            sessions: self.sessions.values().cloned().collect(),
            tickets: self.tickets.values().cloned().collect(),
            fabric_nodes: self.fabric_nodes.values().cloned().collect(),
            policies: self.policies.values().cloned().collect(),
            audit_events: self.audit_events.iter().cloned().collect(),
        }
    }
}

fn push_audit(
    inner: &mut ControlPlaneInner,
    action: &str,
    actor: &str,
    entity: &str,
    consistency: ConsistencyLevel,
    details: serde_json::Value,
) {
    inner.meta.revision = inner.meta.revision.saturating_add(1);
    inner.meta.last_updated_at = now_ts();
    inner.meta.last_actor = actor.to_string();

    let mut event = AuditEvent {
        ts: inner.meta.last_updated_at,
        revision: inner.meta.revision,
        action: action.to_string(),
        actor: actor.to_string(),
        entity: entity.to_string(),
        consistency: consistency.as_str().to_string(),
        details,
        prev_hash: inner.meta.last_event_hash.clone(),
        event_hash: String::new(),
    };
    event.event_hash = hash_audit_event(&event);
    inner.meta.last_event_hash = event.event_hash.clone();
    inner.audit_events.push_back(event);
    while inner.audit_events.len() > AUDIT_CAPACITY {
        inner.audit_events.pop_front();
    }
}

fn terminate_sessions_for_user(
    inner: &mut ControlPlaneInner,
    user_id: &str,
    status: SessionStatus,
    reason: &str,
) {
    for session in inner.sessions.values_mut() {
        if session.user_id == user_id && matches!(session.status, SessionStatus::Active) {
            session.status = status;
            session.updated_at = now_ts();
            session.last_seen_at = now_ts();
            session.terminated_at = Some(now_ts());
            session.termination_reason = reason.to_string();
        }
    }
}

fn terminate_sessions_for_device(
    inner: &mut ControlPlaneInner,
    device_id: &str,
    status: SessionStatus,
    reason: &str,
) {
    for session in inner.sessions.values_mut() {
        if session.device_id == device_id && matches!(session.status, SessionStatus::Active) {
            session.status = status;
            session.updated_at = now_ts();
            session.last_seen_at = now_ts();
            session.terminated_at = Some(now_ts());
            session.termination_reason = reason.to_string();
        }
    }
}

fn revoke_tickets_for_devices(inner: &mut ControlPlaneInner, device_ids: &[String], reason: &str) {
    for ticket in inner.tickets.values_mut() {
        if device_ids
            .iter()
            .any(|device_id| device_id == &ticket.device_id)
            && matches!(ticket.status, TicketStatus::Issued)
        {
            ticket.status = TicketStatus::Revoked;
            ticket.revoked_at = Some(now_ts());
            ticket.reason = reason.to_string();
        }
    }
}

fn expire_tickets(inner: &mut ControlPlaneInner) {
    let now = now_ts();
    for ticket in inner.tickets.values_mut() {
        if matches!(ticket.status, TicketStatus::Issued) && ticket.expires_at <= now {
            ticket.status = TicketStatus::Expired;
            ticket.reason = "expired".to_string();
        }
    }
}

fn hash_audit_event(event: &AuditEvent) -> String {
    let mut hasher = Sha256::new();
    hasher.update(event.ts.to_be_bytes());
    hasher.update(event.revision.to_be_bytes());
    hasher.update(event.action.as_bytes());
    hasher.update(event.actor.as_bytes());
    hasher.update(event.entity.as_bytes());
    hasher.update(event.consistency.as_bytes());
    hasher.update(event.prev_hash.as_bytes());
    hasher.update(event.details.to_string().as_bytes());
    hex_encode(&hasher.finalize())
}

fn hash_ticket(ticket: &[u8]) -> String {
    let digest = Sha256::digest(ticket);
    hex_encode(&digest)
}

fn default_strong_consistency() -> ConsistencyLevel {
    ConsistencyLevel::Strong
}

fn default_eventual_consistency() -> ConsistencyLevel {
    ConsistencyLevel::Eventual
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "omega_control_plane_test_{}_{}_{}.json",
            name,
            std::process::id(),
            now_ts()
        ));
        path
    }

    #[test]
    fn legacy_identity_snapshot_is_loaded_and_extended() {
        let path = temp_path("legacy");
        let legacy = path.with_file_name("identity.json");
        fs::write(&legacy, r#"{"users":[{"user_id":"u-1","status":"active","max_devices":5,"max_concurrent_sessions":3,"created_at":1,"updated_at":1}],"devices":[],"audit_events":[]}"#).expect("write legacy");
        let store = ControlPlaneStore::load(path.clone()).expect("load control plane");
        assert_eq!(store.list_users().len(), 1);
        assert_eq!(store.summary().users, 1);
        let _ = fs::remove_file(legacy);
    }

    #[test]
    fn revoking_device_revokes_issued_tickets() {
        let path = temp_path("revoke_device");
        let store = ControlPlaneStore::load(path.clone()).expect("load");
        let user = store.create_user(5, 3, "test").expect("user");
        let device = store
            .register_device(&user.user_id, "laptop", Platform::Linux, "fp", "test")
            .expect("device");
        store
            .issue_ticket(
                b"ticket-1",
                "flow-1",
                &device.device.device_id,
                "default",
                now_ts() + 60,
                "test",
            )
            .expect("ticket");
        store
            .revoke_device(&device.device.device_id, "test")
            .expect("revoke device");
        assert!(matches!(
            store.authorize_ticket(b"ticket-1", &device.device.device_id),
            Err(AuthFailure::AuthFailed)
        ));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn consume_ticket_is_predictable() {
        let path = temp_path("consume_ticket");
        let store = ControlPlaneStore::load(path.clone()).expect("load");
        let user = store.create_user(5, 3, "test").expect("user");
        let device = store
            .register_device(&user.user_id, "phone", Platform::Android, "fp", "test")
            .expect("device");
        store
            .issue_ticket(
                b"ticket-2",
                "flow-2",
                &device.device.device_id,
                "default",
                now_ts() + 60,
                "test",
            )
            .expect("ticket");
        store.consume_ticket(b"ticket-2", "test").expect("consume");
        assert!(matches!(
            store.authorize_ticket(b"ticket-2", &device.device.device_id),
            Err(AuthFailure::AuthFailed)
        ));
        let _ = fs::remove_file(path);
    }
}
