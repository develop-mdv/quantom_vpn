use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UserStatus {
    Active,
    Blocked,
    Deleted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserRecord {
    pub user_id: String,
    pub status: UserStatus,
    pub max_devices: u32,
    pub max_concurrent_sessions: u32,
    pub created_at: u64,
    pub updated_at: u64,
}

impl UserRecord {
    pub fn is_active(&self) -> bool {
        matches!(self.status, UserStatus::Active)
    }
}
