use omega_core_wire::HandshakeRejectReason;

use super::devices::DeviceRecord;
use super::users::{UserRecord, UserStatus};

#[derive(Debug, Clone)]
pub struct AuthContext {
    pub user: UserRecord,
    pub device: DeviceRecord,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthFailure {
    AuthFailed,
    DeviceRevoked,
    UserBlocked,
    UserDeleted,
    LimitExceeded,
}

impl AuthFailure {
    pub fn as_reject_reason(self) -> HandshakeRejectReason {
        match self {
            Self::AuthFailed => HandshakeRejectReason::AuthFailed,
            Self::DeviceRevoked => HandshakeRejectReason::DeviceRevoked,
            Self::UserBlocked | Self::UserDeleted => HandshakeRejectReason::UserBlocked,
            Self::LimitExceeded => HandshakeRejectReason::LimitExceeded,
        }
    }
}

pub fn user_status_failure(status: &UserStatus) -> Option<AuthFailure> {
    match status {
        UserStatus::Active => None,
        UserStatus::Blocked => Some(AuthFailure::UserBlocked),
        UserStatus::Deleted => Some(AuthFailure::UserDeleted),
    }
}
