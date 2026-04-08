use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HandshakePhase {
    Init,
    Retry,
    Validated,
    Established,
    Resumed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionLifecycle {
    New,
    Active,
    Rekeying,
    Migrating,
    Closing,
    Closed,
}

impl SessionLifecycle {
    pub fn can_send_data(self) -> bool {
        matches!(self, Self::Active | Self::Rekeying | Self::Migrating)
    }
}
