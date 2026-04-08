use serde::{Deserialize, Serialize};

use omega_core_wire::DevicePlatform;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    Windows,
    Linux,
    Macos,
    Android,
    Ios,
    Other,
}

impl Platform {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Windows => "windows",
            Self::Linux => "linux",
            Self::Macos => "macos",
            Self::Android => "android",
            Self::Ios => "ios",
            Self::Other => "other",
        }
    }

    pub fn from_str(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "windows" => Some(Self::Windows),
            "linux" => Some(Self::Linux),
            "macos" => Some(Self::Macos),
            "android" => Some(Self::Android),
            "ios" => Some(Self::Ios),
            "other" => Some(Self::Other),
            _ => None,
        }
    }

    pub fn to_protocol(self) -> DevicePlatform {
        match self {
            Self::Windows => DevicePlatform::Windows,
            Self::Linux => DevicePlatform::Linux,
            Self::Macos => DevicePlatform::Macos,
            Self::Android => DevicePlatform::Android,
            Self::Ios => DevicePlatform::Ios,
            Self::Other => DevicePlatform::Other,
        }
    }

    pub fn from_protocol(platform: DevicePlatform) -> Self {
        match platform {
            DevicePlatform::Windows => Self::Windows,
            DevicePlatform::Linux => Self::Linux,
            DevicePlatform::Macos => Self::Macos,
            DevicePlatform::Android => Self::Android,
            DevicePlatform::Ios => Self::Ios,
            DevicePlatform::Other => Self::Other,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRecord {
    pub device_id: String,
    pub user_id: String,
    pub device_name: String,
    pub platform: Platform,
    pub public_key_fingerprint: String,
    pub token_hash: String,
    pub revoked: bool,
    pub last_seen_at: Option<u64>,
    pub created_at: u64,
    pub updated_at: u64,
}
