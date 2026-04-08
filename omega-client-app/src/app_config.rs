use std::path::{Path, PathBuf};

use anyhow::Context;
use omega_client_runtime::ConnectionProfile;
use serde::{Deserialize, Serialize};

pub const DEFAULT_APP_CONFIG_PATH: &str = "omega-client/state/app-config.json";
const DEFAULT_DIAGNOSTICS_PATH: &str = "omega-client/state/diagnostics.json";
const DEFAULT_LIFECYCLE_PATH: &str = "omega-client/state/lifecycle.json";
const DEFAULT_CONTROL_PATH: &str = "omega-client/state/runtime-control.json";
const DEFAULT_PID_PATH: &str = "omega-client/state/runtime.pid";
const DEFAULT_LOG_PATH: &str = "omega-client/state/runtime.log";
const DEFAULT_UPDATE_ROOT_PATH: &str = "omega-client/state/updates";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DesktopAppConfig {
    pub server_endpoint: String,
    pub device_id: String,
    pub device_token: String,
    pub device_name: String,
    pub profile: ConnectionProfile,
    pub background_mode: bool,
    pub diagnostics_path: PathBuf,
    pub lifecycle_path: PathBuf,
    pub control_path: PathBuf,
    pub pid_path: PathBuf,
    pub log_path: PathBuf,
    pub update_root_path: PathBuf,
    pub install_target_path: Option<PathBuf>,
    pub release_channel: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SanitizedDesktopAppConfig {
    pub server_endpoint: String,
    pub device_id: String,
    pub device_token_masked: String,
    pub device_name: String,
    pub profile: ConnectionProfile,
    pub background_mode: bool,
    pub diagnostics_path: PathBuf,
    pub lifecycle_path: PathBuf,
    pub control_path: PathBuf,
    pub pid_path: PathBuf,
    pub log_path: PathBuf,
    pub update_root_path: PathBuf,
    pub install_target_path: Option<PathBuf>,
    pub release_channel: String,
}

impl Default for DesktopAppConfig {
    fn default() -> Self {
        Self {
            server_endpoint: "127.0.0.1:51820".to_string(),
            device_id: String::new(),
            device_token: String::new(),
            device_name: hostname_fallback(),
            profile: ConnectionProfile::GeneralInternet,
            background_mode: true,
            diagnostics_path: PathBuf::from(DEFAULT_DIAGNOSTICS_PATH),
            lifecycle_path: PathBuf::from(DEFAULT_LIFECYCLE_PATH),
            control_path: PathBuf::from(DEFAULT_CONTROL_PATH),
            pid_path: PathBuf::from(DEFAULT_PID_PATH),
            log_path: PathBuf::from(DEFAULT_LOG_PATH),
            update_root_path: PathBuf::from(DEFAULT_UPDATE_ROOT_PATH),
            install_target_path: None,
            release_channel: "stable".to_string(),
        }
    }
}

impl DesktopAppConfig {
    pub fn load_or_default(path: &Path) -> anyhow::Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(raw) => serde_json::from_str(&raw)
                .map_err(anyhow::Error::from)
                .with_context(|| format!("failed to parse desktop config {}", path.display())),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(err) => Err(err)
                .map_err(anyhow::Error::from)
                .with_context(|| format!("failed to read desktop config {}", path.display())),
        }
    }

    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!(
                    "failed to create desktop config directory {}",
                    parent.display()
                )
            })?;
        }
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)
            .with_context(|| format!("failed to write desktop config {}", path.display()))?;
        Ok(())
    }

    pub fn ensure_ready(&self) -> anyhow::Result<()> {
        if self.server_endpoint.trim().is_empty() {
            anyhow::bail!(
                "desktop client is missing the VPN server endpoint; run `omega-client-app setup`"
            );
        }
        if self.device_id.trim().is_empty() {
            anyhow::bail!("desktop client is missing the device id; run `omega-client-app setup`");
        }
        if self.device_token.trim().is_empty() {
            anyhow::bail!(
                "desktop client is missing the device token; run `omega-client-app setup`"
            );
        }
        Ok(())
    }

    pub fn sanitized(&self) -> SanitizedDesktopAppConfig {
        SanitizedDesktopAppConfig {
            server_endpoint: self.server_endpoint.clone(),
            device_id: self.device_id.clone(),
            device_token_masked: mask_secret(&self.device_token),
            device_name: self.device_name.clone(),
            profile: self.profile,
            background_mode: self.background_mode,
            diagnostics_path: self.diagnostics_path.clone(),
            lifecycle_path: self.lifecycle_path.clone(),
            control_path: self.control_path.clone(),
            pid_path: self.pid_path.clone(),
            log_path: self.log_path.clone(),
            update_root_path: self.update_root_path.clone(),
            install_target_path: self.install_target_path.clone(),
            release_channel: self.release_channel.clone(),
        }
    }
}

pub fn default_app_config_path() -> PathBuf {
    std::env::var("OMEGA_APP_CONFIG_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_APP_CONFIG_PATH))
}

pub fn profile_label(profile: ConnectionProfile) -> &'static str {
    match profile {
        ConnectionProfile::Gaming => "Gaming",
        ConnectionProfile::GeneralInternet => "General Internet",
        ConnectionProfile::RestrictedFallback => "Restricted Fallback",
    }
}

fn mask_secret(secret: &str) -> String {
    if secret.len() <= 8 {
        return "***hidden***".to_string();
    }

    let prefix = &secret[..4];
    let suffix = &secret[secret.len().saturating_sub(4)..];
    format!("{prefix}...{suffix}")
}

fn hostname_fallback() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "omega-desktop".to_string())
}
