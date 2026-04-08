use omega_control::policy::SessionAdmission;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EgressMode {
    Direct,
    RelayAnchored,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExitPolicy {
    pub egress_mode: EgressMode,
    pub allow_full_tunnel: bool,
    pub allow_split_tunnel: bool,
}

pub trait ExitPlanner {
    fn plan(&self, admission: &SessionAdmission) -> ExitPolicy;
}
