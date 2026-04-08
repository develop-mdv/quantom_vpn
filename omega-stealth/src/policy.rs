use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProductMode {
    Fast,
    Balanced,
    Stealth,
    HostileNetwork,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MorphingPolicy {
    Full,
    Balanced,
    Off,
}

impl MorphingPolicy {
    pub fn padding_budget_cap(self) -> usize {
        match self {
            Self::Full => 256,
            Self::Balanced => 96,
            Self::Off => 0,
        }
    }
}
