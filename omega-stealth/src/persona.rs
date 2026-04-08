use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PersonaId {
    Off,
    Randomized,
    QuicLike,
    HostileNetwork,
}

impl PersonaId {
    pub fn from_env(default: Self) -> Self {
        match std::env::var("OMEGA_PERSONA") {
            Ok(value) => Self::parse(&value).unwrap_or(default),
            Err(_) => default,
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "off" | "disabled" | "persona_off" | "none" => Some(Self::Off),
            "randomized" | "random" => Some(Self::Randomized),
            "quic" | "quic_like" | "quic-like" => Some(Self::QuicLike),
            "hostile" | "hostile_network" | "hostile-network" => Some(Self::HostileNetwork),
            _ => None,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Randomized => "randomized",
            Self::QuicLike => "quic_like",
            Self::HostileNetwork => "hostile_network",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeResponseClass {
    SilentDrop,
    UniformReject,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PersonaFallback {
    None,
    PreferQuicLike,
    PreferHostileNetwork,
    YieldToReliability,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct PacketSizeGrammar {
    pub small_min: u16,
    pub small_max: u16,
    pub medium_min: u16,
    pub medium_max: u16,
    pub large_min: u16,
    pub large_max: u16,
    pub small_weight: u8,
    pub medium_weight: u8,
    pub large_weight: u8,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct TimingPolicy {
    pub base_gap_ms: u16,
    pub jitter_ms: u16,
    pub max_extra_gap_ms: u16,
    pub burst_span: u8,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct HandshakeEnvelope {
    pub client_init_grease_len: usize,
    pub server_retry_grease_len: usize,
    pub invalid_probe_response: ProbeResponseClass,
    pub observable_response_classes: u8,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct CoverBudget {
    pub max_padding_bytes: usize,
    pub timing_budget_ms: u16,
    pub overhead_budget_percent: u8,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct PersonaSpec {
    pub id: PersonaId,
    pub packet_size: PacketSizeGrammar,
    pub timing: TimingPolicy,
    pub handshake: HandshakeEnvelope,
    pub cover: CoverBudget,
    pub fallback: PersonaFallback,
    pub target_detectability_auc: f64,
    pub target_jsd: f64,
    pub target_prs: f64,
}

impl PersonaSpec {
    pub fn label(self) -> &'static str {
        self.id.label()
    }
}

pub fn built_in_personas() -> &'static [PersonaSpec] {
    const PERSONAS: [PersonaSpec; 3] = [
        PersonaSpec {
            id: PersonaId::Randomized,
            packet_size: PacketSizeGrammar {
                small_min: 96,
                small_max: 224,
                medium_min: 256,
                medium_max: 544,
                large_min: 880,
                large_max: 1220,
                small_weight: 32,
                medium_weight: 34,
                large_weight: 34,
            },
            timing: TimingPolicy {
                base_gap_ms: 11,
                jitter_ms: 9,
                max_extra_gap_ms: 12,
                burst_span: 3,
            },
            handshake: HandshakeEnvelope {
                client_init_grease_len: 144,
                server_retry_grease_len: 120,
                invalid_probe_response: ProbeResponseClass::UniformReject,
                observable_response_classes: 2,
            },
            cover: CoverBudget {
                max_padding_bytes: 112,
                timing_budget_ms: 14,
                overhead_budget_percent: 18,
            },
            fallback: PersonaFallback::PreferQuicLike,
            target_detectability_auc: 0.62,
            target_jsd: 0.16,
            target_prs: 78.0,
        },
        PersonaSpec {
            id: PersonaId::QuicLike,
            packet_size: PacketSizeGrammar {
                small_min: 144,
                small_max: 272,
                medium_min: 320,
                medium_max: 448,
                large_min: 1080,
                large_max: 1232,
                small_weight: 20,
                medium_weight: 25,
                large_weight: 55,
            },
            timing: TimingPolicy {
                base_gap_ms: 8,
                jitter_ms: 4,
                max_extra_gap_ms: 8,
                burst_span: 2,
            },
            handshake: HandshakeEnvelope {
                client_init_grease_len: 96,
                server_retry_grease_len: 96,
                invalid_probe_response: ProbeResponseClass::UniformReject,
                observable_response_classes: 1,
            },
            cover: CoverBudget {
                max_padding_bytes: 84,
                timing_budget_ms: 10,
                overhead_budget_percent: 12,
            },
            fallback: PersonaFallback::YieldToReliability,
            target_detectability_auc: 0.58,
            target_jsd: 0.11,
            target_prs: 83.0,
        },
        PersonaSpec {
            id: PersonaId::HostileNetwork,
            packet_size: PacketSizeGrammar {
                small_min: 160,
                small_max: 256,
                medium_min: 288,
                medium_max: 512,
                large_min: 640,
                large_max: 928,
                small_weight: 24,
                medium_weight: 56,
                large_weight: 20,
            },
            timing: TimingPolicy {
                base_gap_ms: 14,
                jitter_ms: 6,
                max_extra_gap_ms: 18,
                burst_span: 2,
            },
            handshake: HandshakeEnvelope {
                client_init_grease_len: 176,
                server_retry_grease_len: 144,
                invalid_probe_response: ProbeResponseClass::UniformReject,
                observable_response_classes: 1,
            },
            cover: CoverBudget {
                max_padding_bytes: 144,
                timing_budget_ms: 18,
                overhead_budget_percent: 24,
            },
            fallback: PersonaFallback::YieldToReliability,
            target_detectability_auc: 0.55,
            target_jsd: 0.08,
            target_prs: 88.0,
        },
    ];
    &PERSONAS
}

pub fn persona_spec(id: PersonaId) -> PersonaSpec {
    match id {
        PersonaId::Off => PersonaSpec {
            id,
            packet_size: PacketSizeGrammar {
                small_min: 96,
                small_max: 160,
                medium_min: 256,
                medium_max: 384,
                large_min: 1000,
                large_max: 1180,
                small_weight: 30,
                medium_weight: 20,
                large_weight: 50,
            },
            timing: TimingPolicy {
                base_gap_ms: 4,
                jitter_ms: 1,
                max_extra_gap_ms: 0,
                burst_span: 4,
            },
            handshake: HandshakeEnvelope {
                client_init_grease_len: 0,
                server_retry_grease_len: 0,
                invalid_probe_response: ProbeResponseClass::UniformReject,
                observable_response_classes: 4,
            },
            cover: CoverBudget {
                max_padding_bytes: 0,
                timing_budget_ms: 0,
                overhead_budget_percent: 0,
            },
            fallback: PersonaFallback::None,
            target_detectability_auc: 0.74,
            target_jsd: 0.31,
            target_prs: 52.0,
        },
        PersonaId::Randomized => built_in_personas()[0],
        PersonaId::QuicLike => built_in_personas()[1],
        PersonaId::HostileNetwork => built_in_personas()[2],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtins_expose_three_production_personas() {
        let personas = built_in_personas();
        assert_eq!(personas.len(), 3);
        assert!(personas
            .iter()
            .any(|persona| persona.id == PersonaId::Randomized));
        assert!(personas
            .iter()
            .any(|persona| persona.id == PersonaId::QuicLike));
        assert!(personas
            .iter()
            .any(|persona| persona.id == PersonaId::HostileNetwork));
    }
}
