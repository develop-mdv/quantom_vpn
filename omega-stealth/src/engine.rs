use serde::Serialize;

use omega_transport::reliability::{RecoveryStrategy, ReliabilitySnapshot};
use omega_transport::transport_v2::{PathMode, PathSnapshot};

use crate::chaos::ChaosPrng;
use crate::persona::{persona_spec, PersonaFallback, PersonaId, ProbeResponseClass};

#[derive(Debug, Clone, Serialize)]
pub struct StealthSnapshot {
    pub configured_persona: PersonaId,
    pub active_persona: PersonaId,
    pub target_payload_floor: usize,
    pub cover_budget_bytes: usize,
    pub timing_budget_ms: u16,
    pub detectability_improvement_percent: f64,
    pub invalid_probe_response: ProbeResponseClass,
    pub observable_response_classes: u8,
    pub explanation: String,
}

pub struct StealthEngine {
    configured_persona: PersonaId,
    active_persona: PersonaId,
    target_payload_floor: usize,
    cover_budget_bytes: usize,
    timing_budget_ms: u16,
    detectability_improvement_percent: f64,
    invalid_probe_response: ProbeResponseClass,
    observable_response_classes: u8,
    explanation: String,
}

impl StealthEngine {
    pub fn new(configured_persona: PersonaId) -> Self {
        let spec = persona_spec(configured_persona);
        let baseline = persona_spec(PersonaId::Off);
        Self {
            configured_persona,
            active_persona: configured_persona,
            target_payload_floor: 0,
            cover_budget_bytes: spec.cover.max_padding_bytes,
            timing_budget_ms: spec.cover.timing_budget_ms,
            detectability_improvement_percent: ((baseline.target_detectability_auc
                - spec.target_detectability_auc)
                .max(0.0)
                * 100.0),
            invalid_probe_response: spec.handshake.invalid_probe_response,
            observable_response_classes: spec.handshake.observable_response_classes,
            explanation: format!(
                "persona={} initialized with static cover budget {} B",
                configured_persona.label(),
                spec.cover.max_padding_bytes,
            ),
        }
    }

    pub fn configured_persona(&self) -> PersonaId {
        self.configured_persona
    }

    pub fn max_cover_budget_bytes(&self) -> usize {
        persona_spec(self.configured_persona)
            .cover
            .max_padding_bytes
    }

    pub fn client_init_grease_len(&self) -> usize {
        persona_spec(self.configured_persona)
            .handshake
            .client_init_grease_len
    }

    pub fn server_retry_grease_len(&self) -> usize {
        persona_spec(self.configured_persona)
            .handshake
            .server_retry_grease_len
    }

    pub fn invalid_probe_response(&self) -> ProbeResponseClass {
        persona_spec(self.configured_persona)
            .handshake
            .invalid_probe_response
    }

    pub fn observe_network(
        &mut self,
        path: &PathSnapshot,
        reliability: &ReliabilitySnapshot,
    ) -> StealthSnapshot {
        let baseline = persona_spec(PersonaId::Off);
        let configured_spec = persona_spec(self.configured_persona);
        let mut active = self.configured_persona;
        let mut reasons = Vec::new();

        let severe_reliability = matches!(
            reliability.interactive_strategy,
            RecoveryStrategy::FecMedium | RecoveryStrategy::FecHigh
        ) || matches!(
            reliability.control_strategy,
            RecoveryStrategy::DuplicateOnce
        );

        if path.blackhole_suspected
            || matches!(
                path.mode,
                PathMode::BlackholeRecovery | PathMode::Recovering
            )
        {
            if self.configured_persona != PersonaId::Off {
                active = PersonaId::HostileNetwork;
                reasons.push("path blackhole/recovery pushed persona into hostile_network");
            }
        } else if path.route_action == "consider_quieter_persona"
            && matches!(configured_spec.fallback, PersonaFallback::PreferQuicLike)
        {
            active = PersonaId::QuicLike;
            reasons.push("path manager requested a quieter wire image");
        }

        if severe_reliability
            && matches!(
                configured_spec.fallback,
                PersonaFallback::YieldToReliability
            )
        {
            reasons.push("reliability engine forced stealth to reduce cover/timing budget");
        }

        let active_spec = persona_spec(active);
        let mut cover_scale = path.stealth_budget_percent as f64 / 100.0;
        let mut timing_scale = path.stealth_budget_percent as f64 / 100.0;
        if severe_reliability {
            cover_scale *= 0.55;
            timing_scale *= 0.40;
        }
        if matches!(
            path.mode,
            PathMode::Cautious
                | PathMode::Roaming
                | PathMode::Recovering
                | PathMode::BlackholeRecovery
        ) {
            cover_scale *= 0.80;
            timing_scale *= 0.75;
        }

        let cover_budget_bytes =
            (active_spec.cover.max_padding_bytes as f64 * cover_scale).round() as usize;
        let timing_budget_ms =
            (active_spec.cover.timing_budget_ms as f64 * timing_scale).round() as u16;
        let detectability_improvement_percent =
            ((baseline.target_detectability_auc - active_spec.target_detectability_auc).max(0.0)
                * 100.0)
                * cover_scale.clamp(0.35, 1.0);
        self.active_persona = active;
        self.cover_budget_bytes = cover_budget_bytes;
        self.timing_budget_ms = timing_budget_ms;
        self.detectability_improvement_percent = detectability_improvement_percent;
        self.invalid_probe_response = active_spec.handshake.invalid_probe_response;
        self.observable_response_classes = active_spec.handshake.observable_response_classes;
        self.explanation = if reasons.is_empty() {
            format!(
                "persona={} active with cover={} B timing={} ms and path stealth budget={}%%",
                active.label(),
                cover_budget_bytes,
                timing_budget_ms,
                path.stealth_budget_percent,
            )
        } else {
            format!(
                "persona={} active with cover={} B timing={} ms because {}",
                active.label(),
                cover_budget_bytes,
                timing_budget_ms,
                reasons.join("; "),
            )
        };
        self.snapshot()
    }

    pub fn target_padding_floor(
        &mut self,
        encoded_len: usize,
        payload_budget: usize,
        dynamic_padding_budget: usize,
        chaos: &mut ChaosPrng,
    ) -> Option<usize> {
        if self.active_persona == PersonaId::Off {
            self.target_payload_floor = encoded_len;
            return None;
        }

        let cover_budget = self.cover_budget_bytes.min(dynamic_padding_budget);
        if cover_budget < 8 || encoded_len >= payload_budget {
            self.target_payload_floor = encoded_len;
            return None;
        }

        let sample_target = sample_payload_target(self.active_persona, chaos).min(payload_budget);
        let target_floor = sample_target.min(encoded_len.saturating_add(cover_budget));
        self.target_payload_floor = target_floor;
        if target_floor > encoded_len + 3 {
            Some(target_floor)
        } else {
            None
        }
    }

    pub fn snapshot(&self) -> StealthSnapshot {
        StealthSnapshot {
            configured_persona: self.configured_persona,
            active_persona: self.active_persona,
            target_payload_floor: self.target_payload_floor,
            cover_budget_bytes: self.cover_budget_bytes,
            timing_budget_ms: self.timing_budget_ms,
            detectability_improvement_percent: self.detectability_improvement_percent,
            invalid_probe_response: self.invalid_probe_response,
            observable_response_classes: self.observable_response_classes,
            explanation: self.explanation.clone(),
        }
    }
}

fn sample_payload_target(persona: PersonaId, chaos: &mut ChaosPrng) -> usize {
    match persona {
        PersonaId::Off => 0,
        PersonaId::Randomized => {
            let value = chaos.get_target_size() as usize;
            if value < 256 {
                value + ((chaos.next() as usize % 128) + 64)
            } else {
                value
            }
        }
        PersonaId::QuicLike => match chaos.next() % 100 {
            0..=14 => 176 + (chaos.next() as usize % 48),
            15..=39 => 336 + (chaos.next() as usize % 96),
            _ => 1120 + (chaos.next() as usize % 96),
        },
        PersonaId::HostileNetwork => match chaos.next() % 100 {
            0..=24 => 192 + (chaos.next() as usize % 48),
            25..=79 => 320 + (chaos.next() as usize % 160),
            _ => 640 + (chaos.next() as usize % 192),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use omega_transport::transport_v2::{PathBelief, PathMode, PathSnapshot};

    fn stable_path() -> PathSnapshot {
        PathSnapshot {
            payload_budget: 1100,
            confirmed_payload: 1100,
            search_ceiling_payload: 1320,
            probe_target_payload: None,
            jitter_ms: 4,
            loss_percent: 0.4,
            reordering_percent: 0.5,
            quality_score: 90,
            quality_bucket: "excellent".to_string(),
            mode: PathMode::Stable,
            belief: PathBelief::Stable,
            belief_confidence: 92.0,
            blackhole_suspected: false,
            blackhole_events: 0,
            roam_events: 0,
            pacing_factor_percent: 100,
            stealth_budget_percent: 100,
            route_action: "hold_route".to_string(),
            last_action: String::new(),
            explanation: String::new(),
        }
    }

    fn reliability(strategy: RecoveryStrategy) -> ReliabilitySnapshot {
        ReliabilitySnapshot {
            control_strategy: RecoveryStrategy::RetransmitOnly,
            interactive_strategy: strategy,
            bulk_strategy: RecoveryStrategy::RetransmitOnly,
            stealth_cover_strategy: RecoveryStrategy::RetransmitOnly,
            loss_percent: 0.4,
            burst_loss_percent: 0.6,
            jitter_ms: 4,
            quality_score: 90,
            explainability: String::new(),
        }
    }

    #[test]
    fn quieter_route_switches_randomized_to_quic_like() {
        let mut path = stable_path();
        path.route_action = "consider_quieter_persona".to_string();
        let mut engine = StealthEngine::new(PersonaId::Randomized);
        let snapshot =
            engine.observe_network(&path, &reliability(RecoveryStrategy::RetransmitOnly));
        assert_eq!(snapshot.active_persona, PersonaId::QuicLike);
    }

    #[test]
    fn reliability_pressure_reduces_cover_budget() {
        let mut engine = StealthEngine::new(PersonaId::HostileNetwork);
        let relaxed = engine.observe_network(
            &stable_path(),
            &reliability(RecoveryStrategy::RetransmitOnly),
        );
        let constrained =
            engine.observe_network(&stable_path(), &reliability(RecoveryStrategy::FecHigh));
        assert!(constrained.cover_budget_bytes < relaxed.cover_budget_bytes);
        assert!(constrained.timing_budget_ms < relaxed.timing_budget_ms);
    }

    #[test]
    fn target_floor_respects_cover_budget() {
        let mut engine = StealthEngine::new(PersonaId::QuicLike);
        let _ = engine.observe_network(
            &stable_path(),
            &reliability(RecoveryStrategy::RetransmitOnly),
        );
        let mut chaos = ChaosPrng::new(7);
        let floor = engine
            .target_padding_floor(240, 1232, 64, &mut chaos)
            .unwrap();
        assert!(floor > 240);
        assert!(floor <= 304);
    }
}
