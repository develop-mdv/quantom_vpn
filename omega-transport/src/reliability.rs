use serde::Serialize;

use omega_core_wire::TrafficClass;

use crate::transport_v2::{PathMode, PathSnapshot};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryStrategy {
    RetransmitOnly,
    DuplicateOnce,
    FecLow,
    FecMedium,
    FecHigh,
}

#[derive(Debug, Clone)]
pub struct ProtectionPlan {
    pub class: TrafficClass,
    pub strategy: RecoveryStrategy,
    pub symbol_size: u16,
    pub repair_packets: u32,
    pub duplicate_packets: u8,
    pub redundancy_budget_percent: u16,
    pub latency_budget_ms: u16,
    pub explanation: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReliabilitySnapshot {
    pub control_strategy: RecoveryStrategy,
    pub interactive_strategy: RecoveryStrategy,
    pub bulk_strategy: RecoveryStrategy,
    pub stealth_cover_strategy: RecoveryStrategy,
    pub loss_percent: f64,
    pub burst_loss_percent: f64,
    pub jitter_ms: u64,
    pub quality_score: u8,
    pub explainability: String,
}

pub struct ReliabilityController {
    control_strategy: RecoveryStrategy,
    interactive_strategy: RecoveryStrategy,
    bulk_strategy: RecoveryStrategy,
    stealth_cover_strategy: RecoveryStrategy,
    good_samples: u8,
    last_loss_percent: f64,
    last_burst_loss_percent: f64,
    last_jitter_ms: u64,
    last_quality_score: u8,
    explanation: String,
}

impl ReliabilityController {
    pub fn new() -> Self {
        Self {
            control_strategy: RecoveryStrategy::RetransmitOnly,
            interactive_strategy: RecoveryStrategy::RetransmitOnly,
            bulk_strategy: RecoveryStrategy::RetransmitOnly,
            stealth_cover_strategy: RecoveryStrategy::RetransmitOnly,
            good_samples: 0,
            last_loss_percent: 0.0,
            last_burst_loss_percent: 0.0,
            last_jitter_ms: 0,
            last_quality_score: 100,
            explanation: "clean path: stay on retransmit-only baseline".to_string(),
        }
    }

    pub fn observe_path(&mut self, path: &PathSnapshot) {
        self.last_loss_percent = path.loss_percent;
        self.last_jitter_ms = path.jitter_ms;
        self.last_quality_score = path.quality_score;
        self.last_burst_loss_percent = estimate_burst_loss(path);

        let healthy = path.loss_percent < 1.0
            && path.jitter_ms < 10
            && path.quality_score >= 82
            && !path.blackhole_suspected;
        if healthy {
            self.good_samples = self.good_samples.saturating_add(1).min(12);
        } else {
            self.good_samples = 0;
        }

        let suggested_control =
            if path.loss_percent <= 15.0 && (path.loss_percent >= 1.5 || path.quality_score < 62) {
                RecoveryStrategy::DuplicateOnce
            } else {
                RecoveryStrategy::RetransmitOnly
            };

        let suggested_interactive = if path.loss_percent > 15.0 {
                // At very high loss FEC overhead is counterproductive — it floods
                // the path with repair packets, causing even more congestion and loss.
                RecoveryStrategy::RetransmitOnly
            } else if path.loss_percent >= 6.0 {
                RecoveryStrategy::FecMedium
            } else if path.loss_percent >= 3.0 || path.jitter_ms >= 18 {
                RecoveryStrategy::FecLow
            } else if path.loss_percent >= 1.25 || path.reordering_percent >= 2.5 {
                RecoveryStrategy::FecLow
            } else {
                RecoveryStrategy::RetransmitOnly
            };

        let suggested_bulk = if path.loss_percent <= 15.0 && self.last_burst_loss_percent >= 7.0 {
            RecoveryStrategy::FecLow
        } else {
            RecoveryStrategy::RetransmitOnly
        };

        // When loss is very high, FEC overhead is counterproductive — force
        // immediate de-escalation instead of waiting for good_samples hysteresis.
        let effective_good = if path.loss_percent > 15.0 { 12 } else { self.good_samples };

        self.control_strategy =
            stickier_strategy(self.control_strategy, suggested_control, effective_good);
        self.interactive_strategy = stickier_strategy(
            self.interactive_strategy,
            suggested_interactive,
            effective_good,
        );
        self.bulk_strategy =
            stickier_strategy(self.bulk_strategy, suggested_bulk, effective_good);
        self.stealth_cover_strategy = RecoveryStrategy::RetransmitOnly;

        self.explanation = format!(
            "loss={:.2}%, burst={:.2}%, jitter={} ms, quality={} => control={:?}, interactive={:?}, bulk={:?}",
            self.last_loss_percent,
            self.last_burst_loss_percent,
            self.last_jitter_ms,
            self.last_quality_score,
            self.control_strategy,
            self.interactive_strategy,
            self.bulk_strategy,
        );
    }

    pub fn plan_for(&self, class: TrafficClass, payload_len: usize) -> Option<ProtectionPlan> {
        let strategy = match class {
            TrafficClass::Control => self.control_strategy,
            TrafficClass::Interactive => self.interactive_strategy,
            TrafficClass::Bulk => self.bulk_strategy,
        };
        let symbol_size = align_symbol_size(payload_len.saturating_add(16));

        match class {
            TrafficClass::Control => match strategy {
                RecoveryStrategy::DuplicateOnce if payload_len <= 320 => Some(ProtectionPlan {
                    class,
                    strategy,
                    symbol_size,
                    repair_packets: 0,
                    duplicate_packets: 1,
                    redundancy_budget_percent: 100,
                    latency_budget_ms: 40,
                    explanation: "duplicate once because control traffic is tiny and recovery latency matters more than bandwidth".to_string(),
                }),
                _ => None,
            },
            TrafficClass::Interactive => match strategy {
                RecoveryStrategy::FecLow if payload_len <= 640 => Some(ProtectionPlan {
                    class,
                    strategy,
                    symbol_size,
                    repair_packets: 1,
                    duplicate_packets: 0,
                    redundancy_budget_percent: 100,
                    latency_budget_ms: 80,
                    explanation: "interactive traffic gets one repair packet because the path is mildly lossy and we want to smooth burst loss without waiting for ARQ".to_string(),
                }),
                RecoveryStrategy::FecMedium if payload_len <= 640 => Some(ProtectionPlan {
                    class,
                    strategy,
                    symbol_size,
                    repair_packets: 2,
                    duplicate_packets: 0,
                    redundancy_budget_percent: 200,
                    latency_budget_ms: 80,
                    explanation: "interactive traffic gets two repair packets because retransmit-only would create visible jitter spikes on this path".to_string(),
                }),
                RecoveryStrategy::FecHigh if payload_len <= 448 => Some(ProtectionPlan {
                    class,
                    strategy,
                    symbol_size,
                    repair_packets: 3,
                    duplicate_packets: 0,
                    redundancy_budget_percent: 300,
                    latency_budget_ms: 90,
                    explanation: "interactive traffic gets high FEC because the path is in blackhole or heavy-loss territory and instant recovery is worth the extra overhead".to_string(),
                }),
                _ => None,
            },
            TrafficClass::Bulk => match strategy {
                RecoveryStrategy::FecLow if payload_len <= 384 => Some(ProtectionPlan {
                    class,
                    strategy,
                    symbol_size,
                    repair_packets: 1,
                    duplicate_packets: 0,
                    redundancy_budget_percent: 100,
                    latency_budget_ms: 250,
                    explanation: "bulk traffic only gets one repair packet on small sub-MTU writes when burst loss would otherwise trigger clustered retransmits".to_string(),
                }),
                _ => None,
            },
        }
    }

    pub fn snapshot(&self) -> ReliabilitySnapshot {
        ReliabilitySnapshot {
            control_strategy: self.control_strategy,
            interactive_strategy: self.interactive_strategy,
            bulk_strategy: self.bulk_strategy,
            stealth_cover_strategy: self.stealth_cover_strategy,
            loss_percent: self.last_loss_percent,
            burst_loss_percent: self.last_burst_loss_percent,
            jitter_ms: self.last_jitter_ms,
            quality_score: self.last_quality_score,
            explainability: self.explanation.clone(),
        }
    }
}

fn estimate_burst_loss(path: &PathSnapshot) -> f64 {
    let mut burst = path.loss_percent;
    if path.blackhole_suspected {
        burst += 4.0;
    }
    if path.jitter_ms >= 18 {
        burst += 1.5;
    }
    if matches!(
        path.mode,
        PathMode::Roaming | PathMode::Recovering | PathMode::BlackholeRecovery
    ) {
        burst += 1.0;
    }
    burst.min(100.0)
}

fn strategy_rank(strategy: RecoveryStrategy) -> u8 {
    match strategy {
        RecoveryStrategy::RetransmitOnly => 0,
        RecoveryStrategy::DuplicateOnce => 1,
        RecoveryStrategy::FecLow => 2,
        RecoveryStrategy::FecMedium => 3,
        RecoveryStrategy::FecHigh => 4,
    }
}

fn stickier_strategy(
    current: RecoveryStrategy,
    suggested: RecoveryStrategy,
    good_samples: u8,
) -> RecoveryStrategy {
    let current_rank = strategy_rank(current);
    let suggested_rank = strategy_rank(suggested);
    if suggested_rank > current_rank {
        suggested
    } else if suggested_rank < current_rank {
        if good_samples >= 4 {
            suggested
        } else {
            current
        }
    } else {
        current
    }
}

fn align_symbol_size(value: usize) -> u16 {
    let clamped = value.max(8).min(u16::MAX as usize - 7);
    ((clamped + 7) / 8 * 8) as u16
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport_v2::{PathBelief, PathMode, PathSnapshot};

    fn sample_path(loss_percent: f64, jitter_ms: u64, quality_score: u8) -> PathSnapshot {
        PathSnapshot {
            payload_budget: 1100,
            confirmed_payload: 1100,
            search_ceiling_payload: 1320,
            probe_target_payload: None,
            jitter_ms,
            loss_percent,
            reordering_percent: 0.0,
            quality_score,
            quality_bucket: "good".to_string(),
            mode: PathMode::Stable,
            belief: PathBelief::Stable,
            belief_confidence: 90.0,
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

    #[test]
    fn interactive_path_escalates_to_fec() {
        let mut controller = ReliabilityController::new();
        controller.observe_path(&sample_path(4.0, 22, 54));
        let plan = controller.plan_for(TrafficClass::Interactive, 320).unwrap();
        assert!(matches!(
            plan.strategy,
            RecoveryStrategy::FecLow | RecoveryStrategy::FecMedium | RecoveryStrategy::FecHigh
        ));
        assert!(plan.repair_packets >= 1);
    }

    #[test]
    fn clean_path_returns_to_retransmit_after_hysteresis() {
        let mut controller = ReliabilityController::new();
        controller.observe_path(&sample_path(5.0, 24, 52));
        assert!(controller
            .plan_for(TrafficClass::Interactive, 320)
            .is_some());
        for _ in 0..5 {
            controller.observe_path(&sample_path(0.2, 4, 92));
        }
        assert!(controller
            .plan_for(TrafficClass::Interactive, 320)
            .is_none());
    }

    #[test]
    fn large_messages_stay_on_retransmit_only_budget() {
        let mut controller = ReliabilityController::new();
        controller.observe_path(&sample_path(6.0, 24, 40));
        assert!(controller
            .plan_for(TrafficClass::Interactive, 900)
            .is_none());
        assert!(controller.plan_for(TrafficClass::Bulk, 700).is_none());
    }
}
