use std::cmp::{max, min};
use std::time::{Duration, Instant};

use serde::Serialize;

const DEFAULT_SAFE_PAYLOAD: usize = 1100;
const MIN_PATH_PAYLOAD: usize = 256;
const PROBE_STEP_BYTES: usize = 48;
const PROBE_INTERVAL_SECS: u64 = 4;
const BLACKHOLE_BACKOFF_SECS: u64 = 8;
const ROAM_HOLD_SECS: u64 = 5;
const RECOVERY_HOLD_SECS: u64 = 6;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PathMode {
    Stable,
    Probing,
    Cautious,
    Roaming,
    Recovering,
    BlackholeRecovery,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PathBelief {
    Stable,
    Congested,
    Reordered,
    BlackholeRisk,
    Recovering,
}

#[derive(Debug, Clone, Serialize)]
pub struct PathSnapshot {
    pub payload_budget: usize,
    pub confirmed_payload: usize,
    pub search_ceiling_payload: usize,
    pub probe_target_payload: Option<usize>,
    pub jitter_ms: u64,
    pub loss_percent: f64,
    pub reordering_percent: f64,
    pub quality_score: u8,
    pub quality_bucket: String,
    pub mode: PathMode,
    pub belief: PathBelief,
    pub belief_confidence: f64,
    pub blackhole_suspected: bool,
    pub blackhole_events: u32,
    pub roam_events: u32,
    pub pacing_factor_percent: u8,
    pub stealth_budget_percent: u8,
    pub route_action: String,
    pub last_action: String,
    pub explanation: String,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct PathAckObservation {
    pub acked_bytes: usize,
    pub acked_packets: u32,
    pub reordered_packets: u32,
    pub spurious_reorders: u32,
    pub latest_rtt: Option<Duration>,
    pub probe_success_payload: Option<usize>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct PathLossObservation {
    pub acked_bytes: usize,
    pub lost_bytes: usize,
    pub acked_packets: u32,
    pub lost_packets: u32,
    pub probe_failed_payload: Option<usize>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct PathManagerConfig {
    pub min_payload: usize,
    pub safe_start_payload: usize,
    pub probe_step: usize,
    pub probe_interval: Duration,
    pub blackhole_backoff: Duration,
    pub roam_hold: Duration,
    pub recovery_hold: Duration,
}

impl PathManagerConfig {
    pub(crate) fn for_max_payload(max_payload: usize) -> Self {
        let min_payload = min(max_payload, 640).max(MIN_PATH_PAYLOAD);
        let safe_start_payload =
            min(max_payload, DEFAULT_SAFE_PAYLOAD).max(min_payload.min(max_payload));
        Self {
            min_payload: min_payload.min(max_payload),
            safe_start_payload,
            probe_step: PROBE_STEP_BYTES.min(max_payload.saturating_sub(MIN_PATH_PAYLOAD).max(1)),
            probe_interval: Duration::from_secs(PROBE_INTERVAL_SECS),
            blackhole_backoff: Duration::from_secs(BLACKHOLE_BACKOFF_SECS),
            roam_hold: Duration::from_secs(ROAM_HOLD_SECS),
            recovery_hold: Duration::from_secs(RECOVERY_HOLD_SECS),
        }
    }
}

#[derive(Debug, Clone)]
struct ProbeState {
    target_payload: usize,
    sent_at: Instant,
}

#[derive(Debug, Clone)]
struct BeliefState {
    stable: f64,
    congested: f64,
    reordered: f64,
    blackhole: f64,
    recovering: f64,
}

impl BeliefState {
    fn new() -> Self {
        Self {
            stable: 0.68,
            congested: 0.14,
            reordered: 0.08,
            blackhole: 0.04,
            recovering: 0.06,
        }
    }

    fn normalize(&mut self) {
        let sum = self.stable + self.congested + self.reordered + self.blackhole + self.recovering;
        if sum <= f64::EPSILON {
            *self = Self::new();
            return;
        }
        self.stable /= sum;
        self.congested /= sum;
        self.reordered /= sum;
        self.blackhole /= sum;
        self.recovering /= sum;
    }

    fn apply_evidence(
        &mut self,
        quality_score: u8,
        loss_ratio: f64,
        jitter_ms: f64,
        reordering_ratio: f64,
        blackhole_suspected: bool,
        recovering: bool,
    ) {
        self.stable *= if quality_score >= 70 { 1.22 } else { 0.84 };
        self.congested *= if loss_ratio >= 0.04 || jitter_ms >= 20.0 {
            1.26
        } else {
            0.90
        };
        self.reordered *= if reordering_ratio >= 0.03 { 1.32 } else { 0.88 };
        self.blackhole *= if blackhole_suspected { 1.55 } else { 0.74 };
        self.recovering *= if recovering { 1.38 } else { 0.82 };

        self.stable = self.stable.max(0.01);
        self.congested = self.congested.max(0.01);
        self.reordered = self.reordered.max(0.01);
        self.blackhole = self.blackhole.max(0.01);
        self.recovering = self.recovering.max(0.01);
        self.normalize();
    }

    fn dominant(&self) -> (PathBelief, f64) {
        let values = [
            (PathBelief::Stable, self.stable),
            (PathBelief::Congested, self.congested),
            (PathBelief::Reordered, self.reordered),
            (PathBelief::BlackholeRisk, self.blackhole),
            (PathBelief::Recovering, self.recovering),
        ];
        values
            .into_iter()
            .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
            .unwrap_or((PathBelief::Stable, 1.0))
    }
}

pub(crate) struct PathManager {
    config: PathManagerConfig,
    max_payload: usize,
    confirmed_payload: usize,
    search_ceiling_payload: usize,
    next_probe_at: Instant,
    probe_in_flight: Option<ProbeState>,
    smoothed_rtt: Duration,
    min_rtt: Duration,
    last_rtt_sample: Option<Duration>,
    jitter_ewma_ms: f64,
    loss_ewma: f64,
    reordering_ewma: f64,
    quality_score: u8,
    mode: PathMode,
    belief: BeliefState,
    blackhole_suspected: bool,
    blackhole_events: u32,
    roam_events: u32,
    degrade_streak: u32,
    stability_streak: u32,
    last_ack_at: Instant,
    roam_hold_until: Option<Instant>,
    recovery_hold_until: Option<Instant>,
    last_action: String,
    last_reason: String,
}

impl PathManager {
    pub(crate) fn new(max_payload: usize, initial_rtt: Duration, min_rtt: Duration) -> Self {
        let now = Instant::now();
        let config = PathManagerConfig::for_max_payload(max_payload);
        let confirmed_payload = config
            .safe_start_payload
            .min(max_payload)
            .max(config.min_payload.min(max_payload));
        Self {
            config,
            max_payload,
            confirmed_payload,
            search_ceiling_payload: max_payload,
            next_probe_at: now + Duration::from_secs(PROBE_INTERVAL_SECS),
            probe_in_flight: None,
            smoothed_rtt: initial_rtt,
            min_rtt: if min_rtt.is_zero() { initial_rtt } else { min_rtt.min(initial_rtt) },
            last_rtt_sample: None,
            jitter_ewma_ms: 0.0,
            loss_ewma: 0.0,
            reordering_ewma: 0.0,
            quality_score: 82,
            mode: PathMode::Stable,
            belief: BeliefState::new(),
            blackhole_suspected: false,
            blackhole_events: 0,
            roam_events: 0,
            degrade_streak: 0,
            stability_streak: 1,
            last_ack_at: now,
            roam_hold_until: None,
            recovery_hold_until: None,
            last_action: format!(
                "start from conservative payload {} B and validate larger packets with DPLPMTUD",
                confirmed_payload
            ),
            last_reason: "baseline logic starts below the handshake ceiling and only grows after confirmed delivery".to_string(),
        }
    }

    pub(crate) fn payload_budget(&self, outer_limit: usize) -> usize {
        self.confirmed_payload
            .min(self.search_ceiling_payload)
            .min(self.max_payload)
            .min(outer_limit)
            .max(self.config.min_payload.min(outer_limit.max(1)))
    }

    pub(crate) fn effective_pacing_rate(&self, base_rate_bps: u64) -> u64 {
        let factor = self.pacing_factor_percent() as u64;
        base_rate_bps
            .saturating_mul(factor)
            .checked_div(100)
            .unwrap_or(base_rate_bps)
            .max(1_000)
    }

    pub(crate) fn maybe_probe_target(&self, now: Instant, outer_limit: usize) -> Option<usize> {
        if self.probe_in_flight.is_some() || self.blackhole_suspected {
            return None;
        }
        if now < self.next_probe_at {
            return None;
        }
        if self.quality_score < 70 || self.loss_ewma >= 0.04 || self.jitter_ewma_ms >= 25.0 {
            return None;
        }
        if self.roam_hold_until.is_some_and(|deadline| now < deadline) {
            return None;
        }

        let ceiling = self
            .search_ceiling_payload
            .min(self.max_payload)
            .min(outer_limit);
        if ceiling <= self.confirmed_payload {
            return None;
        }

        let step = self.dynamic_probe_step();
        let target = min(ceiling, self.confirmed_payload.saturating_add(step));
        (target > self.confirmed_payload).then_some(target)
    }

    pub(crate) fn on_probe_sent(&mut self, now: Instant, target_payload: usize) {
        self.probe_in_flight = Some(ProbeState {
            target_payload,
            sent_at: now,
        });
        self.mode = PathMode::Probing;
        self.last_action = format!("sent DPLPMTUD probe at {} B", target_payload);
        self.last_reason = format!(
            "quality {} and low loss/jitter allowed one guarded upward probe",
            self.quality_score
        );
    }

    pub(crate) fn on_ack_batch(
        &mut self,
        now: Instant,
        observation: PathAckObservation,
        smoothed_rtt: Duration,
        min_rtt: Duration,
    ) {
        self.smoothed_rtt = smoothed_rtt;
        if !min_rtt.is_zero() {
            self.min_rtt = if self.min_rtt.is_zero() {
                min_rtt
            } else {
                self.min_rtt.min(min_rtt)
            };
        }

        if observation.acked_packets > 0 {
            self.last_ack_at = now;
            self.loss_ewma = ewma(self.loss_ewma, 0.0, 0.12);
        }

        if let Some(sample) = observation.latest_rtt {
            let sample_ms = sample.as_secs_f64() * 1_000.0;
            if let Some(previous) = self.last_rtt_sample {
                let previous_ms = previous.as_secs_f64() * 1_000.0;
                let jitter_sample = (sample_ms - previous_ms).abs();
                self.jitter_ewma_ms = ewma(self.jitter_ewma_ms, jitter_sample, 0.25);
            }
            self.last_rtt_sample = Some(sample);
        }

        if observation.acked_packets > 0 {
            let reorder_sample = (observation.reordered_packets + observation.spurious_reorders)
                as f64
                / observation.acked_packets.max(1) as f64;
            self.reordering_ewma = ewma(self.reordering_ewma, reorder_sample.clamp(0.0, 1.0), 0.18);
        }

        if let Some(target_payload) = observation.probe_success_payload {
            if self
                .probe_in_flight
                .as_ref()
                .map(|probe| probe.target_payload)
                == Some(target_payload)
            {
                self.probe_in_flight = None;
            }
            self.confirmed_payload = self
                .confirmed_payload
                .max(target_payload)
                .min(self.max_payload);
            self.search_ceiling_payload = self
                .search_ceiling_payload
                .max(self.confirmed_payload)
                .min(self.max_payload);
            self.blackhole_suspected = false;
            self.recovery_hold_until = Some(now + self.config.recovery_hold);
            self.next_probe_at = now + self.config.probe_interval;
            self.stability_streak = self.stability_streak.saturating_add(2).min(8);
            self.degrade_streak = self.degrade_streak.saturating_sub(1);
            self.last_action = format!(
                "confirmed payload {} B after successful probe",
                self.confirmed_payload
            );
            self.last_reason = format!(
                "the larger packet was acknowledged, so the deterministic baseline raised the safe MTU budget to {} B",
                self.confirmed_payload
            );
        } else if observation.acked_packets > 0 && observation.acked_bytes > 0 {
            self.stability_streak = self.stability_streak.saturating_add(1).min(8);
            self.degrade_streak = self.degrade_streak.saturating_sub(1);
        }

        self.refresh_state(now);
    }

    pub(crate) fn on_loss_batch(
        &mut self,
        now: Instant,
        observation: PathLossObservation,
        smoothed_rtt: Duration,
        min_rtt: Duration,
    ) {
        self.smoothed_rtt = smoothed_rtt;
        if !min_rtt.is_zero() {
            self.min_rtt = if self.min_rtt.is_zero() {
                min_rtt
            } else {
                self.min_rtt.min(min_rtt)
            };
        }

        if observation.lost_packets == 0 && observation.lost_bytes == 0 {
            return;
        }

        let total_packets = observation
            .acked_packets
            .saturating_add(observation.lost_packets)
            .max(1);
        let loss_sample = observation.lost_packets as f64 / total_packets as f64;
        self.loss_ewma = ewma(self.loss_ewma, loss_sample.clamp(0.0, 1.0), 0.22);
        self.degrade_streak = self.degrade_streak.saturating_add(1).min(8);
        self.stability_streak = self.stability_streak.saturating_sub(1);

        if let Some(target_payload) = observation.probe_failed_payload {
            if self
                .probe_in_flight
                .as_ref()
                .map(|probe| probe.target_payload)
                == Some(target_payload)
            {
                self.probe_in_flight = None;
            }
            self.search_ceiling_payload = target_payload
                .saturating_sub(self.config.probe_step / 2)
                .max(self.confirmed_payload);
            self.next_probe_at = now + self.config.blackhole_backoff;
            self.last_action = format!(
                "probe at {} B failed, keep confirmed payload at {} B and lower search ceiling to {} B",
                target_payload,
                self.confirmed_payload,
                self.search_ceiling_payload
            );
            self.last_reason = "upward MTU growth is gated by explicit confirmation, so an unconfirmed larger probe only shrinks the search window".to_string();
        }

        let ack_stall = now.saturating_duration_since(self.last_ack_at)
            >= scale_duration(self.smoothed_rtt, 2.0);
        let sustained_loss = observation.lost_packets >= 2 && observation.acked_bytes == 0;
        let large_path = self.confirmed_payload
            > self
                .config
                .min_payload
                .saturating_add(self.config.probe_step);
        if ack_stall && sustained_loss && large_path {
            let reduced_payload = self
                .confirmed_payload
                .saturating_sub(self.dynamic_backoff_step())
                .max(self.config.min_payload);
            if reduced_payload < self.confirmed_payload {
                self.confirmed_payload = reduced_payload;
                self.search_ceiling_payload = max(
                    self.confirmed_payload,
                    self.confirmed_payload
                        .saturating_add(self.config.probe_step),
                )
                .min(self.max_payload);
                self.blackhole_suspected = true;
                self.blackhole_events = self.blackhole_events.saturating_add(1);
                self.recovery_hold_until = Some(now + self.config.recovery_hold);
                self.next_probe_at = now + self.config.blackhole_backoff;
                self.last_action = format!(
                    "blackhole fallback lowered payload to {} B after sustained loss without acknowledgements",
                    self.confirmed_payload
                );
                self.last_reason = "the baseline path manager saw repeated loss at the current size with no fresh ACK progress, which matches a blackhole signature".to_string();
            }
        }

        self.refresh_state(now);
    }

    pub(crate) fn note_peer_roam(&mut self, now: Instant) {
        self.roam_events = self.roam_events.saturating_add(1);
        self.roam_hold_until = Some(now + self.config.roam_hold);
        self.next_probe_at = max_instant(
            self.next_probe_at,
            now + scale_duration(self.smoothed_rtt, 2.0),
        );
        self.degrade_streak = self.degrade_streak.saturating_add(1).min(8);
        self.last_action =
            "peer address changed, hold path steady and freeze upward MTU growth".to_string();
        self.last_reason = "roam events are treated as a controlled transition: keep the route alive, slow pacing slightly and avoid immediate MTU jumps".to_string();
        self.refresh_state(now);
    }

    pub(crate) fn snapshot(&self, outer_limit: usize, now: Instant) -> PathSnapshot {
        let (belief, belief_confidence) = self.belief.dominant();
        PathSnapshot {
            payload_budget: self.payload_budget(outer_limit),
            confirmed_payload: self.confirmed_payload,
            search_ceiling_payload: self.search_ceiling_payload,
            probe_target_payload: self
                .probe_in_flight
                .as_ref()
                .map(|probe| probe.target_payload),
            jitter_ms: self.jitter_ewma_ms.round() as u64,
            loss_percent: round2(self.loss_ewma * 100.0),
            reordering_percent: round2(self.reordering_ewma * 100.0),
            quality_score: self.quality_score,
            quality_bucket: quality_bucket(self.quality_score).to_string(),
            mode: self.current_mode(now),
            belief,
            belief_confidence: round2(belief_confidence * 100.0),
            blackhole_suspected: self.blackhole_suspected,
            blackhole_events: self.blackhole_events,
            roam_events: self.roam_events,
            pacing_factor_percent: self.pacing_factor_percent(),
            stealth_budget_percent: self.stealth_budget_percent(),
            route_action: self.route_action(now),
            last_action: self.last_action.clone(),
            explanation: self.explanation(now),
        }
    }

    #[cfg(test)]
    pub(crate) fn debug_force_probe_due(&mut self) {
        self.next_probe_at = Instant::now();
        self.stability_streak = 6;
        self.quality_score = 90;
        self.loss_ewma = 0.0;
        self.jitter_ewma_ms = 2.0;
        self.blackhole_suspected = false;
    }

    #[cfg(test)]
    pub(crate) fn debug_confirmed_payload(&self) -> usize {
        self.confirmed_payload
    }

    fn refresh_state(&mut self, now: Instant) {
        if self
            .recovery_hold_until
            .is_some_and(|deadline| now >= deadline)
        {
            self.recovery_hold_until = None;
            self.blackhole_suspected = false;
        }
        if self.roam_hold_until.is_some_and(|deadline| now >= deadline) {
            self.roam_hold_until = None;
        }

        self.quality_score = self.compute_quality_score(now);
        let mode = self.current_mode(now);
        self.mode = mode;
        self.belief.apply_evidence(
            self.quality_score,
            self.loss_ewma,
            self.jitter_ewma_ms,
            self.reordering_ewma,
            self.blackhole_suspected,
            matches!(mode, PathMode::Recovering | PathMode::BlackholeRecovery),
        );
    }

    fn current_mode(&self, now: Instant) -> PathMode {
        if self.blackhole_suspected {
            return PathMode::BlackholeRecovery;
        }
        if self.probe_in_flight.is_some() {
            return PathMode::Probing;
        }
        if self.roam_hold_until.is_some_and(|deadline| now < deadline) {
            return PathMode::Roaming;
        }
        if self
            .recovery_hold_until
            .is_some_and(|deadline| now < deadline)
        {
            return PathMode::Recovering;
        }
        if self.degrade_streak >= 2 || self.quality_score < 55 {
            return PathMode::Cautious;
        }
        PathMode::Stable
    }

    fn compute_quality_score(&self, now: Instant) -> u8 {
        let min_rtt_ms = self.min_rtt.as_secs_f64() * 1_000.0;
        let smoothed_rtt_ms = self.smoothed_rtt.as_secs_f64() * 1_000.0;
        let inflation = if min_rtt_ms <= f64::EPSILON {
            0.0
        } else {
            ((smoothed_rtt_ms / min_rtt_ms) - 1.0).max(0.0)
        };
        let loss_penalty = (self.loss_ewma * 420.0).min(42.0);
        let jitter_penalty = (self.jitter_ewma_ms / 3.5).min(18.0);
        let reorder_penalty = (self.reordering_ewma * 220.0).min(12.0);
        let inflation_penalty = (inflation * 24.0).min(16.0);
        let roam_penalty = if self.roam_hold_until.is_some_and(|deadline| now < deadline) {
            8.0
        } else {
            0.0
        };
        let blackhole_penalty = if self.blackhole_suspected { 24.0 } else { 0.0 };
        let quality = 100.0
            - loss_penalty
            - jitter_penalty
            - reorder_penalty
            - inflation_penalty
            - roam_penalty
            - blackhole_penalty;
        quality.round().clamp(5.0, 100.0) as u8
    }

    fn dynamic_probe_step(&self) -> usize {
        if self.quality_score >= 88 && self.loss_ewma < 0.01 && self.jitter_ewma_ms < 8.0 {
            self.config.probe_step.saturating_mul(2).min(96)
        } else {
            self.config.probe_step.max(24)
        }
    }

    fn dynamic_backoff_step(&self) -> usize {
        let jitter_component = (self.jitter_ewma_ms / 2.0).round() as usize;
        self.config
            .probe_step
            .saturating_add(jitter_component)
            .clamp(self.config.probe_step, 128)
    }

    fn pacing_factor_percent(&self) -> u8 {
        match self.mode {
            PathMode::Stable => 100,
            PathMode::Probing => 95,
            PathMode::Cautious => 85,
            PathMode::Roaming => 80,
            PathMode::Recovering => 88,
            PathMode::BlackholeRecovery => 70,
        }
    }

    fn stealth_budget_percent(&self) -> u8 {
        match self.mode {
            PathMode::Stable => 100,
            PathMode::Probing => 90,
            PathMode::Cautious => 75,
            PathMode::Roaming => 70,
            PathMode::Recovering => 80,
            PathMode::BlackholeRecovery => 55,
        }
    }

    fn route_action(&self, now: Instant) -> String {
        if self.blackhole_suspected {
            "prefer_fallback_route".to_string()
        } else if self.roam_hold_until.is_some_and(|deadline| now < deadline) {
            "hold_route_after_roam".to_string()
        } else {
            match self.belief.dominant().0 {
                PathBelief::Congested => "consider_quieter_persona".to_string(),
                PathBelief::Reordered => "hold_route_and_reduce_burstiness".to_string(),
                PathBelief::BlackholeRisk => "prefer_fallback_route".to_string(),
                PathBelief::Recovering => "revalidate_route_cautiously".to_string(),
                PathBelief::Stable => "hold_route".to_string(),
            }
        }
    }

    fn explanation(&self, now: Instant) -> String {
        let (belief, confidence) = self.belief.dominant();
        let probe_text = if let Some(probe) = &self.probe_in_flight {
            format!(
                ", active probe={} B (age={} ms)",
                probe.target_payload,
                now.saturating_duration_since(probe.sent_at).as_millis()
            )
        } else {
            String::new()
        };
        format!(
            "mode={:?}, quality={}, payload={} B, ceiling={} B, loss={:.2}%, jitter={} ms, reordering={:.2}%, belief={:?} ({:.2}%), blackhole={}, route_action={}{}. {}",
            self.current_mode(now),
            self.quality_score,
            self.confirmed_payload,
            self.search_ceiling_payload,
            self.loss_ewma * 100.0,
            self.jitter_ewma_ms.round() as u64,
            self.reordering_ewma * 100.0,
            belief,
            confidence * 100.0,
            self.blackhole_suspected,
            self.route_action(now),
            probe_text,
            self.last_reason,
        )
    }
}

fn ewma(current: f64, sample: f64, weight_new: f64) -> f64 {
    let weight_old = 1.0 - weight_new;
    if current <= f64::EPSILON {
        sample
    } else {
        current * weight_old + sample * weight_new
    }
}

fn round2(value: f64) -> f64 {
    (value * 100.0).round() / 100.0
}

fn quality_bucket(score: u8) -> &'static str {
    match score {
        85..=u8::MAX => "excellent",
        70..=84 => "good",
        55..=69 => "fair",
        35..=54 => "poor",
        _ => "critical",
    }
}

fn scale_duration(duration: Duration, factor: f64) -> Duration {
    let micros = (duration.as_micros() as f64 * factor).round().max(1.0);
    Duration::from_micros(micros.min(u64::MAX as f64) as u64)
}

fn max_instant(a: Instant, b: Instant) -> Instant {
    if a >= b {
        a
    } else {
        b
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn successful_probe_raises_confirmed_payload() {
        let mut manager =
            PathManager::new(1320, Duration::from_millis(90), Duration::from_millis(40));
        manager.debug_force_probe_due();
        let now = Instant::now();
        let probe = manager.maybe_probe_target(now, 1320).unwrap();
        manager.on_probe_sent(now, probe);
        manager.on_ack_batch(
            now + Duration::from_millis(60),
            PathAckObservation {
                acked_bytes: probe,
                acked_packets: 1,
                reordered_packets: 0,
                spurious_reorders: 0,
                latest_rtt: Some(Duration::from_millis(60)),
                probe_success_payload: Some(probe),
            },
            Duration::from_millis(70),
            Duration::from_millis(40),
        );
        assert!(manager.debug_confirmed_payload() >= probe);
        assert!(matches!(
            manager.snapshot(1320, Instant::now()).mode,
            PathMode::Recovering | PathMode::Stable
        ));
    }

    #[test]
    fn blackhole_loss_reduces_payload_budget() {
        let mut manager =
            PathManager::new(1320, Duration::from_millis(90), Duration::from_millis(40));
        manager.confirmed_payload = 1280;
        let now = Instant::now();
        manager.last_ack_at = now - Duration::from_millis(400);
        manager.on_loss_batch(
            now,
            PathLossObservation {
                acked_bytes: 0,
                lost_bytes: 1280,
                acked_packets: 0,
                lost_packets: 3,
                probe_failed_payload: None,
            },
            Duration::from_millis(110),
            Duration::from_millis(40),
        );
        let snapshot = manager.snapshot(1320, Instant::now());
        assert!(snapshot.confirmed_payload < 1280);
        assert!(snapshot.blackhole_suspected);
        assert_eq!(snapshot.mode, PathMode::BlackholeRecovery);
    }

    #[test]
    fn short_spikes_do_not_cause_mode_flap() {
        let mut manager =
            PathManager::new(1320, Duration::from_millis(90), Duration::from_millis(40));
        let now = Instant::now();
        manager.on_loss_batch(
            now,
            PathLossObservation {
                acked_bytes: 900,
                lost_bytes: 120,
                acked_packets: 4,
                lost_packets: 1,
                probe_failed_payload: None,
            },
            Duration::from_millis(95),
            Duration::from_millis(40),
        );
        manager.on_ack_batch(
            now + Duration::from_millis(80),
            PathAckObservation {
                acked_bytes: 1024,
                acked_packets: 5,
                reordered_packets: 0,
                spurious_reorders: 0,
                latest_rtt: Some(Duration::from_millis(88)),
                probe_success_payload: None,
            },
            Duration::from_millis(90),
            Duration::from_millis(40),
        );
        let snapshot = manager.snapshot(1320, Instant::now());
        assert_ne!(snapshot.mode, PathMode::BlackholeRecovery);
        assert!(!snapshot.blackhole_suspected);
    }
}
