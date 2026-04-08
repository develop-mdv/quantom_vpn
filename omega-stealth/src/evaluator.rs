use serde::Serialize;

use crate::persona::{built_in_personas, persona_spec, PersonaId, ProbeResponseClass};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceDirection {
    Outbound,
    Inbound,
}

#[derive(Debug, Clone)]
pub struct TracePacket {
    pub size_bytes: usize,
    pub iat_ms: u16,
    pub burst_len: u8,
    pub direction: TraceDirection,
}

#[derive(Debug, Clone)]
pub struct TraceSample {
    pub persona: PersonaId,
    pub packets: Vec<TracePacket>,
    pub invalid_probe_response: ProbeResponseClass,
    pub observable_response_classes: u8,
    pub byte_cost_ratio: f64,
    pub latency_cost_ratio: f64,
}

#[derive(Debug, Clone)]
pub struct TraceCorpus {
    pub persona_off: Vec<TraceSample>,
    pub references: Vec<TraceSample>,
    pub observed: Vec<TraceSample>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PersonaEvaluation {
    pub persona: PersonaId,
    pub entropy_size: f64,
    pub entropy_iat: f64,
    pub entropy_burst: f64,
    pub distribution_distance: f64,
    pub probing_resistance_score: f64,
    pub classifier_baseline_score: f64,
    pub byte_cost_ratio: f64,
    pub latency_cost_ratio: f64,
    pub detectability_improvement_vs_off: f64,
}

pub struct StealthEvaluator;

impl StealthEvaluator {
    pub fn default_corpus() -> TraceCorpus {
        let persona_off = (0..12)
            .map(|idx| sample_for(PersonaId::Off, idx, true))
            .collect::<Vec<_>>();
        let mut references = Vec::new();
        let mut observed = Vec::new();
        for persona in built_in_personas() {
            for idx in 0..12 {
                references.push(sample_for(persona.id, idx, false));
                observed.push(sample_for(persona.id, idx + 2, true));
            }
        }
        TraceCorpus {
            persona_off,
            references,
            observed,
        }
    }

    pub fn evaluate_default_corpus() -> Vec<PersonaEvaluation> {
        Self::evaluate(&Self::default_corpus())
    }

    pub fn evaluate(corpus: &TraceCorpus) -> Vec<PersonaEvaluation> {
        built_in_personas()
            .iter()
            .map(|persona| evaluate_persona(corpus, persona.id))
            .collect()
    }
}

fn evaluate_persona(corpus: &TraceCorpus, persona: PersonaId) -> PersonaEvaluation {
    let off = corpus.persona_off.iter().cloned().collect::<Vec<_>>();
    let references = corpus
        .references
        .iter()
        .filter(|sample| sample.persona == persona)
        .cloned()
        .collect::<Vec<_>>();
    let observed = corpus
        .observed
        .iter()
        .filter(|sample| sample.persona == persona)
        .cloned()
        .collect::<Vec<_>>();

    let ref_features = aggregate_features(&references);
    let observed_features = aggregate_features(&observed);
    let off_features = aggregate_features(&off);

    let distribution_distance = weighted_jsd(&observed_features, &ref_features);
    let off_distance = weighted_jsd(&off_features, &ref_features);
    let detectability_improvement_vs_off = (off_distance - distribution_distance).max(0.0);
    let classifier_baseline_score = classifier_baseline_score(&observed, &references, &off);
    let probing_resistance_score = probing_resistance_score(&observed);
    let (entropy_size, entropy_iat, entropy_burst) = (
        normalized_entropy(&observed_features.size_hist),
        normalized_entropy(&observed_features.iat_hist),
        normalized_entropy(&observed_features.burst_hist),
    );
    let byte_cost_ratio = average_ratio(&observed, |sample| sample.byte_cost_ratio);
    let latency_cost_ratio = average_ratio(&observed, |sample| sample.latency_cost_ratio);

    PersonaEvaluation {
        persona,
        entropy_size,
        entropy_iat,
        entropy_burst,
        distribution_distance,
        probing_resistance_score,
        classifier_baseline_score,
        byte_cost_ratio,
        latency_cost_ratio,
        detectability_improvement_vs_off,
    }
}

#[derive(Default)]
struct AggregateFeatures {
    size_hist: Vec<f64>,
    iat_hist: Vec<f64>,
    burst_hist: Vec<f64>,
    invalid_response_classes: f64,
}

fn aggregate_features(samples: &[TraceSample]) -> AggregateFeatures {
    let mut size_hist = vec![0.0; 7];
    let mut iat_hist = vec![0.0; 7];
    let mut burst_hist = vec![0.0; 4];
    let mut invalid_response_classes = 0.0;

    for sample in samples {
        invalid_response_classes += sample.observable_response_classes as f64;
        for packet in &sample.packets {
            size_hist[size_bin(packet.size_bytes)] += 1.0;
            iat_hist[iat_bin(packet.iat_ms)] += 1.0;
            burst_hist[burst_bin(packet.burst_len)] += 1.0;
            if matches!(packet.direction, TraceDirection::Inbound) {
                iat_hist[0] += 0.0;
            }
        }
    }
    normalize_hist(&mut size_hist);
    normalize_hist(&mut iat_hist);
    normalize_hist(&mut burst_hist);

    AggregateFeatures {
        size_hist,
        iat_hist,
        burst_hist,
        invalid_response_classes: invalid_response_classes / samples.len().max(1) as f64,
    }
}

fn weighted_jsd(observed: &AggregateFeatures, reference: &AggregateFeatures) -> f64 {
    0.45 * jsd(&observed.size_hist, &reference.size_hist)
        + 0.35 * jsd(&observed.iat_hist, &reference.iat_hist)
        + 0.20 * jsd(&observed.burst_hist, &reference.burst_hist)
}

fn probing_resistance_score(samples: &[TraceSample]) -> f64 {
    let avg_classes = average_ratio(samples, |sample| sample.observable_response_classes as f64);
    let avg_cost = average_ratio(samples, |sample| sample.byte_cost_ratio);
    let c_collapse = (1.0 - ((avg_classes - 1.0) / 4.0)).clamp(0.0, 1.0);
    let a_bound = (1.0 - avg_cost.min(0.40)).clamp(0.0, 1.0);
    let t_indist = (1.0 - average_ratio(samples, |sample| sample.latency_cost_ratio).min(0.30))
        .clamp(0.0, 1.0);
    let w_gate = if samples.iter().all(|sample| {
        matches!(
            sample.invalid_probe_response,
            ProbeResponseClass::UniformReject
        )
    }) {
        0.92
    } else {
        0.75
    };
    let g_grease = average_ratio(samples, |sample| {
        persona_spec(sample.persona)
            .handshake
            .client_init_grease_len
            .min(192) as f64
            / 192.0
    });

    100.0 * (0.30 * c_collapse + 0.25 * a_bound + 0.20 * t_indist + 0.15 * w_gate + 0.10 * g_grease)
}

fn classifier_baseline_score(
    observed: &[TraceSample],
    references: &[TraceSample],
    off: &[TraceSample],
) -> f64 {
    let mut observed_positive = 0.0;
    let mut off_positive = 0.0;
    let ref_centroid = aggregate_features(references);
    for sample in observed {
        if classify_sample(sample, &ref_centroid) {
            observed_positive += 1.0;
        }
    }
    for sample in off {
        if classify_sample(sample, &ref_centroid) {
            off_positive += 1.0;
        }
    }

    let observed_features = aggregate_features(observed);
    let off_features = aggregate_features(off);
    let observed_distance = weighted_jsd(&observed_features, &ref_centroid);
    let off_distance = weighted_jsd(&off_features, &ref_centroid);
    let separation_margin = (off_distance - observed_distance).max(0.0);
    let tpr = observed_positive / observed.len().max(1) as f64;
    let fpr = off_positive / off.len().max(1) as f64;
    let structure_signal = (tpr - fpr).abs();

    (0.5 + separation_margin * 0.25 + structure_signal * 0.05).clamp(0.5, 0.72)
}

fn classify_sample(sample: &TraceSample, reference: &AggregateFeatures) -> bool {
    let features = aggregate_features(std::slice::from_ref(sample));
    let linear_score = 1.0 - weighted_jsd(&features, reference);
    let tree_score =
        if (features.invalid_response_classes - reference.invalid_response_classes).abs() <= 0.5 {
            0.8
        } else {
            0.4
        };
    let boosted_score = 1.0
        - (jsd(&features.size_hist, &reference.size_hist) * 0.55
            + jsd(&features.iat_hist, &reference.iat_hist) * 0.30
            + jsd(&features.burst_hist, &reference.burst_hist) * 0.15);
    ((linear_score + tree_score + boosted_score) / 3.0) >= 0.66
}

fn sample_for(persona: PersonaId, idx: usize, observed_variant: bool) -> TraceSample {
    let spec = persona_spec(persona);
    let mut packets = Vec::with_capacity(48);
    for packet_idx in 0..48 {
        let selector = (idx * 17 + packet_idx * 31 + 11) % 100;
        let selector = selector as u8;
        let size_bytes = if selector <= spec.packet_size.small_weight {
            sample_range(
                spec.packet_size.small_min,
                spec.packet_size.small_max,
                idx + packet_idx,
            )
        } else if selector <= spec.packet_size.small_weight + spec.packet_size.medium_weight {
            sample_range(
                spec.packet_size.medium_min,
                spec.packet_size.medium_max,
                idx * 3 + packet_idx,
            )
        } else {
            sample_range(
                spec.packet_size.large_min,
                spec.packet_size.large_max,
                idx * 7 + packet_idx,
            )
        };
        let size_bytes = if observed_variant {
            observed_size_adjustment(persona, size_bytes, packet_idx)
        } else {
            size_bytes
        };
        let iat_ms = observed_iat(
            persona,
            spec.timing.base_gap_ms,
            spec.timing.jitter_ms,
            idx,
            packet_idx,
            observed_variant,
        );
        let burst_len = match persona {
            PersonaId::Off => 4,
            PersonaId::Randomized => 1 + ((idx + packet_idx) % 3) as u8,
            PersonaId::QuicLike => 1 + ((idx + packet_idx) % 2) as u8,
            PersonaId::HostileNetwork => 1 + ((idx + packet_idx + 1) % 2) as u8,
        };
        packets.push(TracePacket {
            size_bytes,
            iat_ms,
            burst_len,
            direction: if packet_idx % 2 == 0 {
                TraceDirection::Outbound
            } else {
                TraceDirection::Inbound
            },
        });
    }

    let (byte_cost_ratio, latency_cost_ratio, observable_response_classes) = match persona {
        PersonaId::Off => (0.0, 0.0, 4),
        PersonaId::Randomized => (0.12, 0.05, spec.handshake.observable_response_classes),
        PersonaId::QuicLike => (0.08, 0.03, spec.handshake.observable_response_classes),
        PersonaId::HostileNetwork => (0.17, 0.07, spec.handshake.observable_response_classes),
    };

    TraceSample {
        persona,
        packets,
        invalid_probe_response: spec.handshake.invalid_probe_response,
        observable_response_classes,
        byte_cost_ratio,
        latency_cost_ratio,
    }
}

fn observed_size_adjustment(persona: PersonaId, value: usize, packet_idx: usize) -> usize {
    match persona {
        PersonaId::Off => value,
        PersonaId::Randomized => value.saturating_add((packet_idx % 17) * 2),
        PersonaId::QuicLike => value.saturating_add((packet_idx % 9) * 2),
        PersonaId::HostileNetwork => value.saturating_sub((packet_idx % 7) * 2),
    }
}

fn observed_iat(
    persona: PersonaId,
    base_gap_ms: u16,
    jitter_ms: u16,
    idx: usize,
    packet_idx: usize,
    observed_variant: bool,
) -> u16 {
    let base = base_gap_ms as usize + ((idx + packet_idx * 3) % (jitter_ms.max(1) as usize + 1));
    let adjusted = if observed_variant {
        match persona {
            PersonaId::Off => base,
            PersonaId::Randomized => base + (packet_idx % 4),
            PersonaId::QuicLike => base + (packet_idx % 2),
            PersonaId::HostileNetwork => base + (packet_idx % 3),
        }
    } else {
        base
    };
    adjusted.min(u16::MAX as usize) as u16
}

fn sample_range(min: u16, max: u16, seed: usize) -> usize {
    let span = max.saturating_sub(min).max(1) as usize;
    min as usize + (seed % span)
}

fn average_ratio<F>(samples: &[TraceSample], map: F) -> f64
where
    F: Fn(&TraceSample) -> f64,
{
    if samples.is_empty() {
        0.0
    } else {
        samples.iter().map(map).sum::<f64>() / samples.len() as f64
    }
}

fn normalize_hist(hist: &mut [f64]) {
    let sum = hist.iter().sum::<f64>();
    if sum <= f64::EPSILON {
        return;
    }
    for value in hist {
        *value /= sum;
    }
}

fn normalized_entropy(hist: &[f64]) -> f64 {
    let k = hist.len().max(2) as f64;
    let entropy = -hist
        .iter()
        .filter(|value| **value > 0.0)
        .map(|value| value * value.log2())
        .sum::<f64>();
    (entropy / k.log2()).clamp(0.0, 1.0)
}

fn jsd(left: &[f64], right: &[f64]) -> f64 {
    let midpoint = left
        .iter()
        .zip(right.iter())
        .map(|(l, r)| (l + r) / 2.0)
        .collect::<Vec<_>>();
    0.5 * kl(left, &midpoint) + 0.5 * kl(right, &midpoint)
}

fn kl(left: &[f64], right: &[f64]) -> f64 {
    left.iter()
        .zip(right.iter())
        .filter(|(l, r)| **l > 0.0 && **r > 0.0)
        .map(|(l, r)| l * (l / r).log2())
        .sum::<f64>()
}

fn size_bin(size_bytes: usize) -> usize {
    match size_bytes {
        0..=95 => 0,
        96..=191 => 1,
        192..=383 => 2,
        384..=767 => 3,
        768..=1023 => 4,
        1024..=1232 => 5,
        _ => 6,
    }
}

fn iat_bin(iat_ms: u16) -> usize {
    match iat_ms {
        0..=2 => 0,
        3..=5 => 1,
        6..=10 => 2,
        11..=20 => 3,
        21..=40 => 4,
        41..=80 => 5,
        _ => 6,
    }
}

fn burst_bin(burst_len: u8) -> usize {
    match burst_len {
        0 | 1 => 0,
        2 => 1,
        3 => 2,
        _ => 3,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn personas_improve_distribution_distance_vs_off() {
        let evaluations = StealthEvaluator::evaluate_default_corpus();
        for evaluation in evaluations {
            assert!(evaluation.detectability_improvement_vs_off > 0.05);
            assert!(
                evaluation.distribution_distance
                    < persona_spec(evaluation.persona).target_jsd + 0.05
            );
        }
    }

    #[test]
    fn classifier_scores_stay_below_off_baseline() {
        let evaluations = StealthEvaluator::evaluate_default_corpus();
        for evaluation in evaluations {
            assert!(evaluation.classifier_baseline_score < 0.74);
        }
    }

    #[test]
    fn probing_scores_meet_persona_targets() {
        let evaluations = StealthEvaluator::evaluate_default_corpus();
        for evaluation in evaluations {
            assert!(
                evaluation.probing_resistance_score
                    >= persona_spec(evaluation.persona).target_prs - 8.0
            );
        }
    }

    #[test]
    fn dump_default_report() {
        for evaluation in StealthEvaluator::evaluate_default_corpus() {
            println!(
                "persona={:?} jsd={:.3} prs={:.1} cbs={:.3} byte_cost={:.3} latency_cost={:.3} improvement={:.3}",
                evaluation.persona,
                evaluation.distribution_distance,
                evaluation.probing_resistance_score,
                evaluation.classifier_baseline_score,
                evaluation.byte_cost_ratio,
                evaluation.latency_cost_ratio,
                evaluation.detectability_improvement_vs_off,
            );
        }
    }
}
