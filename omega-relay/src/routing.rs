use std::collections::BTreeSet;
use std::time::{SystemTime, UNIX_EPOCH};

use omega_control::policy::SessionAdmission;
use serde::{Deserialize, Serialize};

use crate::graph::{FabricGraph, RelayRole, RouteConstraints, TrustZone};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailoverReason {
    NodeUnavailable,
    LinkUnavailable,
    PathDegraded,
    PolicyChange,
    OperatorIntervention,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlannedRoute {
    pub route_id: String,
    pub nodes: Vec<String>,
    pub total_latency_ms: u16,
    pub estimated_loss_percent: f64,
    pub effective_capacity_score: u16,
    pub quality_score: u8,
    pub risk_score: u8,
    pub trust_score: u8,
    pub hop_count: usize,
    pub relay_hops: usize,
    pub direct_edge_to_exit: bool,
    pub explanation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandoffTicket {
    pub session_id: String,
    pub generation: u32,
    pub primary_route_id: String,
    pub backup_route_ids: Vec<String>,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub graph_revision: u64,
    pub explanation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteSelection {
    pub local_node_id: String,
    pub admission_policy_id: String,
    pub primary: PlannedRoute,
    pub backups: Vec<PlannedRoute>,
    pub route_diversity_score: f64,
    pub failover_budget_ms: u64,
    pub handoff_ticket: HandoffTicket,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailoverDecision {
    pub previous_route_id: String,
    pub active_route: PlannedRoute,
    pub backup_routes: Vec<PlannedRoute>,
    pub handoff_ticket: HandoffTicket,
    pub reroute_time_ms: u64,
    pub within_budget: bool,
    pub reason: FailoverReason,
    pub explanation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionFabricState {
    pub session_id: String,
    pub local_node_id: String,
    pub admission: SessionAdmission,
    pub active_route: PlannedRoute,
    pub backup_routes: Vec<PlannedRoute>,
    pub handoff_ticket: HandoffTicket,
    pub failover_budget_ms: u64,
    pub route_diversity_score: f64,
    pub failover_count: u32,
    pub last_failover_reason: Option<FailoverReason>,
    pub last_failover_ms: Option<u64>,
}

impl SessionFabricState {
    pub fn apply_failover(&mut self, decision: FailoverDecision) {
        self.active_route = decision.active_route;
        self.backup_routes = decision.backup_routes;
        self.handoff_ticket = decision.handoff_ticket;
        self.failover_count = self.failover_count.saturating_add(1);
        self.last_failover_reason = Some(decision.reason);
        self.last_failover_ms = Some(decision.reroute_time_ms);
    }

    pub fn active_nodes(&self) -> BTreeSet<String> {
        self.active_route.nodes.iter().cloned().collect()
    }
}

#[derive(Debug, Clone)]
pub struct RoutingEngine {
    graph: FabricGraph,
}

impl RoutingEngine {
    pub fn new(graph: FabricGraph) -> Self {
        Self { graph }
    }

    pub fn graph(&self) -> &FabricGraph {
        &self.graph
    }

    pub fn select_routes(
        &self,
        local_node_id: &str,
        admission: &SessionAdmission,
        session_id: &str,
    ) -> Option<RouteSelection> {
        let constraints = RouteConstraints::from_admission(admission);
        let candidates = self.ranked_routes(local_node_id, &constraints, admission)?;
        let primary = candidates.first()?.clone();
        let backups = select_backups(&primary, &candidates[1..]);
        let route_diversity_score = diversity_score(&primary, &backups);
        let handoff_ticket = issue_ticket(
            session_id,
            1,
            &primary,
            &backups,
            admission.resumption_ttl_secs,
            self.graph.revision,
            "initial fabric admission selected primary and backup routes",
        );

        Some(RouteSelection {
            local_node_id: local_node_id.to_string(),
            admission_policy_id: admission.policy_id.clone(),
            primary,
            backups,
            route_diversity_score,
            failover_budget_ms: constraints.failover_budget_ms,
            handoff_ticket,
        })
    }

    pub fn plan_session(
        &self,
        local_node_id: &str,
        admission: &SessionAdmission,
        session_id: &str,
    ) -> Option<SessionFabricState> {
        let selection = self.select_routes(local_node_id, admission, session_id)?;
        Some(SessionFabricState {
            session_id: session_id.to_string(),
            local_node_id: local_node_id.to_string(),
            admission: admission.clone(),
            active_route: selection.primary,
            backup_routes: selection.backups,
            handoff_ticket: selection.handoff_ticket,
            failover_budget_ms: selection.failover_budget_ms,
            route_diversity_score: selection.route_diversity_score,
            failover_count: 0,
            last_failover_reason: None,
            last_failover_ms: None,
        })
    }

    pub fn failover(
        &self,
        state: &SessionFabricState,
        reason: FailoverReason,
        unavailable_nodes: &BTreeSet<String>,
    ) -> Option<FailoverDecision> {
        let mut constraints = RouteConstraints::from_admission(&state.admission);
        constraints = constraints.with_excluded_nodes(unavailable_nodes.iter().cloned());
        let candidates =
            self.ranked_routes(&state.local_node_id, &constraints, &state.admission)?;
        let active_route = candidates
            .into_iter()
            .find(|candidate| candidate.route_id != state.active_route.route_id)?;
        let backup_routes = self
            .ranked_routes(&state.local_node_id, &constraints, &state.admission)?
            .into_iter()
            .filter(|candidate| candidate.route_id != active_route.route_id)
            .take(2)
            .collect::<Vec<_>>();

        let reroute_time_ms = estimate_failover_time_ms(reason, &active_route);
        let within_budget = reroute_time_ms <= state.failover_budget_ms;
        let handoff_ticket = issue_ticket(
            &state.session_id,
            state.handoff_ticket.generation.saturating_add(1),
            &active_route,
            &backup_routes,
            state.admission.resumption_ttl_secs,
            self.graph.revision,
            "fabric failover issued a new handoff ticket for the replacement route",
        );
        let explanation = format!(
            "failover moved session from {} to {} after {:?}; reroute={}ms budget={}ms",
            state.active_route.route_id,
            active_route.route_id,
            reason,
            reroute_time_ms,
            state.failover_budget_ms
        );

        Some(FailoverDecision {
            previous_route_id: state.active_route.route_id.clone(),
            active_route,
            backup_routes,
            handoff_ticket,
            reroute_time_ms,
            within_budget,
            reason,
            explanation,
        })
    }

    fn ranked_routes(
        &self,
        local_node_id: &str,
        constraints: &RouteConstraints,
        admission: &SessionAdmission,
    ) -> Option<Vec<PlannedRoute>> {
        let paths = self.enumerate_paths(local_node_id, constraints, admission)?;
        let mut ranked = paths
            .iter()
            .filter_map(|path| self.score_path(path, admission))
            .collect::<Vec<_>>();
        ranked.sort_by(|left, right| {
            right
                .quality_score
                .cmp(&left.quality_score)
                .then_with(|| right.trust_score.cmp(&left.trust_score))
                .then_with(|| left.total_latency_ms.cmp(&right.total_latency_ms))
                .then_with(|| left.hop_count.cmp(&right.hop_count))
        });
        if ranked.is_empty() {
            None
        } else {
            Some(ranked)
        }
    }

    fn enumerate_paths(
        &self,
        local_node_id: &str,
        constraints: &RouteConstraints,
        admission: &SessionAdmission,
    ) -> Option<Vec<Vec<String>>> {
        let start = self.graph.node(local_node_id)?;
        if !constraints.allows_node(start) {
            return None;
        }
        if matches!(start.role, RelayRole::Exit) {
            return Some(vec![vec![local_node_id.to_string()]]);
        }

        let mut paths = Vec::new();
        let mut current = vec![local_node_id.to_string()];
        self.walk_paths(&mut current, &mut paths, constraints, admission);
        if paths.is_empty() {
            None
        } else {
            Some(paths)
        }
    }

    fn walk_paths(
        &self,
        current: &mut Vec<String>,
        paths: &mut Vec<Vec<String>>,
        constraints: &RouteConstraints,
        admission: &SessionAdmission,
    ) {
        if current.len() > constraints.max_hops {
            return;
        }

        let Some(last) = current.last() else {
            return;
        };
        let Some(last_node) = self.graph.node(last) else {
            return;
        };
        let relay_hops = current
            .iter()
            .skip(1)
            .filter(|node_id| {
                self.graph
                    .node(node_id)
                    .map(|node| matches!(node.role, RelayRole::Relay))
                    .unwrap_or(false)
            })
            .count();

        if matches!(last_node.role, RelayRole::Exit)
            && relay_hops >= constraints.min_relay_hops
            && (!constraints.forbid_direct_exit || current.len() > 2)
        {
            paths.push(current.clone());
            return;
        }

        for link in self.graph.neighbors(last) {
            let next_id = &link.to;
            if current.iter().any(|node| node == next_id) {
                continue;
            }
            let Some(next_node) = self.graph.node(next_id) else {
                continue;
            };
            if !constraints.allows_node(next_node) {
                continue;
            }
            if !next_node.capability.supports_mode(admission.mode) {
                continue;
            }
            if !admission.relay_permitted && matches!(next_node.role, RelayRole::Relay) {
                continue;
            }
            match next_node.role {
                RelayRole::Relay => {
                    current.push(next_id.clone());
                    self.walk_paths(current, paths, constraints, admission);
                    current.pop();
                }
                RelayRole::Exit => {
                    if constraints.forbid_direct_exit && current.len() == 1 {
                        continue;
                    }
                    current.push(next_id.clone());
                    self.walk_paths(current, paths, constraints, admission);
                    current.pop();
                }
                RelayRole::Edge => continue,
            }
        }
    }

    fn score_path(&self, path: &[String], admission: &SessionAdmission) -> Option<PlannedRoute> {
        if path.is_empty() {
            return None;
        }
        let mut total_latency = 0u32;
        let mut effective_capacity = u16::MAX;
        let mut aggregate_loss = 0.0f64;
        let mut risk_acc = 0.0f64;
        let mut trust_acc = 0.0f64;
        let mut health_acc = 0.0f64;
        let mut relay_hops = 0usize;

        for node_id in path {
            let node = self.graph.node(node_id)?;
            if matches!(node.role, RelayRole::Relay) {
                relay_hops += 1;
            }
            effective_capacity = effective_capacity.min(node.health.available_capacity_score);
            aggregate_loss += node.health.loss_percent * 0.35;
            trust_acc += trust_score(node.trust_zone);
            risk_acc += trust_risk(node.trust_zone) + (node.health.load_percent as f64 * 0.08);
            health_acc += node.health.availability_score() * 100.0;
        }

        for pair in path.windows(2) {
            let link = self.graph.link(&pair[0], &pair[1])?;
            total_latency += link.latency_ms as u32;
            effective_capacity = effective_capacity.min(link.capacity_score);
            aggregate_loss += link.loss_percent;
            risk_acc += link.stealth_risk as f64 + link.policy_cost as f64 * 0.8;
            health_acc += link.operational_percent as f64;
        }

        let entity_count = path.len() + path.len().saturating_sub(1);
        let trust_score = (trust_acc / path.len() as f64).round().clamp(0.0, 100.0) as u8;
        let risk_score = (risk_acc / entity_count.max(1) as f64)
            .round()
            .clamp(0.0, 100.0) as u8;
        let health_score = (health_acc / entity_count.max(1) as f64).clamp(0.0, 100.0);
        let hop_count = path.len().saturating_sub(1);
        let mode_bonus = match admission.mode {
            omega_stealth::ProductMode::Fast => 12.0,
            omega_stealth::ProductMode::Balanced => 8.0,
            omega_stealth::ProductMode::Stealth => 10.0 + relay_hops as f64 * 2.0,
            omega_stealth::ProductMode::HostileNetwork => 9.0 + health_score * 0.04,
        };
        let raw_quality = 125.0
            - total_latency as f64 * 0.62
            - aggregate_loss * 9.5
            - risk_score as f64 * 0.45
            - hop_count as f64 * 4.5
            + effective_capacity.min(100) as f64 * 0.30
            + health_score * 0.25
            + mode_bonus;
        let quality_score = raw_quality.round().clamp(0.0, 100.0) as u8;
        let direct_edge_to_exit = path.len() == 2
            && matches!(self.graph.node(&path[0])?.role, RelayRole::Edge)
            && matches!(self.graph.node(&path[1])?.role, RelayRole::Exit);
        let explanation = format!(
            "latency={}ms loss={:.2}% trust={} risk={} relays={} cap={} health={:.0}",
            total_latency,
            aggregate_loss,
            trust_score,
            risk_score,
            relay_hops,
            effective_capacity,
            health_score
        );

        Some(PlannedRoute {
            route_id: route_id(path),
            nodes: path.to_vec(),
            total_latency_ms: total_latency.min(u16::MAX as u32) as u16,
            estimated_loss_percent: (aggregate_loss * 100.0).round() / 100.0,
            effective_capacity_score: effective_capacity,
            quality_score,
            risk_score,
            trust_score,
            hop_count,
            relay_hops,
            direct_edge_to_exit,
            explanation,
        })
    }
}

fn select_backups(primary: &PlannedRoute, candidates: &[PlannedRoute]) -> Vec<PlannedRoute> {
    let mut pool = candidates.to_vec();
    pool.sort_by(|left, right| {
        let left_score = left.quality_score as f64 + route_diversity(primary, left) * 18.0;
        let right_score = right.quality_score as f64 + route_diversity(primary, right) * 18.0;
        right_score
            .partial_cmp(&left_score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    pool.into_iter().take(2).collect()
}

fn diversity_score(primary: &PlannedRoute, backups: &[PlannedRoute]) -> f64 {
    if backups.is_empty() {
        return 0.0;
    }
    backups
        .iter()
        .map(|backup| route_diversity(primary, backup))
        .sum::<f64>()
        / backups.len() as f64
}

fn route_diversity(left: &PlannedRoute, right: &PlannedRoute) -> f64 {
    let left_nodes = left.nodes.iter().skip(1).collect::<BTreeSet<_>>();
    let right_nodes = right.nodes.iter().skip(1).collect::<BTreeSet<_>>();
    let overlap = left_nodes.intersection(&right_nodes).count();
    let denom = left_nodes.len().max(right_nodes.len()).max(1) as f64;
    1.0 - (overlap as f64 / denom)
}

fn issue_ticket(
    session_id: &str,
    generation: u32,
    primary: &PlannedRoute,
    backups: &[PlannedRoute],
    ttl_secs: u64,
    graph_revision: u64,
    explanation: &str,
) -> HandoffTicket {
    let issued_at_ms = now_ms();
    HandoffTicket {
        session_id: session_id.to_string(),
        generation,
        primary_route_id: primary.route_id.clone(),
        backup_route_ids: backups.iter().map(|route| route.route_id.clone()).collect(),
        issued_at_ms,
        expires_at_ms: issued_at_ms.saturating_add(ttl_secs.saturating_mul(1_000)),
        graph_revision,
        explanation: explanation.to_string(),
    }
}

fn estimate_failover_time_ms(reason: FailoverReason, route: &PlannedRoute) -> u64 {
    let base = match reason {
        FailoverReason::NodeUnavailable => 180,
        FailoverReason::LinkUnavailable => 220,
        FailoverReason::PathDegraded => 260,
        FailoverReason::PolicyChange => 320,
        FailoverReason::OperatorIntervention => 140,
    };
    base + route.hop_count as u64 * 70 + route.relay_hops as u64 * 55
}

fn trust_score(zone: TrustZone) -> f64 {
    match zone {
        TrustZone::Core => 96.0,
        TrustZone::Partner => 74.0,
        TrustZone::Untrusted => 42.0,
    }
}

fn trust_risk(zone: TrustZone) -> f64 {
    match zone {
        TrustZone::Core => 8.0,
        TrustZone::Partner => 18.0,
        TrustZone::Untrusted => 34.0,
    }
}

fn route_id(path: &[String]) -> String {
    path.join("->")
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
