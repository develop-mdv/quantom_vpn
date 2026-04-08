use std::collections::BTreeSet;

use omega_control::policy::SessionAdmission;
use serde::{Deserialize, Serialize};

use crate::graph::FabricGraph;
use crate::routing::{FailoverReason, RoutingEngine};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FabricFault {
    NodeDown { node_id: String },
    NodeRecovered { node_id: String },
    LinkDown { from: String, to: String },
    LinkRecovered { from: String, to: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulationStep {
    pub event: String,
    pub active_route_id: String,
    pub reroute_time_ms: Option<u64>,
    pub within_budget: bool,
    pub explanation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulationReport {
    pub initial_route_id: String,
    pub final_route_id: String,
    pub reroute_count: usize,
    pub full_disconnects: usize,
    pub avg_failover_time_ms: f64,
    pub within_budget: bool,
    pub route_diversity_score: f64,
    pub steps: Vec<SimulationStep>,
}

#[derive(Debug, Clone)]
pub struct FailureSimulator {
    graph: FabricGraph,
}

impl FailureSimulator {
    pub fn new(graph: FabricGraph) -> Self {
        Self { graph }
    }

    pub fn run(
        &self,
        local_node_id: &str,
        admission: &SessionAdmission,
        session_id: &str,
        faults: &[FabricFault],
    ) -> Option<SimulationReport> {
        let mut graph = self.graph.clone();
        let mut engine = RoutingEngine::new(graph.clone());
        let mut state = engine.plan_session(local_node_id, admission, session_id)?;
        let initial_route_id = state.active_route.route_id.clone();
        let mut reroute_count = 0usize;
        let mut full_disconnects = 0usize;
        let mut total_failover_ms = 0u64;
        let mut failover_events = 0usize;
        let mut within_budget = true;
        let mut steps = Vec::new();
        let mut unavailable_nodes = BTreeSet::new();

        for fault in faults {
            apply_fault(&mut graph, &mut unavailable_nodes, fault);
            engine = RoutingEngine::new(graph.clone());
            let event = describe_fault(fault);
            let impacts_active = route_impacted(&state.active_route.nodes, fault);
            if impacts_active {
                match engine.failover(&state, fault_reason(fault), &unavailable_nodes) {
                    Some(decision) => {
                        within_budget &= decision.within_budget;
                        total_failover_ms =
                            total_failover_ms.saturating_add(decision.reroute_time_ms);
                        failover_events += 1;
                        reroute_count += 1;
                        let explanation = decision.explanation.clone();
                        let active_route_id = decision.active_route.route_id.clone();
                        let reroute_time_ms = decision.reroute_time_ms;
                        let decision_within_budget = decision.within_budget;
                        state.apply_failover(decision);
                        steps.push(SimulationStep {
                            event,
                            active_route_id,
                            reroute_time_ms: Some(reroute_time_ms),
                            within_budget: decision_within_budget,
                            explanation,
                        });
                    }
                    None => {
                        full_disconnects += 1;
                        within_budget = false;
                        steps.push(SimulationStep {
                            event,
                            active_route_id: state.active_route.route_id.clone(),
                            reroute_time_ms: None,
                            within_budget: false,
                            explanation: "fabric had no admissible backup route after the fault"
                                .to_string(),
                        });
                    }
                }
            } else {
                steps.push(SimulationStep {
                    event,
                    active_route_id: state.active_route.route_id.clone(),
                    reroute_time_ms: None,
                    within_budget: true,
                    explanation: "fault did not affect the current active route; handoff state remained unchanged".to_string(),
                });
            }
        }

        Some(SimulationReport {
            initial_route_id,
            final_route_id: state.active_route.route_id.clone(),
            reroute_count,
            full_disconnects,
            avg_failover_time_ms: if failover_events == 0 {
                0.0
            } else {
                total_failover_ms as f64 / failover_events as f64
            },
            within_budget,
            route_diversity_score: state.route_diversity_score,
            steps,
        })
    }
}

fn apply_fault(
    graph: &mut FabricGraph,
    unavailable_nodes: &mut BTreeSet<String>,
    fault: &FabricFault,
) {
    match fault {
        FabricFault::NodeDown { node_id } => {
            graph.mark_node_availability(node_id, false);
            unavailable_nodes.insert(node_id.clone());
        }
        FabricFault::NodeRecovered { node_id } => {
            graph.mark_node_availability(node_id, true);
            unavailable_nodes.remove(node_id);
        }
        FabricFault::LinkDown { from, to } => {
            graph.mark_link_active(from, to, false);
        }
        FabricFault::LinkRecovered { from, to } => {
            graph.mark_link_active(from, to, true);
        }
    }
}

fn route_impacted(active_nodes: &[String], fault: &FabricFault) -> bool {
    match fault {
        FabricFault::NodeDown { node_id } => active_nodes.iter().any(|node| node == node_id),
        FabricFault::NodeRecovered { .. } => false,
        FabricFault::LinkDown { from, to } => active_nodes
            .windows(2)
            .any(|pair| pair[0] == *from && pair[1] == *to || pair[0] == *to && pair[1] == *from),
        FabricFault::LinkRecovered { .. } => false,
    }
}

fn describe_fault(fault: &FabricFault) -> String {
    match fault {
        FabricFault::NodeDown { node_id } => format!("node_down:{node_id}"),
        FabricFault::NodeRecovered { node_id } => format!("node_recovered:{node_id}"),
        FabricFault::LinkDown { from, to } => format!("link_down:{from}->{to}"),
        FabricFault::LinkRecovered { from, to } => format!("link_recovered:{from}->{to}"),
    }
}

fn fault_reason(fault: &FabricFault) -> FailoverReason {
    match fault {
        FabricFault::NodeDown { .. } => FailoverReason::NodeUnavailable,
        FabricFault::NodeRecovered { .. } => FailoverReason::OperatorIntervention,
        FabricFault::LinkDown { .. } => FailoverReason::LinkUnavailable,
        FabricFault::LinkRecovered { .. } => FailoverReason::OperatorIntervention,
    }
}
