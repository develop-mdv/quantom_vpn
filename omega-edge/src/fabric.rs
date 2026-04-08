use std::collections::BTreeSet;
use std::sync::{Arc, RwLock};

use omega_control::policy::SessionAdmission;
use omega_relay::{
    FabricFault, FabricGraph, FailoverDecision, FailoverReason, FailureSimulator, RelayRole,
    RoutingEngine, SessionFabricState, SimulationReport,
};
use omega_transport::transport_v2::PathMode;
use serde::Serialize;

use crate::session::SessionState;

pub type SharedFabric = Arc<RwLock<FabricController>>;

#[derive(Debug, Clone)]
pub struct FabricController {
    local_node_id: String,
    local_role: RelayRole,
    region: String,
    operator: String,
    graph: FabricGraph,
    last_simulation: Option<SimulationReport>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FabricRuntimeView {
    pub local_node_id: String,
    pub local_role: String,
    pub region: String,
    pub operator: String,
    pub graph_revision: u64,
    pub total_nodes: usize,
    pub healthy_nodes: usize,
    pub last_simulation_within_budget: bool,
    pub last_simulation_reroutes: usize,
    pub last_simulation_disconnects: usize,
    pub last_simulation_avg_failover_ms: f64,
}

impl FabricController {
    pub fn from_env(default_role: RelayRole, admission: &SessionAdmission) -> Self {
        let local_role = std::env::var("OMEGA_NODE_ROLE")
            .ok()
            .and_then(|value| parse_role(&value))
            .unwrap_or(default_role);
        let local_node_id = std::env::var("OMEGA_FABRIC_NODE_ID").unwrap_or_else(|_| {
            let suffix = match local_role {
                RelayRole::Edge => "edge-local",
                RelayRole::Relay => "relay-local",
                RelayRole::Exit => "exit-local",
            };
            suffix.to_string()
        });
        let region = std::env::var("OMEGA_FABRIC_REGION").unwrap_or_else(|_| "primary".to_string());
        let operator =
            std::env::var("OMEGA_FABRIC_OPERATOR").unwrap_or_else(|_| "omega-core".to_string());
        let graph = FabricGraph::default_topology(&local_node_id, local_role, &region, &operator);
        let mut controller = Self {
            local_node_id,
            local_role,
            region,
            operator,
            graph,
            last_simulation: None,
        };
        controller.refresh_simulation(admission);
        controller
    }

    pub fn shared(default_role: RelayRole, admission: &SessionAdmission) -> SharedFabric {
        Arc::new(RwLock::new(Self::from_env(default_role, admission)))
    }

    pub fn local_node_id(&self) -> &str {
        &self.local_node_id
    }

    pub fn local_role(&self) -> RelayRole {
        self.local_role
    }

    pub fn graph(&self) -> &FabricGraph {
        &self.graph
    }

    pub fn runtime_view(&self) -> FabricRuntimeView {
        let last = self.last_simulation.clone();
        FabricRuntimeView {
            local_node_id: self.local_node_id.clone(),
            local_role: role_label(self.local_role).to_string(),
            region: self.region.clone(),
            operator: self.operator.clone(),
            graph_revision: self.graph.revision,
            total_nodes: self.graph.nodes.len(),
            healthy_nodes: self.graph.count_healthy_nodes(),
            last_simulation_within_budget: last
                .as_ref()
                .map(|report| report.within_budget)
                .unwrap_or(true),
            last_simulation_reroutes: last
                .as_ref()
                .map(|report| report.reroute_count)
                .unwrap_or(0),
            last_simulation_disconnects: last
                .as_ref()
                .map(|report| report.full_disconnects)
                .unwrap_or(0),
            last_simulation_avg_failover_ms: last
                .as_ref()
                .map(|report| report.avg_failover_time_ms)
                .unwrap_or(0.0),
        }
    }

    pub fn plan_session(
        &self,
        session_id: &str,
        admission: &SessionAdmission,
    ) -> Option<SessionFabricState> {
        RoutingEngine::new(self.graph.clone()).plan_session(
            &self.local_node_id,
            admission,
            session_id,
        )
    }

    pub fn mark_node(
        &mut self,
        node_id: &str,
        healthy: bool,
        admission: &SessionAdmission,
    ) -> bool {
        let changed = self.graph.mark_node_availability(node_id, healthy);
        if changed {
            self.refresh_simulation(admission);
        }
        changed
    }

    pub fn apply_fault(&mut self, fault: FabricFault, admission: &SessionAdmission) -> bool {
        let changed = match fault {
            FabricFault::NodeDown { node_id } => self.graph.mark_node_availability(&node_id, false),
            FabricFault::NodeRecovered { node_id } => {
                self.graph.mark_node_availability(&node_id, true)
            }
            FabricFault::LinkDown { from, to } => self.graph.mark_link_active(&from, &to, false),
            FabricFault::LinkRecovered { from, to } => {
                self.graph.mark_link_active(&from, &to, true)
            }
        };
        if changed {
            self.refresh_simulation(admission);
        }
        changed
    }

    pub fn reconcile_session(&self, session: &mut SessionState) -> Option<FailoverDecision> {
        let transport = session.transport.snapshot();
        let mut unavailable_nodes = BTreeSet::new();
        for node_id in session.fabric.active_route.nodes.iter().skip(1) {
            let unhealthy = self
                .graph
                .node(node_id)
                .map(|node| !node.health.healthy)
                .unwrap_or(true);
            if unhealthy {
                unavailable_nodes.insert(node_id.clone());
            }
        }

        let reason = if !unavailable_nodes.is_empty() {
            Some(FailoverReason::NodeUnavailable)
        } else if transport.path.blackhole_suspected
            || matches!(
                transport.path.mode,
                PathMode::Recovering | PathMode::BlackholeRecovery
            )
        {
            Some(FailoverReason::PathDegraded)
        } else {
            None
        }?;

        let engine = RoutingEngine::new(self.graph.clone());
        let decision = engine.failover(&session.fabric, reason, &unavailable_nodes)?;
        session.apply_fabric_failover(decision.clone());
        Some(decision)
    }

    fn refresh_simulation(&mut self, admission: &SessionAdmission) {
        let simulator = FailureSimulator::new(self.graph.clone());
        self.last_simulation = simulator.run(
            &self.local_node_id,
            admission,
            "fabric-stand",
            &default_fault_plan(self.local_role),
        );
    }
}

fn default_fault_plan(local_role: RelayRole) -> Vec<FabricFault> {
    match local_role {
        RelayRole::Edge => vec![
            FabricFault::NodeDown {
                node_id: "relay-core-1".to_string(),
            },
            FabricFault::LinkDown {
                from: "relay-partner-1".to_string(),
                to: "exit-partner-1".to_string(),
            },
        ],
        RelayRole::Relay => vec![FabricFault::LinkDown {
            from: "relay-core-2".to_string(),
            to: "exit-core-1".to_string(),
        }],
        RelayRole::Exit => vec![FabricFault::NodeRecovered {
            node_id: "relay-core-1".to_string(),
        }],
    }
}

fn parse_role(value: &str) -> Option<RelayRole> {
    match value.trim().to_ascii_lowercase().as_str() {
        "edge" => Some(RelayRole::Edge),
        "relay" => Some(RelayRole::Relay),
        "exit" => Some(RelayRole::Exit),
        _ => None,
    }
}

pub fn role_label(role: RelayRole) -> &'static str {
    match role {
        RelayRole::Edge => "edge",
        RelayRole::Relay => "relay",
        RelayRole::Exit => "exit",
    }
}
