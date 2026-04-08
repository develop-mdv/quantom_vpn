pub mod graph;
pub mod routing;
pub mod simulation;

pub use graph::{
    FabricGraph, FabricLink, NodeHealth, RelayCapability, RelayNode, RelayRole, RouteConstraints,
    TrustZone,
};
pub use routing::{
    FailoverDecision, FailoverReason, HandoffTicket, PlannedRoute, RouteSelection, RoutingEngine,
    SessionFabricState,
};
pub use simulation::{FabricFault, FailureSimulator, SimulationReport, SimulationStep};

use omega_control::policy::SessionAdmission;

pub trait RelaySelector {
    fn select(
        &self,
        local_node_id: &str,
        admission: &SessionAdmission,
        session_id: &str,
    ) -> Option<RouteSelection>;
}

impl RelaySelector for RoutingEngine {
    fn select(
        &self,
        local_node_id: &str,
        admission: &SessionAdmission,
        session_id: &str,
    ) -> Option<RouteSelection> {
        self.select_routes(local_node_id, admission, session_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn engine() -> RoutingEngine {
        RoutingEngine::new(FabricGraph::default_topology(
            "edge-local",
            RelayRole::Edge,
            "test",
            "omega-core",
        ))
    }

    #[test]
    fn balanced_mode_prefers_multi_hop_route() {
        let admission = SessionAdmission::default();
        let plan = engine()
            .plan_session("edge-local", &admission, "session-a")
            .expect("fabric route");
        assert!(plan.active_route.relay_hops >= 1);
        assert!(plan.route_diversity_score >= 0.4);
        assert!(!plan.backup_routes.is_empty());
    }

    #[test]
    fn node_failure_uses_backup_route() {
        let admission = SessionAdmission::default();
        let engine = engine();
        let state = engine
            .plan_session("edge-local", &admission, "session-b")
            .expect("fabric route");
        let mut unavailable = BTreeSet::new();
        unavailable.insert("relay-core-1".to_string());
        let decision = engine
            .failover(&state, FailoverReason::NodeUnavailable, &unavailable)
            .expect("failover decision");
        assert_ne!(decision.previous_route_id, decision.active_route.route_id);
        assert!(decision
            .active_route
            .nodes
            .iter()
            .all(|node| node != "relay-core-1"));
    }

    #[test]
    fn failure_simulation_stays_within_budget() {
        let admission = SessionAdmission::default();
        let simulator = FailureSimulator::new(FabricGraph::default_topology(
            "edge-local",
            RelayRole::Edge,
            "test",
            "omega-core",
        ));
        let report = simulator
            .run(
                "edge-local",
                &admission,
                "session-c",
                &[FabricFault::NodeDown {
                    node_id: "relay-core-1".to_string(),
                }],
            )
            .expect("simulation report");
        assert_eq!(report.full_disconnects, 0);
        assert!(report.reroute_count >= 1);
        assert!(report.within_budget);
    }
}
