use std::collections::{BTreeMap, BTreeSet};

use omega_control::policy::{PrivilegeBoundary, SessionAdmission};
use omega_stealth::ProductMode;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayRole {
    Edge,
    Relay,
    Exit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustZone {
    Core,
    Partner,
    Untrusted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayCapability {
    pub role: RelayRole,
    pub supports_udp: bool,
    pub supports_multipath: bool,
    pub supported_modes: Vec<ProductMode>,
}

impl RelayCapability {
    pub fn supports_mode(&self, mode: ProductMode) -> bool {
        self.supported_modes.is_empty() || self.supported_modes.contains(&mode)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeHealth {
    pub healthy: bool,
    pub operational_percent: u8,
    pub latency_ms: u16,
    pub loss_percent: f64,
    pub available_capacity_score: u16,
    pub load_percent: u8,
}

impl NodeHealth {
    pub fn availability_score(&self) -> f64 {
        if !self.healthy {
            return 0.0;
        }
        let ops = self.operational_percent as f64 / 100.0;
        let cap = self.available_capacity_score.min(100) as f64 / 100.0;
        let load = 1.0 - (self.load_percent.min(100) as f64 / 100.0);
        (ops * 0.45) + (cap * 0.35) + (load * 0.20)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayNode {
    pub node_id: String,
    pub role: RelayRole,
    pub region: String,
    pub operator: String,
    pub trust_zone: TrustZone,
    pub capability: RelayCapability,
    pub health: NodeHealth,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FabricLink {
    pub from: String,
    pub to: String,
    pub latency_ms: u16,
    pub capacity_score: u16,
    pub loss_percent: f64,
    pub stealth_risk: u8,
    pub policy_cost: u8,
    pub operational_percent: u8,
    pub active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteConstraints {
    pub max_hops: usize,
    pub min_relay_hops: usize,
    pub failover_budget_ms: u64,
    pub forbid_direct_exit: bool,
    pub excluded_nodes: BTreeSet<String>,
    pub excluded_zones: BTreeSet<TrustZone>,
}

impl RouteConstraints {
    pub fn from_admission(admission: &SessionAdmission) -> Self {
        let (max_hops, min_relay_hops, failover_budget_ms, forbid_direct_exit) = match admission
            .mode
        {
            ProductMode::Fast => (3, 0, 450, false),
            ProductMode::Balanced => (4, if admission.relay_permitted { 1 } else { 0 }, 800, false),
            ProductMode::Stealth => (
                5,
                if admission.relay_permitted { 2 } else { 0 },
                1_200,
                admission.relay_permitted,
            ),
            ProductMode::HostileNetwork => (
                5,
                if admission.relay_permitted { 1 } else { 0 },
                1_600,
                false,
            ),
        };

        let mut excluded_zones = BTreeSet::new();
        match admission.privileged_boundary {
            PrivilegeBoundary::Public => {}
            PrivilegeBoundary::Device
            | PrivilegeBoundary::Session
            | PrivilegeBoundary::Operator => {
                excluded_zones.insert(TrustZone::Untrusted);
            }
        }

        Self {
            max_hops,
            min_relay_hops,
            failover_budget_ms,
            forbid_direct_exit,
            excluded_nodes: BTreeSet::new(),
            excluded_zones,
        }
    }

    pub fn with_excluded_nodes(mut self, nodes: impl IntoIterator<Item = String>) -> Self {
        for node in nodes {
            self.excluded_nodes.insert(node);
        }
        self
    }

    pub fn allows_node(&self, node: &RelayNode) -> bool {
        !self.excluded_nodes.contains(&node.node_id)
            && !self.excluded_zones.contains(&node.trust_zone)
            && node.health.healthy
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FabricGraph {
    pub revision: u64,
    pub nodes: BTreeMap<String, RelayNode>,
    pub links: Vec<FabricLink>,
}

impl FabricGraph {
    pub fn new() -> Self {
        Self {
            revision: 1,
            nodes: BTreeMap::new(),
            links: Vec::new(),
        }
    }

    pub fn add_node(&mut self, node: RelayNode) {
        self.nodes.insert(node.node_id.clone(), node);
        self.revision = self.revision.saturating_add(1);
    }

    pub fn add_bidirectional_link(&mut self, link: FabricLink) {
        let reverse = FabricLink {
            from: link.to.clone(),
            to: link.from.clone(),
            latency_ms: link.latency_ms,
            capacity_score: link.capacity_score,
            loss_percent: link.loss_percent,
            stealth_risk: link.stealth_risk,
            policy_cost: link.policy_cost,
            operational_percent: link.operational_percent,
            active: link.active,
        };
        self.links.push(link);
        self.links.push(reverse);
        self.revision = self.revision.saturating_add(1);
    }

    pub fn node(&self, node_id: &str) -> Option<&RelayNode> {
        self.nodes.get(node_id)
    }

    pub fn node_mut(&mut self, node_id: &str) -> Option<&mut RelayNode> {
        self.nodes.get_mut(node_id)
    }

    pub fn neighbors(&self, node_id: &str) -> Vec<&FabricLink> {
        self.links
            .iter()
            .filter(|link| link.from == node_id && link.active)
            .collect()
    }

    pub fn link(&self, from: &str, to: &str) -> Option<&FabricLink> {
        self.links
            .iter()
            .find(|link| link.from == from && link.to == to)
    }

    pub fn mark_node_availability(&mut self, node_id: &str, healthy: bool) -> bool {
        let Some(node) = self.node_mut(node_id) else {
            return false;
        };
        node.health.healthy = healthy;
        if !healthy {
            node.health.operational_percent = 0;
        } else if node.health.operational_percent == 0 {
            node.health.operational_percent = 80;
        }
        self.revision = self.revision.saturating_add(1);
        true
    }

    pub fn mark_link_active(&mut self, from: &str, to: &str, active: bool) -> bool {
        let mut changed = false;
        for link in &mut self.links {
            if (link.from == from && link.to == to) || (link.from == to && link.to == from) {
                link.active = active;
                if !active {
                    link.operational_percent = 0;
                } else if link.operational_percent == 0 {
                    link.operational_percent = 80;
                }
                changed = true;
            }
        }
        if changed {
            self.revision = self.revision.saturating_add(1);
        }
        changed
    }

    pub fn count_healthy_nodes(&self) -> usize {
        self.nodes
            .values()
            .filter(|node| node.health.healthy)
            .count()
    }

    pub fn default_topology(
        local_node_id: &str,
        local_role: RelayRole,
        region: &str,
        operator: &str,
    ) -> Self {
        let mut graph = Self::new();
        graph.add_node(make_node(
            local_node_id,
            local_role,
            region,
            operator,
            TrustZone::Core,
            18,
        ));

        match local_role {
            RelayRole::Edge => {
                graph.add_node(make_node(
                    "relay-core-1",
                    RelayRole::Relay,
                    region,
                    "omega-core",
                    TrustZone::Core,
                    26,
                ));
                graph.add_node(make_node(
                    "relay-partner-1",
                    RelayRole::Relay,
                    "eu-west",
                    "partner-a",
                    TrustZone::Partner,
                    34,
                ));
                graph.add_node(make_node(
                    "exit-core-1",
                    RelayRole::Exit,
                    "eu-west",
                    "omega-core",
                    TrustZone::Core,
                    28,
                ));
                graph.add_node(make_node(
                    "exit-partner-1",
                    RelayRole::Exit,
                    "us-east",
                    "partner-b",
                    TrustZone::Partner,
                    42,
                ));

                graph.add_bidirectional_link(make_link(
                    local_node_id,
                    "relay-core-1",
                    18,
                    86,
                    0.5,
                    14,
                    4,
                ));
                graph.add_bidirectional_link(make_link(
                    local_node_id,
                    "relay-partner-1",
                    23,
                    80,
                    0.8,
                    18,
                    8,
                ));
                graph.add_bidirectional_link(make_link(
                    local_node_id,
                    "exit-core-1",
                    31,
                    74,
                    0.7,
                    24,
                    12,
                ));
                graph.add_bidirectional_link(make_link(
                    "relay-core-1",
                    "relay-partner-1",
                    19,
                    84,
                    0.6,
                    16,
                    6,
                ));
                graph.add_bidirectional_link(make_link(
                    "relay-core-1",
                    "exit-core-1",
                    17,
                    92,
                    0.4,
                    12,
                    4,
                ));
                graph.add_bidirectional_link(make_link(
                    "relay-core-1",
                    "exit-partner-1",
                    29,
                    76,
                    0.9,
                    20,
                    10,
                ));
                graph.add_bidirectional_link(make_link(
                    "relay-partner-1",
                    "exit-core-1",
                    25,
                    78,
                    0.9,
                    18,
                    9,
                ));
                graph.add_bidirectional_link(make_link(
                    "relay-partner-1",
                    "exit-partner-1",
                    21,
                    82,
                    0.8,
                    16,
                    7,
                ));
            }
            RelayRole::Relay => {
                graph.add_node(make_node(
                    "relay-core-2",
                    RelayRole::Relay,
                    "eu-west",
                    "omega-core",
                    TrustZone::Core,
                    24,
                ));
                graph.add_node(make_node(
                    "exit-core-1",
                    RelayRole::Exit,
                    region,
                    "omega-core",
                    TrustZone::Core,
                    28,
                ));
                graph.add_node(make_node(
                    "exit-partner-1",
                    RelayRole::Exit,
                    "us-east",
                    "partner-b",
                    TrustZone::Partner,
                    38,
                ));
                graph.add_bidirectional_link(make_link(
                    local_node_id,
                    "relay-core-2",
                    14,
                    88,
                    0.4,
                    12,
                    4,
                ));
                graph.add_bidirectional_link(make_link(
                    local_node_id,
                    "exit-core-1",
                    19,
                    82,
                    0.5,
                    14,
                    5,
                ));
                graph.add_bidirectional_link(make_link(
                    local_node_id,
                    "exit-partner-1",
                    33,
                    75,
                    0.9,
                    20,
                    10,
                ));
                graph.add_bidirectional_link(make_link(
                    "relay-core-2",
                    "exit-core-1",
                    16,
                    90,
                    0.3,
                    10,
                    4,
                ));
                graph.add_bidirectional_link(make_link(
                    "relay-core-2",
                    "exit-partner-1",
                    24,
                    79,
                    0.7,
                    17,
                    7,
                ));
            }
            RelayRole::Exit => {
                graph.add_node(make_node(
                    "relay-core-1",
                    RelayRole::Relay,
                    region,
                    "omega-core",
                    TrustZone::Core,
                    20,
                ));
                graph.add_bidirectional_link(make_link(
                    "relay-core-1",
                    local_node_id,
                    12,
                    90,
                    0.3,
                    8,
                    3,
                ));
            }
        }

        graph
    }
}

fn make_node(
    node_id: &str,
    role: RelayRole,
    region: &str,
    operator: &str,
    trust_zone: TrustZone,
    load_percent: u8,
) -> RelayNode {
    RelayNode {
        node_id: node_id.to_string(),
        role,
        region: region.to_string(),
        operator: operator.to_string(),
        trust_zone,
        capability: RelayCapability {
            role,
            supports_udp: true,
            supports_multipath: !matches!(role, RelayRole::Exit),
            supported_modes: vec![
                ProductMode::Fast,
                ProductMode::Balanced,
                ProductMode::Stealth,
                ProductMode::HostileNetwork,
            ],
        },
        health: NodeHealth {
            healthy: true,
            operational_percent: 92,
            latency_ms: 8,
            loss_percent: 0.2,
            available_capacity_score: 88,
            load_percent,
        },
        tags: vec![
            format!("role:{}", role_label(role)),
            format!("region:{region}"),
        ],
    }
}

fn make_link(
    from: &str,
    to: &str,
    latency_ms: u16,
    capacity_score: u16,
    loss_percent: f64,
    stealth_risk: u8,
    policy_cost: u8,
) -> FabricLink {
    FabricLink {
        from: from.to_string(),
        to: to.to_string(),
        latency_ms,
        capacity_score,
        loss_percent,
        stealth_risk,
        policy_cost,
        operational_percent: 90,
        active: true,
    }
}

fn role_label(role: RelayRole) -> &'static str {
    match role {
        RelayRole::Edge => "edge",
        RelayRole::Relay => "relay",
        RelayRole::Exit => "exit",
    }
}
