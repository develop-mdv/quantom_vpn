use serde::{Deserialize, Serialize};

use omega_stealth::ProductMode;

use crate::identity::{devices::Platform, now_ts, users::UserStatus};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivilegeBoundary {
    Public,
    Device,
    Session,
    Operator,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionAdmission {
    pub policy_id: String,
    pub mode: ProductMode,
    pub relay_permitted: bool,
    pub resumption_ttl_secs: u64,
    pub privileged_boundary: PrivilegeBoundary,
}

impl SessionAdmission {
    pub fn validate(&self) -> Result<(), PolicyValidationError> {
        if self.policy_id.trim().is_empty() {
            return Err(PolicyValidationError::new(
                self.policy_id.clone(),
                "session_admission",
                "policy_id must not be empty",
            ));
        }
        if self.resumption_ttl_secs > 7 * 24 * 60 * 60 {
            return Err(PolicyValidationError::new(
                self.policy_id.clone(),
                "session_admission",
                "resumption_ttl_secs exceeds 7 day safety cap",
            ));
        }
        Ok(())
    }
}

impl Default for SessionAdmission {
    fn default() -> Self {
        Self {
            policy_id: "default".to_string(),
            mode: ProductMode::Balanced,
            relay_permitted: true,
            resumption_ttl_secs: 3600,
            privileged_boundary: PrivilegeBoundary::Session,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum PolicyCondition {
    Any,
    UserIdPrefix(String),
    DeviceIdPrefix(String),
    Platform(Platform),
    UserStatus(UserStatus),
    RequestedMode(ProductMode),
    Region(String),
    NodeRole(String),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum PolicyAction {
    SetMode(ProductMode),
    SetRelayPermitted(bool),
    SetResumptionTtlSecs(u64),
    SetPrivilegeBoundary(PrivilegeBoundary),
    SetMaxRouteHops(u8),
    RequireRouteDiversity(f64),
    PinPath(Vec<String>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    pub rule_id: String,
    pub priority: i32,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub conditions: Vec<PolicyCondition>,
    #[serde(default)]
    pub actions: Vec<PolicyAction>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyObject {
    pub policy_id: String,
    pub version: u64,
    #[serde(default)]
    pub description: String,
    pub enabled: bool,
    #[serde(default)]
    pub rules: Vec<PolicyRule>,
    #[serde(default = "now_ts")]
    pub updated_at: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PolicyOverlay {
    pub max_route_hops: Option<u8>,
    pub required_route_diversity: Option<f64>,
    #[serde(default)]
    pub pinned_path: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct PolicyContext {
    pub user_id: String,
    pub user_status: UserStatus,
    pub device_id: String,
    pub platform: Platform,
    pub requested: SessionAdmission,
    pub region: String,
    pub node_role: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDecision {
    pub admission: SessionAdmission,
    pub overlay: PolicyOverlay,
    #[serde(default)]
    pub matched_rules: Vec<String>,
    #[serde(default)]
    pub matched_policies: Vec<String>,
    pub explainability: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyConflict {
    pub policy_id: String,
    pub left_rule_id: String,
    pub right_rule_id: String,
    pub field: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyValidationError {
    pub policy_id: String,
    pub rule_id: String,
    pub reason: String,
}

impl PolicyValidationError {
    pub fn new(
        policy_id: impl Into<String>,
        rule_id: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            policy_id: policy_id.into(),
            rule_id: rule_id.into(),
            reason: reason.into(),
        }
    }
}

impl std::fmt::Display for PolicyValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "policy {} rule {} is invalid: {}",
            self.policy_id, self.rule_id, self.reason
        )
    }
}

impl std::error::Error for PolicyValidationError {}

pub fn default_bootstrap_policy(admission: &SessionAdmission) -> PolicyObject {
    PolicyObject {
        policy_id: admission.policy_id.clone(),
        version: 1,
        description: "bootstrap runtime admission policy".to_string(),
        enabled: true,
        rules: vec![PolicyRule {
            rule_id: "bootstrap_default".to_string(),
            priority: 0,
            description: "baseline admission derived from server runtime profile".to_string(),
            conditions: vec![PolicyCondition::Any],
            actions: vec![
                PolicyAction::SetMode(admission.mode),
                PolicyAction::SetRelayPermitted(admission.relay_permitted),
                PolicyAction::SetResumptionTtlSecs(admission.resumption_ttl_secs),
                PolicyAction::SetPrivilegeBoundary(admission.privileged_boundary),
            ],
        }],
        updated_at: now_ts(),
    }
}

pub fn validate_policy_object(policy: &PolicyObject) -> Result<(), PolicyValidationError> {
    if policy.policy_id.trim().is_empty() {
        return Err(PolicyValidationError::new(
            "<unknown>",
            "policy",
            "policy_id must not be empty",
        ));
    }
    if policy.rules.is_empty() {
        return Err(PolicyValidationError::new(
            policy.policy_id.clone(),
            "policy",
            "policy must define at least one rule",
        ));
    }

    for rule in &policy.rules {
        if rule.rule_id.trim().is_empty() {
            return Err(PolicyValidationError::new(
                policy.policy_id.clone(),
                "<empty>",
                "rule_id must not be empty",
            ));
        }
        if rule.actions.is_empty() {
            return Err(PolicyValidationError::new(
                policy.policy_id.clone(),
                rule.rule_id.clone(),
                "rule must define at least one action",
            ));
        }
        for action in &rule.actions {
            validate_action(policy, rule, action)?;
        }
    }

    Ok(())
}

pub fn detect_conflicts(policies: &[PolicyObject]) -> Vec<PolicyConflict> {
    let mut conflicts = Vec::new();
    let mut seen =
        std::collections::BTreeMap::<(i32, String, String), (String, String, String)>::new();

    for policy in sorted_policies(policies) {
        if !policy.enabled {
            continue;
        }
        for rule in sorted_rules(&policy.rules) {
            for action in sorted_actions(&rule.actions) {
                let field = action_field(action).to_string();
                let condition_key = normalized_conditions(&rule.conditions);
                let entry_key = (rule.priority, condition_key, field.clone());
                let action_value = normalized_action_value(action);
                if let Some((existing_policy, existing_rule, existing_value)) = seen.get(&entry_key)
                {
                    if existing_value != &action_value {
                        conflicts.push(PolicyConflict {
                            policy_id: policy.policy_id.clone(),
                            left_rule_id: format!("{}:{}", existing_policy, existing_rule),
                            right_rule_id: format!("{}:{}", policy.policy_id, rule.rule_id),
                            field,
                            reason: "same match set and priority drive different values"
                                .to_string(),
                        });
                    }
                } else {
                    seen.insert(
                        entry_key,
                        (policy.policy_id.clone(), rule.rule_id.clone(), action_value),
                    );
                }
            }
        }
    }

    conflicts
}

pub fn evaluate_policies(policies: &[PolicyObject], ctx: &PolicyContext) -> PolicyDecision {
    let mut admission = ctx.requested.clone();
    let mut overlay = PolicyOverlay::default();
    let mut matched_rules = Vec::new();
    let mut matched_policies = Vec::new();

    for policy in sorted_policies(policies) {
        if !policy.enabled {
            continue;
        }
        for rule in sorted_rules(&policy.rules) {
            if !rule
                .conditions
                .iter()
                .all(|condition| matches_condition(condition, ctx))
            {
                continue;
            }

            matched_rules.push(format!("{}:{}", policy.policy_id, rule.rule_id));
            if !matched_policies
                .iter()
                .any(|item| item == &policy.policy_id)
            {
                matched_policies.push(policy.policy_id.clone());
            }
            admission.policy_id = policy.policy_id.clone();

            for action in sorted_actions(&rule.actions) {
                match action {
                    PolicyAction::SetMode(mode) => admission.mode = *mode,
                    PolicyAction::SetRelayPermitted(allowed) => {
                        admission.relay_permitted = *allowed;
                    }
                    PolicyAction::SetResumptionTtlSecs(ttl) => {
                        admission.resumption_ttl_secs = *ttl;
                    }
                    PolicyAction::SetPrivilegeBoundary(boundary) => {
                        admission.privileged_boundary = *boundary;
                    }
                    PolicyAction::SetMaxRouteHops(value) => {
                        overlay.max_route_hops = Some(*value);
                    }
                    PolicyAction::RequireRouteDiversity(value) => {
                        overlay.required_route_diversity = Some(*value);
                    }
                    PolicyAction::PinPath(path) => {
                        overlay.pinned_path = path.clone();
                    }
                }
            }
        }
    }

    let explainability = if matched_rules.is_empty() {
        format!(
            "policy engine kept bootstrap admission {} without overrides",
            admission.policy_id
        )
    } else {
        format!(
            "matched {} rules across policies {}; final admission mode={:?} relay={} ttl={}s",
            matched_rules.len(),
            matched_policies.join(","),
            admission.mode,
            admission.relay_permitted,
            admission.resumption_ttl_secs,
        )
    };

    PolicyDecision {
        admission,
        overlay,
        matched_rules,
        matched_policies,
        explainability,
    }
}

fn validate_action(
    policy: &PolicyObject,
    rule: &PolicyRule,
    action: &PolicyAction,
) -> Result<(), PolicyValidationError> {
    match action {
        PolicyAction::SetResumptionTtlSecs(ttl) if *ttl > 7 * 24 * 60 * 60 => {
            Err(PolicyValidationError::new(
                policy.policy_id.clone(),
                rule.rule_id.clone(),
                "resumption TTL exceeds 7 day safety cap",
            ))
        }
        PolicyAction::SetMaxRouteHops(0) => Err(PolicyValidationError::new(
            policy.policy_id.clone(),
            rule.rule_id.clone(),
            "max_route_hops must be greater than zero",
        )),
        PolicyAction::RequireRouteDiversity(value) if !(0.0..=1.0).contains(value) => {
            Err(PolicyValidationError::new(
                policy.policy_id.clone(),
                rule.rule_id.clone(),
                "required route diversity must be in [0, 1]",
            ))
        }
        PolicyAction::PinPath(nodes) => {
            if nodes.len() < 2 {
                return Err(PolicyValidationError::new(
                    policy.policy_id.clone(),
                    rule.rule_id.clone(),
                    "pin_path requires at least two nodes",
                ));
            }
            let mut uniq = std::collections::BTreeSet::new();
            for node in nodes {
                if !uniq.insert(node.to_ascii_lowercase()) {
                    return Err(PolicyValidationError::new(
                        policy.policy_id.clone(),
                        rule.rule_id.clone(),
                        "pin_path introduces a routing loop via duplicate nodes",
                    ));
                }
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn matches_condition(condition: &PolicyCondition, ctx: &PolicyContext) -> bool {
    match condition {
        PolicyCondition::Any => true,
        PolicyCondition::UserIdPrefix(prefix) => ctx.user_id.starts_with(prefix),
        PolicyCondition::DeviceIdPrefix(prefix) => ctx.device_id.starts_with(prefix),
        PolicyCondition::Platform(platform) => ctx.platform == *platform,
        PolicyCondition::UserStatus(status) => &ctx.user_status == status,
        PolicyCondition::RequestedMode(mode) => ctx.requested.mode == *mode,
        PolicyCondition::Region(region) => ctx.region.eq_ignore_ascii_case(region),
        PolicyCondition::NodeRole(role) => ctx.node_role.eq_ignore_ascii_case(role),
    }
}

fn normalized_conditions(conditions: &[PolicyCondition]) -> String {
    let mut rendered = conditions
        .iter()
        .map(|condition| match condition {
            PolicyCondition::Any => "any".to_string(),
            PolicyCondition::UserIdPrefix(value) => format!("user:{}", value),
            PolicyCondition::DeviceIdPrefix(value) => format!("device:{}", value),
            PolicyCondition::Platform(value) => format!("platform:{}", value.as_str()),
            PolicyCondition::UserStatus(value) => format!("user_status:{:?}", value),
            PolicyCondition::RequestedMode(value) => format!("mode:{:?}", value),
            PolicyCondition::Region(value) => format!("region:{}", value.to_ascii_lowercase()),
            PolicyCondition::NodeRole(value) => format!("role:{}", value.to_ascii_lowercase()),
        })
        .collect::<Vec<_>>();
    rendered.sort();
    rendered.join("|")
}

fn action_field(action: &PolicyAction) -> &'static str {
    match action {
        PolicyAction::SetMode(_) => "mode",
        PolicyAction::SetRelayPermitted(_) => "relay_permitted",
        PolicyAction::SetResumptionTtlSecs(_) => "resumption_ttl_secs",
        PolicyAction::SetPrivilegeBoundary(_) => "privileged_boundary",
        PolicyAction::SetMaxRouteHops(_) => "max_route_hops",
        PolicyAction::RequireRouteDiversity(_) => "required_route_diversity",
        PolicyAction::PinPath(_) => "pin_path",
    }
}

fn normalized_action_value(action: &PolicyAction) -> String {
    match action {
        PolicyAction::SetMode(value) => format!("{:?}", value),
        PolicyAction::SetRelayPermitted(value) => value.to_string(),
        PolicyAction::SetResumptionTtlSecs(value) => value.to_string(),
        PolicyAction::SetPrivilegeBoundary(value) => format!("{:?}", value),
        PolicyAction::SetMaxRouteHops(value) => value.to_string(),
        PolicyAction::RequireRouteDiversity(value) => format!("{value:.4}"),
        PolicyAction::PinPath(value) => value.join("->"),
    }
}

fn sorted_policies<'a>(policies: &'a [PolicyObject]) -> Vec<&'a PolicyObject> {
    let mut sorted = policies.iter().collect::<Vec<_>>();
    sorted.sort_by(|left, right| {
        left.policy_id
            .cmp(&right.policy_id)
            .then_with(|| left.version.cmp(&right.version))
    });
    sorted
}

fn sorted_rules<'a>(rules: &'a [PolicyRule]) -> Vec<&'a PolicyRule> {
    let mut sorted = rules.iter().collect::<Vec<_>>();
    sorted.sort_by(|left, right| {
        right
            .priority
            .cmp(&left.priority)
            .then_with(|| left.rule_id.cmp(&right.rule_id))
    });
    sorted
}

fn sorted_actions<'a>(actions: &'a [PolicyAction]) -> Vec<&'a PolicyAction> {
    let mut sorted = actions.iter().collect::<Vec<_>>();
    sorted.sort_by(|left, right| action_field(left).cmp(action_field(right)));
    sorted
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_policy() -> PolicyObject {
        default_bootstrap_policy(&SessionAdmission::default())
    }

    fn context() -> PolicyContext {
        PolicyContext {
            user_id: "user-001".to_string(),
            user_status: UserStatus::Active,
            device_id: "device-001".to_string(),
            platform: Platform::Linux,
            requested: SessionAdmission::default(),
            region: "primary".to_string(),
            node_role: "edge".to_string(),
        }
    }

    #[test]
    fn conflicting_rules_are_detected() {
        let mut policy_a = base_policy();
        policy_a.policy_id = "policy-a".to_string();
        policy_a.rules = vec![PolicyRule {
            rule_id: "relay_on".to_string(),
            priority: 100,
            description: String::new(),
            conditions: vec![PolicyCondition::Platform(Platform::Linux)],
            actions: vec![PolicyAction::SetRelayPermitted(true)],
        }];

        let mut policy_b = base_policy();
        policy_b.policy_id = "policy-b".to_string();
        policy_b.rules = vec![PolicyRule {
            rule_id: "relay_off".to_string(),
            priority: 100,
            description: String::new(),
            conditions: vec![PolicyCondition::Platform(Platform::Linux)],
            actions: vec![PolicyAction::SetRelayPermitted(false)],
        }];

        let conflicts = detect_conflicts(&[policy_a, policy_b]);
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].field, "relay_permitted");
    }

    #[test]
    fn looping_pin_path_is_rejected() {
        let policy = PolicyObject {
            policy_id: "loop".to_string(),
            version: 1,
            description: String::new(),
            enabled: true,
            rules: vec![PolicyRule {
                rule_id: "bad_path".to_string(),
                priority: 10,
                description: String::new(),
                conditions: vec![PolicyCondition::Any],
                actions: vec![PolicyAction::PinPath(vec![
                    "edge-a".to_string(),
                    "relay-a".to_string(),
                    "relay-a".to_string(),
                ])],
            }],
            updated_at: now_ts(),
        };

        let err = validate_policy_object(&policy).expect_err("loop should be rejected");
        assert!(err.reason.contains("routing loop"));
    }

    #[test]
    fn evaluation_is_deterministic_and_applies_overrides() {
        let base = base_policy();
        let override_policy = PolicyObject {
            policy_id: "linux-fast".to_string(),
            version: 1,
            description: String::new(),
            enabled: true,
            rules: vec![PolicyRule {
                rule_id: "linux_override".to_string(),
                priority: 50,
                description: String::new(),
                conditions: vec![PolicyCondition::Platform(Platform::Linux)],
                actions: vec![
                    PolicyAction::SetMode(ProductMode::Fast),
                    PolicyAction::SetResumptionTtlSecs(900),
                    PolicyAction::SetMaxRouteHops(3),
                ],
            }],
            updated_at: now_ts(),
        };

        let decision = evaluate_policies(&[override_policy.clone(), base.clone()], &context());
        let repeat = evaluate_policies(&[base, override_policy], &context());

        assert_eq!(decision.admission.mode, ProductMode::Fast);
        assert_eq!(decision.admission.resumption_ttl_secs, 900);
        assert_eq!(decision.overlay.max_route_hops, Some(3));
        assert_eq!(decision.matched_rules, repeat.matched_rules);
        assert_eq!(decision.admission.policy_id, repeat.admission.policy_id);
    }
}
