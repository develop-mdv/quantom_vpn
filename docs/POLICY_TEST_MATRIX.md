# Policy Test Matrix

## Engine Contract

Policy engine в `omega-control/src/policy.rs` работает как deterministic ABAC-like overlay:

- policy objects сортируются по `policy_id`, затем по `version`;
- rules сортируются по `priority desc`, затем по `rule_id`;
- actions применяются в стабильном порядке по semantic field;
- одинаковый input context всегда дает одинаковый `PolicyDecision`.

## Static Safety Checks

Перед принятием policy object выполняются validation rules:

- `policy_id` не пустой;
- у policy есть хотя бы одно rule;
- у rule есть `rule_id` и хотя бы одно action;
- `SetMaxRouteHops` не может быть `0`;
- `RequireRouteDiversity` должен лежать в `[0, 1]`;
- `PinPath` должен содержать минимум 2 node и не может содержать duplicate nodes.

Duplicate nodes трактуются как потенциальный routing loop и policy отвергается до попадания в live control plane.

## Conflict Detection Rule

Статический конфликт возникает, если:

- rules имеют одинаковый priority;
- rules имеют одинаковый normalized condition set;
- rules пишут в одно и то же semantic field;
- rules задают разные значения.

Такой policy set reject'ится в `put_policy`.

## Matrix

| ID | Scenario | Input | Expected result | Covered by |
| --- | --- | --- | --- | --- |
| P01 | Bootstrap path | only default runtime admission policy | policy engine leaves requested admission intact | runtime bootstrap + `evaluation_is_deterministic_and_applies_overrides` |
| P02 | Deterministic override | linux device matches override rule | final admission switches mode/TTL deterministically | `evaluation_is_deterministic_and_applies_overrides` |
| P03 | Static conflict detection | two enabled rules set `relay_permitted=true/false` for same match set and priority | conflict is detected and `put_policy` must reject candidate | `conflicting_rules_are_detected` |
| P04 | Route loop rejection | `PinPath([edge-a, relay-a, relay-a])` | validation rejects policy before activation | `looping_pin_path_is_rejected` |
| P05 | Ticket policy propagation | session policy changes `policy_id` and `resumption_ttl_secs` | issued ticket stores final policy_id/ttl from effective admission | live handshake integration |
| P06 | Runtime reconcile safety | blocked/deleted user still matches some policy | auth/reconcile denies session independently of policy overlay | `authorize_resumption` + server reconcile |
| P07 | Node/region selector | context contains `region` and `node_role` | policy engine can specialize admission by deployment role | `PolicyCondition::Region/NodeRole` |
| P08 | Version bump | updating same `policy_id` through `put_policy` | version increments monotonically | `ControlPlaneStore::put_policy` semantics |

## Operational Expectations

### Safe update flow

1. Validate candidate policy.
2. Detect conflicts against existing active set.
3. Persist new version into control plane.
4. Let next handshake/session admission use new deterministic result.

### Unsafe update flow that is now prevented

- adding conflicting relay or boundary rules with same match set;
- shipping looped pinned paths;
- writing ad-hoc policy JSON that runtime interprets inconsistently.

## What is intentionally out of scope in Phase 08

- SMT solver integration in runtime path;
- symbolic route synthesis;
- distributed policy quorum replication;
- dynamic user-defined predicate language.

Для продукта на текущем шаге deterministic ordering + static validation + conflict rejection дают значительно больше практической надежности, чем попытка сразу встроить heavyweight formal machinery без operational closure.
