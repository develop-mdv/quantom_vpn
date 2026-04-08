# Observability Dashboards

## Dashboard 1 - Release Guard

Цель: за 30 секунд понять, можно ли продолжать canary.

Панели:

- `omega_runtime_avg_loss_ratio`
- `omega_runtime_avg_path_quality_score`
- `omega_runtime_blackhole_sessions`
- `omega_handshake_pending`
- `omega_control_plane_policy_conflicts`
- `omega_fabric_healthy_nodes`
- текстовая панель из `state/observability.json -> rollout_guard`

Цветовая логика:

- green: `recommended_action=proceed`
- red: `recommended_action=rollback`

## Dashboard 2 - Handshake Health

Панели:

- `omega_handshake_success_total`
- `omega_handshake_failures_total{reason=*}`
- `omega_handshake_platform_total{platform=*}`
- `omega_handshake_pending`
- correlated trace samples из `trace.ndjson` по `hs-*`

Диагностирует:

- auth regressions;
- cookie/retry pressure;
- resumption failures;
- backlog на handshake path.

## Dashboard 3 - Transport and Path

Панели:

- `omega_packets_in_total`, `omega_packets_out_total`
- `omega_bytes_in_total`, `omega_bytes_out_total`
- `omega_runtime_avg_loss_ratio`
- `omega_runtime_avg_payload_budget`
- `omega_runtime_avg_route_diversity_score`
- `omega_sessions_path_mode{mode=*}`
- `omega_sessions_path_belief{belief=*}`
- `omega_path_roam_total`
- `omega_retransmit_sent_total`, `omega_retransmit_dropped_total`
- `omega_fec_recovery_total`

Диагностирует:

- рост loss/jitter symptoms;
- деградацию path manager;
- черные дыры и DPLPMTUD regressions;
- перекос reliability policy.

## Dashboard 4 - Stealth and Reliability Mix

Панели:

- `omega_sessions_persona{persona=*}`
- `omega_sessions_recovery_strategy{traffic_class=*,strategy=*}`
- `state/observability.json -> differential_privacy.sanitized_counts`
- `state/observability.json -> differential_privacy.noisy_counts`

Диагностирует:

- нештатный перекос persona selection;
- чрезмерный уход трафика в aggressive recovery;
- влияние stealth/reliability knobs на production population.

## Dashboard 5 - Fabric and Control Plane

Панели:

- `omega_fabric_total_nodes`
- `omega_fabric_healthy_nodes`
- `omega_fabric_last_simulation_reroutes`
- `omega_fabric_last_simulation_disconnects`
- `omega_fabric_last_simulation_avg_failover_ms`
- `omega_fabric_failover_total`
- `omega_fabric_operator_actions_total`
- `omega_control_plane_revision`
- `omega_control_plane_active_devices`
- `omega_control_plane_active_sessions`
- `omega_control_plane_issued_tickets`
- `omega_control_plane_policy_conflicts`

Диагностирует:

- failover storms;
- fabric health regressions;
- policy drift;
- rollout-induced control plane inconsistency.

## Обязательные drill-down источники

Любая dashboard должна вести оператора в три места:

1. `cargo run -p omega-server -- admin show_observability`
2. `cargo run -p omega-server -- admin show_rollout_guard`
3. `state/trace.ndjson` с фильтрацией по `correlation_id`

Без этого панели становятся декоративными.
