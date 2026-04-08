# Incident Runbooks

## 1. Плохой canary / rollout guard unhealthy

Симптомы:

- `admin assert_rollout_guard` падает;
- `rollout_guard.recommended_action = rollback`;
- `deploy/update_server.sh` сам инициирует rollback.

Действия:

1. Выполнить `cargo run -p omega-server -- admin show_rollout_guard`.
2. Выполнить `cargo run -p omega-server -- admin show_observability`.
3. Проверить `alerts`, `spc_signals` и `metric_deltas`.
4. Если причина в loss/path/fabric/policy, не расширять canary и откатить релиз.
5. После rollback сохранить snapshot и trace tail для postmortem.

## 2. Всплеск handshake failures

Симптомы:

- alert `Handshake failure spike`;
- рост `omega_handshake_failures_total`;
- backlog в `omega_handshake_pending`.

Действия:

1. Открыть `cargo run -p omega-server -- admin show_observability`.
2. Найти `metrics.handshake_failures_by_reason`.
3. Посмотреть `state/trace.ndjson` по `correlation_id` вида `hs-*`.
4. Сверить, не было ли policy/token revocation в `cargo run -p omega-server -- admin show_audit --limit 100`.
5. Если причина в auth/policy, чинить control plane, а не transport.

## 3. Высокий loss или blackhole recovery

Симптомы:

- `omega_runtime_avg_loss_ratio` выше бюджета;
- `blackhole_suspected_sessions > 0`;
- path mode уходит в `recovering` или `blackhole_recovery`.

Действия:

1. Проверить `cargo run -p omega-server -- admin show_runtime`.
2. Проверить распределения `omega_sessions_path_mode` и `omega_sessions_path_belief`.
3. Проверить `omega_fabric_failover_total` и `omega_fec_recovery_total`.
4. Если деградация началась после rollout, остановить rollout.
5. Сравнить текущий MTU/pacing/FEC behavior с последним стабильным релизом.

## 4. Fabric failover storm

Симптомы:

- растет `omega_fabric_failover_total`;
- `trace.ndjson` полон событий `fabric failover applied during reconcile`;
- `healthy_nodes` падает ниже floor.

Действия:

1. Выполнить `cargo run -p omega-server -- admin list_fabric_nodes`.
2. При необходимости отметить узел через admin command/API.
3. Проверить `last_simulation_*` в observability snapshot.
4. Если failover выходит за budget, rollback релиза обязателен.

## 5. Policy conflicts

Симптомы:

- `omega_control_plane_policy_conflicts > 0`;
- rollout guard блокирует релиз.

Действия:

1. Выполнить `cargo run -p omega-server -- admin show_policy_conflicts`.
2. Заморозить rollout до устранения конфликта.
3. После фикса убедиться, что `admin assert_rollout_guard` снова проходит.

## 6. Что собирать в постмортем

Минимальный пакет:

- `state/observability.json`
- `state/runtime.json`
- tail `state/trace.ndjson`
- `cargo run -p omega-server -- admin show_audit --limit 200`
- если был rollout: вывод `deploy/update_server.sh` и `admin show_rollout_guard`

Этого достаточно, чтобы восстановить причинно-следственную цепочку без догадок.
