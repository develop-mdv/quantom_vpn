# Graph Relay Fabric

`Phase 07` превращает relay subsystem из набора placeholder-типов в рабочий fabric layer со следующими свойствами:

- явные роли `edge`, `relay`, `exit`;
- граф узлов и связей с количественными весами;
- policy-aware route selection;
- backup routes и handoff ticket;
- session failover без уничтожения transport/session identity;
- audit/metrics/runtime snapshot для operational control.

## Роли узлов

- `edge`: принимает клиентский `Omega v2` handshake и держит stealth/transport session lifecycle.
- `relay`: внутренний backbone hop для route diversity, failover и снижения прямой связки `edge -> exit`.
- `exit`: точка egress во внешний интернет.

В текущей реализации один и тот же runtime может быть поднят с `OMEGA_NODE_ROLE=edge|relay|exit`, а graph planner подстраивает локальную topology под выбранную роль.

## Fabric graph

Graph живет в `omega-relay/src/graph.rs` и содержит:

- `RelayNode`: `role`, `region`, `operator`, `trust_zone`, `capability`, `health`, `tags`;
- `FabricLink`: `latency_ms`, `capacity_score`, `loss_percent`, `stealth_risk`, `policy_cost`, `operational_percent`, `active`;
- `RouteConstraints`: ограничения, производные от `SessionAdmission`.

`NodeHealth.availability_score()` вычисляется как

```text
availability = 0.45 * operational + 0.35 * capacity + 0.20 * (1 - load)
```

где все компоненты нормированы в диапазон `[0, 1]`.

## Route selection

Routing engine живет в `omega-relay/src/routing.rs`.

Для каждого допустимого path он считает:

- суммарную latency;
- aggregate loss;
- effective capacity как минимум по узлам и ребрам;
- trust score по `core/partner/untrusted`;
- risk score по stealth/policy/load penalties;
- итоговый `quality_score`.

В текущей версии quality model имеет вид:

```text
Q = 125
    - 0.62 * latency_ms
    - 9.5 * loss_percent
    - 0.45 * risk_score
    - 4.5 * hop_count
    + 0.30 * effective_capacity
    + 0.25 * health_score
    + mode_bonus
```

`mode_bonus` зависит от продуктового режима:

- `fast`: предпочитает короткий path и низкую latency;
- `balanced`: требует хотя бы один relay hop, если relay разрешен policy;
- `stealth`: сильнее поощряет relay diversity и избегает direct `edge -> exit`;
- `hostile-network`: больше ценит устойчивость и health margin.

Backup routes выбираются не только по score, но и по `route_diversity_score`, чтобы резервный путь не повторял primary по тем же relay/exit узлам.

## Session handoff

На этапе `finalize_session(...)` в `omega-edge/src/handshake.rs` fabric planner получает `flow_id` и строит `SessionFabricState`:

- `active_route`;
- `backup_routes`;
- `handoff_ticket` с generation/revision/expiry;
- failover budget;
- route diversity score.

Дальше `SessionState` хранит этот state рядом с transport/stealth state. При failover runtime:

1. сохраняет тот же session/flow identity;
2. обновляет fabric route и handoff ticket;
3. дергает `transport.note_peer_roam(...)`, чтобы transport lifecycle видел migration как штатное roaming/handoff событие;
4. пишет audit event и metrics.

## Failover model

В `omega-edge/src/fabric.rs` работает `FabricController`.

Он выполняет:

- planning новой сессии;
- health updates по узлам fabric;
- фоновую reconcile loop по живым сессиям;
- startup simulation отказов;
- runtime view для snapshot/Prometheus.

Failover инициируется, если:

- любой узел из `active_route` стал unhealthy;
- path manager перевел transport в `recovering`/`blackhole_recovery` или поставил `blackhole_suspected=true`.

Оценка reroute time сейчас детерминированная:

```text
node_unavailable: 180 + 70 * hop_count + 55 * relay_hops
link_unavailable: 220 + 70 * hop_count + 55 * relay_hops
path_degraded:    260 + 70 * hop_count + 55 * relay_hops
```

## Control-plane hooks

`Phase 07` добавляет минимальный, но реальный control coupling:

- `OMEGA_NODE_ROLE`, `OMEGA_FABRIC_NODE_ID`, `OMEGA_FABRIC_REGION`, `OMEGA_FABRIC_OPERATOR`;
- admin command `fabric_mark_node` через `state/admin_commands.ndjson`;
- audit event `fabric_failover`;
- audit event `fabric_mark_node`;
- runtime snapshot с aggregate fabric state;
- Prometheus counters/gauges для failover, route diversity и health graph.

## Simulation stand

В `omega-relay` есть unit/simulation tests, которые подтверждают:

- `balanced` по умолчанию выбирает multi-hop path;
- отказ `relay-core-1` переводит сессию на backup route без использования отказавшего узла;
- default failover simulation проходит без full disconnect и остается в пределах budget.

Для default edge topology типичные модельные значения такие:

- primary route: `edge-local -> relay-core-1 -> exit-core-1`;
- backup route: `edge-local -> relay-partner-1 -> exit-partner-1`;
- node failover estimate: `180 + 2*70 + 1*55 = 375 ms`;
- link failover estimate: `220 + 2*70 + 1*55 = 415 ms`.

Для `balanced` budget равен `800 ms`, так что оба сценария укладываются с запасом.

## Кодовые точки

- `omega-relay/src/graph.rs`
- `omega-relay/src/routing.rs`
- `omega-relay/src/simulation.rs`
- `omega-edge/src/fabric.rs`
- `omega-edge/src/handshake.rs`
- `omega-edge/src/session.rs`
- `omega-edge/src/server.rs`
- `omega-edge/src/runtime.rs`
- `omega-edge/src/metrics.rs`
