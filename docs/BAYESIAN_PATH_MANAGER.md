# Bayesian Path Manager

## Назначение

`Phase 04` переводит path management из набора разрозненных RTT/loss сигналов в единый explainable engine внутри `omega-transport`.

Цель реализации:
- безопасно подбирать рабочий payload budget без ручного MTU-tuning;
- откатываться при blackhole-сценариях до реального рабочего размера;
- не дергаться на коротких всплесках jitter/loss;
- давать человекочитаемое объяснение каждого решения;
- использовать вероятностную модель как усиление baseline, а не как непрозрачную замену.

Реализация живет в `omega-transport/src/transport_v2/path.rs` и подключена к `TransportEndpoint`.

## Базовая логика

Path manager начинается не с handshake ceiling, а с консервативного безопасного бюджета:

- `safe_start_payload = min(max_payload, 1100 B)`;
- `min_payload = clamp(max_payload, 256 B .. 640 B)`;
- `probe_step = 48 B`, а при очень хорошем качестве поднимается до `96 B`;
- `probe_interval = 4 s`;
- `blackhole_backoff = 8 s`;
- `roam_hold = 5 s`;
- `recovery_hold = 6 s`.

Это дает два слоя защиты:
- стартуем ниже handshake ceiling, чтобы не словить фрагментацию сразу после подключения;
- растем только после явного подтверждения доставки более крупного datagram.

## DPLPMTUD

### Модель

`TransportEndpoint::poll_datagram(...)` берет не просто внешний `payload_budget`, а:

`effective_budget = min(external_limit, path.confirmed_payload or probe_target)`

Если path manager считает путь стабильным, он может выдать `probe_target > confirmed_payload`. Тогда transport:
- собирает обычные `ack/control/data` frames;
- при необходимости добавляет `PathFrame(flags=0x02)` чтобы probe был ack-eliciting;
- добивает датаграмму `Padding`-ом до probe size;
- помечает отправленный пакет как `path_probe_target`.

### Условия роста

Upward probe разрешается только если одновременно верны условия:
- `quality_score >= 70`;
- `loss_ewma < 4%`;
- `jitter_ewma < 25 ms`;
- нет `blackhole_suspected`;
- нет активного roam-hold;
- нет другого probe in flight;
- наступил `next_probe_at`.

### Условия отката

Есть два разных сценария:

1. Probe failure.
Если потерян именно пакет, который был отправлен как probe, мы:
- не повышаем `confirmed_payload`;
- сужаем `search_ceiling_payload`;
- откладываем следующий probe на `8 s`.

2. Blackhole signature.
Если одновременно наблюдаются:
- `lost_packets >= 2`;
- `acked_bytes == 0` в текущем batch;
- нет свежего ACK-прогресса дольше примерно `2 * srtt`;
- текущий payload еще можно уменьшать,

то path manager считает это blackhole-паттерном и снижает `confirmed_payload` вниз на backoff-step.

## Path Quality Score

Детерминированный baseline строится на EWMA/penalty модели:

`quality = 100 - loss_penalty - jitter_penalty - reorder_penalty - inflation_penalty - roam_penalty - blackhole_penalty`

Где в текущей реализации:
- `loss_penalty = min(loss_ewma * 420, 42)`
- `jitter_penalty = min(jitter_ms / 3.5, 18)`
- `reorder_penalty = min(reorder_ewma * 220, 12)`
- `inflation_penalty = min((srtt / min_rtt - 1) * 24, 16)`
- `roam_penalty = 8`, пока действует roam-hold
- `blackhole_penalty = 24`, если зафиксирован blackhole

Bucket-ы:
- `85+` -> `excellent`
- `70..84` -> `good`
- `55..69` -> `fair`
- `35..54` -> `poor`
- `<35` -> `critical`

## Hysteresis

Чтобы path manager не флапал:
- рост MTU запрещен во время `roam_hold` и `blackhole_backoff`;
- краткий loss burst повышает `degrade_streak`, но не переводит путь в `blackhole_recovery`;
- возврат после blackhole идет через `recovering`, а не сразу в `stable`;
- pacing тоже меняется ступенчато, а не мгновенно.

Pacing factor по mode:
- `stable` -> `100%`
- `probing` -> `95%`
- `cautious` -> `85%`
- `roaming` -> `80%`
- `recovering` -> `88%`
- `blackhole_recovery` -> `70%`

## Вероятностный слой

Поверх baseline сидит легкая belief model с пятью состояниями:
- `stable`
- `congested`
- `reordered`
- `blackhole_risk`
- `recovering`

Она обновляется мультипликативными likelihood-факторами от текущих сигналов:
- высокий `quality_score` усиливает `stable`;
- рост loss/jitter усиливает `congested`;
- рост reordering усиливает `reordered`;
- blackhole-флаг усиливает `blackhole_risk`;
- recovery-hold усиливает `recovering`.

Важно: belief model ничего не решает сама по себе.
Она только:
- делает decision engine устойчивее;
- влияет на `route_action`;
- попадает в explainability/telemetry.

Критические решения все равно принимаются baseline-логикой:
- probe/no-probe;
- MTU fallback;
- pacing factor;
- mode transition.

## Decision Engine

В snapshot path manager отдает:
- `payload_budget`
- `confirmed_payload`
- `search_ceiling_payload`
- `probe_target_payload`
- `quality_score`
- `mode`
- `belief`
- `belief_confidence`
- `blackhole_suspected`
- `route_action`
- `last_action`
- `explanation`

`route_action` сейчас выдается как explainable recommendation:
- `hold_route`
- `hold_route_after_roam`
- `hold_route_and_reduce_burstiness`
- `consider_quieter_persona`
- `prefer_fallback_route`
- `revalidate_route_cautiously`

Это позволяет следующей фазе подключать real route/persona switching без переписывания baseline.

## Explainability

Каждое решение фиксируется в двух строках:
- `last_action` - что именно сделано;
- `explanation` - почему это было сделано, с текущими loss/jitter/reordering/quality/belief.

Пример:

```text
mode=BlackholeRecovery, quality=31, payload=1004 B, ceiling=1052 B,
loss=18.20%, jitter=22 ms, reordering=1.10%, belief=BlackholeRisk (64.00%),
blackhole=true, route_action=prefer_fallback_route.
The baseline path manager saw repeated loss at the current size with no fresh ACK progress.
```

## Телеметрия

### Client diagnostics

`omega-client-runtime/src/diagnostics.rs` теперь пишет:
- `transport_payload_budget`
- `path_confirmed_payload`
- `path_probe_payload`
- `path_quality_score`
- `path_mode`
- `path_belief`
- `path_belief_confidence_percent`
- `path_route_action`
- `path_blackhole_suspected`
- `path_last_action`
- `path_explanation`

### Server snapshots

`omega-edge/src/session.rs` и `omega-edge/src/runtime.rs` теперь включают:
- `payload_budget`
- `path_quality_score`
- `path_mode`
- `path_belief`
- `blackhole_suspected`
- `path_explanation`

### Prometheus gauges

Добавлены агрегаты:
- `omega_runtime_avg_path_quality_score`
- `omega_runtime_avg_payload_budget`
- `omega_runtime_blackhole_sessions`
- `omega_path_roam_total`

## Acceptance coverage

Фаза закрывает acceptance criteria так:

- Рабочий MTU находится через guarded upward probes и подтверждается только ACK-ами probe-пакетов.
- Blackhole приводит к автоматическому снижению payload budget и переводу path в `blackhole_recovery`.
- Краткие всплески loss/jitter не вызывают hard fallback: это проверено отдельным unit test на hysteresis.
- Решения объясняются через `last_action + explanation + mode + belief + route_action`.
- Bayesian слой не управляет транспортом напрямую, а только усиливает устойчивость baseline decision engine.

## Тесты

В transport tests добавлены сценарии:
- успешный DPLPMTUD probe поднимает `confirmed_payload`;
- sustained loss без ACK вызывает blackhole fallback;
- короткий loss burst не переводит path в blackhole mode;
- endpoint-level probe действительно формирует enlarged datagram и подтверждается ACK-ом.
