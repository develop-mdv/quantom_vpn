# Differential Privacy Telemetry

## Зачем это нужно

Phase 10 вводит телеметрию как боевой инструмент, но не позволяет ей размыть privacy и stealth цели продукта. Поэтому в системе разделены два контура:

- локальный operator-only контур расследования: `state/trace.ndjson`, `state/runtime.json`, `state/sessions.json`, `state/observability.json`;
- privacy-aware экспортный контур: агрегированные счетчики с differential privacy noise.

Идея простая: для расследования инцидента оператору нужны точные локальные данные на самом узле, а для агрегирования, отчетов и внешней аналитики достаточно санитизированных счетчиков.

## Что собирается сейчас

Серверный `observability` task каждые 5 секунд строит snapshot, в который входят:

- `runtime_summary`: активные сессии, средний loss, path quality, payload budget, route diversity;
- `fabric`: здоровье graph fabric, число healthy nodes, последний simulation report;
- `control_plane`: revision, active devices/sessions, tickets, policy conflicts;
- `metrics`: cumulative counters handshake, FEC, retransmit, roam, failover, operator actions;
- `metric_deltas`: приращения за последний интервал;
- `session_distribution`: распределения по path mode, path belief, persona и recovery strategy;
- `alerts`, `spc_signals`, `rollout_guard`;
- `differential_privacy`: sanitized/noisy counts.

## Что запрещено экспортировать

В noisy/sanitized telemetry намеренно исключены поля, которые могут привязать событие к конкретному человеку, устройству или сессии:

- `user_id`
- `device_id`
- `flow_id`
- `client_addr`
- `tunnel_ip`
- сырые trace payloads и произвольные request/response blob-ы

Эти значения могут существовать только в локальном operator-only контуре и не должны попадать в агрегированный export path.

## Текущая DP-модель

Текущая реализация использует Laplace mechanism для счетчиков.

Обозначения:

- истинный счетчик: `c`
- privacy budget: `epsilon`
- scale параметр распределения Laplace: `b = 1 / epsilon`
- noisy значение: `c' = max(0, c + Laplace(0, b))`

При текущем default `OMEGA_DP_EPSILON = 0.75` имеем:

- `b = 1 / 0.75 = 1.333...`
- типичное добавляемое отклонение находится в пределах нескольких единиц счетчика;
- для крупных агрегатов шум почти не меняет operational usefulness;
- для малых значений шум полезно скрывает редкие события.

## Какие счетчики проходят через DP сейчас

В `DifferentialPrivacyTelemetry` сейчас попадают только агрегаты верхнего уровня:

- `active_sessions`
- `handshake_success_total`
- `handshake_failures_total`
- `fabric_failover_total`
- `healthy_fabric_nodes`
- `control_plane_active_devices`
- `control_plane_active_sessions`

Это сознательно ограниченный набор. Phase 10 не пытается зашумить все подряд.

## Почему это совместимо со stealth

Телеметрия не должна подсказывать внешнему наблюдателю форму трафика или session fingerprint. Поэтому:

- persona- и path-распределения хранятся локально в snapshot на узле;
- trace journal не публикуется наружу и нужен только оператору для incident response;
- noisy telemetry не содержит packet-level признаков, raw timing, payload size histograms или peer identifiers;
- `rollout_guard` опирается на агрегаты качества, а не на содержимое трафика.

## Границы доверия

Безопасно считать следующие границы:

- `trace.ndjson` и `observability.json` требуют operator-level доступа к узлу;
- Prometheus endpoint должен оставаться внутри trusted admin perimeter;
- публичный export DP telemetry может использовать только noisy counts;
- если нужен централизованный сбор, туда должен уходить не trace journal, а уже санитизированный snapshot/derived export.

## Практические правила эксплуатации

1. Для живого инцидента сначала читаем точный локальный snapshot/trace, а не noisy export.
2. Для отчетности, capacity review и long-term trend analysis используем noisy aggregates.
3. Если требуется новый telemetry field, сначала нужно доказать, что он:
   - полезен для SRE;
   - не ломает stealth/privacy цели;
   - не дублирует уже существующий локальный trace path.
4. Любой новый идентификатор в export path должен считаться запрещенным по умолчанию.

## Env knobs

- `OMEGA_OBSERVABILITY_SNAPSHOT` - путь к server-side observability snapshot.
- `OMEGA_TRACE_JOURNAL` - путь к NDJSON trace journal.
- `OMEGA_DP_EPSILON` - privacy budget для noisy counts.
- `OMEGA_SPC_WINDOW` - длина rolling window для SPC-сигналов.

## Что еще не делаем специально

Phase 10 не реализует:

- централизованный privacy-preserving analytics backend;
- federated learning;
- сложный privacy accounting на серию запросов;
- автоматическое экспортирование trace journal вне узла.

Это осознанное ограничение. Цель фазы - сделать систему расследуемой и безопасной в эксплуатации, а не построить академически полную privacy platform.
