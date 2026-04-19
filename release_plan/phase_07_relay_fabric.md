# Phase 07 - Graph-Theoretical Relay Fabric & Chaumian Routing topology

## Цель

Построить relay fabric как управляемый граф Edge/Relay/Exit-узлов, который повышает устойчивость, дает route diversity и постепенно усиливает защиту метаданных.

## Результат фазы

- Явное разделение ролей Edge, Relay и Exit.
- Routing engine с динамическим выбором маршрута.
- Session handoff и failover между узлами fabric.

## Подробное ТЗ

1. **Ввести роли узлов и их границы ответственности:**
   - `edge` принимает клиентские stealth-сессии;
   - `relay` обеспечивает внутренний backbone;
   - `exit` дает выход во внешний интернет.
2. **Описать fabric graph и веса ребер:**
   latency, capacity, loss, stealth risk, trust policy и operational health должны участвовать в выборе маршрута.
3. **Реализовать routing engine с ограничениями и резервными маршрутами:**
   - выбор пути по quality/risk score;
   - исключение запрещенных зон;
   - поддержка failover;
   - подготовка к policy-driven route selection.
4. **Сделать session handoff/migration рабочей частью системы:**
   - перенос сессии между узлами;
   - реакция на отказ edge/relay/exit;
   - сохранение целостности session lifecycle.
5. **Усилить fabric за счет научных идей только там, где они не ломают продукт:**
   batching, mixing и anonymity-set подходы полезны, если они дают прирост privacy без неприемлемой латентности.
6. **Подготовить основу для связки fabric с control plane:**
   регистрация узлов, выдача tickets, состояние маршрутов, audit событий и health propagation.

## Артефакты

- `docs/GRAPH_RELAY_FABRIC.md`
- `docs/MIXNET_ANONYMITY.md`
- Стенд или симуляция отказов узлов и перестроения маршрутов.

## Acceptance Criteria

- Edge/Relay/Exit роли работают как отдельные узлы fabric.
- Система выдерживает отказ узла и переводит сессии на резервный маршрут в пределах целевого бюджета времени.
- Routing engine учитывает качество, ограничения политики и операционное состояние графа.
- Session handoff интегрирован с transport и control semantics.

## Метрики успеха

- Снижение числа полных разрывов сессий при отказах узлов.
- Более равномерное распределение нагрузки по fabric.
- Рост route diversity для активных сессий.

## Риски

- Дополнительные хопы увеличат latency.
- Сложность coordination между fabric и control plane может замедлить внедрение.

## Зависимости

- Phase 03 и базовые stealth-механизмы из Phase 06.

## Комментарий по выполнению

Фаза `phase_07_relay_fabric` успешно выполнена `2026-04-07`.

Итог по результатам:

- реализован рабочий `relay fabric` в `omega-relay` с graph model, scoring, backup routes, handoff ticket и failure simulation;
- роли `edge`, `relay`, `exit` теперь выражены как реальные fabric nodes с runtime-конфигурацией через `OMEGA_NODE_ROLE` и связанными metadata;
- `omega-edge` получил fabric controller, startup simulation, session route assignment в handshake finalize, background reconcile loop и failover с audit/metrics;
- `SessionState` и runtime snapshots теперь хранят active route, backup routes, diversity score, handoff generation и failover counters;
- добавлена admin/control связка через `fabric_mark_node`, audit событий `fabric_failover` и `fabric_mark_node`, а также Prometheus метрики fabric health и failover;
- подготовлены артефакты фазы: `docs/GRAPH_RELAY_FABRIC.md`, `docs/MIXNET_ANONYMITY.md`;
- стендовая симуляция отказов подтверждена тестами `omega-relay`: multi-hop selection, backup failover и budget-safe reroute;
- верификация пройдена: `cargo fmt --all`, `cargo check --workspace`, `cargo test --workspace` успешны.
