# Phase 10 - SRE, Statistical Process Control (SPC) & Differential Privacy Telemetry

## Цель

Сделать систему наблюдаемой и управляемой в бою: метрики, трассировка, алерты, canary-релизы, расследование инцидентов и безопасная телеметрия.

## Результат фазы

- Базовый SRE-стек для продукта.
- Управляемый rollout и rollback.
- Осмысленная телеметрия transport, stealth, fabric и control plane.

## Подробное ТЗ

1. **Ввести стандартизированный набор метрик для всех ключевых подсистем:**
   - handshake;
   - transport;
   - FEC/reliability;
   - path manager;
   - personas;
   - relay fabric;
   - control plane.
2. **Сделать logs, traces и correlation IDs частью ежедневной эксплуатации:**
   система должна быть расследуемой без ручного гадания по симптомам.
3. **Построить dashboards и alerting rules сначала для известных классов сбоев:**
   только после этого есть смысл усложнять SRE статистикой и ML-моделями.
4. **Реализовать canary/staged rollout и быстрый rollback:**
   релизная дисциплина должна предотвращать массовые регрессии transport, stealth или control plane.
5. **Сделать privacy-aware telemetry осознанной частью продукта:**
   нужно явно определить, какие данные можно собирать, как они санитизируются и как не ломают stealth/privacy цели.
6. **Использовать SPC, anomaly detection и differential privacy там, где они реально повышают качество эксплуатации:**
   эти методы должны улучшать detection и privacy, а не скрывать систему за непрозрачной математикой.

## Артефакты

- `docs/DIFFERENTIAL_PRIVACY_TELEMETRY.md`
- `docs/ML_ANOMALY_SRE.md`
- Набор dashboards, alerts и runbooks.

## Acceptance Criteria

- Команда может обнаружить и диагностировать основные классы сбоев по метрикам и трассам.
- Canary release способен остановить или откатить заведомо плохой rollout.
- Набор телеметрии документирован и не противоречит stealth/privacy целям продукта.
- Система наблюдаемости усиливает продукт в бою, а не только добавляет красивую аналитику.

## Метрики успеха

- Снижение времени диагностики типовых инцидентов.
- Снижение времени отката неудачного релиза.
- Покрытие основных подсистем наблюдаемостью.

## Риски

- Слишком сложные ML-модели дадут непрозрачные алерты и ложное чувство контроля.
- Избыточная телеметрия может конфликтовать со stealth и privacy задачами.

## Зависимости

- Phase 08.

## Комментарий по выполнению

Фаза `phase_10_observability_sre` успешно выполнена `2026-04-08`.

Итог по результатам:

- на сервере реализован отдельный observability layer: `state/observability.json` с runtime summary, fabric/control-plane SRE summary, metric deltas, session distributions, SPC signals, known alerts, differential privacy telemetry и `rollout_guard`;
- добавлен correlation-aware `state/trace.ndjson`, а handshake/session/fabric/admin/control-plane lifecycle теперь пишет объяснимые trace events с `correlation_id`;
- метрики расширены до transport/path/persona/reliability/fabric/control-plane distributions и counters, которые реально пригодны для расследования инцидентов и release gating;
- admin CLI получил команды `show_observability`, `show_rollout_guard`, `assert_rollout_guard`, поэтому оператор может диагностировать деградацию и проверять canary без ручного чтения внутренних файлов;
- `deploy/update_server.sh` переведен на staged rollout discipline: после рестарта он ждет healthy `assert_rollout_guard` и автоматически делает rollback при плохом canary;
- `deploy/diagnose_server.sh` и `deploy/omega-alerts.yml` теперь учитывают observability snapshot и rollout guard как штатную часть production health model;
- документация фазы подготовлена: `docs/DIFFERENTIAL_PRIVACY_TELEMETRY.md`, `docs/ML_ANOMALY_SRE.md`, `docs/OBSERVABILITY_DASHBOARDS.md`, `docs/INCIDENT_RUNBOOKS.md`, а навигация и operational reference обновлены.

Проверка выполнена успешно:

- `cargo fmt --all`
- `cargo check --workspace`
- `cargo test --workspace`

Неблокирующее замечание вне этой фазы осталось прежним: в `omega-transport/src/transport_v2/endpoint.rs` сохраняется warning про `unused assignment` для `remaining`, на корректность результатов Phase 10 он не влияет.
