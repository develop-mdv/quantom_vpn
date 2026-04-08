# Client Usability And Diagnostic Report

## Что это за отчет

Это не маркетинговая презентация, а engineering report по тем user flows, которые реально закрыты кодом Phase 09.

Здесь проверяется не красота UI, а то, достигаем ли мы product goals:

- пользователь может подключиться без чтения transport internals;
- ошибки объясняются по классу;
- background runtime живет отдельно от launcher UX;
- update path не принимает неподписанный релиз.

## Test Matrix

| Сценарий | Ожидаемое поведение | Реализованный surface |
| --- | --- | --- |
| Первичная настройка | Пользователь вводит server/device id/token/profile и получает сохраненный desktop config | `omega-client-app setup` |
| Нормальное подключение | Пользователь запускает runtime в фоне и видит понятный статус | `omega-client-app connect`, `status` |
| Смена профиля | Пользователь меняет high-level profile без ручного редактирования env vars | `omega-client-app profile set ...` |
| Мягкое отключение | UI просит runtime завершиться без blind kill | `runtime-control.json`, `disconnect` |
| Повторное подключение | Пользователь не ищет вручную pid/logs, а вызывает один reconnect action | `omega-client-app reconnect` |
| Диагностика проблем | Пользователь или support получает lifecycle + diagnostics + report bundle | `status --advanced`, `export-diagnostics` |
| Подмена релиза | Клиент отвергает bundle без достаточного числа подписей | `update verify` |
| Подмена содержимого после verify | Apply повторно проверяет digest/length и не принимает mutated bundle | `update apply` |

## Human-Readable Diagnostic Outcomes

### Configuration error

Сигнал:

- нет `device_id` или `device_token` в desktop config.

Ожидаемый outcome:

- пользователь получает не raw panic, а рекомендацию пройти `setup`.

### Credentials error

Сигнал:

- runtime не может использовать device credentials.

Ожидаемый outcome:

- lifecycle пишет `failure_scope=credentials`;
- launcher показывает suggestion проверить device id/token или выполнить token rotation.

### Handshake failure

Сигнал:

- timeout/retry exhaustion/UDP reachability issue.

Ожидаемый outcome:

- lifecycle пишет `failure_scope=handshake`;
- suggested action рекомендует проверить reachability/firewall или попробовать `Restricted Fallback`.

### Routing failure

Сигнал:

- конфликтующий VPN adapter, ошибка full-tunnel route install.

Ожидаемый outcome:

- lifecycle пишет `failure_scope=routing`;
- launcher предлагает закрыть конкурирующие адаптеры и повторить connect.

### Transport degradation

Сигнал:

- poor/critical path quality, blackhole hints, growing recovery overhead.

Ожидаемый outcome:

- basic status сообщает `path quality`, `RTT`, `loss` и suspected issue;
- advanced status показывает `path belief`, `confidence`, `reliability strategy`, `FEC counters`.

## Update Safety Scenarios

### Positive path

1. Trusted root присутствует локально.
2. Manifest подписан threshold-числом trusted keys.
3. Bundle digest и length совпадают.
4. Bundle stage-ится и потом apply-ится с backup.

### Rejected path

Должны завершаться ошибкой:

- manifest expired;
- wrong channel;
- unknown target;
- invalid signature threshold;
- wrong digest;
- wrong length.

## Cognitive Load Outcome

Главный UX intentionally сокращен до нескольких решений:

- подключен ли клиент;
- какой профиль активен;
- есть ли проблема;
- что делать дальше.

Все вероятностные/advanced величины перенесены в `status --advanced` и support report. Это уменьшает главный cognitive load, но сохраняет explainability для оператора.

## Remaining Gaps

Phase 09 честно не претендует на завершение всего desktop UX мира. Остаются следующие шаги:

- platform-native tray icon и notifications;
- background auto-reconnect supervisor как отдельный долгоживущий desktop service;
- signed timestamp/snapshot metadata layer поверх текущего update manifest;
- richer localization/internationalization.

## Code Reference

- `omega-client-app/src/main.rs`
- `omega-client-app/src/launcher.rs`
- `omega-client-app/src/update.rs`
- `omega-client-runtime/src/lifecycle.rs`
- `omega-client-runtime/src/diagnostics.rs`
