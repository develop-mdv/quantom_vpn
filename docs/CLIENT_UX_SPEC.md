# Client UX Spec

## Цель Phase 09

Сделать клиент таким, чтобы обычный пользователь видел понятную модель продукта, а оператор или support-инженер мог быстро дойти до причин проблемы без чтения transport internals.

## Архитектурный принцип

Клиент разделен на два процесса:

- `omega-client-app` - desktop-facing launcher/supervisor UX;
- `omega-client-runtime` - privileged background runtime, который поднимает handshake, UDP datapath, TUN и routing.

Это дает два эффекта:

1. UI crash не должен валить live tunnel process.
2. Human-readable status можно строить поверх lifecycle/diagnostics snapshots, а не поверх парсинга stdout.

## Основная пользовательская модель

### Простые профили

Пользователь видит только три профиля:

- `Gaming`
- `General Internet`
- `Restricted Fallback`

Эти профили скрывают техническую детализацию `morphing/persona/tunnel tuning`.

Соответствие:

- `Gaming` -> latency-first
- `General Internet` -> balanced default
- `Restricted Fallback` -> censorship/hostile-network bias

### Базовые действия

Launcher должен поддерживать:

- `setup`
- `connect`
- `disconnect`
- `reconnect`
- `status`
- `profile set`
- `export-diagnostics`
- `update verify/stage/apply`

## Runtime Boundary

### Files used by the launcher

Launcher читает и пишет только product-facing state:

- `omega-client/state/app-config.json`
- `omega-client/state/lifecycle.json`
- `omega-client/state/diagnostics.json`
- `omega-client/state/runtime-control.json`
- `omega-client/state/runtime.pid`
- `omega-client/state/runtime.log`

### Lifecycle snapshot

`lifecycle.json` теперь фиксирует:

- `state`
- `message`
- `failure_scope`
- `suggested_action`
- `handshake_rtt_ms`
- `tunnel_ip`
- `reconnect_recommended`

Состояния:

- `starting`
- `handshaking`
- `connected`
- `degraded`
- `closing`
- `stopped`
- `failed`

### Control command

Launcher отключает runtime не через blind kill, а сначала через `runtime-control.json` с командой `stop`. Только если runtime не вышел вовремя, launcher делает force-kill.

## Diagnostics UX

## Basic view

Обычный `status` показывает только то, что помогает принять решение прямо сейчас:

- connected / connecting / failed / stopped;
- выбранный профиль;
- адрес сервера;
- runtime message;
- path quality + RTT + loss;
- tunnel IP;
- suspected issue и suggested action, если они есть.

### Advanced view

`status --advanced` показывает уже operator-facing детали:

- lifecycle state и failure scope;
- path belief + confidence;
- active/configured persona;
- detectability delta;
- reliability strategies;
- FEC / duplicate counters;
- пути к diagnostics/lifecycle/log файлам.

### Error taxonomy

Launcher обязан объяснять проблему по классу, а не generic timeout-строкой.

Сейчас для user-facing flows выделены как минимум:

- configuration error
- credentials error
- handshake failure
- routing failure
- transport stop/unexpected close
- secure update verification failure

Для каждого класса у lifecycle snapshot есть `message` и `suggested_action`.

## Connect Flow

1. Пользователь проходит `setup`.
2. Launcher сохраняет понятный desktop config.
3. `connect` поднимает background runtime process.
4. Launcher ждет, пока lifecycle перейдет в `connected` или `failed`.
5. В обычном случае пользователь видит краткий status, а не raw transport logs.

## Disconnect/Reconnect Flow

### Disconnect

1. Launcher пишет `stop` command.
2. Runtime публикует `closing`.
3. После cleanup публикуется `stopped`.
4. Если runtime завис, launcher делает force-kill и чистит `runtime.pid`.

### Reconnect

1. Выполняется `disconnect`.
2. Затем поднимается новый runtime process.
3. Пользователь снова получает обычный `status`.

## Export Flow

`export-diagnostics` должен собрать support-ready пакет:

- sanitized launcher config;
- lifecycle snapshot;
- diagnostics snapshot;
- runtime log;
- markdown support report.

Таким образом support не зависит от ручного копирования разных файлов.

## Probabilistic UX Rule

Вероятностные метрики показываются только когда они помогают объяснять поведение системы:

- path belief confidence;
- detectability delta;
- reliability strategy;
- suspected issue.

Они не должны превращаться в перегруженный главный экран. Поэтому basic UX держит только outcome + next action, а advanced UX открывает детали по запросу.

## Code Reference

- `omega-client-app/src/main.rs`
- `omega-client-app/src/app_config.rs`
- `omega-client-app/src/launcher.rs`
- `omega-client-runtime/src/lifecycle.rs`
- `omega-client-runtime/src/diagnostics.rs`
- `omega-client-runtime/src/runtime.rs`
