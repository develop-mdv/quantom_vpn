# Operations

Этот документ описывает текущий практический запуск проекта: локально, на сервере и через GitHub Actions.

## Что нужно для запуска

### Сервер

- Linux с поддержкой TUN.
- Права, позволяющие создать TUN и открыть нужный UDP port.
- Для production обычно нужен systemd и root/capabilities.

### Клиент

- Rust toolchain, если запуск идет из исходников.
- На Windows нужен `wintun.dll`.
- Основной user-facing путь сейчас идет через `omega-client-app setup/connect/status`.
- `start_client.bat` остается рабочим, но это legacy wrapper для env-driven `omega-client`.

## Локальный happy path

### 1. Создать пользователя

```bash
cargo run -p omega-server -- admin create_user --max-devices 5 --max-sessions 3
```

### 2. Зарегистрировать устройство

```bash
cargo run -p omega-server -- admin register_device \
  --user-id <user_uuid> \
  --device-name "laptop" \
  --platform windows
```

Сохрани из вывода:

- `device_id`
- `token`

### 3. Запустить сервер

```bash
cargo run -p omega-server
```

### 4. Настроить desktop client

```bash
cargo run -p omega-client-app -- setup \
  --server <server_ip>:51820 \
  --device-id <device_uuid> \
  --device-token <device_token_hex> \
  --device-name laptop \
  --profile general
```

### 5. Подключить и проверить статус

```bash
cargo run -p omega-client-app -- connect
cargo run -p omega-client-app -- status
cargo run -p omega-client-app -- status --advanced
```

### Legacy env-driven запуск

```bash
OMEGA_SERVER=<server_ip>:51820 \
OMEGA_DEVICE_ID=<device_uuid> \
OMEGA_DEVICE_TOKEN=<device_token_hex> \
OMEGA_DEVICE_NAME="laptop" \
cargo run -p omega-client
```

## Повседневные команды

### Клиент

```bash
cargo run -p omega-client-app -- status
cargo run -p omega-client-app -- connect
cargo run -p omega-client-app -- disconnect
cargo run -p omega-client-app -- reconnect
cargo run -p omega-client-app -- export-diagnostics
cargo run -p omega-client-app -- show-config
```

### Сервер

```bash
cargo run -p omega-server -- admin list_users
cargo run -p omega-server -- admin list_active_sessions
cargo run -p omega-server -- admin show_runtime
cargo run -p omega-server -- admin show_observability
cargo run -p omega-server -- admin show_rollout_guard
cargo run -p omega-server -- admin assert_rollout_guard
cargo run -p omega-server -- admin show_audit --limit 50
```

## Built-in admin и runtime files

### Built-in admin

По умолчанию сервер поднимает built-in web admin на `127.0.0.1:8081`, если не задан `OMEGA_ADMIN_WEB_DISABLE=true`.

### Основные server files

- `state/control_plane.json` - users, devices, sessions, tickets, policies, fabric nodes, audit.
- `state/sessions.json` - active session views.
- `state/runtime.json` - runtime snapshot сервера.
- `state/observability.json` - rollout guard, alerts, SRE signals.
- `state/trace.ndjson` - correlation-aware trace journal.

### Основные client files

- `omega-client/state/app-config.json` - launcher config.
- `omega-client/state/lifecycle.json` - lifecycle snapshot runtime.
- `omega-client/state/diagnostics.json` - negotiated MTU, path quality, counters, DNS checks.
- `omega-client/state/runtime-control.json` - soft stop и launcher/runtime coordination.
- `omega-client/state/resumption_ticket.hex` - локальный resumption state.

## Production deploy

### Обычный релизный путь

Основной production flow сейчас такой:

1. Push в `main`.
2. `deploy-server.yml` собирает `omega-server --release`.
3. Workflow загружает на сервер:
   - `omega-server`
   - `setup_nat.sh`
   - `update_server.sh`
   - `diagnose_server.sh`
   - `omega-server.service`
   - `omega-alerts.yml`
4. На сервере запускается `update_server.sh`.
5. Скрипт обновляет бинарник, systemd unit и alert rules.
6. Затем он ждет healthy service и прогоняет rollout guard.
7. После этого workflow повторно применяет `setup_nat.sh` и запускает `diagnose_server.sh`.

### Когда запускать `bootstrap-network.yml`

Этот workflow нужен не для обычного релиза, а для сетевого bootstrap/repair:

- новый VPS;
- переустановка ОС;
- слетели nftables, NAT, `ip_forward`, MSS clamping;
- поменялся public interface или порты;
- бинарник уже задеплоен, но трафик не идет и проблема похожа именно на firewall/NAT.

Если менялся только Rust-код, обычно достаточно обычного push и `deploy-server.yml`.

### Alert rules

`deploy/omega-alerts.yml` теперь входит в auto-deploy bundle.

Поведение такое:

- rules-файл копируется на сервер автоматически;
- по умолчанию кладется в `/opt/omega/omega-alerts.yml`;
- если задан `DEPLOY_PROMETHEUS_SERVICE_NAME`, deploy также попробует сделать `systemctl reload`, а при необходимости `restart` Prometheus;
- если этот secret не задан, файл все равно уедет на сервер, но Prometheus нужно будет перечитать отдельно.

## GitHub Actions secrets

### Минимально достаточный набор

Для базового server auto-deploy обычно достаточно:

- `DEPLOY_HOST`
- `DEPLOY_USER`
- `DEPLOY_SSH_KEY`

У тебя уже есть еще и `DEPLOY_PATH`, это нормально и полезно: workflow будет складывать release bundle в указанную временную папку на сервере.

### Что очень желательно добавить

- `DEPLOY_KNOWN_HOSTS`

Workflow умеет fallback на `ssh-keyscan`, если secret пустой, так что без него deploy тоже может сработать. Но pinned host key в secrets делает deploy заметно надежнее и предсказуемее.

### Часто используемые optional secrets

- `DEPLOY_PORT`
- `DEPLOY_PATH`
- `DEPLOY_SERVICE_NAME`
- `DEPLOY_INSTALL_DIR`
- `DEPLOY_KEEP_RELEASES`

### Optional secrets для alert rules

- `DEPLOY_ALERTS_DEST`
- `DEPLOY_PROMETHEUS_SERVICE_NAME`

### Optional secrets для сетевого контура

- `DEPLOY_CLIENT_CIDR`
- `DEPLOY_VPN_PORT`
- `DEPLOY_VPN_PROTOCOL`
- `DEPLOY_METRICS_PORT`

## Диагностика и triage

### Самые полезные команды

```bash
cargo run -p omega-server -- admin show_rollout_guard
cargo run -p omega-server -- admin show_observability
cargo run -p omega-server -- admin show_runtime
cargo run -p omega-server -- admin list_active_sessions
cargo run -p omega-server -- admin show_audit --limit 200
```

### Скрипты сервера

```bash
sudo bash deploy/setup_nat.sh
sudo bash deploy/diagnose_server.sh
```

`setup_nat.sh` отвечает за `ip_forward`, nftables/NAT, MSS clamping и сетевые sysctl.

`diagnose_server.sh` проверяет:

- sysctl tuning;
- nftables rules;
- systemd service status;
- UDP listener;
- runtime snapshot;
- observability snapshot;
- rollout guard и базовые policy/profile ожидания.

### Рекомендуемый triage order

1. `show_rollout_guard`
2. `show_observability`
3. `show_runtime`
4. `state/trace.ndjson`
5. `show_audit --limit 200`
6. `deploy/diagnose_server.sh`

## Что важно помнить

- `start_client.bat` не сломан, но это legacy path. Основной UX сейчас в `omega-client-app`.
- `bootstrap-network.yml` не нужно запускать после каждого push.
- `omega-alerts.yml` теперь деплоится автоматически, но auto-reload Prometheus включается только при наличии соответствующего systemd unit в secrets.