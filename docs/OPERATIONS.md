# Operations

## Что нужно для запуска

### Сервер

- Linux с поддержкой TUN.
- Права, позволяющие создать TUN и bind-иться на нужный UDP port.
- Для production по умолчанию предполагается systemd + root/capabilities.

### Клиент

- Rust toolchain, если запуск идет из исходников.
- На Windows нужен `wintun.dll`.
- В репозитории есть `start_client.bat`, который умеет:
  - подняться с правами администратора;
  - прочитать `.env`;
  - при необходимости скачать `wintun.dll`;
  - запустить `omega-client`.

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

Нужно сохранить:

- `device_id`
- `token`

### 3. Запустить сервер

```bash
cargo run -p omega-server
```

Сервер по умолчанию:

- слушает `0.0.0.0:51820`
- поднимает TUN `10.7.0.1/16`
- пишет snapshots в `state/`
- поднимает metrics на `127.0.0.1:9090`
- поднимает built-in web admin на `127.0.0.1:8081`

### 4. Запустить клиент

```bash
OMEGA_SERVER=203.0.113.1:51820 \
OMEGA_DEVICE_ID=<device_uuid> \
OMEGA_DEVICE_TOKEN=<device_token_hex> \
OMEGA_DEVICE_NAME="laptop" \
cargo run -p omega-client
```

## Windows-клиент через `.env`

Рекомендуемый путь:

1. Скопировать `.env.example` в `.env`.
2. Заполнить `OMEGA_SERVER`, `OMEGA_DEVICE_ID`, `OMEGA_DEVICE_TOKEN`.
3. При необходимости скорректировать профиль, MTU, DNS и diagnostics path.
4. Запустить `start_client.bat` от имени администратора.

`start_client.bat` дополнительно удобен тем, что при отсутствии `wintun.dll` сам подтянет сборку Wintun.

## Администрирование

### CLI-команды

```bash
cargo run -p omega-server -- admin list_users
cargo run -p omega-server -- admin block_user --user-id <user_uuid>
cargo run -p omega-server -- admin unblock_user --user-id <user_uuid>
cargo run -p omega-server -- admin delete_user --user-id <user_uuid>
cargo run -p omega-server -- admin register_device --user-id <user_uuid> --device-name "laptop" --platform windows
cargo run -p omega-server -- admin revoke_device --device-id <device_uuid>
cargo run -p omega-server -- admin list_user_devices --user-id <user_uuid>
cargo run -p omega-server -- admin list_active_sessions
cargo run -p omega-server -- admin show_runtime
cargo run -p omega-server -- admin terminate_session --flow-id <32_hex_flow_id>
cargo run -p omega-server -- admin show_audit --limit 50
```

### Built-in web admin

Если `OMEGA_ADMIN_WEB_DISABLE` не задан, сервер поднимает web admin.

По умолчанию:

```text
http://127.0.0.1:8081/
```

Через UI можно:

- создать пользователя;
- зарегистрировать устройство и сразу получить одноразовый token;
- block/unblock/delete пользователя;
- revoke устройство;
- terminate активную сессию;
- скопировать шаблон `.env` для клиента.

## Runtime-файлы и что в них смотреть

### Сервер

| Файл | Что хранит |
| --- | --- |
| `state/identity.json` | Пользователи, устройства, audit events. |
| `state/sessions.json` | Активные сессии в виде `ActiveSessionView`. |
| `state/runtime.json` | Runtime config + summary + sessions. |
| `state/admin_commands.ndjson` | Очередь команд для terminate session. |

### Клиент

| Файл | Что хранит |
| --- | --- |
| `omega-client/state/diagnostics.json` | Текущее состояние клиента, negotiated MTU, handshake RTT, DNS check, counters и path quality. |

## Диагностика

### Самые полезные точки проверки

- `cargo run -p omega-server -- admin show_runtime`
- `cargo run -p omega-server -- admin list_active_sessions`
- `cargo run -p omega-server -- admin show_audit`
- `omega-client/state/diagnostics.json`
- Prometheus endpoint на `OMEGA_METRICS_BIND`

### Linux server bootstrap/health

```bash
sudo OMEGA_VPN_PORT=443 bash deploy/setup_nat.sh
sudo bash deploy/diagnose_server.sh
```

`setup_nat.sh` делает:

- `ip_forward=1`
- loose `rp_filter`
- `nftables` rules
- `MASQUERADE` для клиентской подсети
- MSS clamping
- увеличенные UDP conntrack timeouts

`diagnose_server.sh` проверяет:

- sysctl tuning
- nftables rules
- systemd service status
- UDP listener
- runtime snapshot
- профиль, IPv6 mode и morphing policy

## Метрики

Сервер публикует Prometheus exporter через `metrics-exporter-prometheus`.

Типовые метрики:

- `omega_active_sessions`
- `omega_packets_in_total`
- `omega_packets_out_total`
- `omega_bytes_in_total`
- `omega_bytes_out_total`
- `omega_handshake_success_total`
- `omega_handshake_failures_total`
- `omega_nack_sent_total`
- `omega_nack_received_total`
- `omega_retransmit_sent_total`

## Production deployment

### Systemd

В репозитории есть пример unit-файла `deploy/omega-server.service`.

Он по умолчанию предполагает:

- бинарник в `/opt/omega/omega-server`
- profile `gaming`
- bind `0.0.0.0:443`
- admin web и metrics только на localhost
- state-файлы в `/opt/omega/state/*`

### Rolling update script

`deploy/update_server.sh`:

- складывает новый бинарник в `/opt/omega/releases/`
- переключает symlink `/opt/omega/omega-server`
- обновляет systemd unit при необходимости
- рестартует сервис
- при неуспехе откатывается на прошлый бинарник
- чистит старые релизы

### GitHub Actions

#### `deploy-server.yml`

Срабатывает при push в `main`, если затронуты:

- `omega-server/**`
- `omega-core/**`
- `Cargo.toml`
- `Cargo.lock`
- deploy scripts / workflow

Workflow:

1. собирает `omega-server --release`
2. подготавливает bundle
3. закачивает его на VPS по SSH
4. вызывает `deploy/update_server.sh`
5. повторно применяет `setup_nat.sh`
6. запускает `diagnose_server.sh`

Основные secrets:

- `DEPLOY_HOST`
- `DEPLOY_USER`
- `DEPLOY_SSH_KEY`
- `DEPLOY_KNOWN_HOSTS`

Опциональные secrets:

- `DEPLOY_PORT`
- `DEPLOY_PATH`
- `DEPLOY_SERVICE_NAME`
- `DEPLOY_INSTALL_DIR`
- `DEPLOY_KEEP_RELEASES`
- `DEPLOY_CLIENT_CIDR`
- `DEPLOY_VPN_PORT`
- `DEPLOY_VPN_PROTOCOL`
- `DEPLOY_METRICS_PORT`

#### `bootstrap-network.yml`

Ручной workflow для случаев, когда нужно отдельно накатить или перепроверить сетевой bootstrap на сервере:

- загружает `setup_nat.sh` и `diagnose_server.sh`
- применяет сетевые правила
- прогоняет пост-bootstrap диагностику

## Docker/dev container

В проекте есть:

- `Dockerfile.dev`
- `docker-compose.yml`

Они нужны для Linux-oriented development environment с `NET_ADMIN`, `/dev/net/tun`, сетевыми утилитами и Rust toolchain.

Это удобный путь для локальных экспериментов с TUN/UDP, но не обязательный слой для обычной разработки.
