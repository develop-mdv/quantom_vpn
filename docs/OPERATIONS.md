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

Для Windows GUI можно взять `connection_code` из вывода команды или позже
скопировать его из карточки устройства во встроенной web-админке. Там же
показывается `OMEGA_DEVICE_TOKEN` для ручной настройки.

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

## Windows GUI client

Для пользовательского запуска на Windows есть отдельная WPF-оболочка
`omega-client-app`. Она не заменяет VPN runtime, а запускает существующий
`omega-client.exe`, сама формирует env-настройки, читает diagnostics и просит
runtime остановиться через `OMEGA_CONTROL_PATH`.

Сборка portable и installer package:

```powershell
powershell -ExecutionPolicy Bypass -File omega-client-app/package-windows-client.ps1
```

Результат:

- `omega-client-app/artifacts/windows-client/portable/OmegaVPN`
- `omega-client-app/artifacts/windows-client/installer`

Portable-папку удобно использовать для тестов: запустить `Omega.Client.App.exe`
от имени администратора, вставить код подключения и нажать `Подключить`.
Клиент принимает компактный `omega://connect/<base64url-json>` или вставленный
текст с `OMEGA_SERVER`, `OMEGA_DEVICE_ID`, `OMEGA_DEVICE_TOKEN`. После первого
подключения профиль сохраняется, и дальше его можно выбрать из списка.

GUI-клиент по умолчанию запускает runtime с `OMEGA_IPV6_POLICY=tunnel`, поэтому
IPv6-трафик идет через туннель при серверном `OMEGA_IPV6_MODE=nat66`.

Installer package содержит `Omega.Client.Setup.exe` и `payload/`. Setup копирует
payload в `%ProgramFiles%\Omega VPN`, создает ярлыки и scheduled task для
elevated autostart.

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

В production unit из `deploy/omega-server.service` built-in admin публикуется на:

```text
http://<SERVER_IP>:8081/
```

Через UI можно:

- создать пользователя;
- зарегистрировать устройство и получить код подключения;
- block/unblock/delete пользователя;
- revoke устройство;
- terminate активную сессию;
- скопировать `omega://connect/...` код для Windows-клиента и `OMEGA_DEVICE_TOKEN`
  из карточки устройства в любой момент. Для устройств, зарегистрированных до
  включения хранения токена, нужно перевыпустить устройство.

## Runtime-файлы и что в них смотреть

### Сервер

| Файл | Что хранит |
| --- | --- |
| `state/identity.json` | Пользователи, устройства, audit events, сохраненные `device_token` для админки. |
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
- `net.ipv6.conf.all.forwarding=1`, если `OMEGA_VPN_IPV6_MODE=nat66`
- loose `rp_filter`
- `nftables` rules
- `MASQUERADE` для клиентской подсети
- NAT66 для клиентского IPv6 prefix, если включен `nat66`
- MSS clamping
- увеличенные UDP conntrack timeouts
- input rule для framed TCP fallback, если `OMEGA_TCP_ENABLE=1`

`diagnose_server.sh` проверяет:

- sysctl tuning
- persisted nftables config через `nft -c -f`
- live nftables rules, включая NAT66 и TCP fallback input rule
- IPv6 route/egress сервера при `OMEGA_VPN_IPV6_MODE=nat66`
- systemd service status
- UDP listener
- TCP fallback listener, если `OMEGA_TCP_ENABLE=1`
- runtime snapshot
- профиль, IPv6 mode и morphing policy

## Client networking

Клиент теперь сам управляет full/split route lifecycle и tunnel DNS на поддерживаемых desktop-платформах:

- Windows
- Linux
- macOS

Для IPv6 full-tunnel клиенту нужен `OMEGA_IPV6_POLICY=tunnel`, а серверу `OMEGA_IPV6_MODE=nat66`.

Post-connect diagnostics теперь разделяют состояние туннеля на конкретные проверки:

- IPv4 egress через туннель
- IPv6 egress через туннель, если включен `OMEGA_IPV6_POLICY=tunnel`
- tunnel DNS
- DNS leak guard
- выбранный effective MTU после `OMEGA_MTU_POLICY=auto`

Клиент пишет `connected_healthy`, когда обязательные проверки прошли, и `connected_degraded`,
когда туннель поднят, но качество или leak-check требуют внимания.

### DNS leak guard и strict kill switch

`OMEGA_DNS_LEAK_GUARD=strict` теперь не просто смотрит на факт вызова команды настройки DNS: клиент читает DNS обратно с tunnel interface и падает, если ожидаемые DNS не закрепились. В `warn` режиме это остается warning + degraded diagnostics.

`OMEGA_KILL_SWITCH=strict` сейчас намеренно узкий и безопасный: поддержан только Windows full-tunnel. Он чистит старые Omega firewall rules, fail-fast'ит unsupported modes и ставит firewall block на DNS TCP/UDP 53 для физических адаптеров, чтобы DNS не ушел мимо tunnel DNS. Linux/macOS strict пока возвращает ошибку вместо иллюзии защиты.

### TCP fallback

UDP остается основным транспортом для gaming profile. Framed TCP fallback включается на сервере через `OMEGA_TCP_ENABLE=1` и `OMEGA_TCP_BIND`, открывается в `setup_nat.sh` через `OMEGA_TCP_PORT`, а на клиенте выбирается через:

```env
OMEGA_TRANSPORT=udp   # default, быстрый путь
OMEGA_TRANSPORT=tcp   # принудительно framed TCP
OMEGA_TRANSPORT=auto  # UDP handshake, затем TCP fallback
```

Это именно framed TCP fallback для случаев, где UDP заблокирован или нестабилен. HTTPS/TLS camouflage пока не реализован и должен добавляться отдельным слоем поверх этой базы.

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

`deploy/update_server.sh` после рестарта сервиса может запускать `diagnose_server.sh`.
Если diagnostics возвращает ошибку, deploy script откатывает symlink на предыдущий server binary.
Отключение gate для аварийных ручных операций: `OMEGA_DEPLOY_HEALTHCHECK=0`.

Он по умолчанию предполагает:

- бинарник в `/opt/omega/omega-server`
- profile `gaming`
- bind `[::]:443` для внешнего dual-stack UDP listener
- framed TCP fallback listener `[::]:443`
- `OMEGA_IPV6_MODE=nat66`
- built-in admin на публичном `:8081`
- metrics только на localhost
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
- `DEPLOY_CLIENT_CIDR_V6`
- `DEPLOY_VPN_PORT`
- `DEPLOY_VPN_PROTOCOL`
- `DEPLOY_VPN_IPV6_MODE`
- `DEPLOY_TCP_ENABLE`
- `DEPLOY_TCP_PORT`
- `DEPLOY_ADMIN_WEB_PUBLIC`
- `DEPLOY_ADMIN_WEB_PORT`
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
