# Config Reference

Ниже перечислены основные переменные и конфигурационные поля, которые реально используются текущим кодом и deploy-скриптами. Это curated reference: только то, что нужно для запуска, отладки и деплоя.

## Общие переменные

| Переменная | Default | Значение |
| --- | --- | --- |
| `RUST_LOG` | `info` через fallback | Уровень логирования `tracing`. |

## Client runtime

### Обязательные на практике

| Переменная | Default | Значение |
| --- | --- | --- |
| `OMEGA_SERVER` | `127.0.0.1:51820` | Адрес сервера. Для реального подключения почти всегда задается явно. |
| `OMEGA_DEVICE_ID` | нет | UUID устройства из `register_device`. |
| `OMEGA_DEVICE_TOKEN` | нет | Hex token устройства из `register_device`. |

### Идентификация и profile selection

| Переменная | Default | Значение |
| --- | --- | --- |
| `OMEGA_DEVICE_NAME` | `omega-client` | Имя устройства, попадает в handshake и diagnostics. |
| `OMEGA_PLATFORM` | auto-detect | `windows`, `linux`, `macos`, `android`, `ios`, `other`. |
| `OMEGA_PROFILE` | `gaming` | Профиль соединения: `gaming`, `general`, `restricted`. |
| `OMEGA_MORPHING` | profile-based | `full`, `balanced`, `off`. |
| `OMEGA_PERSONA` | profile-based | `randomized`, `quic_like`, `hostile_network`, `off`. |
| `OMEGA_BACKGROUND_MODE` | `false` | Помечает runtime как запущенный из desktop launcher/background UX. |

### Tunnel and network behavior

| Переменная | Default | Значение |
| --- | --- | --- |
| `OMEGA_TUNNEL_MODE` | `full` | `full` или `split`. |
| `OMEGA_SPLIT_ROUTES` | пусто | Список CIDR через запятую для split tunnel. |
| `OMEGA_TUN_MTU` | по профилю | MTU туннеля с clamp в безопасный диапазон. |
| `OMEGA_KEEPALIVE_SECS` | по профилю | Интервал keepalive. |
| `OMEGA_DNS_POLICY` | зависит от tunnel mode | `tunnel` или `system`. |
| `OMEGA_DNS_SERVERS` | `1.1.1.1,8.8.8.8` | IPv4 DNS servers для tunnel DNS policy. |
| `OMEGA_IPV6_POLICY` | зависит от tunnel mode | `disabled` или `passthrough`. |
| `OMEGA_NETWORK_DIAG` | `true` | Включает post-connect UDP DNS diagnostic. |

### Client state paths

| Переменная | Default | Значение |
| --- | --- | --- |
| `OMEGA_DIAGNOSTICS_PATH` | `omega-client/state/diagnostics.json` | JSON diagnostics snapshot. |
| `OMEGA_LIFECYCLE_PATH` | `omega-client/state/lifecycle.json` | Lifecycle snapshot клиента. |
| `OMEGA_CONTROL_PATH` | `omega-client/state/runtime-control.json` | Launcher -> runtime control file. |
| `OMEGA_RESUME_TICKET_PATH` | `omega-client/state/resumption_ticket.hex` | Локально сохраненный opaque resumption ticket и `resumption_secret`. |

### Handshake retry policy

| Переменная | Default | Значение |
| --- | --- | --- |
| `OMEGA_HANDSHAKE_ATTEMPTS` | `5` | Количество попыток handshake. |
| `OMEGA_HANDSHAKE_TIMEOUT_MS` | `1500` | Timeout одной попытки. |
| `OMEGA_HANDSHAKE_BACKOFF_MS` | `500` | Пауза между попытками. |

## Desktop launcher config

Эти настройки хранятся в `omega-client/state/app-config.json`, а не в env vars runtime.

| Поле | Default | Значение |
| --- | --- | --- |
| `server_endpoint` | `127.0.0.1:51820` | Что launcher передаст в `OMEGA_SERVER`. |
| `device_id` | пусто | Сохраненный device id. |
| `device_token` | пусто | Сохраненный device token. |
| `device_name` | hostname fallback | Имя устройства для launcher/runtime. |
| `profile` | `general_internet` | User-facing профиль по умолчанию. |
| `background_mode` | `true` | Запускать runtime как background process. |
| `install_target_path` | `null` | Куда `update apply` пишет verified bundle. |
| `release_channel` | `stable` | Канал, который launcher требует от signed release manifest. |

## Server runtime

### Core runtime

| Переменная | Default | Значение |
| --- | --- | --- |
| `OMEGA_BIND` | `0.0.0.0:51820` | UDP bind address сервера. |
| `OMEGA_PROFILE` | `gaming` | Профиль сервера: `gaming`, `general`, `restricted`. |
| `OMEGA_MORPHING` | profile-based | `full`, `balanced`, `off`. |
| `OMEGA_PERSONA` | profile-based | Persona override: `randomized`, `quic_like`, `hostile_network`, `off`. |
| `OMEGA_NODE_ROLE` | `edge` | Роль fabric node: `edge`, `relay`, `exit`. |
| `OMEGA_FABRIC_NODE_ID` | role-based | Идентификатор локального fabric node. |
| `OMEGA_FABRIC_REGION` | `primary` | Region label для fabric graph. |
| `OMEGA_FABRIC_OPERATOR` | `omega-core` | Operator label для trust separation. |
| `OMEGA_TUN_MTU` | по профилю | MTU серверного TUN. |
| `OMEGA_UDP_RCVBUF` | `8388608` | Размер UDP receive buffer. |
| `OMEGA_UDP_SNDBUF` | `8388608` | Размер UDP send buffer. |
| `OMEGA_ALLOW_LEGACY_V1` | `false` | Разрешает version 1 пройти version-check, но не возвращает старый auth model. |

### Admin, snapshots и control plane

| Переменная | Default | Значение |
| --- | --- | --- |
| `OMEGA_METRICS_BIND` | `127.0.0.1:9090` | HTTP listener Prometheus exporter. |
| `OMEGA_ADMIN_WEB_BIND` | `127.0.0.1:8081` | Built-in web admin bind address. |
| `OMEGA_ADMIN_WEB_DISABLE` | `false` | Полностью отключает web admin. |
| `OMEGA_CLIENT_SERVER` | не задан | Только UI hint: какой `OMEGA_SERVER` показывать в web admin. |
| `OMEGA_IDENTITY_DB` | `state/identity.json` | Legacy identity snapshot для migration/import path. |
| `OMEGA_CONTROL_PLANE_DB` | `state/control_plane.json` | Typed source of truth control plane. |
| `OMEGA_TOKEN_PEPPER` | пусто | Pepper для SHA-256 hash device token. |
| `OMEGA_RUNTIME_SNAPSHOT` | `state/runtime.json` | Runtime snapshot сервера. |
| `OMEGA_SESSION_SNAPSHOT` | `state/sessions.json` | Session snapshot сервера. |
| `OMEGA_OBSERVABILITY_SNAPSHOT` | `state/observability.json` | SRE snapshot с alerts и rollout guard. |
| `OMEGA_TRACE_JOURNAL` | `state/trace.ndjson` | Correlation-aware trace journal. |

### Rollout guard и SRE

| Переменная | Default | Значение |
| --- | --- | --- |
| `OMEGA_DP_EPSILON` | `0.75` | Privacy budget для noisy aggregate counts. |
| `OMEGA_CANARY_MIN_PATH_QUALITY_SCORE` | `45` | Минимальный допустимый `avg_path_quality_score`. |
| `OMEGA_CANARY_MAX_LOSS_RATIO` | `0.08` | Максимальный допустимый `avg_loss_ratio`. |
| `OMEGA_CANARY_MAX_BLACKHOLE_SESSIONS` | `0` | Допустимое число blackhole-suspected sessions. |
| `OMEGA_CANARY_MAX_POLICY_CONFLICTS` | `0` | Максимальное число policy conflicts перед rollback. |
| `OMEGA_CANARY_MIN_HEALTHY_FABRIC_NODES` | `1` | Минимум healthy fabric nodes для canary. |
| `OMEGA_SPC_WINDOW` | `24` | Размер rolling window для SPC baseline. |

### Handshake anti-abuse

| Переменная | Default | Значение |
| --- | --- | --- |
| `OMEGA_HANDSHAKE_MAX_ATTEMPTS_PER_WINDOW` | `48` | Per-IP handshake attempts в одном window. |
| `OMEGA_HANDSHAKE_RATE_WINDOW_SECS` | `10` | Длина rate window в секундах. |
| `OMEGA_HANDSHAKE_BLOCK_SECS` | `30` | Сколько заблокированный IP остается в throttle state. |

## Deploy and update script

Эти переменные читает `deploy/update_server.sh`.

| Переменная | Default | Значение |
| --- | --- | --- |
| `OMEGA_SERVICE_NAME` | `omega-server` | Какой systemd unit рестартовать. |
| `OMEGA_INSTALL_DIR` | `/opt/omega` | Базовая папка установки. |
| `OMEGA_KEEP_RELEASES` | `5` | Сколько прошлых релизов хранить. |
| `OMEGA_RELEASE_ID` | timestamp | Явный идентификатор staged release. |
| `OMEGA_ALERTS_DEST` | `/opt/omega/omega-alerts.yml` | Куда установить `deploy/omega-alerts.yml`. |
| `OMEGA_PROMETHEUS_SERVICE_NAME` | empty | Имя Prometheus systemd unit для reload/restart после обновления alert rules. |
| `OMEGA_CANARY_ATTEMPTS` | `12` | Сколько раз ждать healthy `assert_rollout_guard`. |
| `OMEGA_CANARY_DELAY_SECS` | `5` | Пауза между rollout guard checks. |

## Network bootstrap and diagnostics scripts

Эти переменные используются `deploy/setup_nat.sh`, `deploy/diagnose_server.sh` и связанными workflow.

| Переменная | Default | Значение |
| --- | --- | --- |
| `OMEGA_PUBLIC_IFACE` | auto-detect | Публичный сетевой интерфейс. |
| `OMEGA_TUN_IFACE_PATTERN` | `tun*` | Шаблон tunnel interface для nftables checks. |
| `OMEGA_CLIENT_CIDR` | `10.7.0.0/16` | Подсеть VPN-клиентов для NAT и forward rules. |
| `OMEGA_VPN_PORT` | `443` | Публичный VPN port для firewall/bootstrap. |
| `OMEGA_VPN_PROTO` | `udp` | Ожидаемый transport протокол. |
| `OMEGA_VPN_IPV6_MODE` | `disabled` | Текущий datapath ожидает IPv4-only tunnel mode. |
| `OMEGA_SSH_PORT` | `22` | SSH port, который нельзя потерять при bootstrap. |
| `OMEGA_ADMIN_WEB_PUBLIC` | `0` | Публиковать ли built-in admin UI наружу. |
| `OMEGA_ADMIN_WEB_PORT` | `8081` | TCP port built-in admin UI. |
| `OMEGA_METRICS_PUBLIC` | `0` | Публиковать ли Prometheus metrics наружу. |
| `OMEGA_METRICS_PORT` | `9090` | TCP port Prometheus metrics. |
| `OMEGA_RMEM_MAX` | `8388608` | `net.core.rmem_max`. |
| `OMEGA_WMEM_MAX` | `8388608` | `net.core.wmem_max`. |
| `OMEGA_NETDEV_MAX_BACKLOG` | `4096` | `net.core.netdev_max_backlog`. |
| `OMEGA_UDP_RMEM_MIN` | `262144` | `net.ipv4.udp_rmem_min`. |
| `OMEGA_UDP_WMEM_MIN` | `262144` | `net.ipv4.udp_wmem_min`. |
| `OMEGA_CONNTRACK_UDP_TIMEOUT` | `120` | UDP conntrack timeout. |
| `OMEGA_CONNTRACK_UDP_STREAM` | `180` | UDP stream conntrack timeout. |
| `OMEGA_NFT_TRACE` | `0` | Включить `nftrace` для VPN forward path. |
| `OMEGA_RUNTIME_SNAPSHOT` | `/opt/omega/state/runtime.json` в diagnose script | Путь к runtime snapshot для server diagnostics. |
| `OMEGA_OBSERVABILITY_SNAPSHOT` | `/opt/omega/state/observability.json` в diagnose script | Путь к observability snapshot для diagnostics. |
| `OMEGA_SERVER_BIN` | `/opt/omega/omega-server` в diagnose script | Какой бинарник использовать для admin rollout checks. |

## Практические замечания

- Для desktop UX лучше использовать `omega-client-app`, а не голые env vars.
- `start_client.bat` полезен для legacy Windows flow, но не является главным путем запуска.
- `OMEGA_CONTROL_PLANE_DB` - фактический source of truth для control plane.
- `OMEGA_ALERTS_DEST` и `OMEGA_PROMETHEUS_SERVICE_NAME` нужны только для alert-rule deployment, а не для обычной работы VPN datapath.