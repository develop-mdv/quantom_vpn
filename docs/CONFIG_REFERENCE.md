# Config Reference

Ниже перечислены переменные, которые реально читаются текущим кодом и скриптами.

## Общие переменные

| Переменная | Default | Где используется | Значение |
| --- | --- | --- | --- |
| `RUST_LOG` | `info` через fallback | client/server/systemd | Уровень логирования `tracing`. |

## Client runtime

### Обязательные на практике

| Переменная | Default | Значение |
| --- | --- | --- |
| `OMEGA_SERVER` | `127.0.0.1:51820` | Адрес сервера. Для реального подключения почти всегда должен быть задан явно. |
| `OMEGA_DEVICE_ID` | нет | UUID устройства из `register_device`. |
| `OMEGA_DEVICE_TOKEN` | нет | Hex token устройства из `register_device`. |

### Идентификация и platform hints

| Переменная | Default | Значение |
| --- | --- | --- |
| `OMEGA_DEVICE_NAME` | `omega-client` | Имя устройства, попадает в handshake и diagnostics. |
| `OMEGA_PLATFORM` | auto-detect | Явный platform hint: `windows`, `linux`, `macos`, `android`, `ios`, `other`. |

### Профиль и routing

| Переменная | Default | Значение |
| --- | --- | --- |
| `OMEGA_PROFILE` | `gaming` | Профиль соединения: `gaming`, `general`, `restricted`. |
| `OMEGA_MORPHING` | profile-based | `full`, `balanced`, `off`. Для `restricted` default = `full`, для `general` = `balanced`, для `gaming` = `off`. |
| `OMEGA_TUNNEL_MODE` | `full` | `full` или `split`. |
| `OMEGA_SPLIT_ROUTES` | пусто | Список CIDR через запятую для split tunnel. Без него `split` откатится обратно в `full`. |
| `OMEGA_SPLIT_ROUTES_V6` | пусто | IPv6 CIDR через запятую для split tunnel. Можно использовать отдельно или вместе с `OMEGA_SPLIT_ROUTES`. |

### Сетевые параметры клиента

| Переменная | Default | Значение |
| --- | --- | --- |
| `OMEGA_TUN_MTU` | по профилю | MTU туннеля. `gaming=1380`, `general=1360`, `restricted=1280`, затем clamp `1200..1420`. |
| `OMEGA_TRANSPORT` | `udp` | `udp`, `tcp`, `auto`. `udp` остается основным быстрым режимом; `tcp` использует framed TCP fallback; `auto` сначала пробует UDP handshake, затем TCP. |
| `OMEGA_MTU_POLICY` | `auto` | `auto` включает encrypted PMTU probe после handshake и до создания TUN; `fixed` использует negotiated MTU без probe. |
| `OMEGA_MTU_PROBE_TIMEOUT_MS` | `450` | Timeout каждого PMTU probe-кандидата, clamp `150..2000`. |
| `OMEGA_KEEPALIVE_SECS` | по профилю | Интервал keepalive. `gaming=25`, `general=15`, `restricted=10`, минимум `5`. |
| `OMEGA_DNS_POLICY` | зависит от tunnel mode | `tunnel` для full-tunnel по умолчанию, `system` для split-tunnel. |
| `OMEGA_DNS_SERVERS` | `1.1.1.1,8.8.8.8` | DNS servers для tunnel DNS policy. Поддерживаются IPv4 и IPv6 адреса. |
| `OMEGA_IPV6_POLICY` | зависит от tunnel mode | `disabled` для full-tunnel, `passthrough` для split-tunnel. Можно явно включить `tunnel`, чтобы клиент поднимал dual-stack TUN, принимал IPv6 lease из handshake и ставил IPv6 routes на Windows/Linux/macOS. |
| `OMEGA_DNS_LEAK_GUARD` | `warn` | `off`, `warn`, `strict`. В `strict` клиент не продолжает работу, если tunnel DNS нельзя назначить или readback не подтверждает ожидаемые DNS. В `warn` пишет warning/diagnostics degraded и продолжает. |
| `OMEGA_KILL_SWITCH` | `soft` | `off`, `soft`, `strict`. `strict` сейчас поддержан только на Windows full-tunnel: клиент чистит stale routes/firewall rules, fail-fast'ит unsupported modes и блокирует DNS на физических адаптерах. Linux/macOS strict пока намеренно fail-fast. |
| `OMEGA_NETWORK_DIAG` | `true` | Включает post-connect UDP DNS diagnostic. |
| `OMEGA_DIAGNOSTICS_PATH` | `omega-client/state/diagnostics.json` | Путь к JSON diagnostics snapshot. |
| `OMEGA_CONTROL_PATH` | не задан | Optional JSON control file. Windows GUI пишет `{"command":"stop"}`, чтобы клиент вышел через штатный cleanup вместо принудительного kill. |

### Handshake retry policy

| Переменная | Default | Значение |
| --- | --- | --- |
| `OMEGA_HANDSHAKE_ATTEMPTS` | `5` | Количество попыток handshake, минимум `1`. |
| `OMEGA_HANDSHAKE_TIMEOUT_MS` | `1500` | Timeout одной попытки, минимум `250`. |
| `OMEGA_HANDSHAKE_BACKOFF_MS` | `500` | Пауза между попытками, минимум `100`. |

## Server runtime

### Core runtime

| Переменная | Default | Значение |
| --- | --- | --- |
| `OMEGA_BIND` | `0.0.0.0:51820` | UDP bind address сервера. |
| `OMEGA_TCP_ENABLE` | `false` в коде, `1` в production unit | Включает framed TCP fallback listener. UDP остается основным datapath. |
| `OMEGA_TCP_BIND` | значение `OMEGA_BIND` | Bind address framed TCP fallback listener, например `[::]:443`. |
| `OMEGA_PROFILE` | `gaming` | Профиль сервера: `gaming`, `general`, `restricted`. |
| `OMEGA_MORPHING` | profile-based | `full`, `balanced`, `off`. Default рассчитывается от профиля. |
| `OMEGA_TUN_MTU` | по профилю | MTU серверного TUN. |
| `OMEGA_UDP_RCVBUF` | `8388608` | Размер UDP receive buffer. |
| `OMEGA_UDP_SNDBUF` | `8388608` | Размер UDP send buffer. |
| `OMEGA_ALLOW_LEGACY_V1` | `false` | Разрешает version 1 пройти version-check. Но полноценный legacy режим это сейчас не дает: device auth все равно обязателен. |
| `OMEGA_IPV6_MODE` | `disabled` | `disabled` или `nat66`. В `nat66` сервер поднимает dual-stack TUN, выдает клиентам `fd70:7::/64` leases и пишет dual-stack runtime snapshot. |

### Admin и observability

| Переменная | Default | Значение |
| --- | --- | --- |
| `OMEGA_METRICS_BIND` | `127.0.0.1:9090` | HTTP listener Prometheus exporter. |
| `OMEGA_ADMIN_WEB_BIND` | `127.0.0.1:8081` | Built-in web admin bind address. |
| `OMEGA_METRICS_PUBLIC` | `false` | Если `OMEGA_METRICS_BIND` не задан явно, переводит metrics listener на публичный bind с портом из `OMEGA_METRICS_PORT` или default `9090`. |
| `OMEGA_METRICS_PORT` | `9090` | Порт для implicit public metrics bind. |
| `OMEGA_ADMIN_WEB_PUBLIC` | `false` | Если `OMEGA_ADMIN_WEB_BIND` не задан явно, переводит built-in admin на публичный bind с портом из `OMEGA_ADMIN_WEB_PORT` или default `8081`. |
| `OMEGA_ADMIN_WEB_PORT` | `8081` | Порт для implicit public admin bind. |
| `OMEGA_ADMIN_WEB_DISABLE` | `false` | Полностью отключает web admin. |
| `OMEGA_CLIENT_SERVER` | не задан | Только UI hint: какой `OMEGA_SERVER` показывать в web admin для клиента. |

### State и identity

| Переменная | Default | Значение |
| --- | --- | --- |
| `OMEGA_IDENTITY_DB` | `state/identity.json` | Identity store: users, devices, audit. |
| `OMEGA_TOKEN_PEPPER` | `omega-change-this-token-pepper` | Pepper для хеширования device token. В проде должен быть переопределен. |
| `OMEGA_SESSION_SNAPSHOT` | `state/sessions.json` | JSON snapshot активных сессий. |
| `OMEGA_RUNTIME_SNAPSHOT` | `state/runtime.json` | JSON runtime snapshot сервера. |
| `OMEGA_ADMIN_COMMANDS` | `state/admin_commands.ndjson` | Очередь админ-команд для terminate session. |

## Bootstrap и diagnostics scripts

Эти переменные используются `deploy/setup_nat.sh` и `deploy/diagnose_server.sh`.

| Переменная | Default | Значение |
| --- | --- | --- |
| `OMEGA_PUBLIC_IFACE` | auto-detect | Публичный сетевой интерфейс. |
| `OMEGA_TUN_IFACE_PATTERN` | `tun*` | Шаблон tunnel interface для nftables. |
| `OMEGA_CLIENT_CIDR` | `10.7.0.0/16` | Подсеть VPN-клиентов для NAT и forward rules. |
| `OMEGA_CLIENT_CIDR_V6` | `fd70:7::/64` | IPv6 prefix VPN-клиентов для NAT66 и forward rules. |
| `OMEGA_VPN_PORT` | `443` | Публичный VPN port для firewall/bootstrap. |
| `OMEGA_VPN_PROTO` | `udp` | Primary datapath должен оставаться `udp`; framed TCP fallback включается отдельными `OMEGA_TCP_*`. |
| `OMEGA_TCP_ENABLE` | `1` | Открывать и проверять framed TCP fallback port в nftables/diagnostics. |
| `OMEGA_TCP_PORT` | `OMEGA_VPN_PORT` | Публичный TCP fallback port для firewall/bootstrap. Должен совпадать с портом в `OMEGA_TCP_BIND`. |
| `OMEGA_VPN_IPV6_MODE` | `disabled` | `disabled` или `nat66` для deploy-скриптов. В `nat66` скрипты включают IPv6 forwarding, `ip6` forward rules и NAT66 для `OMEGA_CLIENT_CIDR_V6`. |
| `OMEGA_SSH_PORT` | `22` | SSH port, который нельзя потерять при bootstrap. |
| `OMEGA_ADMIN_WEB_PUBLIC` | `0` | Публиковать ли built-in admin web наружу. |
| `OMEGA_ADMIN_WEB_PORT` | `8081` | TCP port built-in admin web. |
| `OMEGA_METRICS_PUBLIC` | `0` | Публиковать ли Prometheus metrics наружу. |
| `OMEGA_METRICS_PORT` | `9090` | TCP port metrics. |
| `OMEGA_RMEM_MAX` | `8388608` | `net.core.rmem_max`. |
| `OMEGA_WMEM_MAX` | `8388608` | `net.core.wmem_max`. |
| `OMEGA_NETDEV_MAX_BACKLOG` | `4096` | `net.core.netdev_max_backlog`. |
| `OMEGA_UDP_RMEM_MIN` | `262144` | `net.ipv4.udp_rmem_min`. |
| `OMEGA_UDP_WMEM_MIN` | `262144` | `net.ipv4.udp_wmem_min`. |
| `OMEGA_CONNTRACK_UDP_TIMEOUT` | `120` | UDP conntrack timeout. |
| `OMEGA_CONNTRACK_UDP_STREAM` | `180` | UDP stream conntrack timeout. |
| `OMEGA_NFT_TRACE` | `0` | Включить `nftrace` для VPN forward path. |
| `OMEGA_SERVICE_NAME` | `omega-server` | Имя systemd unit для diagnostics/update scripts. |

## Deploy/update script

Эти переменные читает `deploy/update_server.sh`.

| Переменная | Default | Значение |
| --- | --- | --- |
| `OMEGA_SERVICE_NAME` | `omega-server` | Какой systemd unit рестартовать. |
| `OMEGA_INSTALL_DIR` | `/opt/omega` | Каталог установки бинарей и релизов. |
| `OMEGA_KEEP_RELEASES` | `5` | Сколько прошлых релизов хранить. |
| `OMEGA_RELEASE_ID` | timestamp | Идентификатор релиза для `releases/omega-server-*`. |

## Практические замечания

- Самый важный production override на сервере - это `OMEGA_TOKEN_PEPPER`.
- В production задавайте `OMEGA_CLIENT_SERVER=<SERVER_IP_OR_DOMAIN>:443`, иначе
  web admin может генерировать коды подключения с placeholder-адресом.
- Для split tunnel недостаточно только `OMEGA_TUNNEL_MODE=split`; нужны валидные `OMEGA_SPLIT_ROUTES`, `OMEGA_SPLIT_ROUTES_V6` или обе переменные сразу.
- Для полноценного inner IPv6 нужно согласованно включать `OMEGA_IPV6_MODE=nat66` на сервере и `OMEGA_IPV6_POLICY=tunnel` на клиенте. Перед этим проверьте, что VPS имеет IPv6 egress: `ip -6 route get 2606:4700:4700::1111`. Если маршрута нет, оставьте `OMEGA_IPV6_MODE=disabled`.
- Для TCP fallback нужно включить серверный listener (`OMEGA_TCP_ENABLE=1`, `OMEGA_TCP_BIND=[::]:443`), открыть порт через `setup_nat.sh`, а на клиенте выбрать `OMEGA_TRANSPORT=tcp` или `auto`. Если TCP `443` уже занят nginx/xray/другим сервисом, не включайте Omega TCP fallback на этом же endpoint.
- Built-in web admin сейчас plain HTTP. Для публичного варианта используйте `http://<SERVER_IP>:8081/`, не `https://`.
- `OMEGA_PROFILE=gaming` теперь по умолчанию выбирает `OMEGA_MORPHING=off`, чтобы не тратить throughput на padding и лишнюю избыточность.
- Если `OMEGA_MORPHING=off`, latency и throughput обычно становятся лучше, но traffic cover будет слабее.
- `OMEGA_ALLOW_LEGACY_V1` не стоит считать полноценной backward compatibility feature.
