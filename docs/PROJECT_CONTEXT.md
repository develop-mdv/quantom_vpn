# Project Context

## Что это за проект

`Omega VPN` - Rust workspace из трех крейтов:

- `omega-core` - протокол, криптография, anti-replay, ARQ, chaos-based traffic morphing, FEC primitives.
- `omega-server` - серверный runtime: UDP listener, TUN, identity store, session manager, web admin, metrics и snapshots.
- `omega-client` - клиентский runtime: handshake, TUN, dual-stack route/DNS orchestration на Windows/Linux/macOS, diagnostics.

Проект ориентирован на собственный UDP-туннель с маскировкой под STUN/RTP и управлением устройствами на сервере.

## Текущая правда по реализации

- Это не WireGuard и не OpenVPN. В проекте используется собственный `Omega` wire protocol поверх UDP.
- Handshake заворачивается в `STUN Binding Request/Response`.
- Handshake v2 использует `ML-KEM-768` и device auth (`device_id` + `device_token`).
- Data plane использует `RTP header + Omega header + ChaCha20-Poly1305`.
- Реально работающая надежность в текущем datapath - это `ARQ/NACK`, retransmit cache и adaptive extra redundancy.
- Транспорт по умолчанию остается UDP, но есть framed TCP fallback: сервер может слушать TCP рядом с UDP, клиент умеет `OMEGA_TRANSPORT=tcp|auto`.
- `ChaosPrng` используется для выбора целевых размеров пакетов и управления padding budget.
- Сервер ведет multi-user / multi-device identity store с audit trail.
- Клиент пишет runtime diagnostics в JSON, сервер пишет session/runtime snapshots и Prometheus metrics.

## Что важно не перепутать

- Сервер умеет dual-stack TUN: `10.7.0.1/16` и при `OMEGA_IPV6_MODE=nat66` еще `fd70:7::1/64`.
- Лизы для клиентов выдаются из диапазонов `10.7.0.2 - 10.7.255.254` и, если IPv6 включен, `fd70:7::2 - fd70:7::fffe`.
- Plain device token показывается только в момент `register_device`; в identity store хранится только hash.
- `OMEGA_ALLOW_LEGACY_V1` сейчас только ослабляет проверку версии handshake. Полноценный "старый режим без auth" он не включает.

## Важные ограничения текущей версии

- Проект в alpha-stage и не скрывает этого.
- TCP fallback уже есть как framed Omega packets over TCP. HTTPS/TLS camouflage поверх него пока не реализован.
- Inner IPv6 теперь есть в handshake/session/datapath/TUN bootstrap, но deploy-модель пока только `nat66`, без routed-prefix orchestration.
- Strict kill switch пока не является полноценной WFP/global outbound политикой: production-safe first pass поддержан на Windows full-tunnel и закрывает DNS leakage на физических адаптерах; Linux/macOS strict fail-fast.
- В `omega-core` есть `RaptorQ/FEC` примитивы и флаги handshake, но живой datapath их пока не использует как полноценный FEC packet path.
- Split tunnel теперь умеет IPv4 и IPv6 route selection, но полноценного split-DNS orchestration все еще нет.

## Основные сущности

- `UserRecord` - пользователь с лимитами `max_devices` и `max_concurrent_sessions`.
- `DeviceRecord` - зарегистрированное устройство пользователя.
- `SessionState` - активная tunnel session c `flow_id`, `client_addr`, `tunnel_ip`, `tunnel_ipv6`, ARQ state и morphing state.
- `AuditEvent` - журнал административных и auth-событий.

## Куда смотреть в коде

- Server entrypoint: `omega-server/src/main.rs`
- Client entrypoint: `omega-client/src/main.rs`
- Wire format: `omega-core/src/protocol.rs`
- Handshake: `omega-server/src/handshake.rs`
- Server datapath: `omega-server/src/datapath.rs`
- Client config: `omega-client/src/config.rs`
- Identity model: `omega-server/src/identity/mod.rs`
- Session lifecycle: `omega-server/src/session.rs`

## Runtime-файлы, которые часто нужны в разговоре

- `state/identity.json` или путь из `OMEGA_IDENTITY_DB`
- `state/sessions.json` или путь из `OMEGA_SESSION_SNAPSHOT`
- `state/runtime.json` или путь из `OMEGA_RUNTIME_SNAPSHOT`
- `state/admin_commands.ndjson` или путь из `OMEGA_ADMIN_COMMANDS`
- `omega-client/state/diagnostics.json` или путь из `OMEGA_DIAGNOSTICS_PATH`

## Для быстрых обсуждений

Если нужен максимально короткий summary проекта, держи в голове такую формулу:

`Omega VPN = custom UDP tunnel + STUN/RTP cover + PQ handshake + device-based auth + ARQ-based reliability + JSON snapshots + built-in admin surfaces`
