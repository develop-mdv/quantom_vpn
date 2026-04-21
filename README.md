# Omega VPN

`Omega VPN` - Rust workspace с собственным UDP-туннелем, STUN/RTP cover traffic, post-quantum handshake, device-based auth и встроенными runtime/admin surface-ами.

## Что уже есть в проекте

- `omega-core`: wire protocol, crypto, anti-replay, ARQ, chaos-based packet morphing, FEC primitives.
- `omega-server`: UDP server runtime, TUN, identity store, session manager, web admin, metrics, snapshots.
- `omega-client`: client runtime, Windows routing/DNS/IPv6 guard, diagnostics.

## Важная честная оговорка по текущему состоянию

Сейчас проект нужно воспринимать так:

- это **не** WireGuard и не OpenVPN, а собственный `Omega` protocol;
- datapath сейчас **UDP-only**;
- tunnel family сейчас **IPv4-only**;
- рабочая надежность сегодня строится вокруг **ARQ/NACK + retransmit cache + adaptive redundancy**;
- в кодовой базе уже есть `RaptorQ/FEC` примитивы, но полноценный FEC packet path пока не доведен до живого runtime.

## Документация

Основная база знаний теперь лежит в `docs/`:

- `docs/README.md` - навигация по документации.
- `docs/PROJECT_CONTEXT.md` - короткий контекст проекта для быстрых обсуждений.
- `docs/ARCHITECTURE.md` - handshake, datapath, identity, sessions, observability.
- `docs/CONFIG_REFERENCE.md` - все важные `OMEGA_*` переменные и defaults.
- `docs/OPERATIONS.md` - запуск, администрирование, диагностика, deploy, GitHub Actions.
- `docs/REPO_MAP.md` - карта репозитория и где лежит какая логика.

Специализированные материалы:

- `docs/GAMING_NETWORKING.md`
- `DEPLOY.md`
- `resource_budget.md`

## Быстрый старт

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

### 3. Запустить сервер

```bash
cargo run -p omega-server
```

### 4. Запустить клиент

```bash
OMEGA_SERVER=<server_ip>:51820 \
OMEGA_DEVICE_ID=<device_uuid> \
OMEGA_DEVICE_TOKEN=<device_token_hex> \
OMEGA_DEVICE_NAME="laptop" \
cargo run -p omega-client
```

## Ключевые runtime-файлы

- `state/identity.json` - users/devices/audit
- `state/sessions.json` - активные сессии
- `state/runtime.json` - runtime snapshot сервера
- `state/admin_commands.ndjson` - очередь admin-команд
- `omega-client/state/diagnostics.json` - diagnostics snapshot клиента

## Для следующей работы по проекту

Если нужно быстро включиться в разработку или обсуждение, лучший маршрут такой:

1. `docs/PROJECT_CONTEXT.md`
2. `docs/ARCHITECTURE.md`
3. `docs/REPO_MAP.md`
4. `docs/CONFIG_REFERENCE.md` или `docs/OPERATIONS.md` по ситуации
