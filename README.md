# Omega VPN

`Omega VPN` - это Rust workspace с собственным `Omega v2` VPN-протоколом, hybrid post-quantum handshake, transport v2, typed control plane, relay fabric, desktop launcher/runtime split и встроенным observability/security контуром.

## Что проект из себя представляет сейчас

Проект уже не сводится к одному серверу и одному клиенту. Сейчас это набор связанных подсистем:

- `omega-core-wire` и `omega-core-crypto` - wire format и криптографический фундамент;
- `omega-transport` - transport v2, replay protection, reliability, FEC;
- `omega-stealth` - personas, anti-probing и morphing policy;
- `omega-control` - typed control plane, policy engine, tickets, audit chain;
- `omega-edge` - серверный edge runtime;
- `omega-relay` - relay fabric graph и failover model;
- `omega-client-runtime` - privileged клиентский runtime;
- `omega-client-app` - launcher UX, lifecycle, diagnostics и secure update path.

## Что уже реализовано

По итогам пройденных фаз в репозитории уже есть:

- formal protocol basis, threat model, product modes и KPI baseline;
- workspace refactor с чистыми crate boundaries;
- handshake v2 с `X25519 + ML-KEM-768`, retry/cookie, resumption и transcript binding;
- transport v2 с ACK ranges, pacing, congestion control и CID rotation;
- path intelligence, DPLPMTUD и blackhole recovery;
- adaptive reliability/FEC engine;
- stealth personas и anti-probing policy;
- relay fabric и route failover;
- typed control plane и deterministic policy engine;
- launcher/runtime split для desktop client;
- observability/SRE слой с rollout guard, alerts и trace journal;
- security beta package: proofs, audit package, beta checklist, updater hardening и handshake anti-abuse.

## Честные ограничения текущей версии

- datapath сейчас `UDP-only`;
- tunnel family сейчас `IPv4-only`;
- полноценного TCP fallback нет;
- updater пока без transparency log и без полного TUF timestamp/snapshot layer;
- local client secret storage пока не вынесен в OS-native keystore;
- formal models глубже всего покрывают handshake/security assumptions, а не весь runtime one-to-one.

## Где смотреть документацию

Главная навигация лежит в [docs/README.md](/D:/ProgHub/myboroda_vpn/docs/README.md).

Если нужен быстрый маршрут:

- [docs/PROJECT_CONTEXT.md](/D:/ProgHub/myboroda_vpn/docs/PROJECT_CONTEXT.md) - краткая актуальная картина проекта.
- [docs/ARCHITECTURE.md](/D:/ProgHub/myboroda_vpn/docs/ARCHITECTURE.md) - как собраны основные подсистемы.
- [docs/PROTOCOL_V2_FORMAL_SPEC.md](/D:/ProgHub/myboroda_vpn/docs/PROTOCOL_V2_FORMAL_SPEC.md) и [docs/DOLEV_YAO_THREAT_MODEL.md](/D:/ProgHub/myboroda_vpn/docs/DOLEV_YAO_THREAT_MODEL.md) - protocol/security basis.
- [docs/PROTOCOL_PROOFS.md](/D:/ProgHub/myboroda_vpn/docs/PROTOCOL_PROOFS.md), [docs/FORMAL_VERIFICATION_REPORT.md](/D:/ProgHub/myboroda_vpn/docs/FORMAL_VERIFICATION_REPORT.md), [docs/INDEPENDENT_AUDIT_PACKAGE.md](/D:/ProgHub/myboroda_vpn/docs/INDEPENDENT_AUDIT_PACKAGE.md), [docs/BETA_READINESS_CHECKLIST.md](/D:/ProgHub/myboroda_vpn/docs/BETA_READINESS_CHECKLIST.md) - текущий security/beta слой.
- [docs/OPERATIONS.md](/D:/ProgHub/myboroda_vpn/docs/OPERATIONS.md) и [docs/CONFIG_REFERENCE.md](/D:/ProgHub/myboroda_vpn/docs/CONFIG_REFERENCE.md) - запуск, диагностика, rollout и env vars.

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

Legacy compatibility path по-прежнему доступен:

```bash
OMEGA_SERVER=<server_ip>:51820 \
OMEGA_DEVICE_ID=<device_uuid> \
OMEGA_DEVICE_TOKEN=<device_token_hex> \
OMEGA_DEVICE_NAME=laptop \
cargo run -p omega-client
```

## Ключевые runtime-файлы

- `state/control_plane.json` - typed source of truth для users/devices/sessions/tickets/policies/fabric nodes и audit.
- `state/sessions.json` - активные сессии.
- `state/runtime.json` - runtime snapshot сервера.
- `state/observability.json` - rollout guard, alerts, metric deltas, SRE snapshot.
- `state/trace.ndjson` - correlation-aware trace journal.
- `omega-client/state/app-config.json` - launcher config.
- `omega-client/state/lifecycle.json` - lifecycle snapshot клиентского runtime.
- `omega-client/state/diagnostics.json` - diagnostics snapshot клиента.
- `omega-client/state/runtime-control.json` - launcher -> runtime control command.

## Текущий результат проекта

По состоянию репозитория у нас уже есть крепкий pre-beta фундамент: protocol, transport, control plane, client UX, observability и security package собраны в одну систему, а workspace проходит `cargo fmt --all`, `cargo check --workspace` и `cargo test --workspace`.

Следующая работа уже не про "собрать каркас с нуля", а про расширение beta, эксплуатационные проверки на живом трафике и дальнейшее снятие оставшихся ограничений.
