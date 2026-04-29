# Repo Map

## Корень репозитория

### Workspace и общие файлы

- `Cargo.toml` - Rust workspace (`omega-core`, `omega-server`, `omega-client`).
- `Cargo.lock` - lockfile workspace.
- `README.md` - главная входная точка в документацию.
- `DEPLOY.md` - подробный Linux/VPS deploy playbook.
- `resource_budget.md` - ресурсные оценки и пропускная способность.
- `.env.example` - пример env для клиента.
- `start_client.bat` - Windows entrypoint для клиента.
- `omega-client-app/` - WPF/.NET Windows GUI, setup app и package script для portable/installer артефактов.
- `docker-compose.yml` и `Dockerfile.dev` - dev container / local Linux sandbox.

## `omega-core/`

Библиотека общих сетевых и криптографических примитивов.

- `src/lib.rs` - экспорт модулей.
- `src/protocol.rs` - packet format, STUN wrapper, handshake payloads, reject reasons, NACK format.
- `src/crypto.rs` - `SessionKeys`, HKDF, AEAD, `FlowId`.
- `src/replay.rs` - anti-replay window.
- `src/arq.rs` - retransmit queue, gap detection, loss estimator.
- `src/chaos.rs` - packet size morphing PRNG.
- `src/raptorq_mgr.rs` - FEC primitives.
- `benches/*` - benchmark-и.

Когда идти сюда:

- меняется wire format;
- меняется cryptographic derivation;
- меняется ARQ/replay behavior;
- нужно понять, какие packet types и handshake payloads вообще существуют.

## `omega-server/`

Серверный runtime и административная логика.

- `src/main.rs` - server bootstrap, admin CLI, snapshot tasks, web admin startup.
- `src/handshake.rs` - handshake pipeline и валидация auth/device/session limit.
- `src/datapath.rs` - UDP <-> TUN loops, NACK handling, roaming, encryption/decryption.
- `src/session.rs` - `SessionState`, `SessionManager`, IP leases, cleanup, snapshots.
- `src/runtime.rs` - server profile, morphing policy, runtime snapshot schema.
- `src/metrics.rs` - Prometheus metrics wiring.
- `src/web_admin.rs` - built-in HTTP admin UI.

### `omega-server/src/identity/`

- `mod.rs` - `IdentityStore`, persistence, audit, register/revoke/auth.
- `users.rs` - `UserRecord`, `UserStatus`.
- `devices.rs` - `DeviceRecord`, platform enum.
- `auth.rs` - auth result/failure mapping.
- `limits.rs` - лимиты устройств и concurrent sessions.

Когда идти сюда:

- меняется handshake auth;
- меняется модель пользователей/устройств;
- меняется выдача tunnel IP;
- меняется web admin или admin CLI;
- нужно отладить, почему сессии не создаются или завершаются.

## `omega-client/`

Клиентский runtime и platform-specific routing.

- `src/main.rs` - client bootstrap, handshake, TUN, UDP loops, Windows routing/DNS/IPv6 logic.
- `src/config.rs` - весь env-driven runtime config клиента.
- `src/diagnostics.rs` - JSON snapshot клиента и path quality summary.
- `state/` - runtime output, не источник кода.

Когда идти сюда:

- меняется env-конфигурация клиента;
- нужно поменять split/full tunnel behavior;
- нужно править Windows routes/DNS/IPv6 guard;
- нужно расширить diagnostics.

## `omega-client-app/`

Windows GUI поверх существующего клиента.

- `src/Omega.Client.App.Core/` - настройки, validation, env generation, diagnostics mapping, lifecycle/control helpers.
- `src/Omega.Client.App/` - WPF окно, tray icon, connect/disconnect workflow.
- `src/Omega.Client.Setup/` - setup executable для копирования payload в `%ProgramFiles%\Omega VPN`, ярлыков и scheduled task.
- `tests/Omega.Client.App.Tests/` - offline console test harness без внешних NuGet test packages.
- `package-windows-client.ps1` - сборка portable и installer package.

Когда идти сюда:

- меняется Windows GUI;
- меняется упаковка portable/installer;
- нужно поменять UX connect/disconnect;
- нужно расширить отображение diagnostics без изменения VPN datapath.

## `deploy/`

Операционные скрипты и systemd units.

- `setup_nat.sh` - nftables/NAT/sysctl bootstrap.
- `diagnose_server.sh` - server path diagnostics.
- `update_server.sh` - release switch + restart + rollback.
- `omega-server.service` - production-like systemd unit для сервера.
- `omega-client.service` - пример systemd unit для клиента.

Когда идти сюда:

- меняется production bootstrap;
- меняется NAT/MSS/metrics exposure;
- меняется схема установки бинарника на VPS.

## `.github/workflows/`

- `deploy-server.yml` - автоматический deploy сервера после push в `main`.
- `bootstrap-network.yml` - ручной bootstrap и проверка сетевого контура.

Когда идти сюда:

- меняется CI/CD;
- меняется набор deploy secrets;
- нужно понять, что именно происходит на GitHub runner и на VPS.

## `docs/`

Актуальная база знаний проекта.

- `README.md` - индекс документации.
- `PROJECT_CONTEXT.md` - короткий контекст.
- `ARCHITECTURE.md` - архитектура.
- `CONFIG_REFERENCE.md` - env и defaults.
- `OPERATIONS.md` - запуск, диагностика, deploy.
- `REPO_MAP.md` - этот файл.
- `GAMING_NETWORKING.md` - узкая заметка по gaming-профилю.

## Карта типовых изменений

### Меняем handshake или packet format

Смотри:

- `omega-core/src/protocol.rs`
- `omega-core/src/crypto.rs`
- `omega-server/src/handshake.rs`
- `omega-client/src/main.rs`

### Меняем надежность канала

Смотри:

- `omega-core/src/arq.rs`
- `omega-core/src/chaos.rs`
- `omega-core/src/raptorq_mgr.rs`
- `omega-server/src/datapath.rs`
- `omega-client/src/main.rs`

### Меняем identity и device model

Смотри:

- `omega-server/src/identity/mod.rs`
- `omega-server/src/identity/users.rs`
- `omega-server/src/identity/devices.rs`
- `omega-server/src/web_admin.rs`
- `omega-server/src/main.rs`

### Меняем observability и runtime snapshots

Смотри:

- `omega-client/src/diagnostics.rs`
- `omega-server/src/runtime.rs`
- `omega-server/src/metrics.rs`
- `omega-server/src/main.rs`

### Меняем deploy/network bootstrap

Смотри:

- `deploy/setup_nat.sh`
- `deploy/diagnose_server.sh`
- `deploy/update_server.sh`
- `deploy/omega-server.service`
- `.github/workflows/deploy-server.yml`
- `.github/workflows/bootstrap-network.yml`
