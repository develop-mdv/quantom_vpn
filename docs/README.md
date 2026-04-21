# Omega VPN Docs

Этот каталог - единая база знаний по проекту. Он собран по текущему коду, а не по историческим обещаниям, поэтому отсюда лучше начинать любое знакомство с репозиторием.

## С чего читать

- `PROJECT_CONTEXT.md` - короткий контекст проекта для быстрых обсуждений и онбординга.
- `ARCHITECTURE.md` - как устроены handshake, datapath, identity, session management и observability.
- `CONFIG_REFERENCE.md` - справочник по `OMEGA_*` переменным и их дефолтам.
- `OPERATIONS.md` - запуск, администрирование, диагностика, деплой, GitHub Actions.
- `REPO_MAP.md` - навигация по папкам и ключевым файлам.

## Короткий маршрут по задачам

- Хочу понять, что реально уже реализовано: начни с `PROJECT_CONTEXT.md`.
- Хочу добавить фичу в протокол или datapath: открой `ARCHITECTURE.md` и `REPO_MAP.md`.
- Хочу настроить клиент или сервер: смотри `CONFIG_REFERENCE.md`.
- Хочу поднять сервер, зарегистрировать устройство или проверить прод: смотри `OPERATIONS.md`.
- Хочу понять, где в коде лежит нужная логика: смотри `REPO_MAP.md`.

## Источники истины

Документация привязана к конкретным участкам кода:

- Протокол и wire format: `omega-core/src/protocol.rs`
- Криптография и flow/session keys: `omega-core/src/crypto.rs`
- ARQ, replay protection, morphing primitives: `omega-core/src/arq.rs`, `omega-core/src/replay.rs`, `omega-core/src/chaos.rs`
- Серверный handshake и datapath: `omega-server/src/handshake.rs`, `omega-server/src/datapath.rs`
- Server runtime и snapshots: `omega-server/src/main.rs`, `omega-server/src/runtime.rs`, `omega-server/src/session.rs`
- Identity, audit и device auth: `omega-server/src/identity/*`
- Web admin: `omega-server/src/web_admin.rs`
- Клиентский runtime, Windows routing и diagnostics: `omega-client/src/main.rs`, `omega-client/src/config.rs`, `omega-client/src/diagnostics.rs`
- Деплой и сетевой bootstrap: `deploy/*`, `.github/workflows/*`

## Как поддерживать документацию актуальной

Если меняется код, нужно обновлять и соответствующий документ:

- Новый `OMEGA_*` env var или измененный default -> `CONFIG_REFERENCE.md`
- Изменение handshake, packet format, routing, session lifecycle -> `ARCHITECTURE.md`
- Новый operational runbook, workflow, systemd, deploy script -> `OPERATIONS.md`
- Перестройка папок или перенос ответственных модулей -> `REPO_MAP.md`
- Изменение фактического статуса проекта или ограничений -> `PROJECT_CONTEXT.md` и корневой `README.md`

## Специализированные материалы

Ниже остаются полезные узкие документы:

- `../DEPLOY.md` - детальный deploy playbook для Linux/VPS.
- `GAMING_NETWORKING.md` - заметки по gaming-профилю, MTU и UDP-first настройкам.
- `../resource_budget.md` - ресурсные оценки и производственные бюджеты.
