# Repo Map

Этот документ показывает репозиторий на уровне директорий и точек входа. Для подробной карты crates и dependency boundaries смотри `REPO_MAP_V2.md`.

## Корень репозитория

- `README.md` - главная входная точка в проект.
- `DEPLOY.md` - первичный Linux/VPS deploy playbook.
- `resource_budget.md` - ресурсные оценки и бюджеты.
- `.env.example` - пример legacy env-driven клиентского запуска.
- `start_client.bat` - Windows wrapper для legacy `omega-client` flow.
- `docs/` - актуальная база знаний по архитектуре, операциям, security и subsystem docs.
- `relese_plan/` - исторический план фаз и acceptance criteria.
- `deploy/` - scripts и unit files для production bootstrap/deploy.
- `.github/workflows/` - GitHub Actions для auto-deploy и network bootstrap.

## Основные crates

### Foundations

- `omega-core-wire/` - handshake и transport wire types.
- `omega-core-crypto/` - crypto primitives и key schedule.
- `omega-transport/` - transport v2, reliability, replay, FEC.
- `omega-stealth/` - personas и morphing policy.

### Control and fabric

- `omega-control/` - control plane, policy engine, identity/tickets/audit.
- `omega-relay/` - relay graph и route selection.
- `omega-exit/` - exit-role contracts.

### Runtime

- `omega-edge/` - server runtime.
- `omega-client-runtime/` - privileged client runtime.

### App and compatibility

- `omega-client-app/` - desktop launcher.
- `omega-server/` - server entrypoint и admin CLI.
- `omega-client/` - compatibility client entrypoint.
- `omega-core/` - compatibility facade.

## Операционный контур

### `deploy/`

- `setup_nat.sh` - nftables/NAT/sysctl bootstrap.
- `diagnose_server.sh` - server diagnostics и rollout checks.
- `update_server.sh` - staged deploy, restart, rollback, rollout guard.
- `omega-server.service` - example systemd unit.
- `omega-alerts.yml` - Prometheus alert rules, которые теперь входят в auto-deploy bundle.

### `.github/workflows/`

- `deploy-server.yml` - обычный server auto-deploy после push в `main`.
- `bootstrap-network.yml` - ручной network bootstrap/repair workflow.

## Где искать изменения по типу задачи

- Меняется handshake или packet layout -> `omega-core-wire/`, `omega-core-crypto/`, `docs/PROTOCOL_V2_FORMAL_SPEC.md`.
- Меняется transport/path/reliability -> `omega-transport/`, `omega-stealth/`, `docs/STOCHASTIC_TRANSPORT_V2.md`, `docs/BAYESIAN_PATH_MANAGER.md`.
- Меняется control plane/policy -> `omega-control/`, `docs/BFT_CONTROL_PLANE.md`, `docs/CONTROL_PLANE_STATE_MODEL.md`.
- Меняется server runtime -> `omega-edge/`, `omega-server/`, `docs/ARCHITECTURE.md`, `docs/OPERATIONS.md`.
- Меняется client UX/runtime -> `omega-client-app/`, `omega-client-runtime/`, `docs/CLIENT_UX_SPEC.md`.
- Меняется deploy/CI/CD -> `deploy/`, `.github/workflows/`, `DEPLOY.md`, `docs/OPERATIONS.md`.