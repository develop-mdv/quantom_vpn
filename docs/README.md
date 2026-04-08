# Omega VPN Docs

Эта папка содержит актуальную документацию по текущему состоянию проекта. Исторический план фаз лежит отдельно в `../relese_plan/` и не должен восприниматься как основная operational reference.

## С чего начать

1. `PROJECT_CONTEXT.md` - короткая и честная картина проекта на текущий момент.
2. `ARCHITECTURE.md` - как сейчас устроены client, server, control plane, fabric и observability.
3. `REPO_MAP.md` - верхнеуровневая карта репозитория.
4. `REPO_MAP_V2.md` - подробная карта workspace и crate boundaries.
5. `CONFIG_REFERENCE.md` - реальные `OMEGA_*` переменные и launcher config.
6. `OPERATIONS.md` - запуск, диагностика, CI/CD и day-2 operations.
7. `../DEPLOY.md` - отдельный Linux/VPS deploy playbook.

## Основные блоки документации

### Продукт и архитектура

- `PROJECT_CONTEXT.md` - high-level summary и текущие ограничения.
- `ARCHITECTURE.md` - актуальная архитектурная схема и runtime boundaries.
- `ARCHITECTURE_AXIOMS.md` - архитектурные правила и инварианты зависимостей.
- `DEPENDENCY_DAG.md` - dependency DAG по workspace.
- `REPO_MAP.md` - репозиторий на уровне директорий и точек входа.
- `REPO_MAP_V2.md` - детальная карта crates после refactor.

### Протокол и криптография

- `PROTOCOL_V2_FORMAL_SPEC.md` - формальная рамка `Omega v2`.
- `DOLEV_YAO_THREAT_MODEL.md` - threat model и классы противника.
- `HANDSHAKE_PQC_V2.md` - handshake v2 и hybrid KEX.
- `HANDSHAKE_PQC_COST_ESTIMATE.md` - handshake budget и cost estimate.
- `PROTOCOL_PROOFS.md` - proof obligations и code-level invariants.
- `FORMAL_VERIFICATION_REPORT.md` - покрытие formal work и его границы.
- `models/handshake_v2_proverif.pv` и `models/handshake_v2_tamarin.spthy` - formal skeleton models.

### Transport, path, stealth и reliability

- `STOCHASTIC_TRANSPORT_V2.md` - frame transport, ACK ranges, pacing и CC.
- `BAYESIAN_PATH_MANAGER.md` - path scoring, MTU adaptation, blackhole handling.
- `SHANNON_RELIABILITY_ENGINE.md` - retransmit/FEC/reliability budgets.
- `ADVERSARIAL_STEALTH_ENGINE.md` - personas, probing resistance и runtime coupling.
- `STEALTH_METRICS.md` - stealth KPI и detectability metrics.
- `STEALTH_PERSONA_DETECTABILITY_REPORT.md` - persona measurements и overhead.
- `WGAN_PERSONA_MODELS.md` - offline research workflow для stealth traces.

### Relay, control plane и клиенты

- `GRAPH_RELAY_FABRIC.md` - relay/edge/exit graph model и failover.
- `MIXNET_ANONYMITY.md` - допустимые anonymity идеи и их границы.
- `BFT_CONTROL_PLANE.md` - consistency model и audit chain.
- `CONTROL_PLANE_STATE_MODEL.md` - typed entities и lifecycle.
- `POLICY_TEST_MATRIX.md` - policy semantics и validation matrix.
- `CLIENT_UX_SPEC.md` - launcher UX и runtime boundary.
- `CLIENT_USABILITY_DIAGNOSTIC_REPORT.md` - usability и diagnostics findings.
- `TUF_UPDATE_SPEC.md` - signed update path и apply semantics.

### Operations, SRE и beta readiness

- `CONFIG_REFERENCE.md` - curated runtime/deploy variable reference.
- `OPERATIONS.md` - local run, production deploy, diagnostics и CI/CD.
- `OBSERVABILITY_DASHBOARDS.md` - dashboards и signals.
- `INCIDENT_RUNBOOKS.md` - incident response playbooks.
- `DIFFERENTIAL_PRIVACY_TELEMETRY.md` - privacy boundary telemetry.
- `ML_ANOMALY_SRE.md` - SPC/anomaly logic.
- `INDEPENDENT_AUDIT_PACKAGE.md` - единая точка входа для security review.
- `BETA_READINESS_CHECKLIST.md` - beta gate checklist.

## Практический маршрут по задачам

- Нужно быстро понять проект: `PROJECT_CONTEXT.md` -> `ARCHITECTURE.md` -> `REPO_MAP.md`.
- Нужно менять код: `REPO_MAP_V2.md` -> `ARCHITECTURE_AXIOMS.md` -> нужный subsystem document.
- Нужно запускать и деплоить: `OPERATIONS.md` -> `../DEPLOY.md` -> `CONFIG_REFERENCE.md`.
- Нужно разбираться с security/beta: `DOLEV_YAO_THREAT_MODEL.md` -> `PROTOCOL_PROOFS.md` -> `INDEPENDENT_AUDIT_PACKAGE.md`.

## Что считать историческими материалами

- `../relese_plan/` - план фаз и их acceptance criteria. Это важный инженерный архив, но не главный источник текущих runtime-правил.
- Отдельные research/report documents полезны как supporting evidence, но operational source of truth находятся в `ARCHITECTURE.md`, `CONFIG_REFERENCE.md`, `OPERATIONS.md` и `README.md` репозитория.