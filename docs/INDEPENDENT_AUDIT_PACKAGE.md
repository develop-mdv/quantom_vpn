# Independent Audit Package

## Назначение

Этот документ собирает в одном месте материалы, которые нужны внешнему аудитору перед review `Omega` closed beta build.

## Что передавать аудитору

### Архитектура и trust boundaries

- `docs/ARCHITECTURE.md`
- `docs/REPO_MAP_V2.md`
- `docs/ARCHITECTURE_AXIOMS.md`

### Threat model и protocol basis

- `docs/DOLEV_YAO_THREAT_MODEL.md`
- `docs/PROTOCOL_V2_FORMAL_SPEC.md`
- `docs/HANDSHAKE_PQC_V2.md`
- `docs/STOCHASTIC_TRANSPORT_V2.md`
- `docs/PROTOCOL_PROOFS.md`
- `docs/FORMAL_VERIFICATION_REPORT.md`

### Update, control plane, observability

- `docs/TUF_UPDATE_SPEC.md`
- `docs/BFT_CONTROL_PLANE.md`
- `docs/CONTROL_PLANE_STATE_MODEL.md`
- `docs/OPERATIONS.md`
- `docs/INCIDENT_RUNBOOKS.md`
- `docs/OBSERVABILITY_DASHBOARDS.md`

### Code entrypoints for review

- `omega-edge/src/handshake.rs`
- `omega-edge/src/abuse.rs`
- `omega-core-crypto/src/handshake.rs`
- `omega-core-wire/src/handshake_v2.rs`
- `omega-client-app/src/update.rs`
- `omega-client-runtime/src/handshake.rs`
- `omega-control/src/control_plane.rs`
- `omega-control/src/policy.rs`

## Audit scope

### Priority 0

- handshake state machine;
- hybrid crypto composition and transcript binding;
- retry cookie and resumption ticket handling;
- updater trust model and stage/apply confinement;
- control plane auth/session/ticket lifecycle.

### Priority 1

- transport header protection and replay semantics;
- relay route assignment and failover coupling with policy;
- observability/rollback surfaces that operators rely on during incidents.

## Attack surface map

| Surface | Main risk classes | Current primary defenses |
| --- | --- | --- |
| UDP handshake | probing, flood, malformed state transitions, auth abuse | retry cookie, transcript binding, anti-probing outcomes, per-IP abuse guard, trace correlation |
| Resumption path | ticket replay, opaque capability misuse, local secret corruption | sealed ticket, consumed ticket lifecycle, bounded local parser, temp-file write path |
| Updater | traversal, oversized metadata, weak threshold handling, substituted bundle | threshold signatures, size bounds, basename-only staging, SHA-256 and length re-check on apply |
| Control plane | stale ticket/session state, policy conflicts, auth drift | typed records, audit chain, deterministic policy evaluation, rollout guard + admin surfaces |
| Observability/admin | weak incident visibility, rollback hesitation | observability snapshot, trace journal, rollout guard, runbooks |
| Relay fabric | unsafe reroute or degraded anonymity assumptions | route planner, failover budgets, explainable route state, explicit trust metadata |

## Known limitations accepted before closed beta

- protocol остается `UDP-only` и `IPv4-only`;
- updater пока без TUF timestamp/snapshot roles и transparency log;
- local resumption state еще не использует OS-native secret store;
- rate limiting на handshake сейчас per-IP и не пытается быть глобальной anti-DDoS системой;
- formal models покрывают handshake skeleton, а не весь transport/runtime one-to-one.

Ни одно из этих ограничений не считается blocking для closed beta, но каждое должно быть прозрачно зафиксировано в audit notes.

## Incident response package

### Что должно быть доступно оператору

- `state/observability.json`
- `state/trace.ndjson`
- `state/runtime.json`
- `state/sessions.json`
- `state/control_plane.json`
- `cargo run -p omega-server -- admin show_observability`
- `cargo run -p omega-server -- admin show_rollout_guard`
- `cargo run -p omega-server -- admin show_audit --limit 200`

### Базовый security triage

1. Проверить `show_rollout_guard` и зафиксировать, healthy ли rollout.
2. Проверить `show_observability` и наличие `handshake` / `control_plane` / `fabric` alerts.
3. По `state/trace.ndjson` собрать correlation id для инцидента.
4. При подозрении на rollout regression откатить через существующий release rollback path.
5. Зафиксировать known-good build, affected users/devices/sessions и итоговую mitigation action.

## Private security testing before wider beta

Минимальный intake package:

- reproducible environment;
- exact build or commit hash;
- packet capture / trace correlation id / staged artifact when relevant;
- severity estimate;
- proposed reproduction steps.

Severity handling:

- critical: immediate beta freeze / rollback consideration;
- high: block rollout expansion until fix or explicit risk acceptance;
- medium: fix in next beta hardening window;
- low: backlog with owner.

## Exit condition for audit package readiness

Пакет считается готовым, если одновременно верно:

- auditor может пройти от high-level architecture до review-critical files без поиска по репозиторию вслепую;
- known limitations перечислены явно;
- incident response path привязан к существующим metrics/trace/admin surfaces;
- proof and test docs объясняют, какие security claims supported кодом прямо сейчас.

