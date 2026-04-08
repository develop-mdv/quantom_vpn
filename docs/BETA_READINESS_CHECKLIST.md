# Beta Readiness Checklist

## Как использовать

Это checklist для закрытой beta. Он объединяет security, stability, rollback и support readiness в одном языке, чтобы релиз не проходил дальше только потому, что код компилируется.

## Product and security gates

- [x] Актуальные architecture, threat model и protocol docs собраны и связаны между собой.
- [x] Для handshake есть formal/proof package: `PROTOCOL_PROOFS.md`, `FORMAL_VERIFICATION_REPORT.md`, ProVerif/Tamarin models.
- [x] Update path закрывает threshold, digest, size-bound и path-confinement bug classes.
- [x] Handshake anti-abuse path реализован и наблюдаем через metrics + trace events.
- [x] Resumption local state проходит bounded parsing и безопасную запись через temp replacement.
- [x] Known limitations и accepted beta risks перечислены явно в audit package.

## Engineering gates

- [x] `cargo fmt --all` проходит.
- [x] `cargo check --workspace` проходит.
- [x] `cargo test --workspace` проходит.
- [x] Security-relevant negative tests добавлены для updater, local resumption storage и handshake anti-abuse.
- [x] Rollback path уже существует в `deploy/update_server.sh` и связан с rollout guard.
- [x] Incident runbooks и operator evidence paths зафиксированы в `docs/OPERATIONS.md` и `docs/INCIDENT_RUNBOOKS.md`.

## Closed beta operational targets

Перед расширением beta оператор должен контролировать следующие окна:

- connect success: целевой floor `>= 98%` на canary window;
- crash-free client sessions: целевой floor `>= 99.5%`;
- handshake rate-limit false positives: target `near zero`, любое заметное срабатывание требует trace review;
- incident rollback time: целевой target `<= 5 minutes` от подтвержденного rollout regression до отката;
- critical open security findings: `0`.

## Evidence for those targets

- `state/observability.json`
- `state/trace.ndjson`
- `omega-client/state/lifecycle.json`
- `omega-client/state/diagnostics.json`
- Prometheus metrics including `omega_handshake_success_total`, `omega_handshake_failures_total`, `omega_handshake_rate_limited_total`

## Go / No-Go questions

Перед стартом очередного beta ring ответ на каждый вопрос должен быть `yes`:

- [x] Есть ли rollback-ready build и оператор знает процедуру отката?
- [x] Есть ли trace/metrics/admin surface, чтобы расследовать handshake, updater и control-plane incidents?
- [x] Есть ли единый audit package для внешнего review?
- [x] Переведены ли formal assumptions в code checks и tests, а не только в prose?
- [x] Зафиксированы ли accepted limitations, чтобы beta не обещала больше, чем реально реализовано?

## Current phase-11 status

По состоянию завершения этой фазы репозиторий закрывает pre-beta engineering/security gates:

- proofs/report/checklist собраны;
- handshake anti-abuse, updater hardening и secure local resumption storage внедрены;
- workspace verification проходит полностью.

Live fleet metrics из этого документа измеряются уже на staged beta rollout через rollout guard, observability snapshot и operator runbooks, а не объявляются выполненными без наблюдения трафика.

