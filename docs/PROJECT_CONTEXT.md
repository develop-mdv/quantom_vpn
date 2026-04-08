# Project Context

## Что это за проект

`Omega VPN` - это Rust workspace c собственным VPN-протоколом `Omega v2`, который строится вокруг:

- custom UDP transport вместо WireGuard/OpenVPN;
- handshake v2 с `X25519 + ML-KEM-768`;
- device-based authentication через `device_id + device_token`;
- transport v2 с frame layer, ACK ranges, pacing и congestion control;
- path intelligence, stealth personas, relay fabric и typed control plane;
- отдельного desktop launcher и background runtime;
- встроенных observability и security hardening surface-ов.

Проект уже не выглядит как один монолитный "VPN-клиент и VPN-сервер". Сейчас это набор связанных подсистем, из которых можно собирать управляемую VPN-платформу с relay/control plane/launcher/ops/security контуром.

## Из чего состоит текущий workspace

- `omega-core-wire` - wire format handshake и transport v2.
- `omega-core-crypto` - ключевая криптография, hybrid handshake secrets, key update derivation.
- `omega-transport` - transport v2, replay protection, scheduler, reliability и FEC primitives.
- `omega-stealth` - personas, anti-probing и morphing policy.
- `omega-control` - typed control plane, policy engine, tickets, audit chain.
- `omega-edge` - серверный edge runtime: handshake, datapath, sessions, metrics, observability.
- `omega-relay` - relay fabric graph, routing и failover model.
- `omega-client-runtime` - privileged runtime клиента.
- `omega-client-app` - launcher UX, lifecycle, diagnostics, signed update path.
- `omega-core`, `omega-client` - compatibility shims/legacy entrypoints.

## Что реально уже достигнуто

По итогам Phase 00 - Phase 11 проект получил цельный каркас:

- формализован protocol vision, threat model, product modes и KPI;
- workspace разделен на доменные crates с более чистыми границами;
- реализован handshake v2 с hybrid `X25519 + ML-KEM-768`, retry/cookie и resumption;
- live runtime переведен на transport v2 с ACK ranges, pacing, congestion control и CID rotation;
- добавлены path intelligence, DPLPMTUD, adaptive packet sizing и blackhole recovery;
- reliability выросла до adaptive retransmit/FEC-модели;
- stealth layer оформлен через production personas и anti-probing policy;
- relay fabric и failover path встроены в runtime;
- control plane стал typed и policy-driven;
- клиент разделен на launcher и background runtime;
- observability/SRE слой получил rollout guard, alerts, trace journal и runbooks;
- security beta phase добавила audit package, proof docs, updater hardening, handshake anti-abuse и secure local resumption storage.

## Текущая правда по системе

- это собственный `Omega` protocol, а не обертка над чужим VPN-протоколом;
- основной datapath сейчас `UDP-only`;
- tunnel family сейчас `IPv4-only`;
- handshake маскируется через `STUN Binding Request/Response` surface;
- transport надежность строится вокруг `transport v2`, а legacy `ARQ/NACK` остается compatibility/reference слоем;
- small control/interactive traffic уже может использовать live repair-oriented FEC path;
- сервер и клиент уже имеют product-facing diagnostics/admin surfaces, а не только сетевой код.

## Что важно не перепутать

- проект уже сильно ушел от ранней трехкрейтовой схемы; актуальная карта модулей лежит в `docs/REPO_MAP_V2.md`;
- source of truth для control plane теперь `state/control_plane.json`, а не старый `identity.json`;
- launcher `omega-client-app` и privileged runtime `omega-client-runtime` - это разные слои с разными обязанностями;
- security и formal work в проекте теперь связаны с кодом и тестами, а не живут отдельно как research-only документы.

## Ключевые ограничения на текущий момент

- полноценного TCP fallback все еще нет;
- полноценной IPv6-туннелизации все еще нет;
- updater пока без transparency log и без TUF timestamp/snapshot role separation;
- local secret storage на клиенте пока не вынесен в OS-native keystore;
- formal models глубже всего покрывают handshake и trust assumptions вокруг него, а не весь runtime one-to-one.

Эти ограничения не делают репозиторий пустым или "игрушечным", но их важно честно держать в голове при планировании beta и production rollout.

## Куда смотреть в первую очередь

- Хочу быстро понять проект: `docs/PROJECT_CONTEXT.md`
- Хочу понять архитектуру целиком: `docs/ARCHITECTURE.md`
- Хочу понять protocol/security basis: `docs/PROTOCOL_V2_FORMAL_SPEC.md`, `docs/DOLEV_YAO_THREAT_MODEL.md`, `docs/PROTOCOL_PROOFS.md`
- Хочу понять code layout: `docs/REPO_MAP_V2.md`, `docs/DEPENDENCY_DAG.md`
- Хочу понять rollout/ops/security readiness: `docs/OPERATIONS.md`, `docs/OBSERVABILITY_DASHBOARDS.md`, `docs/INDEPENDENT_AUDIT_PACKAGE.md`, `docs/BETA_READINESS_CHECKLIST.md`

## Короткая формула проекта

`Omega VPN = custom VPN platform on top of hybrid handshake + transport v2 + stealth personas + relay/control plane + launcher/runtime split + observability/security package`
