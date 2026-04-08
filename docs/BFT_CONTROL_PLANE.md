# BFT Control Plane

## Что реально реализовано в Phase 08

Phase 08 не делает вид, что в репозитории уже живет полноценная распределенная BFT-система. Фактическая реализация сейчас такая:

- typed `ControlPlaneStore` в `omega-control/src/control_plane.rs`;
- единый durable snapshot `state/control_plane.json`;
- deterministic audit chain с `revision`, `prev_hash`, `event_hash`;
- cross-process synchronization через reload-from-disk на admin/auth/control-plane operations;
- явно зафиксированные границы `strong` vs `eventual` consistency;
- runtime reconcile loops в `omega-edge/src/server.rs`, которые приводят live sessions/fabric в соответствие с control-plane state.

Это честная CFT-first модель с BFT-ready surface, а не недореализованный псевдо-консенсус.

## Consistency Contract

### Strongly consistent domains

Для текущей поддерживаемой топологии эти операции считаются критичными и должны проходить как единый typed state transition с немедленной записью в control-plane snapshot:

- user lifecycle: `create/block/unblock/delete`;
- device lifecycle: `register/revoke/rotate token`;
- session lifecycle: `activate/terminate/revoke`;
- ticket lifecycle: `issue/consume/revoke/expire`;
- policy lifecycle: `put policy`, version bump, conflict rejection;
- audit append и revision bump.

### Eventually consistent domains

Эти данные допускают bounded lag и обслуживаются reconcile/task-based projection layers:

- fabric membership projection из relay graph;
- fabric node health / operator marks;
- session route updates после failover;
- runtime/session snapshots для UI/diagnostics.

### Почему граница именно такая

Если сделать eventual consistency для `device revoke`, `ticket consume` или `session terminate`, то можно получить:

- race между revoke и resume;
- повторное использование resumption ticket;
- split-brain по active session state;
- недостоверный audit trail.

Поэтому identity/session/ticket/policy state лежат в strong domain, а fabric observability и topology hints остаются eventual.

## Failure Model

### Что поддерживается сейчас

- single durable control-plane state file;
- несколько локальных процессов (`omega-server admin`, runtime, web admin), синхронизирующихся через reload/store discipline;
- deterministic recovery после process restart;
- predictable revocation enforcement через reconcile loop.

### Что не заявляется как готовое в этой фазе

- Byzantine quorum replication;
- leader election;
- geographically distributed write quorum;
- concurrent multi-writer consensus log.

## BFT-Ready Surface

Чтобы перейти к следующей distributed фазе без перелома модели, уже выделены правильные слои:

- `ControlPlaneMeta.revision/term`;
- typed snapshot вместо raw ad-hoc JSON objects;
- append-only audit hash chain;
- deterministic policy evaluation order;
- separation of `strong` and `eventual` domains;
- runtime projection, а не storage-as-UI.

Это позволяет заменить локальный snapshot backend на replicated log или Raft/CFT-слой без переписывания session/ticket/policy semantics.

## Regional Failure Semantics

При текущей реализации региональные сбои трактуются так:

- потеря runtime-процесса не теряет control-plane state, потому что lifecycle mutations уже durably persisted;
- после рестарта runtime rereads control-plane state и reconcile loop заново применяет revocation/session termination intent;
- eventual domains (fabric health, route projection) могут отставать, но не должны переопределять strong control decisions.

## Audit Construction

Каждое контрольное действие создает audit event с полями:

- `revision`;
- `action`;
- `actor`;
- `entity`;
- `details`;
- `prev_hash`;
- `event_hash`.

Это не Merkle tree, а hash-chained audit log. Для продукта на текущей стадии этого достаточно, чтобы:

- восстановить последовательность операторских действий;
- доказать reorder/tamper anomalies;
- связать session/ticket/policy transitions с конкретным actor.

## Практический вывод

Phase 08 фиксирует правильную архитектурную позицию:

- control plane уже typed и deterministic;
- strong/evenual contract уже выражен в коде;
- revocation/ticket/session semantics больше не размазаны по raw JSON и runtime side effects;
- полноценный distributed consensus остается следующей инфраструктурной эволюцией, а не ложным обещанием текущей фазы.
