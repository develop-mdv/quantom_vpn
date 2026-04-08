# Repo Map V2

## Назначение

Этот документ описывает рабочую карту workspace после `phase_01_workspace_refactor`.
Главный принцип: код разделен по продуктовым доменам, а старые entrypoint-ы оставлены только как compatibility/app shims.

## Корневые crates

### Foundations

- `omega-core-crypto` - ключевая криптография и key schedule.
- `omega-core-wire` - wire structures, STUN framing, handshake payloads, packet headers.
- `omega-transport` - ARQ, anti-replay, FEC primitives и transport lifecycle types.
- `omega-stealth` - `ChaosPrng`, `MorphingPolicy`, `ProductMode`.

### Control / Fabric

- `omega-control` - identity store, device auth, control-policy domain types.
- `omega-relay` - relay role types и selection contracts.
- `omega-exit` - exit role policy types и egress contracts.

### Runtime

- `omega-edge` - edge runtime: handshake, datapath, sessions, metrics, runtime snapshots.
- `omega-client-runtime` - клиентский runtime без UI/app glue.

### App / Compatibility

- `omega-client-app` - новый product-grade клиентский entrypoint.
- `omega-server` - server app entrypoint и admin CLI.
- `omega-client` - compatibility shim, который просто вызывает `omega-client-runtime`.
- `omega-core` - compatibility facade поверх новых foundation crates.

## Детализация по crate

### `omega-core-crypto`

Ответственность:
- `SessionKeys`
- `derive_flow_id`
- HKDF / AEAD primitives

Не знает о:
- TUN
- UDP runtime
- identity store
- admin/UI

### `omega-core-wire`

Ответственность:
- `FlowId`
- `RtpHeader`
- `OmegaHeader`
- `ClientHello`, `ServerHello`, `HandshakeReject`
- `NackMessage`

Не знает о:
- crypto state
- runtime orchestration
- control-plane storage

### `omega-transport`

Ответственность:
- `RetransmitQueue`
- `GapDetector`
- `LossEstimator`
- `ReplayFilter`
- `FecEncoder/FecDecoder/FecState`
- `HandshakePhase`, `SessionLifecycle`

Не знает о:
- UI
- identity database
- Windows routing

### `omega-stealth`

Ответственность:
- `ChaosPrng`
- `MorphingPolicy`
- `ProductMode`

Не знает о:
- encoder/decoder state
- session admission
- admin surfaces

### `omega-control`

Ответственность:
- `IdentityStore`
- users/devices/audit
- `SessionAdmission`
- `PrivilegeBoundary`

Не знает о:
- TUN/UDP loops
- packet encryption
- client UI

### `omega-edge`

Ответственность:
- server handshake pipeline
- session manager
- datapath loops
- metrics/runtime snapshots
- admin command queue processing

Зависит от:
- foundations
- control plane

Не экспортирует:
- client UI logic

### `omega-client-runtime`

Ответственность:
- env-driven client config
- handshake and tunnel bootstrap
- diagnostics
- Windows routing orchestration
- client lifecycle state

Не знает о:
- admin CLI/web UI
- server identity store internals

### `omega-client-app`

Ответственность:
- инициализация tracing
- запуск `omega-client-runtime`

### `omega-server`

Ответственность:
- инициализация tracing
- admin CLI
- запуск `omega-edge`

## Migration Map

| Старый домен | Новый домен |
| --- | --- |
| `omega-core/src/crypto.rs` | `omega-core-crypto` |
| `omega-core/src/protocol.rs` | `omega-core-wire` |
| `omega-core/src/arq.rs`, `replay.rs`, `raptorq_mgr.rs` | `omega-transport` |
| `omega-core/src/chaos.rs` | `omega-stealth` |
| `omega-server/src/identity/*` | `omega-control/src/identity/*` |
| `omega-server/src/handshake.rs`, `datapath.rs`, `session.rs`, `runtime.rs`, `metrics.rs` | `omega-edge` |
| `omega-client/src/config.rs`, `diagnostics.rs`, runtime logic | `omega-client-runtime` |
| `omega-client/src/main.rs` | `omega-client-app` + compatibility shim |

## Что считать точками входа теперь

- Клиент нового формата: `cargo run -p omega-client-app`
- Клиент совместимости: `cargo run -p omega-client`
- Сервер: `cargo run -p omega-server`

## Где вносить изменения дальше

- Меняется wire layout -> `omega-core-wire`
- Меняется key schedule -> `omega-core-crypto`
- Меняется reliability/FEC/replay -> `omega-transport`
- Меняется stealth mode/policy -> `omega-stealth`
- Меняется identity/admission/control policy -> `omega-control`
- Меняется server runtime/data path -> `omega-edge`
- Меняется client bootstrap/diagnostics -> `omega-client-runtime`
