# Architecture Axioms

## Axiom 1. Dependency Direction Is Product-Domain Driven

Foundation crates не зависят от runtime crates.
Разрешенное направление сверху вниз:

- wire/crypto/transport/stealth -> reusable primitives
- control/relay/exit -> policy and topology domain
- edge/client-runtime -> orchestration
- app shims -> only entrypoints

## Axiom 2. Transport Does Not Know UI

`omega-transport` и `omega-edge::datapath` не должны зависеть от:

- web admin
- CLI formatting
- desktop/client UI

Любые operational surfaces живут вне transport hot path.

## Axiom 3. Crypto And Wire Stay Runtime-Agnostic

`omega-core-crypto` и `omega-core-wire` не хранят:

- identity store state
- async runtime handles
- TUN/UDP orchestration
- OS-specific routing logic

## Axiom 4. Control Plane Is Explicit

Identity, admission и policy должны существовать как отдельный control-domain.
Control plane не должен быть размазан по клиентскому runtime и не должен требовать UI-слоя для своих типов.

## Axiom 5. Stealth Failure Must Not Corrupt Transport Correctness

Если stealth logic меняется или деградирует, transport correctness должен сохраняться.
Следствие:

- `MorphingPolicy` задает бюджеты и shaping intent
- encoder/decoder semantics не зависят от косметического shaping
- сбой stealth не должен ломать replay/ARQ/FEC invariants

## Axiom 6. Stateful Pipelines Live In Libraries, Not In App Mains

`main.rs` в app crates должен делать только:

- инициализацию tracing
- чтение CLI режима
- запуск соответствующей library API

Вся stateful runtime-логика должна жить в `omega-edge` и `omega-client-runtime`.

## Axiom 7. Critical State Transitions Must Be Typed

Фиксированные типы после `phase_01`:

- `omega_transport::lifecycle::HandshakePhase`
- `omega_transport::lifecycle::SessionLifecycle`
- `omega_client_runtime::lifecycle::ClientLifecycleState`
- `omega_control::policy::PrivilegeBoundary`
- `omega_control::policy::SessionAdmission`

Если новая функциональность меняет жизненный цикл сессии, это должно выражаться через явный тип или API, а не скрытые bool-флаги.

## Axiom 8. Compatibility Shims Are Transitional

`omega-core` и `omega-client` остаются как compatibility-layer, но новая разработка должна идти в новые доменные crates.

## Axiom 9. No Cycles Across Key Domains

Нельзя создавать циклы между:

- foundation crates
- control plane
- runtime orchestration
- relay/exit domain

Если для новой фичи требуется цикл, значит граница выбрана неверно.

## Axiom 10. Hot Path Must Stay Profilable

Datapath-модули должны оставаться достаточно изолированными, чтобы можно было профилировать отдельно:

- crypto cost
- wire parsing
- replay/ARQ/FEC cost
- stealth shaping cost
- edge orchestration overhead

## Axiom 11. Platform-Specific Code Is Runtime-Local

Windows routing, DNS и adapter policy не должны попадать в foundation/control crates.
OS-specific behavior живет в `omega-client-runtime` или соответствующем edge/app слое.

## Axiom 12. Relay And Exit Are First-Class Domains Even Before Full Runtime

Даже пока relay/exit еще не получили полный runtime, их типы и контракты должны жить в отдельных crates.
Это уменьшает будущую архитектурную кашу в `phase_07+`.


