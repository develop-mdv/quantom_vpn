# Phase 08 - Control Plane, State Consensus and Formal Policy Engine

## Цель

Построить надежный control plane для устройств, сессий, токенов, routing policies и orchestration fabric, сохранив при этом математическую строгость там, где она реально повышает устойчивость и проверяемость системы.

## Результат фазы

- Реплицируемый state model для control plane.
- Policy engine с явной моделью правил.
- Управляемый lifecycle устройств, сессий и ключевого материала.

## Подробное ТЗ

1. **Уйти от JSON как primary source of truth к настоящей state model:**
   нужен устойчивый источник истины для устройств, токенов, сессий, узлов fabric и policy-объектов.
2. **Выбрать и зафиксировать рабочую модель консистентности, а не абстрактно требовать всё сразу:**
   - что обязано быть strongly consistent;
   - что может быть eventually consistent;
   - как ведет себя система при региональных сбоях;
   - где оправдан crash-fault tolerant consensus, а где достаточно более простой схемы.
3. **Реализовать lifecycle сущностей control plane:**
   - device;
   - session;
   - token/ticket;
   - relay/edge registration;
   - policy objects.
4. **Сделать policy engine рабочим инструментом продукта:**
   - ABAC или близкая формальная модель;
   - детерминированная оценка правил;
   - версионирование политик;
   - тестирование конфликтов;
   - запрет опасных routing loops и неконсистентных состояний.
5. **Построить криптографическую оркестрацию вокруг продукта:**
   - key rotation;
   - session revocation;
   - ticket issuance;
   - audit trail;
   - управление доступом узлов fabric.
6. **Использовать формальные и распределенные методы как усиление живой системы:**
   BFT, SMT-проверка политик и Merkle/audit конструкции нужны там, где они реально уменьшают риск split-brain, policy-conflicts или неаудируемых действий, а не как самоцель.

## Артефакты

- `docs/BFT_CONTROL_PLANE.md`
- Спецификация state model и API schema.
- Policy test matrix.

## Acceptance Criteria

- Control plane становится единым источником истины для устройств, сессий и политик.
- Revocation, ticket issuance и session termination выполняются предсказуемо в поддерживаемой топологии.
- Политики оцениваются детерминированно и проходят тестовую матрицу конфликтов.
- Audit trail достаточен для расследования действий администратора и автоматических систем.
- Границы между strict consistency и eventual consistency зафиксированы и реализованы осознанно.

## Метрики успеха

- Отсутствие несогласованных состояний в целевой схеме деплоя.
- Предсказуемое время применения критичных control plane операций.
- Снижение ручных операций и неявной логики в администрировании fabric.

## Риски

- Попытка сразу прыгнуть к BFT-системе максимальной строгости может сорвать сроки продукта.
- Слишком слабая модель консистентности сломает revocation, routing policies и handoff semantics.

## Зависимости

- Phase 07 и базовые session semantics из Phase 02.

## Комментарий по выполнению

Фаза `phase_08_control_plane` успешно выполнена `2026-04-07`.

Что получилось по итогу:

- в `omega-control` реализован полноценный typed `ControlPlaneStore` вместо identity-only модели;
- зафиксированы strong/eventual consistency boundaries для identity/session/ticket/policy/fabric domains;
- добавлены lifecycle модели для `user/device/session/ticket/fabric node/policy object`;
- реализован deterministic ABAC-like policy engine с versioning, conflict detection и route-loop safety validation;
- handshake v2 теперь использует control plane для `policy evaluation`, `ticket issuance` и `ticket consume`;
- session lifecycle, revoke semantics и fabric failover projection теперь зеркалятся в control plane через runtime integration и reconcile loops;
- admin CLI расширен control-plane oriented командами (`show_control_plane`, `list_policies`, `show_policy_conflicts`, `list_fabric_nodes`, `rotate_device_token`);
- добавлены документы `docs/BFT_CONTROL_PLANE.md`, `docs/CONTROL_PLANE_STATE_MODEL.md`, `docs/POLICY_TEST_MATRIX.md`.

Результат проверки:

- `cargo fmt --all` - успешно;
- `cargo check --workspace` - успешно;
- `cargo test --workspace` - успешно.

Открытая честная оговорка:

- полноценный distributed quorum/BFT replication в этой фазе сознательно не внедрялся; вместо этого в коде и документации зафиксирован CFT-first control-plane contract с BFT-ready state/audit surface, чтобы не симулировать несуществующую распределенную строгость.
