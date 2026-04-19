# Phase 01 - Workspace Refactor and Axiomatic Architectural Boundaries

## Цель

Перестроить текущий workspace так, чтобы transport, stealth, relay, control plane и клиентский runtime развивались независимо, но без потери производительности и управляемости.

## Результат фазы

- Репозиторий разделен по продуктовым доменам.
- Критические зависимости между подсистемами зафиксированы.
- Криптография, wire format и runtime orchestration отделены друг от друга.

## Подробное ТЗ

1. **Переразделить workspace по доменам продукта:**
   - `omega-core-crypto`;
   - `omega-core-wire`;
   - `omega-transport`;
   - `omega-stealth`;
   - `omega-relay`;
   - `omega-control`;
   - `omega-client-runtime`;
   - `omega-client-app`;
   - `omega-edge`;
   - `omega-exit`.
2. **Зафиксировать направление зависимостей и убрать архитектурную кашу:**
   - transport не знает про UI;
   - crypto/wire не завязаны на runtime;
   - control plane не размазан по клиентскому коду;
   - stealth не должен ломать encoder/decoder при сбое.
3. **Вынести stateful-логику из `main`-пайплайнов в явные модули и интерфейсы.**
4. **Применить строгую типизацию там, где она реально окупается:**
   - состояния handshake;
   - lifecycle session;
   - проверенные wire-структуры;
   - privileged/runtime границы.
5. **Подготовить техническую базу для дальнейших фаз:**
   - unit-testability transport/stealth без полного runtime;
   - dependency DAG;
   - fault isolation между доменами;
   - профилировочные точки в hot path.
6. **Научную часть фазы использовать для инженерной пользы:**
   typestate, инварианты и архитектурные аксиомы должны уменьшать число ошибок и упрощать дальнейшее развитие, а не превращаться в чисто теоретическую модель.

## Артефакты

- Обновленный `Cargo.toml` с четкими workspace constraints.
- `docs/REPO_MAP_V2.md`
- `docs/ARCHITECTURE_AXIOMS.md`
- Матрица зависимостей (Dependency DAG).

## Acceptance Criteria

- Workspace собирается и тестируется после разделения.
- Нет циклических зависимостей между ключевыми crate-ами.
- Клиентский runtime не зависит от admin/UI логики.
- Критические state transitions выражены через явные API или типы.
- Есть понятная карта миграции старого кода в новую архитектуру.

## Метрики успеха

- Снижается цикломатическая сложность ключевых runtime entrypoints.
- Transport и stealth можно тестировать изолированно.
- Hot path становится проще профилировать и оптимизировать.

## Риски

- Избыточное дробление абстракций приведет к потере производительности.
- Команда потеряет время на выведение идеальных интерфейсов вместо рабочего каркаса.

## Зависимости

- Формализованная архитектура и threat model из Phase 00.
