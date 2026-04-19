# Phase 06 - Adversarial Stealth Engine и Проверка Энтропии

## Цель

Построить stealth engine как отдельную подсистему продукта: с wire personas, измеримой detectability, управляемым overhead и устойчивым поведением при probing.

## Результат фазы

- Плагинная система personas.
- Stealth evaluator с trace corpus и baseline-классификаторами.
- Базовая защита от probing и предсказуемая интеграция stealth с transport.

## Подробное ТЗ

1. **Определить persona model как реальную спецификацию wire behavior:**
   - packet size grammar;
   - timing policy;
   - handshake envelope;
   - cover budget;
   - fallback behavior.
2. **Собрать corpus реальных и целевых traces для сравнения:**
   stealth должен оцениваться относительно реального наблюдаемого поведения, а не против абстрактной интуиции.
3. **Реализовать несколько persona-профилей, пригодных для продакшена:**
   - `randomized`;
   - `quic-like` или `webrtc-like`;
   - `hostile-network`.
4. **Сделать evaluator, который реально управляет разработкой personas:**
   - статистические тесты;
   - baseline classifiers;
   - сравнение с v1 и persona-off режимом;
   - оценка overhead и regression risk.
5. **Сделать anti-probing частью persona engine:**
   - ограниченное число observable response classes;
   - отсутствие явных ошибок, раскрывающих протокол;
   - выравнивание реакции на невалидные initial packets в разумных пределах.
6. **Интегрировать stealth с transport и reliability:**
   - когда persona имеет право увеличить padding или timing shaping;
   - когда persona обязана уступить ради живучести сессии;
   - как persona влияет на path manager и FEC.
7. **Научную часть встроить в продукт:**
   WGAN, entropy shaping и adversarial ML стоит делать только там, где они дают измеримый выигрыш по detectability при приемлемом overhead.

## Артефакты

- `docs/ADVERSARIAL_STEALTH_ENGINE.md`
- `docs/WGAN_PERSONA_MODELS.md`
- Отчет тестирования detectability для каждой persona.

## Acceptance Criteria

- Есть не менее трех persona с документированными trade-offs.
- Persona-режимы измеримо снижают detectability относительно текущего wire image или persona-off режима.
- Невалидные initial/probe пакеты не дают очевидно разных observable outcomes по типу ошибки.
- Overhead и latency budget для каждой persona задокументированы и контролируются.

## Метрики успеха

- Снижение detectability относительно текущего wire image.
- Управляемый overhead для каждой persona.
- Повышение устойчивости к базовым probing-сценариям на стенде.

## Риски

- Слишком тяжелые persona models ухудшат CPU usage и QoS.
- Агрессивный timing shaping может разрушить опыт интерактивного трафика.

## Зависимости

- Phase 02 и Phase 03.

## Комментарий по выполнению

Фаза `phase_06_stealth_personas` успешно выполнена `2026-04-07`.

Итог по результатам:

- реализован отдельный stealth subsystem в `omega-stealth` с production persona model: `randomized`, `quic_like`, `hostile_network` и `off` baseline;
- добавлены `StealthEngine` и `StealthEvaluator` с trace corpus, JSD/PRS/CBS метриками и regression tests;
- клиент и сервер получили `OMEGA_PERSONA`, profile-based defaults и stealth telemetry в diagnostics/runtime snapshots;
- handshake стал persona-aware: init/retry grease зависит от persona, invalid probe paths сведены к ограниченному набору observable outcomes через anti-probing policy;
- outbound transport path теперь использует persona-driven padding floor и ограниченный cover budget;
- подготовлены артефакты фазы: `docs/ADVERSARIAL_STEALTH_ENGINE.md`, `docs/WGAN_PERSONA_MODELS.md`, `docs/STEALTH_PERSONA_DETECTABILITY_REPORT.md`;
- в detectability report подтверждено измеримое улучшение относительно `persona_off` для всех production personas;
- верификация пройдена: `cargo fmt --all`, `cargo check --workspace`, `cargo test --workspace` успешны.
