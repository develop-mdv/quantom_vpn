# Phase 04 - Bayesian Path Intelligence, MTU and Machine Learning Network Adaptation

## Цель

Сделать path management адаптивным: безопасно подбирать MTU, замечать деградацию пути, избегать blackhole-сценариев и готовить основу для более умных вероятностных моделей без потери управляемости.

## Результат фазы

- Рабочий DPLPMTUD и adaptive packet sizing.
- Path quality scoring и blackhole detection.
- Контролируемое поведение path roam/switch.

## Подробное ТЗ

1. **Сделать базовый path manager на детерминированных сигналах:**
   - RTT;
   - jitter;
   - loss;
   - reordering;
   - результаты handshake/roam.
2. **Реализовать DPLPMTUD как часть transport runtime:**
   - безопасное зондирование;
   - понижение MTU при blackhole-признаках;
   - возврат к более крупному MTU только при наличии уверенных данных.
3. **Добавить adaptive packet sizing и hysteresis:**
   система не должна дергаться на каждом всплеске потерь или джиттера.
4. **Сделать path quality scoring и decision engine:**
   - когда снижать MTU;
   - когда снижать pacing/агрессию recovery;
   - когда менять маршрут или persona;
   - как учитывать stealth budget.
5. **Использовать байесовские и HMM-идеи как усиление, а не замену базовой логики:**
   сначала должен появиться работающий path manager, затем вероятностная модель улучшает его устойчивость и предсказуемость.
6. **Добавить explainability:**
   система должна уметь ответить, почему она снизила MTU, сменила маршрут или перешла в более осторожный режим.

## Артефакты

- `docs/BAYESIAN_PATH_MANAGER.md`
- Спецификация DPLPMTUD и path scoring.
- Имплементация path manager в Rust.

## Acceptance Criteria

- Система находит рабочий MTU и корректно откатывается при blackhole-сценариях.
- Кратковременные всплески jitter/loss не вызывают лишних переключений пути.
- Решения path manager можно объяснить по телеметрии.
- Вероятностная часть улучшает поведение системы, а не подменяет ее непрозрачной моделью.

## Метрики успеха

- Снижение MTU-related потерь и retransmit spikes.
- Снижение числа ручных override-настроек MTU.
- Улучшение устойчивости сессии при изменении качества сети.

## Риски

- Слишком сложная статистическая модель может оказаться тяжелой для слабых устройств.
- Ошибки в hysteresis дадут либо flapping, либо слишком медленную адаптацию.

## Зависимости

- Phase 03 - наличие точных frame-based метрик.

## Комментарий по выполнению

Фаза `Phase 04 - Bayesian Path Intelligence, MTU and Machine Learning Network Adaptation` успешно выполнена `2026-04-06`.

Итог по результатам:
- в `omega-transport` реализован explainable `path manager` на детерминированных сигналах `RTT/jitter/loss/reordering`;
- DPLPMTUD встроен прямо в `transport runtime`: upward probes идут через `PathFrame + Padding`, а при blackhole-паттернах payload budget автоматически понижается;
- добавлены adaptive packet sizing, hysteresis, `path quality score`, `mode` и `route_action` decision engine;
- поверх baseline добавлен легкий probabilistic layer (`stable/congested/reordered/blackhole_risk/recovering`), который улучшает устойчивость, но не подменяет базовую логику;
- explainability выведена в telemetry: клиентские diagnostics, server session/runtime snapshots и Prometheus gauges теперь показывают `payload budget`, `quality`, `mode`, `belief`, `blackhole` и текстовое объяснение последнего решения;
- roam-события учитываются отдельно и не вызывают агрессивного MTU роста сразу после смены адреса;
- подготовлен инженерный артефакт `docs/BAYESIAN_PATH_MANAGER.md` с формулами, правилами DPLPMTUD и описанием probabilistic overlay.

Проверка выполнения:
- `cargo check --workspace` — успешно;
- `cargo test -p omega-transport` — успешно;
- `cargo test --workspace` — успешно.

