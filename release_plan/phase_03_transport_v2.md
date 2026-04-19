# Phase 03 - Stochastic Transport Core v2 & Control Theory CC

## Цель

Построить новый transport core, который даст продукту собственный быстрый и устойчивый datapath: frame-based pipeline, loss recovery, pacing, congestion control, queueing и защищенное transport metadata.

## Результат фазы

- Новый transport frame layer.
- Работающий congestion control и pacing.
- Loss detection без retransmit storm.
- Каркас для FEC, path intelligence и stealth personas.

## Подробное ТЗ

1. **Перейти от packet-centric логики к frame-centric transport-слою:**
   - `data frame`;
   - `ack frame`;
   - `control frame`;
   - `path frame`;
   - `fec frame`.
2. **Разделить scheduling и packet assembly:**
   transport должен сначала планировать полезные единицы передачи, а затем собирать пакеты под конкретный budget по MTU, stealth и pacing.
3. **Реализовать новый механизм ACK/loss detection:**
   - ACK ranges;
   - новый тайминг потерь;
   - защита от spurious retransmit;
   - корректная реакция на reordering.
4. **Добавить congestion control и pacing как центральную часть transport-а:**
   - не допускать burst-отправок;
   - различать congestion и random loss;
   - держать interactive и bulk traffic под разными ограничениями.
5. **Скрыть лишние transport-признаки:**
   - header protection;
   - ротация connection IDs;
   - снижение очевидности packet counters и служебных паттернов.
6. **Добавить scheduler для traffic classes:**
   - `control`;
   - `interactive`;
   - `bulk`;
   - дальнейшая интеграция со `stealth cover`.
7. **Использовать научную часть там, где она усиливает код:**
   симуляторы, stochastic models и control-theory нужны для выбора и проверки алгоритма, а не для абстрактного доказательства без имплементации.

## Артефакты

- `docs/STOCHASTIC_TRANSPORT_V2.md`
- Спецификация congestion control и pacing formulas.
- Тестовый симулятор/стенд с loss, jitter и reordering.

## Acceptance Criteria

- Transport v2 реально передает трафик через frame layer.
- На контролируемых стендах transport v2 не впадает в retransmit storm и не вызывает congestion collapse.
- Throughput и latency under loss лучше или стабильнее v1 на заранее выбранных сценариях.
- Transport готов к интеграции с FEC, path manager и stealth engine.

## Метрики успеха

- Снижается дисперсия RTT и burstiness отправки.
- Растет goodput на сетях с умеренными потерями.
- Поведение `cwnd` и pacing rate становится наблюдаемым и управляемым.

## Риски

- Слишком сложный congestion control может стать тяжелым для user-space.
- Ошибки в scheduler или loss detection дадут регрессии по latency.

## Зависимости

- Phase 02 должен предоставлять независимые криптографические контексты для transport frames.

## Комментарий по выполнению

Фаза `phase_03_transport_v2` успешно выполнена `2026-04-06`.

Что получено по итогу:

- в `omega-core-wire` добавлен реальный `transport v2` frame layer: `data/ack/control/path/fec/padding`;
- в `omega-transport` реализован `TransportEndpoint` со scheduler-ом по traffic classes, packet assembly, ACK ranges, loss detection, pacing и congestion control;
- в `omega-edge` и `omega-client-runtime` live datapath переведен с legacy `NACK` packet path на новый frame-based transport;
- добавлены header protection для outer `seq/packet_type` и внутренняя rotation-модель `connection_id` через `path frame`;
- подготовлен transport doc artifact `docs/STOCHASTIC_TRANSPORT_V2.md` с formulas, scheduling rules и validation stand;
- validation выполнена успешно через `cargo check --workspace` и `cargo test --workspace`.

Практический результат фазы: transport v2 реально передает трафик через frame layer, держит ACK/loss семантику без retransmit storm, дает наблюдаемые `cwnd/pacing_rate`, приоритизирует `interactive` над `bulk` и создает рабочую базу для следующей интеграции FEC/path intelligence/stealth cover.
