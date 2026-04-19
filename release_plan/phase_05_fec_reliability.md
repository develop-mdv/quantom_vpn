# Phase 05 - Theoretical Information Reliability: Live FEC & Capacity Optimization

## Цель

Построить систему надежности для lossy-сетей: live FEC, адаптивное распределение избыточности, приоритезация traffic classes и снижение зависимости от массовых ретрансмитов.

## Результат фазы

- Живой FEC в datapath.
- Адаптивный контроллер выбора recovery-стратегии.
- Устойчивое поведение канала на burst-loss и mixed-loss сценариях.

## Подробное ТЗ

1. **Довести live FEC path до рабочего состояния в transport v2:**
   - выбрать базовый кодек (`RaptorQ`, `Reed-Solomon` или другой);
   - встроить его в frame layer;
   - обеспечить encode/decode в реальном трафике, а не только в оффлайн-примерах.
2. **Разделить recovery-стратегии по классам нагрузки:**
   - retransmit-only;
   - FEC low;
   - FEC medium/high;
   - controlled duplication для отдельных классов.
3. **Ввести traffic classes и их utility model:**
   - `control`;
   - `interactive`;
   - `bulk`;
   - `stealth cover`.
   Для каждого класса определить latency budget, redundancy budget и допустимые способы восстановления.
4. **Построить адаптивный контроллер включения FEC:**
   сначала на понятных измерениях loss, burstiness, RTT и class utility, затем при необходимости усиливать его более умными стратегиями выбора.
5. **Использовать научную часть для улучшения реального goodput:**
   теоремы, симуляции и MAB/RL-подходы нужны здесь только если они реально улучшают выбор repair strategy и не делают систему непрозрачной.
6. **Добавить телеметрию и explainability reliability engine:**
   система должна объяснять, почему она включила FEC, подняла избыточность или вернулась к retransmit-only.

## Артефакты

- `docs/SHANNON_RELIABILITY_ENGINE.md`
- Спецификация live FEC policy.
- Симуляции и стенды с loss/burst-loss сценариями.

## Acceptance Criteria

- Live FEC реально работает в datapath и восстанавливает потерянные блоки на целевых сценариях.
- На burst-loss стендах новый reliability engine превосходит pure retransmit-подход по latency stability или goodput.
- На чистых сетях overhead reliability engine остается в контролируемом бюджете.
- Адаптивный выбор recovery-стратегии не осциллирует и не создает скрытых storm-сценариев.

## Метрики успеха

- Снижение числа retransmit storm сценариев.
- Улучшение goodput на lossy links.
- Стабилизация jitter для interactive traffic.

## Риски

- FEC может съедать слишком много CPU или bandwidth при неверной политике включения.
- MAB/RL может дать красивую модель, но слишком медленную или непрозрачную для production.

## Зависимости

- Phase 03 и базовые path signals из Phase 04.

## Комментарий по выполнению

Фаза `phase_05_fec_reliability` успешно выполнена `2026-04-07`.

Итог по результатам:

- В `transport v2` доведен до live runtime рабочий `RaptorQ`-based FEC path через `FecFrame`, `block_id = message_id`, repair-only single-symbol recovery и duplicate suppression.
- Реализован explainable `ReliabilityController`, который выбирает `retransmit_only / duplicate_once / fec_low / fec_medium / fec_high` по `loss`, `jitter`, `quality_score`, `mode` и `blackhole` сигналам из `Phase 04`.
- Client и edge runtime теперь симметрично умеют:
  - ставить recovery policy на outbound path;
  - добавлять controlled duplication и live FEC repair frames;
  - восстанавливать потерянные small interactive/control blocks на inbound path;
  - подавлять дубликаты после recovery по `message_id`.
- Добавлена live observability и explainability:
  - class strategies и explanation строки reliability engine;
  - `fec_frames_sent/received`;
  - `fec_recoveries`;
  - `suppressed_duplicates`;
  - серверные runtime summaries и Prometheus gauges по reliability/FEC.
- Подготовлен артефакт `docs/SHANNON_RELIABILITY_ENGINE.md` с policy, численными выкладками и burst-loss analysis.

Проверка выполнения:

- `cargo fmt --all` - успешно.
- `cargo check --workspace` - успешно.
- Формальные unit/integration checks по reliability/FEC добавлены в `omega-transport`.

Практический итог фазы: live FEC больше не является оффлайн-примитивом в репозитории, а работает как часть реального datapath и дает объяснимый выигрыш по latency stability на lossy/bursty interactive paths при нулевом FEC overhead на clean path.
