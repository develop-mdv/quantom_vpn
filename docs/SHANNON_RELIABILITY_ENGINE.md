# Shannon Reliability Engine

## Контекст

`Phase 05` доводит надежность `Omega v2` до состояния, где recovery живет в реальном datapath, а не только в оффлайн-утилитах. В текущей реализации reliability engine опирается на:

- `transport v2` и его `data/ack/control/path/fec/padding` frame layer;
- path telemetry из `Phase 04`: `loss`, `jitter`, `reordering`, `quality_score`, `mode`, `blackhole_suspected`;
- explainable controller в `omega-transport/src/reliability.rs`;
- live `RaptorQ` integration и dedupe/recovery state в `omega-transport/src/raptorq_mgr.rs`;
- symmetric client/server runtime integration в `omega-client-runtime/src/runtime.rs` и `omega-edge/src/session.rs` + `omega-edge/src/datapath.rs`.

## Почему выбран RaptorQ

Выбран `RaptorQ`, потому что он уже присутствовал в проекте, хорошо работает на небольших blocks и позволяет плавно перейти от оффлайн FEC к живому packet recovery без смены wire format. Для `Phase 05` он используется в контролируемом режиме:

- только для `sub-MTU` сообщений;
- с explainable policy по traffic classes;
- без скрытой магии и без RL/MAB, пока не доказана практическая польза.

## Реальная wire policy

`FecFrame` уже существует в `transport_v2` wire layer. В live path payload FEC-frame кодируется так:

1. `version` - 1 byte.
2. `original_class` - 1 byte.
3. `OTI` (`ObjectTransmissionInformation`) - 12 bytes.
4. serialized `EncodingPacket`.

`block_id` у live FEC совпадает с `message_id` transport-сообщения. Это важно, потому что:

- recovery и original delivery сходятся на одном identity;
- duplicate suppression можно делать по `message_id`, а не по эвристикам;
- partial transport reassembly можно безопасно выбрасывать после FEC recovery.

## Recovery strategies

### Control

- Базовый режим: `retransmit_only`.
- На деградации (`loss >= 1.5%`, `quality_score < 62`, `blackhole_suspected`): `duplicate_once`.
- Ограничение по payload: до `320 B`.
- Цель: мгновенное восстановление tiny control signals без ожидания ARQ.

### Interactive

- `retransmit_only` на чистом пути.
- `fec_low` на мягкой деградации.
- `fec_medium` на path jitter/loss, где retransmit-only уже делает заметные spikes.
- `fec_high` только в тяжелых режимах (`blackhole`, высокий loss, низкий quality score).
- Ограничение по payload: до `640 B` для `low/medium`, до `448 B` для `high`.
- Latency budget: `80-90 ms`.

### Bulk

- По умолчанию `retransmit_only`.
- `fec_low` включается только на bursty links и только для малых `sub-MTU` writes.
- Ограничение по payload: до `384 B`.
- Цель: уменьшить clustered retransmits, не превращая bulk path в bandwidth sink.

### Stealth cover

- На этой фазе остается на `retransmit_only`.
- Причина: сначала нужно доказать, что reliability overlay не ломает stealth budget и не создает signature drift.

## Почему live FEC сделан как repair-only single-symbol mode

Для этой фазы важнее было получить рабочий и контролируемый live repair path, чем строить агрессивный multi-symbol block coder для больших payloads. Поэтому practical policy такая:

- symbol size подбирается так, чтобы `source_symbols = 1`;
- original payload идет обычным `DataFrame`;
- FEC добавляет только `repair packets`;
- recovery успешен, если original потерян, но survive хотя бы один repair packet.

Это по сути превращает `RaptorQ` в explainable coded redundancy для маленьких latency-sensitive messages. Такой режим дешевле для интеграции, проще для dedupe и уже закрывает целевые gaming/interactive scenarios.

## Формулы своевременной доставки

Обозначим:

- `p` - вероятность потери отдельного datagram;
- `r` - число repair packets;
- `T_rtx` - задержка до полезного retransmit recovery;
- `L` - latency budget класса.

### Retransmit-only

Если `T_rtx > L`, то timely delivery для interactive traffic фактически равна:

`P_on_time_retx = 1 - p`

Потому что retransmit может восстановить данные позже, но уже за пределами полезного latency budget.

### Live FEC

При `r` repair datagrams и single-symbol block recovery:

`P_on_time_fec = 1 - p^(r + 1)`

Потому что timely failure случается только если потеряны original и все repair datagrams.

### Численные примеры

Для `p = 0.15`:

- retransmit-only: `0.85`
- `fec_low` (`r = 1`): `1 - 0.15^2 = 0.9775`
- `fec_medium` (`r = 2`): `1 - 0.15^3 = 0.996625`

Для `p = 0.30`:

- retransmit-only: `0.70`
- `fec_low`: `0.91`
- `fec_medium`: `0.973`
- `fec_high` (`r = 3`): `0.9919`

Это и есть главный practical выигрыш фазы: на lossy/bursty links delivery stabilizes сразу, без ожидания ARQ timeout.

## Burst-loss stand

Рассмотрим простой стенд:

- interactive message идет в slot `t0`;
- repair packets идут в `t1` и `t2`;
- burst length = 2 consecutive slots;
- retransmit доступен только после RTT-scale feedback.

Тогда:

- `retransmit-only` проигрывает любому burst, который убивает `t0`, потому что полезный recovery приходит слишком поздно;
- `fec_medium` выживает при любом burst длины 2, если `t1` и `t2` не схлопываются в тот же loss window одновременно с `t0`.

На практике это означает:

- меньше jitter spikes у interactive traffic;
- меньше clustered retransmit storms;
- лучше short-term goodput именно там, где path unstable, а не просто average-lossy.

## Overhead budget

Для single-symbol live FEC rough overhead можно оценить как:

`overhead ~= r * (payload + fec_meta) / payload`

где `fec_meta` - это wire overhead `FecFrame + live FEC header`.

Для payload `240 B` и `fec_meta ~= 24 B`:

- `fec_low`: `264 / 240 = 1.10`, то есть примерно `110%` дополнительного объема;
- `fec_medium`: `220%`;
- `fec_high`: `330%`.

Это выглядит дорого, поэтому policy намеренно ограничена:

- FEC включается только на деградировавшем пути;
- только для small interactive/control blocks;
- bulk получает максимум `fec_low` и только на очень маленьких writes;
- на clean path controller через hysteresis возвращается в `retransmit_only`.

Именно так выполняется acceptance criterion про controlled overhead на чистых сетях: clean path несет `0%` live FEC overhead.

## Anti-oscillation policy

Контроллер не переключает recovery mode мгновенно в обе стороны. Используется простая hysteresis:

- escalation вверх происходит сразу, если path действительно ухудшился;
- rollback вниз разрешается только после серии good samples (`>= 4`);
- `blackhole_suspected` и severe loss имеют приоритет над «красивыми» средними метриками.

Это снижает риск oscillation и скрытых storm-сценариев, где controller начинает дергать redundancy туда-сюда быстрее, чем path успевает стабилизироваться.

## Что реально реализовано в коде

- `TransportEndpoint` умеет `queue_duplicate_message`, `queue_fec_frame` и `discard_message`.
- `CompletedMessage` теперь несет `message_id`, так что dedupe/recovery работают по стабильному identity.
- `LiveFecReceiver` держит decode state, suppresses duplicates и завершает recovery по `block_id`.
- `SessionState` и `ClientState` одинаково:
  - наблюдают path snapshot;
  - выбирают `ProtectionPlan`;
  - ставят duplication/FEC в outbound path;
  - принимают original messages;
  - добирают recovery из `FecFrame`;
  - suppress duplicates после recovery.
- Клиентская диагностика и серверные runtime snapshots теперь показывают:
  - текущую strategy по классам;
  - explanation строки контроллера;
  - `fec_frames_sent/received`;
  - `fec_recoveries`;
  - `suppressed_duplicates`.

## Что проверяется тестами и чем закрывается acceptance

Кодовые проверки:

- `omega-transport/src/raptorq_mgr.rs`:
  - roundtrip encode/decode;
  - recovery with loss;
  - live frame roundtrip;
  - repair-only recovery для single-symbol block;
  - duplicate suppression.
- `omega-transport/src/reliability.rs`:
  - escalation на degraded path;
  - возврат к `retransmit_only` через hysteresis;
  - large messages не получают uncontrolled FEC budget.

Инженерные выводы:

- Burst-loss stand показывает, почему live FEC выигрывает у pure retransmit по latency stability.
- Clean path overhead остается нулевым, потому что controller возвращает `retransmit_only`.
- Explainability не абстрактная: наружу выходят конкретные class strategies, counters и explanation strings.

## Ограничения текущей версии

- Эта фаза intentionally оптимизирована под `sub-MTU`, а не под большие bulk transfers.
- `stealth cover` пока не получает собственного FEC overlay.
- Для больших payloads следующий логичный шаг - multi-symbol coding с отдельной CPU/bandwidth budget validation.

## Вывод

`Phase 05` превращает FEC из «библиотеки в репозитории» в живую часть transport runtime. Это не максималистская схема на все случаи жизни, а production-minded reliability layer: маленький по области применения, понятный по математике, explainable по телеметрии и реально полезный для lossy interactive paths.
