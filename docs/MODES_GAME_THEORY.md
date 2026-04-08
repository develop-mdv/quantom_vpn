# Omega Product Modes And Game Theory

## Зачем нужен этот документ

`fast`, `balanced`, `stealth` и `hostile-network` - это не маркетинговые названия, а заранее определенные стратегии поведения протокола под разный риск-профиль сети и наблюдателя.

Каждый mode фиксирует:

- допустимую latency-пенальти;
- предел redundancy;
- предел cover budget;
- detectability budget;
- правила escalation и fallback.

## Общая функция полезности

В `Omega v2` mode выбирается как решение задачи:

```text
U(mode) =
  w_success * SuccessRate
  - w_latency * LatencyCost
  - w_bytes * ByteCost
  - w_detect * DetectabilityRisk
  - w_instability * FailureRisk
```

Разные режимы меняют веса:

| Mode | Что максимизируем |
| --- | --- |
| `fast` | Полезную производительность при умеренном риске детекта |
| `balanced` | Компромисс stealth/throughput/reliability |
| `stealth` | Минимизацию detectability при приемлемой usable performance |
| `hostile-network` | Вероятность живого соединения в агрессивной сети |

## Канонические бюджеты

### Определения

- `LatencyCost = (RTT95_mode - RTT95_fast_baseline) / RTT95_fast_baseline`
- `RedundancyRatio = (B_retransmit + B_fec + B_duplicate) / B_unique_payload`
- `CoverBudget = (B_padding + B_dummy + B_persona_overhead) / B_unique_payload`
- `DetectabilityBudget = {JSD_size, JSD_iat, CBS, PRS}`

`CBS` и `PRS` определены в `STEALTH_METRICS.md`.

### Нормативная таблица режимов

| Mode | `LatencyCost` | `RedundancyRatio` | `CoverBudget` | `JSD_size` | `JSD_iat` | `CBS` | `PRS` |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `fast` | `<= 0.20` | `<= 0.08` | `<= 0.05` | `<= 0.20` | `<= 0.22` | `<= 0.72` | `>= 45` |
| `balanced` | `<= 0.35` | `<= 0.18` | `<= 0.15` | `<= 0.14` | `<= 0.16` | `<= 0.64` | `>= 60` |
| `stealth` | `<= 0.75` | `<= 0.28` | `<= 0.35` | `<= 0.08` | `<= 0.10` | `<= 0.58` | `>= 75` |
| `hostile-network` | `<= 1.20` | `<= 0.45` | `<= 0.12` | `<= 0.15` | `<= 0.18` | `<= 0.63` | `>= 85` |

Ключевая инженерная идея:

- `stealth` тратит больше байтов на shape similarity;
- `hostile-network` тратит больше байтов на survivability и probe-hardening, а не на большой dummy cover.

## Поведение каждого режима

### `fast`

Назначение:

- минимальная latency-пенальти;
- лучший gaming/interactive UX;
- допустим более заметный wire image.

Нормативное поведение:

- прямой или минимально сложный path;
- небольшой padding budget;
- только ограниченная extra redundancy;
- ускоренный rekey не обязателен, если нет риска probing.

Fallback policy:

- при loss ratio `> 1.5%` на окне `15s` перейти в `balanced`;
- при repeated malformed probing или suspicious transcript behavior перейти в `stealth`;
- при silent post-handshake drop или forced MTU collapse перейти в `hostile-network`.

### `balanced`

Назначение:

- дефолтный режим продукта;
- рабочий компромисс между stealth и throughput.

Нормативное поведение:

- умеренный padding;
- адаптивная redundancy;
- ограниченный persona shaping по размерам и таймингам;
- готовность к мягкой relay escalation.

Fallback policy:

- в `fast`, если сеть стабильна, loss низкий и policy разрешает low-latency bias;
- в `stealth`, если classifier/probing risk повышен;
- в `hostile-network`, если path деградирует и появляются признаки hostile UDP environment.

### `stealth`

Назначение:

- минимизировать detectability при условии, что сессия остается пригодной к использованию;
- делать wire image похожим на выбранную persona, а не просто "зашумленным".

Нормативное поведение:

- высокий cover budget;
- более строгий pacing;
- handshake persona и data persona должны быть согласованы;
- policy SHOULD чаще разрешать relay usage и earlier key update;
- стабильные ошибки и ответные transcript-ветки должны быть максимально схлопнуты.

Fallback policy:

- в `balanced`, если stealth budgets удерживаются и сеть стабильна, но product utility падает из-за overhead;
- в `hostile-network`, если сеть начинает actively punish shaping и нужно спасать connectivity.

### `hostile-network`

Назначение:

- сохранить живое соединение в сети, которая активно мешает UDP path;
- переживать selective drop, MTU damage, route coercion и probing.

Нормативное поведение:

- меньший packetization budget;
- lower MTU preference;
- более высокий redundancy/FEC budget;
- anti-probing жестче, чем в остальных режимах;
- relay/path diversification допускается чаще, чем heavy dummy cover.

Fallback policy:

- в `balanced` только после устойчивого окна стабильности не меньше `5` минут;
- в `stealth`, если hostile pressure спал, но detectability risk остался высоким.

## Mode transition rules

Для policy engine фиксируется базовый transition contract:

| Переход | Триггер |
| --- | --- |
| `fast -> balanced` | sustained loss, растущий NACK/retransmit pressure, latency drift |
| `balanced -> fast` | длительная стабильность и low-risk policy |
| `balanced -> stealth` | высокий detectability risk, policy mandate, probing pressure |
| `stealth -> balanced` | overhead превышает budget, а detectability risk снижен |
| `balanced -> hostile-network` | silent UDP degradation, MTU collapse, repeated post-handshake failure |
| `hostile-network -> balanced` | устойчивое окно стабильности и нормализация path |

Transition MUST быть hysteresis-aware, чтобы избежать oscillation.

## Hysteresis и антифлаппинг

Для всех auto-transitions действуют правила:

- режим не меняется чаще, чем один раз в `30` секунд;
- downgrade из более дорогого режима допускается только после окна стабильности;
- upgrade в более защитный режим допускается быстрее, чем downgrade;
- ручной operator policy имеет приоритет над автоматикой.

## Связь с текущими профилями проекта

Текущие runtime-профили уже можно трактовать как промежуточные аналоги:

| Текущий профиль | Ближайший будущий mode |
| --- | --- |
| `gaming` | `fast` |
| `general_internet` | `balanced` |
| `restricted_fallback` | `hostile-network` |

Это не один-в-один mapping, но именно так нужно мыслить migration path.

## Что mode обязан определять в policy object

Каждый product mode MUST приводить к concrete runtime policy:

- packetization ceiling;
- padding budget cap;
- pacing profile;
- redundancy/FEC policy;
- relay eligibility;
- key update cadence;
- observability verbosity;
- fallback sequence.

Если режим не определяет хотя бы эти поля, он не считается инженерно завершенным.

## Что считается провалом режима

Mode считается нерабочим, если:

- формально соблюден только latency budget, но провален `PRS` или `CBS`;
- сеть выживает только за счет перехода в другой режим, а текущий называется "рабочим";
- detectability budget не выражен числами;
- runtime не может объяснить, почему выбрал этот mode и из-за какого триггера покинул его.

