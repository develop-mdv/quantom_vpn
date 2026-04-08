# Stealth Metrics For Omega v2

## Принцип

Stealth в `Omega` измеряется не "ощущением незаметности", а набором рабочих метрик, пригодных для:

- лабораторных стендов;
- nightly regression;
- runtime policy decisions;
- acceptance gate для следующих фаз.

Шенноновская энтропия сама по себе недостаточна, поэтому `Omega v2` использует стек из нескольких метрик.

## Единица анализа

### Окна измерения

- handshake window: первые `8` пакетов или до события `Established`;
- flow window: rolling окно `60s`;
- hostile window: rolling окно `15s` для быстрых mode transitions.

### Обязательные признаки

В лабораторных pcap-замерах MUST собираться:

- размер UDP payload;
- inter-arrival time;
- направление пакета;
- burst length;
- отношение handshake/data/control/fec кадров;
- число различных ответов на invalid probe classes.

В runtime допускаются только агрегаты и гистограммы, без хранения payload.

## M1. Entropy Profile

### Определение

`EntropyProfile` - это вектор:

```text
EP = (H_size_norm, H_iat_norm, H_burst_norm, H_dir_norm)
```

где каждая компонента:

```text
H_norm(X) = -Σ p_i log2(p_i) / log2(k)
```

`k` - число bin-ов соответствующей гистограммы.

### Бины

Базовые бины по размеру UDP payload:

- `0-95`
- `96-191`
- `192-383`
- `384-767`
- `768-1023`
- `1024-1232`
- `>1232`

Базовые бины по `IAT` в миллисекундах:

- `0-2`
- `2-5`
- `5-10`
- `10-20`
- `20-40`
- `40-80`
- `>80`

### Как использовать

`EntropyProfile` нужен не как самоцель, а как ранний сигнал:

- слишком низкая энтропия делает трафик жестко сигнатурным;
- слишком высокая энтропия без привязки к persona часто выглядит как искусственное "шумление".

Следовательно, `Omega` оптимизирует не максимум энтропии, а близость к целевому cover profile.

## M2. Distribution Distance To Persona

### Определение

Для каждой persona фиксируется эталонный профиль `Q`.
Наблюдаемый профиль `P` сравнивается с `Q` через Jensen-Shannon distance.

```text
JSD(P || Q) = 0.5 * KL(P || M) + 0.5 * KL(Q || M)
M = (P + Q) / 2
```

Композитная distance-метрика:

```text
DD_persona =
  0.45 * JSD_size +
  0.35 * JSD_iat +
  0.20 * JSD_burst
```

### Практический смысл

- `JSD_size` ловит слишком узнаваемые size fingerprints;
- `JSD_iat` ловит pacing anomalies;
- `JSD_burst` ловит нереалистичную микроструктуру потока.

`DD_persona` MUST сравниваться по mode budget и по drift относительно прошлых релизов.

## M3. Probing Resistance Score

### Что именно измеряем

`Probing Resistance Score` должен отражать не криптографическую secrecy как таковую, а то, насколько сложно активному prober-у построить oracle.

Используются пять нормализованных компонент:

- `C_collapse`: сколько invalid probe classes схлопываются в малое число ответов;
- `A_bound`: насколько хорошо соблюдается amplification bound;
- `T_indist`: насколько timing invalid paths близок между собой;
- `W_gate`: насколько дорогая работа отложена до validation;
- `G_grease`: насколько transcript содержит rotatable и non-static признаки.

Нормативная формула:

```text
PRS = 100 * (
  0.30 * C_collapse +
  0.25 * A_bound +
  0.20 * T_indist +
  0.15 * W_gate +
  0.10 * G_grease
)
```

### Интерпретация

- `PRS < 50`: протокол дает удобный oracle;
- `50-70`: базовая защита есть, но probing может быть практичным;
- `70-85`: хорошая инженерная устойчивость;
- `> 85`: уровень для `hostile-network`.

## M4. Classifier Baseline Score

### Зачем нужен

Если простые baseline-классификаторы уверенно отделяют `Omega` от целевого cover traffic, stealth недостаточен вне зависимости от субъективных ощущений.

### Нормативный benchmark

Минимальный baseline suite:

- logistic regression;
- random forest;
- gradient boosting.

Опционально:

- lightweight 1D CNN на size/time sequence.

### Фичи

Обязательные feature groups:

- первые `8` handshake packet sizes и directions;
- первые `64` packet sizes для data path;
- bucketized IAT;
- burst statistics;
- ratio control/data/padding/fec.

### Score

Нормативный score:

```text
CBS = max(AUC_lr, AUC_rf, AUC_gb)
```

Нижняя граница идеала - `0.50`.
Чем ближе score к `0.50`, тем меньше baseline-модели умеют распознавать `Omega`.

## M5. Cost Of Stealth

Stealth без измерения цены быстро превращается в бесконтрольный расход latency и bandwidth.

Используются три обязательные cost-метрики:

```text
LatencyCost = (RTT95_mode - RTT95_fast_baseline) / RTT95_fast_baseline
ThroughputCost = 1 - Goodput_mode / Goodput_fast_baseline
ByteCost = (B_total - B_unique_payload) / B_unique_payload
```

При необходимости для decision dashboards можно использовать агрегат:

```text
StealthCost = 0.4 * LatencyCost + 0.4 * ThroughputCost + 0.2 * CpuCost
```

Но нормативными остаются именно отдельные cost-метрики, а не только агрегат.

## M6. Handshake Detectability Budget

Для handshake вводится отдельный набор контрольных величин:

- first datagram size;
- number of datagrams before validation;
- response diversity under malformed input;
- amplification factor;
- fragmentation rate на стенде с path MTU `1280`.

Handshake stealth считается неприемлемым, если любой из этих сигналов стабильно выходит за budget, даже при хорошем steady-state traffic profile.

## Что измеряется в runtime, а что только в лаборатории

| Метрика | Runtime | Lab/pcap |
| --- | --- | --- |
| `EntropyProfile` | Да, по гистограммам | Да |
| `JSD_size/JSD_iat/JSD_burst` | Частично, если есть эталон persona | Да, обязательно |
| `PRS` | Частично, по counters и timing | Да, обязательно |
| `CBS` | Нет | Да, обязательно |
| `LatencyCost/ThroughputCost/ByteCost` | Да | Да |

`CBS` не должен вычисляться на production endpoint-е. Это офлайновая регрессионная метрика.

## Минимальный измерительный pipeline

Чтобы метрики были реально рабочими, pipeline MUST включать:

1. Сбор pcap на стенде по mode/persona/path condition.
2. Экстракцию size/timing/burst features.
3. Сравнение с cover profile.
4. Прогон baseline classifiers.
5. Сравнение c предыдущим release baseline.

## Правила принятия инженерных решений

Фича считается stealth-полезной только если выполняется хотя бы одно:

- снижает `CBS`;
- повышает `PRS`;
- снижает `DD_persona`;
- удерживает те же stealth-метрики при меньшем `LatencyCost` или `ByteCost`.

Фича НЕ считается stealth-полезной, если:

- повышает энтропию, но ухудшает `JSD`;
- делает трафик "хаотичнее", но baseline classifier распознает его лучше;
- повышает `PRS`, но ломает budgets выбранного mode.

## Какие артефакты требуются от следующих фаз

`phase_02`:

- handshake probe corpus;
- amplification and response-collapse measurements.

`phase_03` и `phase_05`:

- transport and reliability traces under controlled loss.

`phase_06`:

- persona library и target cover distributions.

`phase_07`:

- relay-path comparisons и detectability impact of relay changes.

## Чего нельзя делать с этими метриками

Запрещенные упрощения:

- принимать рост энтропии за автоматическое улучшение stealth;
- смотреть только на средние значения и игнорировать `p95`/tails;
- объявлять mode "скрытным", если `CBS` не измерялся;
- использовать единственный target profile для всех network conditions.
