# KPI Baseline And Shannon Calculations

## Назначение

Этот документ переводит stealth/performance/security KPI в формулы и базовые расчеты, которые можно использовать в спецификации, симуляторах и regression-стендах.

## Канонические формулы

### Shannon entropy

Для дискретного распределения `P = {p_1 ... p_k}`:

```text
H(P) = -Σ p_i log2(p_i)
H_norm(P) = H(P) / log2(k)
```

`H_norm` лежит в диапазоне `[0, 1]`.

### Jensen-Shannon distance

```text
JSD(P || Q) = 0.5 * KL(P || M) + 0.5 * KL(Q || M)
M = (P + Q) / 2
```

### Channel cost

```text
RedundancyRatio = (B_retransmit + B_fec + B_duplicate) / B_unique_payload
CoverBudget = (B_padding + B_dummy + B_persona_overhead) / B_unique_payload
ByteCost = (B_total - B_unique_payload) / B_unique_payload
```

### Performance cost

```text
LatencyCost = (RTT95_mode - RTT95_fast_baseline) / RTT95_fast_baseline
ThroughputCost = 1 - Goodput_mode / Goodput_fast_baseline
```

### Anti-amplification

```text
AmplificationFactor_pre_validation =
  BytesSentByServer_pre_validation / BytesReceivedFromClient_pre_validation
```

Нормативный target: `AmplificationFactor_pre_validation <= 1.0`.

## Базовые bins для entropy/JSD

| Измерение | Bin-ы |
| --- | --- |
| UDP payload size | `0-95`, `96-191`, `192-383`, `384-767`, `768-1023`, `1024-1232`, `>1232` |
| IAT ms | `0-2`, `2-5`, `5-10`, `10-20`, `20-40`, `40-80`, `>80` |
| Burst length | `1`, `2`, `3-4`, `5-8`, `9-16`, `>16` |

## Расчет 1. Почему текущий `ClientHello` слишком велик

Текущий handshake несет:

- fixed fields: `4 B`
- `ML-KEM-768` encapsulation key: `1184 B`
- `device_id`: `16 B`
- `device_token`: `32 B`
- `platform + name_len`: `2 B`
- `device_name`: `N B`

Итого:

```text
ClientHello payload = 1238 + N
STUN-wrapped payload = 1258 + N
IPv4 total = 1286 + N
IPv6 total = 1306 + N
```

Примеры:

| `device_name` length | Payload | STUN | UDP/IPv4 total | UDP/IPv6 total |
| --- | --- | --- | --- | --- |
| `0` | `1238` | `1258` | `1286` | `1306` |
| `10` | `1248` | `1268` | `1296` | `1316` |
| `32` | `1270` | `1290` | `1318` | `1338` |

Следствие:

- даже пустой `device_name` не помещается в безопасный IPv6 UDP budget `1232`;
- handshake MUST быть разбит на несколько transcript stages;
- ранняя device identity MUST быть убрана из первого пакета.

## Расчет 2. Базовая эффективность текущего datapath

Текущий фиксированный overhead datapath:

```text
RTP header 12 B + Omega header 21 B + AEAD tag 16 B = 49 B
```

Эффективность без padding/redundancy:

```text
PayloadEfficiency = Payload / (Payload + 49)
```

Примеры:

| Payload | Efficiency |
| --- | --- |
| `64 B` | `0.5664` |
| `256 B` | `0.8393` |
| `512 B` | `0.9127` |
| `1200 B` | `0.9608` |

Вывод:

- для маленьких пакетов fixed overhead очень дорог;
- heavy cover/padding на мелких пакетах особенно быстро съедает goodput;
- product modes обязаны жить в численных budgets, а не в "чем больше padding, тем лучше".

## Расчет 3. Shannon entropy на простом примере

Пусть наблюдаем распределение packet-size bins:

```text
P_spiky = [0.70, 0.20, 0.08, 0.02]
P_flat  = [0.35, 0.30, 0.20, 0.15]
```

Тогда:

| Distribution | `H(P)` | `H_norm(P)` |
| --- | --- | --- |
| `P_spiky` | `1.2290` | `0.6145` |
| `P_flat` | `1.9261` | `0.9631` |

Это полезно как индикатор, но не как конечный stealth verdict.

Почему:

- `P_flat` выглядит менее сигнатурно по entropy;
- но если целевая persona на самом деле близка к `P_spiky`, то `P_flat` может быть хуже по detectability.

## Расчет 4. JSD как более практичная stealth-метрика

Для:

```text
P = [0.70, 0.20, 0.08, 0.02]
Q = [0.35, 0.30, 0.20, 0.15]
```

получаем:

```text
JSD(P || Q) = 0.1099
```

Инженерный смысл:

- entropy говорит "насколько распределение размазано";
- `JSD` говорит "насколько оно похоже на нужный cover profile".

Именно поэтому `phase_00` фиксирует `JSD` и `CBS` как обязательные companions к Shannon-based анализу.

## Расчет 5. Goodput price по режимам

Для payload `512 B` и budgets из product modes:

```text
TotalBytesPerUsefulPayload =
  512 + 49 + 512 * CoverBudget + 512 * RedundancyRatio
```

Получаем:

| Mode | Total bytes | Payload efficiency |
| --- | --- | --- |
| `fast` | `627.56` | `0.8159` |
| `balanced` | `729.96` | `0.7014` |
| `stealth` | `883.56` | `0.5795` |
| `hostile-network` | `852.84` | `0.6006` |

Вывод:

- `stealth` платит больше за similarity и pacing freedom;
- `hostile-network` платит почти столько же, но байты уходят на survivability, а не на heavy cover;
- эти режимы нельзя смешивать в одном budget.

## Расчет 6. Latency cost на понятном baseline

Если `RTT95_fast_baseline = 42 ms`, то:

| Mode RTT95 | `LatencyCost` |
| --- | --- |
| `54 ms` | `0.2857` |
| `68 ms` | `0.6190` |
| `87 ms` | `1.0714` |

Отсюда видно:

- `hostile-network` может оставаться valid mode даже при большой latency-пенальти, если он сохраняет `SuccessRate`;
- для `fast` и `balanced` такие значения были бы неприемлемы.

## KPI, которые становятся обязательными для следующих фаз

### Security KPI

- `AmplificationFactor_pre_validation <= 1.0`
- no raw device identity before validated stage
- successful key update without session teardown
- replay attempts do not recreate valid session state

### Performance KPI

- `LatencyCost` и `ThroughputCost` по каждому mode
- goodput under controlled loss
- session continuity under NAT rebinding/path change

### Stealth KPI

- `EntropyProfile`
- `JSD_size`, `JSD_iat`, `JSD_burst`
- `CBS`
- `PRS`

## Как эти расчеты применять на практике

1. Любая новая stealth-идея сначала проверяется против `JSD`, а не только против `H_norm`.
2. Любая reliability-идея должна выражаться через `RedundancyRatio` и `LatencyCost`.
3. Любая handshake-идея должна проверяться против `AmplificationFactor` и packetization budget.
4. Любой новый mode обязан иметь численный cost profile.

Если предложение нельзя подставить в эти формулы, оно еще недостаточно инженерно сформулировано для `Omega v2`.

