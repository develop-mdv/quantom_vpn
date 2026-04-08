# Omega Protocol v2 Formal Spec

## Статус документа

Этот документ является нормативной архитектурной базой для `Omega v2`.

- Формулировки `MUST`, `SHOULD`, `MAY` используются в инженерно-нормативном смысле.
- Документ фиксирует целевую модель продукта для `phase_01+`.
- Текущий код в репозитории является рабочим alpha-контуром и не считается полной реализацией этой спецификации.

## Зачем нужен `v2`

Текущая реализация уже доказывает жизнеспособность собственного UDP-туннеля, но в ней есть ограничения, которые нельзя оставлять неформализованными:

1. Device identity раскрывается слишком рано. Сейчас `ClientHello` несет `device_id` и `device_token` до установления безопасной стадии handshake.
2. Первый пакет слишком велик для "тихого" поведения на плохих путях. Размер текущего `ClientHello`:
   - payload: `1238 + device_name_len` байт;
   - STUN envelope: `1258 + device_name_len` байт;
   - c UDP/IPv4: `1286 + device_name_len` байт;
   - c UDP/IPv6: `1306 + device_name_len` байт.
3. Даже при пустом `device_name` пакет превышает безопасный для IPv6 UDP budget `1232` байта (`1280 - 40 - 8`), а значит провоцирует фрагментацию и сигнатурность.
4. В протоколе еще не зафиксированы как обязательные свойства `key update`, `session migration`, `resumption`, anti-amplification и формальный stealth budget.

Из этого следует главное решение `phase_00`: `Omega v2` MUST быть спроектирован как stealth-first протокол с отдельными инвариантами для handshake, transport, stealth engine, relay fabric и control plane.

## Что считается "собственным протоколом"

`Omega v2` считается собственным протоколом только если в продукте существуют и развиваются как независимые домены все пять слоев ниже:

| Домен | Что является собственной логикой `Omega` | Что не допускается как архитектурная подмена |
| --- | --- | --- |
| Handshake lifecycle | Собственный state machine, transcript, anti-abuse, resumption, key update schedule | Передача установления сессии внешнему VPN-протоколу |
| Transport frame layer | Собственные frame-типы, packet number/epoch model, reliability/FEC semantics | Использование чужого datapath как "основного канала" |
| Stealth engine | Собственные personas, shaping, pacing, cover budgets, wire image control | Маскировка как косметический padding поверх чужого транспорта |
| Relay fabric | Собственные edge/relay/exit роли, path policy, admission, relay capability model | Прозрачный L4 proxy без собственной policy/runtime логики |
| Control plane | Собственная policy model, session admission, revocation, telemetry contract | Размазанная по runtime логика без формальной модели состояний |

Если хотя бы один из этих доменов подменяется готовым VPN как "основой", продукт перестает соответствовать этой спецификации.

## Цели протокола

`Omega v2` MUST одновременно оптимизировать:

- secrecy и forward secrecy трафика;
- сокрытие device identity до безопасной стадии handshake;
- устойчивость к replay, probing и path degradation;
- управляемость wire image через product modes;
- возможность session continuity при NAT rebinding, path migration и relay migration;
- инженерную измеримость stealth/performance/security свойств.

## Не-цели

Эта спецификация честно не обещает:

- полную неразличимость от произвольного интернет-трафика для глобального противника;
- защиту при полном компромиссе endpoint-устройства;
- бесплатную stealth-функциональность без latency/throughput overhead;
- мгновенную устойчивость к любому государственному DPI без итеративных измерений и обновлений personas.

## Нормативные инварианты

### INV-01. PFS и гибридный KEX

Каждая новая сессия MUST использовать ephemeral секреты и MUST смешивать как минимум:

- `X25519`;
- `ML-KEM-768`.

Нормативная схема key schedule:

```text
ikm = x25519_shared || mlkem768_shared
early_secret = HKDF-Extract(0, ikm)
handshake_secret = HKDF-Expand(early_secret, "omega hs" || transcript_hash)
app_secret_0 = HKDF-Expand(handshake_secret, "omega app 0" || transcript_hash)
resumption_master = HKDF-Expand(app_secret_0, "omega resume" || transcript_hash)
update_master = HKDF-Expand(app_secret_0, "omega update" || transcript_hash)
```

Точные label-и и transcript framing будут заморожены в `phase_02`, но принцип гибридного KEX и иерархии секретов фиксируется уже сейчас.

### INV-02. Device identity скрывается до безопасной стадии

До завершения anti-amplification и reachability validation клиент MUST NOT передавать:

- `device_id` в открытом виде;
- `device_token` в открытом виде;
- стабильный идентификатор устройства или пользователя, пригодный для сигнатурного профилирования.

Допустимы только:

- ephemeral ключи;
- capability hints без стабильной идентичности;
- cookie/retry proof;
- зашифрованный или privacy-preserving credential envelope.

### INV-03. Replay resistance

Протокол MUST иметь защиту от replay на двух уровнях:

- handshake: через freshness tokens, transcript binding и ограниченную валидность retry/cookie;
- transport: через packet numbers, epoch binding и sliding anti-replay window.

Resumption tickets MUST быть либо одноразовыми, либо иметь явно ограниченный replay window и bind к policy context.

### INV-04. Key update

Transport secrets MUST обновляться без разрыва сессии:

- по времени: не реже одного раза в `10` минут;
- по объему: не реже одного раза в `2^20` пакетов на направление;
- по событию: при mode escalation, path migration, relay migration или policy-triggered re-auth.

Смежные эпохи MUST приниматься в overlap-окне, достаточном для reordering, но не бесконечно. Базовый budget: `max(3 * PTO, 128 пакетов)`.

### INV-05. Migration и session continuity

Session identity MUST быть отделена от конкретного `src_addr`.

Протокол MUST поддерживать:

- NAT rebinding без полного re-handshake;
- path validation challenge/response;
- relay migration без повторного раскрытия device identity;
- resumable session lifecycle для кратковременных потерь связности.

### INV-06. Управляемый wire image

Wire image MUST быть параметризован через `persona` и `mode`.

Это означает:

- первые пакеты handshake не должны иметь один жестко узнаваемый размерный паттерн;
- data plane не должен иметь единственный фиксированный timing/size профиль;
- stealth engine должен менять shaping, не ломая transport correctness;
- detectability MUST управляться бюджетами, а не фразой "сделать скрытнее".

## Состояния протокола

Минимальный state machine `Omega v2`:

```text
Init -> Retry -> Validated -> Established -> Updating -> Migrating -> Closing -> Closed
                       \-> Resumed ----------/
```

### `Init`

Клиент отправляет первичное сообщение без стабильной device identity.

`Init` MUST:

- укладываться в pre-validation budget;
- содержать только ephemeral и grease-поля;
- не заставлять сервер выполнять дорогостоящую stateful работу без ограничения.

### `Retry`

Сервер может ответить stateless cookie/retry.

`Retry` MUST:

- ограничивать amplification factor;
- доказывать reachability клиента;
- не создавать distinguishable oracle для unauthenticated probes.

### `Validated`

Клиент подтверждает cookie и предоставляет зашифрованный credential envelope.

На этой стадии сервер MAY перейти к более дорогой криптографии и state allocation.

### `Established`

Стороны получают transport secrets, session handle, mode policy, path parameters и начальную persona.

### `Resumed`

Сессия восстанавливается через resumption ticket или аналогичный scoped secret без полной процедуры идентификации.

### `Updating`

Идет rekey без разрыва сессии и без смены product mode по умолчанию.

### `Migrating`

Меняется path/relay/edge, но сессия продолжает существовать после path validation.

## Handshake packetization budget

`Omega v2` MUST прямо учитывать path MTU и антифрагментационный дизайн.

| Этап | Нормативный предел | Причина |
| --- | --- | --- |
| Первый клиентский datagram до validation | `<= 900 B` UDP payload | Минимизировать сигнатурность и избежать пограничной фрагментации |
| Первый ответ сервера до validation | `<= размеру принятого datagram` | Anti-amplification |
| Любой handshake datagram на общем интернете | `<= 1232 B` UDP payload | Безопасный IPv6 budget |
| Handshake transcript до `Established` | MUST быть packetizable без обязательной IP fragmentation | Устойчивость на плохих путях |

Из этого следует архитектурное решение:

- гибридный KEX MUST быть распределен по transcript-стадиям;
- большие криптографические артефакты MUST NOT концентрироваться в одном первом пакете;
- `phase_02` MUST реализовать multi-flight envelope.

## Frame layer `v2`

Бинарная раскладка frame layer будет уточняться в `phase_03`, но semantic contract фиксируется сейчас.

Каждый transport packet MUST включать:

- `connection_id` или эквивалент session handle;
- `path_id`;
- `packet_number`;
- `epoch`;
- frame set;
- AEAD protection над transport metadata.

Обязательные frame-классы:

- `STREAM_DATA` или эквивалент полезной нагрузки;
- `ACK` и/или `NACK`;
- `FEC_PARITY` и `FEC_CONTROL`;
- `PATH_CHALLENGE` / `PATH_RESPONSE`;
- `KEY_UPDATE`;
- `PING` / keepalive;
- `CLOSE`;
- `PADDING`.

Stealth persona MAY влиять на outer envelope, pacing и padding, но MUST NOT менять семантику correctness frame-слоя.

## Relay fabric

`Omega v2` проектируется не как одиночный "сервер с UDP", а как fabric из ролей:

- `edge`: первая точка приема;
- `relay`: промежуточный hop для path diversification;
- `exit`: точка выхода в интернет;
- `controller`: admission, policy, revocation, telemetry.

Нормативные требования:

- compromise одного relay MUST ограничивать blast radius и не раскрывать все control plane секреты;
- path selection MUST опираться на mode policy и path intelligence;
- relay fabric MUST поддерживать degradation от multi-hop к direct edge без полной архитектурной перестройки.

## Control plane и policy model

Control plane MUST быть явной подсистемой, а не набором env-флагов и ad-hoc runtime решений.

Policy object MUST определять:

- допустимые `modes`;
- allowed personas;
- relay eligibility;
- resumption lifetime;
- key update cadence override;
- observability/privacy budget;
- fallback rules.

Policy decision MUST быть bind-нут к session transcript или session admission token.

## Что должно быть доказано математикой, а что измерениями

| Тема | Тип строгости | Что считается завершением |
| --- | --- | --- |
| Secrecy, authentication, replay safety handshake | Формальная модель + тесты | Модель свойств в ProVerif/Tamarin и unit/integration tests |
| Anti-amplification factor | Арифметическое ограничение + property tests | Явно доказанный bound и тесты на transcript branches |
| Key schedule separation | Формальная криптографическая аргументация | Документированный HKDF schedule и negative tests |
| Packet size / IAT shaping | Инженерная эвристика + измерения | Pcap-анализ, JSD/CBS budget и regression bench |
| FEC scheduling и redundancy policy | Симулятор + стенд | Loss-simulator + live tests |
| Path scoring и relay selection | Эвристика, проверенная экспериментом | Decision memo + controlled rollout data |

## Открытые вопросы и их владельцы

| Вопрос | Решение фазы 00 | Где закрывается окончательно |
| --- | --- | --- |
| Точная бинарная форма `InitHello/AuthCommit` | Фиксируется только envelope и budgets | `phase_02` |
| Конкретный набор frame-типов и ACK/NACK/FEC grammar | Фиксируется semantic contract | `phase_03` и `phase_05` |
| Persona library и cover targets | Фиксируются метрики и бюджеты | `phase_06` |
| Relay path policy | Фиксируются роли и blast-radius требования | `phase_07` |
| Policy object schema | Фиксируются обязательные поля | `phase_08` |

## Инженерные последствия для следующих фаз

`phase_01` MUST разделить workspace так, чтобы handshake, wire, stealth, relay и control plane могли развиваться независимо.

`phase_02` MUST:

- убрать раннюю утечку device identity;
- реализовать гибридный KEX как multi-flight transcript;
- доказать bounded amplification;
- заложить resumption и key update.

`phase_03+` MUST трактовать stealth engine как отдельный домен над transport, а не как случайный padding в datapath.

## Критерий готовности этой спецификации

Спецификация `phase_00` считается готовой, если любая следующая фича может быть проверена вопросами:

1. Какие инварианты `INV-*` она обязана сохранить?
2. В каком состоянии протокола она действует?
3. Какой budget по размеру, detectability и migration она потребляет?
4. Нужна ли для нее математика, стенд или достаточно runtime-эвристики?

Если на любой из этих вопросов нельзя ответить, работа выходит за пределы допустимой неопределенности `Omega v2`.
