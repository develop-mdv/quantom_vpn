# Dolev-Yao Threat Model For Omega v2

## Назначение документа

Этот документ задает threat model, которая реально управляет архитектурой `Omega v2`, а не существует отдельно от кода.

Модель состоит из двух слоев:

1. Символический слой в духе Dolev-Yao: сеть считается полностью контролируемой противником.
2. Операционный слой: добавляются реальные ограничения интернета, DPI, relay compromise, degraded UDP и control plane partial compromise.

## Границы системы

В модели участвуют:

- `C`: клиентский runtime;
- `E`: edge ingress;
- `R`: relay;
- `X`: exit;
- `P`: control plane;
- публичная сеть между ними.

За пределами модели как trusted boundary находятся только:

- локальная память живого процесса до его компрометации;
- корректность используемых криптопримитивов;
- доверенный код, который реально исполняется без supply-chain компромисса.

## Основные активы

Что именно мы защищаем:

1. Конфиденциальность tunneled payload.
2. PFS для завершенных сессий.
3. Сокрытие device identity до безопасной стадии handshake.
4. Аутентичность session admission и control policy.
5. Устойчивость к replay, probing и forced path degradation.
6. Ограничение blast radius при компрометации relay/control части.
7. Наблюдаемость без лишней утечки оператору или сети.

## Базовые допущения

Threat model честно опирается на следующие assumptions:

- AEAD, HKDF, X25519 и ML-KEM-768 считаются криптографически корректными в рамках принятых гипотез.
- Клиентское устройство при полном компромиссе не может гарантировать secrecy уже украденных живых ключей.
- Не предполагается, что все relay, все control plane узлы и оба endpoint-а компрометированы одновременно до установления и во время жизни каждой сессии.
- Оператор может совершать ошибки конфигурации, поэтому часть control plane компромиссов рассматривается как реалистичный сценарий, а не как экзотика.

## Классы противника

### A1. Пассивный наблюдатель на L3/L4

Возможности:

- видеть размеры, тайминги, адреса, длительность и направление пакетов;
- собирать статистику по handshake и длительным сессиям;
- строить size/timing classifiers.

Не может:

- нарушать криптографию;
- менять пакеты в транзите.

Главная цель:

- отличить `Omega` от целевого cover traffic;
- связать наблюдения с конкретным устройством или mode profile.

### A2. Активный модификатор и инжектор пакетов

Возможности:

- дропать, дублировать, задерживать, переупорядочивать пакеты;
- инжектировать собственные datagram-ы;
- делать replay старых пакетов;
- форсировать path migration и congestion-like аномалии.

Главная цель:

- сорвать handshake;
- создать distinguishable error behavior;
- вызвать session desync, retransmit storm или amplification.

### A3. Активный prober / DPI

Возможности:

- отправлять невалидные, почти валидные и адаптивно мутирующие handshake-пакеты;
- измерять timing, packet size и response diversity;
- повторять probing с большого числа адресов.

Главная цель:

- получить oracle, по которому `Omega` можно сигнатурно распознать;
- заставить сервер выполнять дорогую работу до валидации клиента;
- извлечь стабильные признаки protocol stack.

### A4. Хостильный провайдер или сеть с деградацией UDP

Возможности:

- rate-limit UDP;
- selectively drop large packets;
- портить MTU;
- допускать только узкий класс traffic patterns;
- принудительно ухудшать маршрут после успешного handshake.

Главная цель:

- сделать протокол непрактичным без явной блокировки;
- спровоцировать скрытую деградацию качества;
- вынудить клиента выбрать легко классифицируемое поведение.

### A5. Частично компрометированный relay/control контур

Возможности:

- получить секреты, policy objects или метаданные одного edge/relay/control узла;
- подменять path decisions или admission ответы в пределах компрометированного узла;
- собирать telemetry и session metadata, доступные этому узлу.

Главная цель:

- увеличить blast radius компрометации;
- deanonymize пользователей через control/relay correlation;
- выдавать вредные policy для ухудшения detectability или availability.

## Матрица возможностей по доменам

| Противник | Handshake | Transport | Stealth | Relay fabric | Control plane |
| --- | --- | --- | --- | --- | --- |
| A1 | Видит transcript sizes/timings | Видит packet cadence | Строит classifier | Видит path shape | Видит только то, что утечет по сети |
| A2 | Replay, drop, inject | Reorder, loss, tamper | Ломает pacing assumptions | Форсирует migration | Может подменять in-flight ответы без server auth |
| A3 | Активно probe-ит transcript | Вызывает edge cases | Ищет distinguishable responses | Проверяет relay exposure | Имитирует клиентов и edge узлы |
| A4 | Режет большие initial packets | Деградирует UDP path | Наказывает лишний cover overhead | Рвет multi-hop | Косвенно ломает policy outcome через path conditions |
| A5 | Читает или меняет локальный handshake state узла | Видит local session metadata | Узнает persona policy, если она локальна | Компрометирует hop graph | Подделывает admission/policy в пределах доступа |

## Security goals в формальном виде

### G1. Payload secrecy

Если `C` и terminating server-side role честны на момент сессии, а криптографические предпосылки выполняются, то A1-A4 не должны узнавать plaintext tunneled payload.

### G2. Forward secrecy

Если компрометация long-term control или device metadata происходит после завершения сессии, это не должно раскрывать прошлый tunneled payload.

### G3. Identity pre-protection

До события `Validated(session)` A1-A4 не должны получать raw device identity или пригодный для устойчивой корреляции device fingerprint.

### G4. Bounded amplification

До события `Validated(session)` сервер не должен посылать клиенту больше байт, чем клиент подтвердил своей достижимостью, кроме явно ограниченного технического epsilon.

### G5. Replay safety

Повтор старого handshake или transport packet не должен:

- восстанавливать старую сессию без разрешения;
- приводить к state confusion;
- открывать oracle по control decisions.

### G6. Compartmentalization

Компрометация одного relay/control узла не должна автоматически давать:

- расшифровку прошлых сессий;
- полный граф всех relay choices;
- глобальную возможность подделывать admission для всех users/devices.

## Архитектурные решения, которые прямо следуют из threat model

### TM-01. Ранний handshake без стабильной identity

Поскольку A1 и A3 видят/прощупывают первые пакеты, `Init` MUST не нести `device_id` и `device_token` в открытом виде.

### TM-02. Stateless retry и bounded work

Поскольку A2 и A3 могут массово инжектировать пакеты, до cookie validation сервер MUST:

- держать bounded amplification;
- избегать дорогих state allocations;
- избегать полного гибридного KEX на каждый произвольный input.

### TM-03. Transcript collapse

Поскольку A3 ищет сигнатурные различия, невалидные пакеты SHOULD вести к малому числу различимых исходов:

- молчание;
- stateless retry;
- минимальный reject после безопасной стадии.

### TM-04. Path-aware protocol

Поскольку A4 может selective-drop large UDP packets и наказывать burstiness, packetization MUST быть частью протокола, а не "сетевой настройки потом".

### TM-05. Migration-first session model

Поскольку A2 и A4 способны вызывать rebinding и route churn, session continuity MUST быть отделена от `src_addr`.

### TM-06. Stealth budgets вместо интуиции

Поскольку A1 и A3 строят classifiers, stealth MUST измеряться через `entropy`, `JSD`, `classifier baseline` и `probing resistance`, а не субъективно.

### TM-07. Control plane scoping

Поскольку A5 реалистичен, control objects MUST быть:

- scoped;
- versioned;
- rotatable;
- auditable.

### TM-08. Relay blast radius limits

Компрометация одного relay MUST ограничиваться видимостью и возможностями этого relay. Глобальные мастер-секреты всей fabric модели недопустимы.

## Что именно должен выдерживать каждый домен

| Домен | Обязательная устойчивость |
| --- | --- |
| Handshake | A1, A2, A3 и частично A4 до уровня безопасного establishment |
| Transport | A1, A2, A4 при сохранении confidentiality/integrity и controlled degradation |
| Stealth engine | A1, A3, частично A4 через budgets и transcript collapse |
| Relay fabric | A1-A4 на сетевом уровне и A5 на узловом уровне |
| Control plane | A2 через authenticated policy delivery и A5 через scoped trust model |

## Что не считается провалом модели

Следующие вещи не трактуются как нарушение threat model, потому что это не обещание продукта:

- обнаружение факта "есть какой-то нестандартный UDP-трафик" глобальным всевидящим наблюдателем;
- полная невидимость при полном endpoint compromise;
- отсутствие любых performance потерь в `stealth` или `hostile-network`;
- защита от оператора, который одновременно контролирует client endpoint, edge, control plane и exit.

## Практические сценарии атаки и обязательный ответ архитектуры

| Сценарий | Класс | Обязательный ответ |
| --- | --- | --- |
| Passive classifier различает первый пакет по размеру | A1 | Handshake split, `<= 900 B` first flight, hidden identity |
| Replay старого `AuthCommit` | A2 | Freshness, cookie binding, ticket replay limits |
| Prober шлет почти корректный transcript и смотрит на timing | A3 | Transcript collapse, bounded work, indistinguishable reject classes |
| Сеть режет все UDP payload > `1200 B` | A4 | Packetization below safe MTU, hostile-network mode, relay/path adaptation |
| Компрометирован один relay | A5 | Scoped secrets, no global decryption, policy isolation |
| Компрометирован admission controller после завершения сессии | A5 | PFS, non-recoverable traffic secrets |

## Какие свойства должны быть верифицированы формально

Минимальный обязательный набор для `phase_02`:

- secrecy of traffic secrets;
- authentication between client and accepting server role;
- absence of early identity disclosure in symbolic transcript;
- replay-resistance for retry/ticket paths;
- agreement on session identifiers and epochs.

## Какие свойства должны проверяться экспериментом

Минимальный обязательный набор для `phase_03+`:

- packetization under MTU stress;
- classifier resistance на pcap datasets;
- probing resistance under malformed and adaptive transcripts;
- degradation behavior under loss/jitter/drop shaping;
- blast radius simulation при relay/control compromise.

## Резидуальные риски

Даже при выполнении этой threat model остаются риски:

- persona drift со временем делает старый cover-профиль детектируемым;
- оператор может ошибочно включить слишком шумную observability;
- hostile network может сделать протокол экономически дорогим даже без полного блокирования;
- partial compromise control plane может ухудшить detectability через вредные policy, даже если не раскрывает payload.

Именно поэтому `Omega v2` рассматривает stealth, reliability и policy как связанные подсистемы, а не независимые улучшения.
