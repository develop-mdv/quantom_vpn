# Phase 02 - Post-Quantum Handshake v2 and Zero-Knowledge Session Lifecycle

## Цель

Перевести handshake протокола на гибридную постквантовую криптографию, скрыть идентичность клиента до безопасной стадии установления сессии и построить расширяемый lifecycle для long-lived stealth-сессий.

## Результат фазы

- Рабочий Handshake v2 на гибридном KEX.
- Stateless retry и anti-amplification защита.
- Privacy-preserving схема device authentication.
- Подготовленная база для resumption, key update и anti-probing.

## Подробное ТЗ

1. **Переспроектировать handshake как явный автомат состояний:**
   `Init -> Retry -> Validated -> Established -> Resumed`, с четкими условиями переходов и отдельной обработкой ошибок.
2. **Реализовать гибридный key exchange:**
   - X25519;
   - ML-KEM-768;
   - единый HKDF schedule;
   - разделение секретов по эпохам и направлениям трафика.
3. **Убрать утечку device identity на ранней стадии:**
   - до завершения безопасной части handshake не передавать `device_id` и `device_token` в виде, пригодном для сигнатурного анализа;
   - минимизировать стабильные поля initial packets.
4. **Сделать anti-amplification и anti-abuse частью протокола, а не побочной логикой:**
   - stateless retry cookies;
   - bounded amplification factor;
   - ограничение дорогостоящей работы до валидации клиента.
5. **Продумать размер и форму первых пакетов:**
   - не провоцировать случайную фрагментацию;
   - спрятать слишком узнаваемые признаки large KEM payload;
   - зафиксировать envelope для дальнейшей stealth-интеграции.
6. **Добавить session resumption и key update:**
   - resumption tickets;
   - обновление traffic secrets без разрыва активной сессии;
   - подготовка к migration и multi-path сценариям.
7. **Научную часть фазы довести до практики:**
   - Zero-Knowledge или близкие по свойствам схемы рассматривать не как обязательный флаг, а как способ реально снизить утечку identity metadata;
   - формальная модель handshake должна служить проверке уязвимостей и уточнению wire design, а не жить отдельно.

## Артефакты

- `docs/HANDSHAKE_PQC_V2.md`
- Модель свойств handshake для ProVerif / Tamarin.
- Оценка накладных расходов (CPU cycles / Byte overhead) для гибридного KEX.

## Acceptance Criteria

- Handshake v2 успешно устанавливает сессию на целевых платформах.
- Сырая device identity не утечет в ранних пакетах в виде, пригодном для простого сигнатурного профилирования.
- Amplification factor ограничен и измерен.
- Handshake packetization не приводит к систематической фрагментации.
- Resumption и key update работают без разрыва сессии.

## Метрики успеха

- Дополнительная RTT-пенальти на слабых устройствах укладывается в бюджет продукта.
- Снижается количество handshake-specific признаков, по которым можно выделять клиента.
- CPU overhead hybrid KEX документирован и контролируем.

## Риски

- Рост размера initial packet из-за ML-KEM может повысить detectability.
- Преждевременное усложнение handshake полноценным ZK может сорвать сроки и увеличить поверхность ошибок.

## Зависимости

- Завершенная Phase 01.

## Комментарий по выполнению

Фаза `phase_02_handshake_v2` успешно выполнена по состоянию на `2026-04-06`.

Итог по результатам:
- реализован `Handshake v2` как явный state machine с путями `Init -> Retry -> Validated -> Established` и `Init -> Retry -> Resumed`;
- внедрен hybrid KEX: `X25519 + ML-KEM-768` с отдельным `app_secret`, `resumption_secret` и `update_secret`;
- ранняя утечка `device_id` и `device_token` убрана: identity передается только внутри encrypted credential envelope после retry/cookie validation;
- anti-amplification встроен в протокол через stateless retry cookie и bounded pre-validation response;
- большой `ML-KEM` payload вынесен из первого пакета и разбит на chunk-ы, чтобы не делать первый flight сигнатурным;
- добавлен resumption path через opaque ticket и локально сохраненный `resumption_secret`;
- заложена база для `key update` через `KeyUpdateFrameV2` и отдельный key schedule;
- подготовлены инженерные артефакты: `docs/HANDSHAKE_PQC_V2.md`, `docs/HANDSHAKE_PQC_COST_ESTIMATE.md`, `docs/models/handshake_v2_proverif.pv`, `docs/models/handshake_v2_tamarin.spthy`;
- workspace verification пройдена: `cargo check --workspace` и `cargo test --workspace` завершились успешно.
