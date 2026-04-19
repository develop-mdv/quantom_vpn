# Phase 09 - Probabilistic UX & Cognitive Ergonomics of Clients

## Цель

Довести клиент до product-grade состояния: надежное подключение, понятные профили, хорошая диагностика, безопасные обновления и при этом сохранить пространство для умного вероятностного UX там, где он реально помогает пользователю.

## Результат фазы

- Product-grade desktop clients.
- Простая модель режимов для обычного пользователя.
- Advanced diagnostics и secure update path.

## Подробное ТЗ

1. **Сделать основной desktop-клиент с полноценным рабочим UX:**
   - connect/disconnect;
   - выбор профиля;
   - статус подключения;
   - reconnect;
   - tray/background mode;
   - экспорт диагностики.
2. **Свести продуктовые режимы к понятной пользовательской модели:**
   техническая сложность transport/stealth не должна выливаться в перегруженный UI.
3. **Сделать human-readable диагностику:**
   клиент должен объяснять, что сломалось, на каком уровне это произошло и что можно сделать автоматически.
4. **Реализовать безопасный update channel:**
   защита от подмены обновлений и понятный trust model для клиентских релизов должны быть частью продукта, а не послесловием.
5. **Разделить UI и privileged/runtime части клиента:**
   локальный сбой интерфейса не должен разрушать transport и сетевые компоненты.
6. **Использовать вероятностные и UX-исследования только для усиления понятности:**
   confidence intervals, stealth score, path confidence и другие продвинутые представления нужны там, где они реально помогают пользователю или оператору, а не перегружают интерфейс.

## Артефакты

- `docs/TUF_UPDATE_SPEC.md`
- Спецификация клиентского UX и diagnostics flows.
- Репорты usability/diagnostic testing.

## Acceptance Criteria

- Новый пользователь может установить клиент, подключиться и понять статус без чтения внутренней документации.
- Клиент объясняет основные классы ошибок без бессмысленных generic timeout-сообщений.
- Обновления проходят через защищенный канал и проверку подписи.
- Advanced diagnostics доступны, но не перегружают основной интерфейс.

## Метрики успеха

- Сокращение числа непонятных user-facing ошибок.
- Рост доли успешных self-serve подключений без ручной помощи.
- Снижение времени первичной диагностики проблем.

## Риски

- Слишком сложный UI отпугнет обычного пользователя.
- Разделение UI/runtime потребует дополнительной платформенной инженерии.

## Зависимости

- Phase 04 и Phase 08.

---

## Комментарий по выполнению

Фаза `phase_09_clients_ux` успешно выполнена `2026-04-07`.

Итог по результатам:

- реализован `omega-client-app` как desktop launcher с `setup`, `connect`, `disconnect`, `reconnect`, `status`, `profile set`, `export-diagnostics` и `update verify/stage/apply`;
- клиент разделен на UI/launcher и privileged runtime части: background runtime теперь живет отдельным процессом, а launcher работает через `app-config`, `lifecycle`, `diagnostics`, `runtime-control`, `runtime.pid` и `runtime.log`;
- в `omega-client-runtime` добавлены typed lifecycle snapshots и human-readable failure scopes/recovery hints, чтобы пользователь видел не generic timeout, а понятный класс сбоя и следующее действие;
- basic UX сведен к трем понятным профилям `Gaming / General Internet / Restricted Fallback`, а advanced path/reliability/stealth telemetry вынесена в `status --advanced` и export bundle;
- реализован безопасный update path с pinned root, threshold `ed25519` signatures, channel/expiry checks, digest+length verification, staging и backup-before-apply;
- добавлены артефакты фазы: `docs/CLIENT_UX_SPEC.md`, `docs/CLIENT_USABILITY_DIAGNOSTIC_REPORT.md`, `docs/TUF_UPDATE_SPEC.md`, а также обновлены `README.md`, `docs/README.md`, `docs/ARCHITECTURE.md` и `docs/CONFIG_REFERENCE.md`.

Проверка завершена успешно:

- `cargo fmt --all`
- `cargo check --workspace`
- `cargo test --workspace`

Неблокирующее замечание осталось прежним и не относится к Phase 09: warning в `omega-transport/src/transport_v2/endpoint.rs` про `unused assignment` для `remaining`.
