# TUF Update Spec

## Цель

Клиентский update path должен принимать релизы только после криптографической проверки, не смешивать transport/runtime статус с логикой обновлений и оставлять человеку прозрачную trust model.

В Phase 09 это реализовано как локальный TUF-подобный pipeline в `omega-client-app/src/update.rs`:

- pinned `TrustedReleaseRoot` c threshold ключами;
- `SignedReleaseManifest` с каналом, expiry, target metadata и signature set;
- verify -> stage -> apply как три явных шага;
- backup предыдущего бинаря перед заменой;
- отказ при любой несогласованности длины, SHA-256, channel, expiry или signature threshold.

## Trust Model

### 1. Trusted root

Локальный trusted root хранит:

- `version`
- `threshold`
- список `keys[]`

Каждый ключ содержит:

- `key_id`
- `algorithm`
- `public_key_hex`

Сейчас допускается только `ed25519`.

Клиент не доверяет manifest сам по себе. Он доверяет только pinned root и проверяет, что:

- `threshold >= 1`;
- manifest требует `min_root_version <= root.version`;
- количество валидных подписей от разных trusted keys не меньше `threshold`.

### 2. Signed manifest

`SignedReleaseManifest` состоит из двух частей:

- `signed`
- `signatures`

`signed` включает:

- `version`
- `channel`
- `expires_at_ms`
- `min_root_version`
- `targets[]`

`ReleaseTarget` включает:

- `target_id`
- `file_name`
- `version`
- `platform`
- `length`
- `sha256_hex`
- `description`

Подписи считаются по canonical payload `serde_json::to_vec(&manifest.signed)`.

### 3. Verified bundle

Bundle считается доверенным только если одновременно выполняется всё ниже:

- channel manifest совпадает с ожидаемым channel клиента;
- manifest не просрочен;
- threshold signatures verified;
- target найден однозначно;
- `bundle.len() == target.length`;
- `SHA256(bundle) == target.sha256_hex`.

## Update Flow

### Verify

`omega-client-app update verify <root.json> <manifest.json> <bundle> [--target-id ...]`

Результат:

- bundle не устанавливается;
- пользователь получает только итог криптографической проверки и identity target.

### Stage

`omega-client-app update stage <root.json> <manifest.json> <bundle> [--target-id ...]`

Результат:

- bundle копируется в `omega-client/state/updates/staged/<target>-<version>/`;
- рядом пишется `receipt.json`;
- staged content больше не зависит от исходного временного пути.

`receipt.json` фиксирует:

- `target_id`
- `version`
- `channel`
- `staged_bundle_path`
- `manifest_path`
- `root_path`
- `sha256_hex`
- `length`
- `verified_at_ms`

### Apply

`omega-client-app update apply <staged-dir> [--target path]`

Результат:

- staged bundle перечитывается и повторно хешируется;
- при наличии существующего target создается backup в `omega-client/state/updates/backup/`;
- только после этого verified bundle записывается в install target;
- в staged directory пишется `applied.json`.

## Anti-rollback и anti-substitution свойства

### Что уже закрыто

- downgrade через manifest от более старого root version блокируется `min_root_version`;
- подмена bundle после verify блокируется повторной проверкой `length + sha256` на стадии apply;
- подмена manifest сторонним ключом блокируется threshold signature policy;
- cross-channel substitution (`beta` вместо `stable`) блокируется сравнением channel.

### Что остается следующими шагами

- отдельный signed timestamp/snapshot layer;
- multi-root rotation playbook;
- transparency/audit publishing для клиентских release artifacts;
- platform-native auto-restart после apply.

## UX Rules

Update UX намеренно разбит на три шага, чтобы не было магии:

- `verify` отвечает на вопрос "этому релизу можно доверять?";
- `stage` отвечает на вопрос "релиз подготовлен локально и зафиксирован?";
- `apply` отвечает на вопрос "verified bundle действительно заменил install target?".

Если проверка не проходит, клиент обязан показать не generic error, а конкретный класс сбоя:

- invalid signature threshold;
- expired manifest;
- wrong release channel;
- bundle digest mismatch;
- bundle length mismatch;
- unknown target id.

## Code Reference

- `omega-client-app/src/update.rs`
- `omega-client-app/src/main.rs`
- `omega-client-app/src/app_config.rs`

## Phase 11 hardening addendum

В Phase 11 updater trust model был ужесточен в трех местах:

- root/manifest/receipt parsing теперь ограничены по размеру;
- `TrustedReleaseRoot` и `SignedReleaseManifest` проходят structural validation до принятия bundle;
- `ReleaseTarget.file_name` теперь обязан быть безопасным basename без traversal/separator semantics.

Дополнительно теперь проверяется:

- `1 <= threshold <= number_of_keys`;
- отсутствие duplicate `key_id`, duplicate manifest signatures и duplicate targets;
- фиксированные размеры `ed25519` public key / signature и `sha256` digest;
- ограничение на `target.length` и повторная confinement-check логика при `stage`.

Это переводит updater trust model из уровня "подписан и хеш совпал" в уровень "подписан, структурно валиден и безопасен для локального stage/apply path".

