# Formal Verification Report

## Цель

Зафиксировать, какие formal/mathematical артефакты реально используются в текущем security hardening цикле и какие изменения в коде были сделаны по итогам этого анализа перед closed beta.

## Входные артефакты

- `docs/PROTOCOL_V2_FORMAL_SPEC.md`
- `docs/DOLEV_YAO_THREAT_MODEL.md`
- `docs/models/handshake_v2_proverif.pv`
- `docs/models/handshake_v2_tamarin.spthy`
- `docs/PROTOCOL_PROOFS.md`

## Объем покрытия

### 1. Handshake v2

Covered properties:

- secrecy для derived session secrets в гибридной схеме `X25519 + ML-KEM-768`;
- binding transcript hash к `Init -> Retry -> Auth -> KEM/Resume`;
- distinction между fresh и resumed session path;
- opacity retry cookie и resumption ticket относительно пассивного наблюдателя.

Coverage boundary:

- formal models здесь используются как proof skeleton, а не как claim о полном доказательстве всей реализации один-в-один;
- transport scheduling, pacing, FEC, relay graph и client UX не входят в ядро Dolev-Yao модели.

### 2. Update path

Для updater formal benefit достигается не через отдельный symbolic model, а через перевод trust assumptions в строгие validation invariants:

- bounded root/manifest/receipt parsing;
- threshold consistency `1 <= threshold <= |keys|`;
- fixed-length checks для public keys, signatures и digests;
- basename-only target file names;
- size bound для signed target.

Это intentionally проверяется кодом и negative tests, потому что именно здесь value formal work в продукте состоит в elimination of bug classes, а не в построении абстрактной модели package manager.

### 3. Beta hardening outside formal crypto model

Следующие изменения не относятся к pure formal verification, но являются прямым следствием threat model и beta risk review:

- per-IP handshake rate limiting и traceable `ServerBusy` outcome;
- secure local write path для resumption ticket;
- observability integration для abuse detection.

## Findings -> Code Changes

### Finding A: handshake lacked explicit anti-abuse budget

Risk:

- probing/flood traffic могло занимать handshake state surface без явного feedback loop для оператора;
- anti-probing policy сама по себе не ограничивала объем входящих попыток.

Change:

- добавлен `omega-edge/src/abuse.rs`;
- `omega-edge/src/handshake.rs` теперь вызывает `HandshakeAbuseGuard` до дальнейшей обработки payload;
- `omega-edge/src/metrics.rs` и `omega-edge/src/observability.rs` получили `handshake_rate_limited_total` и delta-based alerting.

### Finding B: updater accepted signed file names without confinement check

Risk:

- signed manifest мог указать traversal-like `file_name`, и stage path оказался бы зависим от недоверенного имени.

Change:

- `omega-client-app/src/update.rs` получил `safe_file_name_component(...)`;
- введены bounds на root/manifest/receipt/target sizes;
- добавлены structural checks для threshold, duplicate keys/signatures/targets и fixed-size crypto material.

### Finding C: resumption state write path was too loose for beta

Risk:

- plaintext state записывался напрямую в целевой файл без temp replacement;
- parser принимал слишком свободный local state format.

Change:

- `omega-client-runtime/src/handshake.rs` пишет resumption state через temp file + `rename`;
- на Unix используется `0o600` через `OpenOptionsExt`;
- parser отклоняет oversized file, empty ticket и invalid secret length.

## Test Evidence

Security-relevant tests added or now directly covering formal assumptions:

- `omega-client-app/src/update.rs`
- `verify_bundle_rejects_invalid_root_threshold`
- `verify_bundle_rejects_unsafe_target_file_name`
- `stage_verified_bundle_rejects_escape_file_name`
- `hex_roundtrip_covers_all_byte_values`
- `omega-client-runtime/src/handshake.rs`
- `parse_stored_resumption_rejects_invalid_secret_len`
- `parse_stored_resumption_roundtrip`
- `write_private_file_roundtrip`
- `omega-edge/src/abuse.rs`
- `guard_blocks_after_budget_is_exhausted`
- `guard_recovers_after_block_expires`
- `cleanup_removes_stale_entries`

Workspace verification:

- `cargo fmt --all`
- `cargo check --workspace`
- `cargo test --workspace`

## Residual Known Gaps

- handshake formal models остаются skeleton-level и должны расширяться, если в протокол добавятся новые key update или relay-coupled transitions;
- updater пока без separate timestamp/snapshot roles и transparency log;
- local client secrets пока не вынесены в Windows DPAPI / macOS Keychain / Linux secret service;
- rate limiting сейчас per-IP и intentionally simple; для более широкой beta может понадобиться coupling с reputation/fabric telemetry.

## Итог

Formal work в текущей фазе дало не только документы, но и конкретные code-level изменения:

- сузило observable classes для probing/abuse path;
- закрыло traversal/threshold/size bug classes в updater;
- ужесточило локальное хранение resumption state;
- добавило тесты, которые проверяют именно те инварианты, на которых держится trust model closed beta.

