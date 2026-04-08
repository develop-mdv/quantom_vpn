# Protocol Proofs

## Цель

Этот документ фиксирует proof obligations для `Omega v2` и связывает их с текущей реализацией. Он не подменяет собой Tamarin/ProVerif модели и код-review, а задает единый каркас того, какие security-свойства мы считаем обязательными перед beta.

## Обозначения

- `X = DH(client_x25519, server_x25519)`
- `K = ML-KEM-768 shared secret`
- `T = H(transcript)`
- `S = HKDF-Extract(0, X || K || T)`
- `SK = HKDF-Expand(S, context)`
- `cookie = AEAD(cookie_key, aad=COOKIE_AAD, plaintext=client tuple + cid + mtu + fec + client_pk)`
- `ticket = AEAD(ticket_key, aad=TICKET_AAD, plaintext=device_id + resumption_secret + expiry)`

В коде это реализовано в:

- `omega-core-crypto/src/handshake.rs`
- `omega-edge/src/handshake.rs`
- `omega-core-wire/src/handshake_v2.rs`

## Proof Obligation 1: Hybrid handshake secrecy

### Требование

Сессионные ключи `session_keys`, `update_secret`, `resumption_secret` и `flow_id` не должны быть вычислимы для противника, если не скомпрометированы одновременно оба канала гибридного KEX или серверные long-term secrets.

### Инженерная формулировка

Для гибридного handshake используется композиция:

```text
S = HKDF-Extract(0, X || K || T)
SK = HKDF-Expand(S, role, labels, transcript hash)
```

Информальный composition bound:

```text
Adv_secrecy(SK)
  <= Adv_x25519(X)
   + Adv_mlkem768(K)
   + Adv_hkdf(S)
   + Adv_hash(T)
```

То есть если хотя бы один из `X25519` или `ML-KEM-768` сохраняет secrecy, а transcript не подделан, итоговый `SK` остается вычислительно скрытым с точностью до стандартных допущений по `HKDF` и `Hash`.

### Кодовые следствия

- transcript hash входит в derivation и связывает `Init -> Retry -> Auth -> KEM chunks`;
- resumed path использует отдельный `derive_resumption_handshake_secrets(...)`;
- `device_id` и `device_token` не раскрываются до зашифрованного credential payload.

## Proof Obligation 2: Retry cookie связывает handshake с адресом клиента

### Требование

Off-path противник не должен уметь породить валидный `ClientAuthV2` без получения корректного `ServerRetryV2` для того же `client_addr`, `connection_id` и `client_x25519_public`.

### Доказательная идея

`cookie` шифрует и аутентифицирует tuple:

```text
(issued_at, connection_id, client_mtu, fec_support, client_x25519_public, client_addr)
```

Следовательно, успешная подмена требует либо:

- знания `cookie_key`, либо
- успешной подделки AEAD tag.

Информально:

```text
Pr[forge valid cookie] <= Adv_aead(cookie_key)
```

### Кодовые следствия

- в `omega-edge/src/handshake.rs` cookie повторно открывается и сверяется по `connection_id`, `client_x25519_public`, `client_addr` и freshness;
- stale/invalid cookie приводит к reject или silent drop в зависимости от persona anti-probing policy.

## Proof Obligation 3: Resumption ticket остается opaque capability

### Требование

Resumption ticket не должен раскрывать `device_id`, `policy_id`, `flow_id` или `resumption_secret` пассивному наблюдателю.

### Доказательная идея

На wire передается только opaque `ticket`, зашифрованный под `ticket_key`. Клиент локально хранит `ticket + resumption_secret`, а сервер повторно валидирует ticket и policy admission перед активацией resumed session.

### Кодовые следствия

- `omega-edge/src/handshake.rs` запечатывает ticket через `seal_ticket(...)`;
- `omega-client-runtime/src/handshake.rs` в Phase 11 пишет resumption state через temp-file + rename и ограниченный формат `ticket=<hex> / secret=<hex>`;
- parser отклоняет пустой ticket, неверную длину secret и oversized local state.

## Proof Obligation 4: Anti-probing выдает ограниченные observable classes

### Требование

Для `randomized`, `quic_like` и `hostile_network` persona внешний наблюдатель не должен получать детализированный oracle по причинам отказа.

### Инженерная формулировка

Observable outcomes сводятся к малому множеству:

- `silent_drop`
- `uniform_reject(AuthFailed)`
- `uniform_reject(ServerBusy)` для rate limiting

Это уменьшает distinguishability probing-атак и закрывает прямой reason oracle по malformed/auth/version paths.

### Кодовые следствия

- `anti_probe_outcome(...)` в `omega-edge/src/handshake.rs` коллапсирует reject reason для non-`off` personas;
- Phase 11 добавляет `HandshakeAbuseGuard`, чтобы flood/probing кампании получали единый `ServerBusy` outcome и trace correlation вместо разного поведения по стадиям handshake.

## Proof Obligation 5: Update path принимает только безопасный и локально confinement-friendly target

### Требование

Signed manifest сам по себе не должен позволять:

- path traversal при stage/apply;
- oversized root/manifest/receipt parsing;
- invalid threshold/root shape;
- acceptance malformed digest/signature/public key lengths.

### Инженерная формулировка

Принимается только target, для которого одновременно верно:

```text
threshold >= 1
threshold <= |keys|
algorithm = ed25519
len(pubkey) = 32 bytes
len(signature) = 64 bytes
len(sha256) = 32 bytes
file_name in SafeBasenameAlphabet
0 < target.length <= MAX_RELEASE_TARGET_BYTES
```

### Кодовые следствия

- `omega-client-app/src/update.rs` теперь валидирует root/manifest/receipt через size bounds и structural checks;
- `safe_file_name_component(...)` запрещает `/`, `\`, `:`, `.`/`..` и non-basename values;
- `stage_verified_bundle(...)` повторно проверяет confinement внутри stage dir;
- негативные тесты закрывают threshold misuse, digest mismatch и traversal cases.

## Связка proof -> code -> test

| Свойство | Код | Проверка |
| --- | --- | --- |
| Hybrid secrecy и transcript binding | `omega-core-crypto/src/handshake.rs`, `omega-edge/src/handshake.rs` | `docs/models/handshake_v2_proverif.pv`, `docs/models/handshake_v2_tamarin.spthy`, unit tests в crypto/wire crates |
| Retry/address binding | `omega-edge/src/handshake.rs` | handshake state machine + anti-probe behavior |
| Local resumption secrecy hygiene | `omega-client-runtime/src/handshake.rs` | `parse_stored_resumption_*`, `write_private_file_roundtrip` |
| Update threshold and confinement | `omega-client-app/src/update.rs` | `verify_bundle_*`, `stage_verified_bundle_rejects_escape_file_name`, `hex_roundtrip_covers_all_byte_values` |
| Anti-abuse observable class | `omega-edge/src/abuse.rs`, `omega-edge/src/handshake.rs`, `omega-edge/src/observability.rs` | `guard_*` tests + `omega_handshake_rate_limited_total` metric + trace events |

## Что Phase 11 поменяла в реализации

- добавлен per-IP handshake rate limiting с traceable `ServerBusy` outcome;
- secure update path получил explicit bounds и basename-only staging policy;
- local resumption ticket storage стал ограниченным по размеру и пишется через temp-file replacement;
- proof obligations теперь отражены в negative tests, а не только в prose.

## Границы доказательств

- текущие ProVerif/Tamarin артефакты покрывают в первую очередь secrecy/authenticity skeleton для handshake, а не весь transport stack;
- anti-DoS/rate limiting не является Dolev-Yao свойством и оценивается инженерно и через metrics/rollout guard;
- updater trust model пока без signed timestamp/snapshot layer и без transparency log;
- локальное хранение resumption state hardened на уровне файловой гигиены, но еще не вынесено в OS-native keystore.

