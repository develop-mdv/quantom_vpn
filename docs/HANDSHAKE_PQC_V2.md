# Handshake PQC v2

## Назначение

Этот документ фиксирует реализованный `phase_02` handshake для `Omega v2`.
Цель handshake: получить hybrid session secret, не раскрывать `device_id`/`device_token` в первых пакетах и удерживать packetization внутри IPv6-safe budget.

## Реализованный state machine

```text
Init -> Retry -> Validated -> Established
     \-> Retry -> Resumed
```

Семантика стадий:
- `Init`: клиент отправляет маленький `ClientInitV2` без device identity.
- `Retry`: сервер отвечает cookie + server X25519 public key и не делает дорогую stateful работу.
- `Validated`: клиент отправляет encrypted credential envelope и затем KEM key chunks.
- `Established`: сервер завершает hybrid KEX и выдает resumption ticket.
- `Resumed`: клиент использует opaque ticket + новый X25519 share без повторной передачи device token.

## Wire Messages

### `ClientInitV2`

Поля:
- `connection_id: 8 B`
- `client_mtu: 2 B`
- `fec_support: 1 B`
- `client_x25519_public: 32 B`
- `grease: variable`

Свойства:
- не содержит `device_id`
- не содержит `device_token`
- не содержит стабильный user/device marker

### `ServerRetryV2`

Поля:
- `connection_id`
- `server_mtu_hint`
- `server_x25519_public`
- `cookie`
- `grease`

Cookie зашифрован и bind-ится к:
- `client_addr`
- `connection_id`
- `client_x25519_public`
- `client_mtu`
- `fec_support`
- `issued_at`

### `ClientAuthV2`

Поля:
- `connection_id`
- `client_x25519_public`
- `cookie`
- `credential_nonce`
- `credential_ciphertext`

`credential_ciphertext` шифруется ключом:

```text
x25519_shared = DH(client_x25519_secret, server_x25519_public)
credential_key = HKDF("omega-v2-credential", x25519_shared, SHA256(cookie) || connection_id)
```

Plaintext credential envelope:
- `device_id: 16 B`
- `device_token: 32 B`
- `platform: 1 B`
- `device_name_len: 1 B`
- `device_name: variable`

### `ClientKemChunkV2`

Поля:
- `connection_id`
- `chunk_index`
- `chunk_count`
- `total_len`
- `chunk`

`ML-KEM-768` encapsulation key режется на несколько datagram-ов.
Текущий профиль реализации: `768 B + 416 B`.

### `ClientResumeV2`

Поля:
- `connection_id`
- `client_x25519_public`
- `cookie`
- `ticket`

Ticket opaque для сети и не раскрывает `device_id` напрямую.

### `ServerCompleteV2`

Поля:
- `connection_id`
- `resumed`
- `fec_enabled`
- `flow_id`
- `tunnel_ip`
- `server_mtu`
- `ciphertext` (`ML-KEM` ciphertext для full handshake, пусто для resumed path)
- `resumption_ticket`

## Hybrid Key Schedule

### Full Handshake

```text
x25519_shared = DH(client_x25519_secret, server_x25519_public)
mlkem_shared  = Decap(client_mlkem_secret, server_ciphertext)
transcript_hash = H(init* || retry* || auth || mlkem_ek)

ikm = x25519_shared || mlkem_shared
root = HKDF-Extract("omega-v2-root", ikm)
app_secret_0      = HKDF-Expand(root, "omega-v2-app-0" || transcript_hash)
resumption_secret = HKDF-Expand(root, "omega-v2-resume" || transcript_hash)
update_secret     = HKDF-Expand(root, "omega-v2-update" || transcript_hash)
flow_id           = HKDF-Expand(root, "omega-v2-flow" || transcript_hash)[0..16]
```

### Resumed Handshake

```text
x25519_shared = DH(client_x25519_secret, server_x25519_public)
ikm = x25519_shared || resumption_secret
root = HKDF-Extract("omega-v2-root", ikm)
```

## Packet Budget

Ниже размеры полезной нагрузки UDP до STUN envelope и отдельно итог с STUN:

| Message | Raw handshake payload | STUN-wrapped UDP payload | Комментарий |
| --- | ---: | ---: | --- |
| `ClientInitV2` | `206 B` | `226 B` | Малый первый datagram, без identity leakage |
| `ServerRetryV2` | `165 B` | `185 B` | Меньше `ClientInitV2`, amplification bounded |
| `ClientAuthV2` | `210 + name_len B` | `230 + name_len B` | identity только в encrypted envelope |
| `ClientKemChunkV2[0]` | `784 B` | `804 B` | chunk 0 |
| `ClientKemChunkV2[1]` | `432 B` | `452 B` | chunk 1 |
| `ServerCompleteV2` full | `1209 B` | `1229 B` | Укладывается в `1232 B` IPv6-safe budget |
| `ServerCompleteV2` resumed | `121 B` | `141 B` | Быстрый resumed path |

Следствия:
- первый client datagram сильно меньше `900 B`
- server pre-validation ответ меньше client init
- ML-KEM вынесен из первого flight
- full completion помещается в `1232 B` budget с запасом `3 B`

## Anti-Amplification и Anti-Abuse

Реализовано:
- сервер до `Validated` не аллоцирует session state
- до `Validated` сервер не делает `ML-KEM encapsulate`
- cookie ограничен по времени (`10 s`)
- cookie bind-ится к `client_addr` и `connection_id`
- retry response меньше init request

## Privacy Model

До `Validated` по сети видны только:
- `connection_id`
- `client_mtu`
- `fec_support`
- ephemeral `X25519` public key
- opaque retry cookie

По сети не видны напрямую:
- `device_id`
- `device_token`
- `user_id`

## Resumption

Текущая реализация:
- сервер выдает opaque ticket после full handshake
- клиент сохраняет opaque ticket и локальный `resumption_secret`
- resumed handshake не передает `device_token` заново
- ticket одноразово помечается использованным на стороне сервера

## Key Update

В `phase_02` реализованы:
- `KeyUpdateFrameV2`
- `derive_key_update_keys(update_secret, next_epoch)`
- отделение `update_secret` от `app_secret_0`

Это означает, что crypto/wire база для live rekey уже есть.
Автоматическое epoch overlap и scheduling лучше доводить вместе с packet epoch model в `phase_03`, чтобы не вшивать временный механизм поверх текущего frame layer.

## Что считается закрытым по Phase 02

Закрыто кодом:
- hybrid X25519 + ML-KEM-768 handshake
- retry cookie
- encrypted credential envelope
- chunked KEM upload
- resumption ticket path
- packet budget under IPv6-safe completion envelope

Закрыто инженерной базой:
- transcript-bound key schedule
- key-update derivation
- formal model skeletons
- cost / byte budget
