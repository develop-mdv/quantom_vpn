# Handshake PQC Cost Estimate

## Статус

Это инженерная оценка, а не benchmark из perf-lab.
Числа ниже нужны для budget planning `phase_02/03`.

## Byte Overhead

| Component | Bytes |
| --- | ---: |
| `ClientInitV2` payload | `206` |
| `ServerRetryV2` payload | `165` |
| `ClientAuthV2` payload without name | `210` |
| `ML-KEM-768` key upload total | `1184` |
| `ServerCompleteV2` full payload | `1209` |
| `Resumption ticket` opaque bytes | `84` |

Full fresh handshake transcript over UDP payload:

```text
226 + 185 + (230 + name_len) + 804 + 452 + 1229
= 3126 + name_len bytes
```

Для `device_name = 12 B`:

```text
3138 B total UDP payload across all flights
```

## CPU Cost Envelope

Приближенные затраты в cycles на современном x86-64 / ARM64 классе mid-range:

| Operation | Estimate |
| --- | ---: |
| X25519 scalar mult | `80k .. 150k cycles` |
| ML-KEM-768 keygen | `400k .. 650k cycles` |
| ML-KEM-768 encaps | `500k .. 800k cycles` |
| ML-KEM-768 decaps | `550k .. 850k cycles` |
| HKDF / transcript hash | `10k .. 25k cycles` |
| Small AEAD seal/open | `< 20k cycles` |

## End-to-End Estimate

### Fresh handshake

Client:
- X25519
- ML-KEM keygen
- ML-KEM decapsulation
- credential AEAD seal
- HKDF/transcript hashing

Budget:

```text
~1.05M .. 1.69M cycles
```

Server:
- X25519
- credential AEAD open
- ML-KEM encapsulation
- HKDF/transcript hashing
- ticket seal

Budget:

```text
~0.63M .. 1.01M cycles
```

### Resumed handshake

Client and server:
- X25519
- ticket/cookie AEAD
- HKDF/transcript hashing

Budget per side:

```text
~0.12M .. 0.22M cycles
```

## Practical Reading

Следствие для продукта:
- resumed path заметно дешевле full handshake
- основная CPU цена fresh path сидит в ML-KEM, а не в identity envelope
- runtime budget контролируется chunked packetization, а не только crypto cycles

## Risk Notes

- если в `phase_03` появятся более тяжелые transcript/frame checks, fresh path вырастет умеренно, но порядок величины не сменится
- если ticket станет больше `84 B`, full `ServerCompleteV2` начнет давить на `1232 B` budget
