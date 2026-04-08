# Adversarial Stealth Engine

## Цель

`phase_06_stealth_personas` превращает stealth из набора padding-эвристик в отдельную подсистему с формальной persona model, измеримой detectability и объяснимыми runtime decisions.

## Persona Model

Каждая persona задается пятью блоками:

- `packet size grammar`
- `timing policy`
- `handshake envelope`
- `cover budget`
- `fallback behavior`

Реализация находится в `omega-stealth/src/persona.rs`, live adaptation - в `omega-stealth/src/engine.rs`, evaluator - в `omega-stealth/src/evaluator.rs`.

## Продакшен-persona profiles

| Persona | Handshake grease | Max cover budget | Timing budget | Invalid probe response | Observable classes | Основной trade-off |
| --- | --- | --- | --- | --- | --- | --- |
| `randomized` | init `144 B`, retry `120 B` | `112 B` | `14 ms` | `uniform_reject` | `2` | Лучший general-purpose cover при умеренном overhead. |
| `quic_like` | init `96 B`, retry `96 B` | `84 B` | `10 ms` | `uniform_reject` | `1` | Самый тихий wire image и лучший latency budget. |
| `hostile_network` | init `176 B`, retry `144 B` | `144 B` | `18 ms` | `uniform_reject` | `1` | Максимальная probing resistance и resilience под фильтрацией. |
| `off` | `0 B` | `0 B` | `0 ms` | legacy/off baseline | `4` | Минимальный overhead без stealth shaping. |

## Runtime integration

### Client and server selection

`OMEGA_PERSONA` поддерживается и на клиенте, и на сервере.

Profile-based defaults:

- `gaming -> randomized`
- `general -> quic_like`
- `restricted -> hostile_network`

### Handshake envelope

- клиентский `ClientInitV2.grease` теперь persona-aware;
- серверный `ServerRetryV2.grease` строится от handshake envelope persona;
- invalid handshake/probe paths проходят через `anti_probe_outcome(...)`, что схлопывает причины отказа в ограниченное число observable classes.

### Transport shaping

Persona budget применяется на outbound path после сборки transport datagram:

- вычисляется `target_payload_floor`;
- при наличии допустимого cover budget добавляется `TransportFrame::Padding(...)`;
- shaping ограничен `payload_budget`, текущим `padding_budget` и adaptation из `StealthEngine`.

### Reliability and path intelligence coupling

`StealthEngine.observe_network(...)` получает `PathSnapshot + ReliabilitySnapshot` и меняет active persona/budget:

- blackhole/recovery path форсирует `hostile_network`;
- `consider_quieter_persona` из path manager переводит `randomized -> quic_like`;
- при высоком reliability pressure cover и timing budget режутся, чтобы stealth уступал живучести сессии.

## Anti-probing policy

Нормативная цель этой фазы: invalid initial/probe paths не должны выдавать богатый oracle.

Практически это выражено так:

- `persona != off` использует `uniform_reject` как основной invalid response class;
- cookie/auth/resume/KEM error paths сводятся к ограниченному набору observable outcomes;
- expensive work откладывается до validation state, а handshake envelope ротируется persona policy.

## Explainability and telemetry

Stealth snapshot публикует:

- `configured_persona`
- `active_persona`
- `persona_target_payload`
- `persona_cover_budget_bytes`
- `persona_timing_budget_ms`
- `persona_detectability_improvement_percent`
- `persona_invalid_probe_response`
- `persona_observable_response_classes`
- `persona_explanation`

Эти поля уходят в:

- клиентский diagnostics snapshot;
- серверный session/runtime snapshot.

## Что считается завершением фазы

Фаза считается принятой, если одновременно выполнено следующее:

- есть не менее трех production-persona с documented trade-offs;
- detectability измеряется evaluator-ом, а не только описывается словами;
- anti-probing вынесен в persona engine;
- transport/reliability/path manager используют stealth budget объяснимо и ограниченно.
