# WGAN Persona Models

## Статус

В `Omega` WGAN и другие adversarial generative models рассматриваются как offline research tooling, а не как live runtime dependency.

Это принципиальное решение фазы `phase_06_stealth_personas`:

- runtime datapath не должен зависеть от тяжелой ML-модели;
- persona policy обязана быть объяснимой, типизированной и воспроизводимой;
- ML-модель допустима только как генератор кандидатов для corpus/reference traces.

## Где WGAN реально полезен

WGAN-пайплайн имеет смысл только в offline контуре:

1. Собрать целевые trace corpora для `quic_like`, `webrtc_like`, hostile mobile NAT и т.п.
2. Натренировать генератор packet size / IAT / burst profiles.
3. Сэмплировать кандидатов persona grammar.
4. Прогнать кандидатов через `StealthEvaluator`.
5. Принять в продукт только те grammar/policy, которые проходят по budget.

## Что остается инвариантом даже при использовании WGAN

Любая ML-предложенная persona обязана после дискретизации превратиться в конечную спецификацию:

- конечные size bins;
- конечные timing windows;
- конечный cover budget;
- finite observable response classes;
- явное fallback behavior.

То есть в runtime все равно живет deterministic `PersonaSpec`, а не нейросеть.

## Acceptance gate для ML-derived persona

Новая persona MAY быть принята в продукт только если одновременно соблюдается:

- `DD_persona` лучше, чем у текущей production persona того же класса;
- `CBS < 0.74` на baseline suite;
- `PRS >= 70` для general profiles и `>= 85` для hostile profile;
- `ByteCost` и `LatencyCost` не выходят за budget фазы;
- rollout можно объяснить через стабильные bins/ranges без opaque weights.

## Почему live WGAN не включен в Phase 06

Причины отказа от runtime ML в этой фазе:

- повышенный CPU/latency overhead;
- сложность explainability;
- рост риска нестабильного wire image между релизами;
- плохая пригодность для formal review и regression gating.

## Практический вывод

`Phase 06` закладывает место для adversarial ML research, но production path остается rule-based:

- `omega-stealth/src/persona.rs` - persona grammar и budgets;
- `omega-stealth/src/engine.rs` - live adaptation;
- `omega-stealth/src/evaluator.rs` - detectability regression gate.
