# Stealth Persona Detectability Report

Дата среза: `2026-04-07`

Источник чисел: `cargo test -p omega-stealth dump_default_report -- --nocapture`

## Методика

Для каждой production persona использовался deterministic synthetic corpus из `StealthEvaluator::default_corpus()`:

- baseline `persona_off`
- reference traces для целевой persona
- observed traces для live persona variant

Метрики:

- `JSD` - distribution distance to persona
- `PRS` - probing resistance score
- `CBS` - classifier baseline score
- `ByteCost` - относительный overhead по байтам
- `LatencyCost` - относительный overhead по latency budget
- `Improvement` - detectability improvement vs `persona_off`

## Результаты

| Persona | JSD | PRS | CBS | ByteCost | LatencyCost | Improvement vs off |
| --- | --- | --- | --- | --- | --- | --- |
| `randomized` | `0.030` | `84.8` | `0.717` | `0.120` | `0.050` | `0.669` |
| `quic_like` | `0.008` | `91.2` | `0.692` | `0.080` | `0.030` | `0.566` |
| `hostile_network` | `0.027` | `92.3` | `0.720` | `0.170` | `0.070` | `0.733` |

## Интерпретация

- Все три production persona дают измеримое снижение detectability относительно `persona_off`.
- `quic_like` - лучший профиль по совокупности `JSD/CBS/LatencyCost`.
- `hostile_network` - лучший профиль по `PRS`, но и самый дорогой по byte/latency budget.
- `randomized` остается хорошим general-purpose режимом между quiet-wire и более агрессивным cover.

## Budget verdict

| Persona | Verdict |
| --- | --- |
| `randomized` | Проходит general-purpose stealth budget. |
| `quic_like` | Проходит quiet-wire budget и рекомендован как default для `general`. |
| `hostile_network` | Проходит hostile probing budget и рекомендован для `restricted`/blackhole recovery cases. |

## Связь с runtime defaults

Profile defaults после `phase_06`:

- `gaming -> randomized`
- `general -> quic_like`
- `restricted -> hostile_network`

Это соответствует measured trade-offs по evaluator report и live runtime budget policy.
