# ML Anomaly SRE

## Принцип фазы

В этой фазе продукт делает ставку не на «магический ML», а на explainable SRE-подход:

- сначала deterministic alerts для известных failure classes;
- затем SPC для detection дрейфа;
- только потом offline ML/anomaly research как дополнительный слой.

Именно поэтому live runtime сейчас использует SPC и known alerts, а не opaque модель, которая принимает rollout decisions без объяснений.

## Что считается аномалией сейчас

`observability` task поддерживает rolling window и строит `SpcSignal` по трем метрикам:

- `runtime.avg_loss_ratio`
- `runtime.avg_path_quality_score`
- `metrics.fabric_failover_delta`

Параметры:

- размер окна: `OMEGA_SPC_WINDOW`, default `24`;
- частота sample: `5` секунд;
- default horizon: `24 * 5 = 120` секунд истории;
- сигнал считается meaningful только начиная с `sample_count >= 8`.

## Формула SPC

Для окна значений `x1 ... xn` считаются:

- `mean = (x1 + ... + xn) / n`
- `sigma = sqrt(sum((xi - mean)^2) / n)`
- `LCL = mean - 3 * sigma`
- `UCL = mean + 3 * sigma`

Сигнал считается `out_of_control`, если:

- собрано хотя бы 8 наблюдений;
- `sigma > 0`;
- текущее значение вышло за `[LCL, UCL]`.

Это намеренно простая и объяснимая схема.

## Почему не full ML в runtime

Полноценная online ML-модель на этой стадии принесла бы больше рисков, чем пользы:

- непрозрачные ложные срабатывания;
- сложность разбора, почему rollout остановлен;
- риск подменить здравую SRE-дисциплину красивой вероятностной оболочкой;
- дополнительную attack surface на telemetry pipeline.

Поэтому live decisions сейчас принимает `rollout_guard`, который основан на явных thresholds и health signals.

## Текущий rollout guard

Guard считается unhealthy, если выполняется хотя бы одно условие:

- `policy_conflicts > OMEGA_CANARY_MAX_POLICY_CONFLICTS`
- `healthy_fabric_nodes < OMEGA_CANARY_MIN_HEALTHY_FABRIC_NODES`
- `blackhole_suspected_sessions > OMEGA_CANARY_MAX_BLACKHOLE_SESSIONS`
- `avg_loss_ratio > OMEGA_CANARY_MAX_LOSS_RATIO`
- `avg_path_quality_score < OMEGA_CANARY_MIN_PATH_QUALITY_SCORE`
- `handshake_pending > 128`

Default budgets:

- `OMEGA_CANARY_MIN_PATH_QUALITY_SCORE = 45`
- `OMEGA_CANARY_MAX_LOSS_RATIO = 0.08`
- `OMEGA_CANARY_MAX_BLACKHOLE_SESSIONS = 0`
- `OMEGA_CANARY_MAX_POLICY_CONFLICTS = 0`
- `OMEGA_CANARY_MIN_HEALTHY_FABRIC_NODES = 1`

## Known alerts, которые идут раньше SPC

Phase 10 сначала детектирует хорошо известные operational классы:

- handshake failure spike;
- loss ratio above budget;
- blackhole recovery triggered;
- policy conflicts detected;
- healthy fabric nodes below floor;
- pending handshake backlog;
- SPC out-of-control signal.

Такой порядок нужен специально: known failure > explainable anomaly > research ML.

## Как это читать оператору

- `alerts` отвечают на вопрос «что уже явно плохо».
- `spc_signals` отвечают на вопрос «не ушла ли система из привычного режима, даже если hard threshold еще не пробит».
- `rollout_guard` отвечает на вопрос «можно ли продолжать canary/rollout прямо сейчас».

## Дальнейший ML roadmap

Если Phase 10 покажет полезность SPC baseline, следующим безопасным развитием может быть только offline research path:

- anomaly scoring на исторических observability snapshots;
- clusterization failure signatures по incident classes;
- рекомендация runbook, а не автоматическое действие;
- обязательная explainability в виде top contributing features.

Иными словами: ML может помогать оператору, но не должен подменять operator intent и deterministic rollback discipline.
