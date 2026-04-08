# Mixnet Anonymity Notes

`Phase 07` не превращает `Omega` в полноценный heavy mixnet. Вместо этого проект закладывает безопасный продуктовый baseline, где privacy-идеи из mixnet мира используются только там, где они дают измеримую пользу без разрушения latency budget.

## Что реально полезно

Для текущего продукта полезны три класса идей:

- `route diversity`: не держать все сессии на одном и том же `edge -> exit` path;
- `bounded mixing`: иногда выгодно чуть расширить anonymity set за счет relay diversity и ограниченного queueing, но без секундных batch windows;
- `operational compartmentalization`: разные trust zones и разные operators уменьшают blast radius одной компрометации.

## Что пока не стоит делать в live runtime

Следующие техники сознательно не включены в datapath `Phase 07`:

- большие batch windows;
- постоянный cover-only relay churn;
- случайные задержки поверх интерактивного трафика;
- packet reordering ради anonymity ценой QoS;
- глобальная mix scheduler, которая ломает predictability transport v2.

Причина проста: `Omega` остается low-latency VPN/tunnel системой, а не high-latency anonymity network.

## Модель anonymity gain

Внутри fabric полезно мыслить не абстрактным лозунгом "больше хопов = больше privacy", а более узкой оценкой:

```text
privacy_gain ~= route_diversity * trust_separation * operator_separation
cost ~= added_latency + failover_complexity + observability_blindness
```

Если `cost > gain`, mixnet-like прием не должен попадать в live runtime.

## Safe guardrails

Для продового применения мы используем такие ограничения:

- path selection не должен выходить за session failover budget;
- `fast` режим не обязан форсировать relay hops;
- `stealth` режим может запрещать direct `edge -> exit`, но все равно остается в bounded hop-count;
- любой privacy improvement должен быть объясним через snapshot/metrics, а не скрыт в непрозрачной эвристике;
- failover и handoff важнее, чем косметический anonymity bonus.

## Как это связано с `Phase 07`

Текущая реализация уже дает полезный privacy baseline:

- primary и backup route могут идти через разные relay/exit узлы;
- trust zone и operator участвуют в score/risk модели;
- node compromise имеет ограниченный blast radius;
- route churn управляется policy и handoff ticket, а не хаотическим перебором.

Это не полный Chaumian mixnet, но это правильная продуктовая основа, на которую дальше можно аккуратно добавлять:

- bounded batching для control traffic;
- ограниченный session class mixing;
- route cohort randomization;
- offline anonymity-set evaluation на trace corpus.

## Практический вывод

Если очередная privacy-идея:

- повышает route diversity;
- не ломает transport latency/QoS;
- не уничтожает explainability;
- измеримо уменьшает correlation surface,

то ее стоит рассматривать для следующей фазы. Если нет, она должна оставаться research-only.
