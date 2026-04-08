# Dependency DAG

## Mermaid DAG

```mermaid
flowchart TD
  OCW["omega-core-wire"]
  OCC["omega-core-crypto"]
  OST["omega-stealth"]
  OTR["omega-transport"]
  OCTL["omega-control"]
  ORL["omega-relay"]
  OEX["omega-exit"]
  OED["omega-edge"]
  OCR["omega-client-runtime"]
  OCA["omega-client-app"]
  OCL["omega-client"]
  OCS["omega-server"]
  OCOMP["omega-core (compat)"]

  OTR --> OCW
  OCTL --> OCW
  OCTL --> OST
  ORL --> OCTL
  ORL --> OST
  OEX --> OCTL
  OED --> OCC
  OED --> OCW
  OED --> OTR
  OED --> OST
  OED --> OCTL
  OCR --> OCC
  OCR --> OCW
  OCR --> OTR
  OCR --> OST
  OCA --> OCR
  OCL --> OCR
  OCS --> OED
  OCS --> OCTL
  OCOMP --> OCC
  OCOMP --> OCW
  OCOMP --> OTR
  OCOMP --> OST
```

## Dependency Matrix

| Crate | Direct deps |
| --- | --- |
| `omega-core-crypto` | none |
| `omega-core-wire` | none |
| `omega-stealth` | none |
| `omega-transport` | `omega-core-wire` |
| `omega-control` | `omega-core-wire`, `omega-stealth` |
| `omega-relay` | `omega-control`, `omega-stealth` |
| `omega-exit` | `omega-control` |
| `omega-edge` | `omega-core-crypto`, `omega-core-wire`, `omega-transport`, `omega-stealth`, `omega-control` |
| `omega-client-runtime` | `omega-core-crypto`, `omega-core-wire`, `omega-transport`, `omega-stealth` |
| `omega-client-app` | `omega-client-runtime` |
| `omega-client` | `omega-client-runtime` |
| `omega-server` | `omega-edge`, `omega-control` |
| `omega-core` | `omega-core-crypto`, `omega-core-wire`, `omega-transport`, `omega-stealth` |

## Rules

- `omega-edge` не может зависеть от `omega-client-runtime`.
- `omega-client-runtime` не может зависеть от `omega-server` или `omega-control` storage internals.
- `omega-transport` не может зависеть от app/runtime/UI crates.
- `omega-control` не может зависеть от `omega-edge`.
- `omega-relay` и `omega-exit` могут зависеть только вниз по DAG.

## Why This Matters

Эта DAG-структура делает возможным:

- изолированное тестирование transport/stealth;
- дальнейшее разрастание relay fabric без циклов;
- сохранение тонких app entrypoints;
- более понятный profiling hot path;
- постепенную миграцию старых shim-crates без архитектурного долга.
