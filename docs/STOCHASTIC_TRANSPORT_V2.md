# Stochastic Transport v2

## Назначение

`Transport v2` переводит `Omega` с packet-centric `NACK + retransmit cache` на frame-centric transport core с собственными очередями, ACK ranges, loss detection, pacing и congestion control.

Реализация в коде:

- `omega-core-wire/src/transport_v2.rs`
- `omega-transport/src/transport_v2/*`
- `omega-edge/src/datapath.rs`
- `omega-client-runtime/src/runtime.rs`

## Wire Layer

Внутри зашифрованного transport payload теперь используются frame-типы:

- `data frame`: фрагменты user payload с `message_id`, `fragment_offset`, `message_len`, `traffic_class`.
- `ack frame`: `ack_delay_micros` + список `AckRange(start, end)`.
- `control frame`: `keepalive`, `close`, базовые control signals.
- `path frame`: `observed_rtt_micros`, `delivery_rate_kbps`, `next_connection_id`, `rotation_epoch`.
- `fec frame`: каркас для будущих repair shards.
- `padding frame`: задел под stealth cover packetization.

Outer envelope остался `RTP + OmegaHeader + AEAD`, но `seq` и `packet_type` теперь маскируются через header protection.

## Header Protection

Текущая схема:

- `header_protection_key = SHA256("omega-v2-header-protection" || app_secret)`
- per-packet mask = `SHA256(header_protection_key || flow_id || rtp.sequence || rtp.timestamp || rtp.ssrc)`
- mask применяется к `seq[4B]` и `packet_type[1B]`

Это не делает `flow_id` невидимым, но убирает прямую наблюдаемость packet counter и control/data pattern на outer header.

## Connection ID Rotation

Внутренний `connection_id` transport layer теперь ротируется детерминированно:

- `cid(epoch) = SHA256("omega-v2-transport-cid" || update_secret || epoch)[0..8]`
- текущий epoch по умолчанию меняется каждые `96` transport packets
- новый `connection_id` анонсируется через `path frame`

На этой фазе outer session lookup еще идет по `flow_id`, а rotation используется как transport metadata и как база для path intelligence следующей фазы.

## Scheduler

Порядок отбора в packet assembly:

1. pending `ack frame`
2. retransmit queue
3. control/path frames
4. `interactive` data
5. `bulk` data

Семантика:

- transport сначала планирует logical units (`QueuedMessage`), а не сразу UDP packet.
- packet assembler режет `data frame` под актуальный `payload_budget`.
- `interactive` получает приоритет над `bulk`.
- `bulk` ограничен долей окна `cwnd`: по умолчанию не больше `70%` in-flight бюджета.

## RTT, Loss и ACK

ACK grammar:

- receiver хранит множество принятых packet numbers;
- ACK строится как список contiguous ranges, а не bitmap/NACK window;
- out-of-order доставка не считается потерей автоматически.

Текущие формулы:

```text
rttvar = (3/4) * rttvar + (1/4) * |srtt - sample|
srtt   = (7/8) * srtt   + (1/8) * sample
loss_delay = 9/8 * max(latest_rtt, srtt)
loss if:
  largest_acked - packet_number >= 3
  OR now - sent_at >= loss_delay
```

Spurious retransmit снижается за счет двух условий сразу:

- packet threshold = `3`
- time threshold = `9/8 * max(latest_rtt, srtt)`

## Congestion Control и Pacing

Текущая модель intentionally lightweight, но наблюдаемая и управляемая.

Начальные параметры:

```text
initial_cwnd = 10 * max_datagram_size
min_cwnd     = 2  * max_datagram_size
ack_delay    = 0 ms
```

Рост окна:

```text
slow start:            cwnd += acked_bytes
congestion avoidance:  cwnd += MSS * acked_bytes / cwnd
```

Реакция на потери:

```text
if random_loss:
  cwnd = max(0.9 * cwnd, 2 * MSS)
else congestion_loss:
  ssthresh = max(cwnd / 2, 2 * MSS)
  cwnd = ssthresh
```

Классификация `random loss` против congestion event:

- единичная потеря;
- нет заметной RTT inflation (`srtt <= 1.2 * min_rtt`);
- acked bytes не меньше lost bytes в том же событии.

Pacing:

```text
base_rate = cwnd * 8 / srtt
slow_start_gain = 5/4
ca_gain         = 4/3
pacing_interval = packet_bytes * 8 / pacing_rate
floor           = 200 us
```

Это убирает burst-отправки и делает `pacing_rate` наблюдаемым через snapshot transport state.

## Validation Stand

Текущий deterministic stand лежит в `omega-transport/src/transport_v2/tests.rs` и покрывает:

- fragmentation/reassembly;
- ACK range generation under reordering;
- bytes-in-flight reduction on ACK;
- priority of `interactive` over `bulk`;
- bounded retransmission after timeout;
- connection-id rotation after configured packet interval.

Это не заменяет full network simulator, но уже дает контролируемый regression bench для loss/reorder/scheduling semantics и защищает от возврата к retransmit storm-поведению.

## Ограничения фазы

На `2026-04-06` зафиксировано так:

- data path реально идет через frame layer и ACK ranges;
- header protection и inner connection-id rotation реализованы;
- `flow_id` как outer lookup handle пока не ротируется;
- FEC frame layer готов, но full repair path остается предметом следующей transport/FEC фазы;
- stealth cover теперь должен интегрироваться поверх scheduler/assembler, а не поверх legacy packet cache.
