# Control Plane State Model And API Schema

## Source Of Truth

`omega-control` теперь хранит единый typed state model в `ControlPlaneStore`.

Durable backend:

- `state/control_plane.json`

Read-only projections:

- `state/sessions.json` - session snapshot для UI/ops;
- `state/runtime.json` - runtime/fabric summary;
- `state/admin_commands.ndjson` - command queue для runtime-only действий.

Ключевой принцип: snapshot JSON больше не является первичной моделью. Первична typed state machine в коде, а JSON - только durable serialization этого состояния.

## Core Objects

### `ControlPlaneMeta`

Глобальный meta-layer для snapshot:

- `revision` - монотонный номер мутации;
- `term` - слот под future replicated leadership epoch;
- `last_updated_at` - unix timestamp последней strong mutation;
- `last_actor` - кто сделал последнюю control-plane мутацию;
- `last_event_hash` - голова audit hash chain;
- `consistency` - контракт по доменам `identity/session/ticket/policy/fabric`.

### `UserRecord`

- `user_id`
- `status = active | blocked | deleted`
- `max_devices`
- `max_concurrent_sessions`
- `created_at`
- `updated_at`

### `DeviceRecord`

- `device_id`
- `user_id`
- `device_name`
- `platform`
- `public_key_fingerprint`
- `token_hash`
- `revoked`
- `last_seen_at`
- `created_at`
- `updated_at`

### `SessionRecord`

- `flow_id`
- `user_id`
- `device_id`
- `tunnel_ip`
- `client_addr`
- `policy_id`
- `mode`
- `relay_permitted`
- `privileged_boundary`
- `active_route_id`
- `backup_route_ids`
- `route_diversity_score`
- `fabric_ticket_generation`
- `status = active | terminated | revoked | expired`
- `consistency = strong`
- `created_at`
- `updated_at`
- `last_seen_at`
- `terminated_at`
- `termination_reason`

### `TicketRecord`

- `ticket_id`
- `ticket_hash`
- `flow_id`
- `device_id`
- `policy_id`
- `issued_at`
- `expires_at`
- `consumed_at`
- `revoked_at`
- `status = issued | consumed | revoked | expired`
- `consistency = strong`
- `reason`

### `FabricNodeRecord`

- `node_id`
- `role = edge | relay | exit`
- `region`
- `operator`
- `graph_revision`
- `healthy`
- `operational_percent`
- `trust_label`
- `last_seen_at`
- `consistency = eventual`

### `PolicyObject`

- `policy_id`
- `version`
- `description`
- `enabled`
- `rules[]`
- `updated_at`

### `AuditEvent`

- `ts`
- `revision`
- `action`
- `actor`
- `entity`
- `consistency`
- `details`
- `prev_hash`
- `event_hash`

## Lifecycle Transitions

### User lifecycle

- `active -> blocked`
- `blocked -> active`
- `active|blocked -> deleted`

Effects:

- `blocked/deleted` user terminates active sessions and invalidates tickets.

### Device lifecycle

- `registered -> revoked`
- `registered -> token_rotated`

Effects:

- revoke/token rotation terminates active sessions for device;
- revoke/token rotation invalidates issued tickets for device.

### Session lifecycle

- `active` on successful handshake finalization;
- `terminated` on operator action, peer close, idle timeout or control-plane reconcile;
- `revoked` on device/user revoke path.

### Ticket lifecycle

- `issued -> consumed`
- `issued -> revoked`
- `issued -> expired`

`consume_ticket` теперь предсказуемо переводит ticket в terminal state и блокирует повторное resume usage.

## Runtime API Surface

Ключевые методы `ControlPlaneStore`:

- `create_user`
- `block_user`
- `unblock_user`
- `delete_user`
- `register_device`
- `revoke_device`
- `rotate_device_token`
- `authenticate_device`
- `authorize_resumption`
- `ensure_bootstrap_policy`
- `put_policy`
- `evaluate_session_admission`
- `activate_session`
- `update_session_route`
- `terminate_session_record`
- `issue_ticket`
- `authorize_ticket`
- `consume_ticket`
- `upsert_fabric_node`
- `mark_fabric_node`
- `summary`
- `recent_audit`

## CLI Surface

`omega-server admin` теперь имеет control-plane oriented команды:

- `list_active_sessions`
- `show_control_plane`
- `list_policies`
- `show_policy_conflicts`
- `list_fabric_nodes`
- `rotate_device_token`

Остальные user/device commands тоже работают уже поверх нового typed control plane.

## Runtime Integration Points

### Handshake

`omega-edge/src/handshake.rs` теперь:

- оценивает policy decision при session creation;
- создает `SessionActivation` projection;
- issue/consume resumption tickets через control plane;
- пишет `policy_decision` audit событие.

### Session manager

`omega-edge/src/session.rs` теперь:

- проецирует `activate_session` в control plane;
- пишет `terminate_session_record` при remove/terminate/idle timeout;
- остается runtime owner для packet state, но не для control truth.

### Server runtime

`omega-edge/src/server.rs` теперь:

- bootstrap'ит default policy;
- регистрирует fabric graph nodes в control plane;
- гоняет `spawn_control_plane_reconcile_task`, чтобы revoke/terminate из CLI доходили до live sessions;
- обновляет session route projection после fabric failover.

## Backward Compatibility

Если `state/control_plane.json` отсутствует, store умеет подхватить legacy sibling `identity.json` и мигрировать model-forward без ручного конвертера.

Это важно для существующих installation paths и для upgrade без разрушения device inventory.
