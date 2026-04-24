# VPN Reliability P0 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make Omega recover cleanly from client/network/deploy failures and prove that IPv4, IPv6, DNS, and MTU are healthy after connection.

**Architecture:** Add a small encrypted control probe for PMTU discovery before TUN creation, extend client diagnostics with explicit health-check states, and make route/DNS lifecycle safer through stale cleanup and rollback. Keep strict traffic blocking opt-in so the default path improves reliability without risking a machine stuck offline.

**Tech Stack:** Rust workspace, Tokio UDP, existing Omega encrypted packet format, Windows PowerShell/route tooling, Linux/macOS route helpers, Bash deploy scripts.

---

### Task 1: Path MTU Probe Protocol

**Files:**
- Modify: `omega-core/src/protocol.rs`
- Modify: `omega-client/src/config.rs`
- Modify: `omega-client/src/main.rs`
- Modify: `omega-client/src/diagnostics.rs`
- Modify: `omega-server/src/datapath.rs`

- [ ] Add `PacketType::PathProbe` and `PacketType::PathProbeReply`.
- [ ] Add client config `OMEGA_MTU_POLICY=fixed|auto` and `OMEGA_MTU_PROBE_TIMEOUT_MS`.
- [ ] After handshake key derivation, send encrypted probe packets from largest to smallest candidate MTU.
- [ ] Make the server echo path probes without writing them to TUN.
- [ ] Build TUN with the selected MTU and write probe results to diagnostics.

### Task 2: Post-Connect Health Model

**Files:**
- Modify: `omega-client/src/diagnostics.rs`
- Modify: `omega-client/src/main.rs`

- [ ] Add health statuses for IPv4 egress, IPv6 egress, DNS, DNS leak guard, and MTU.
- [ ] Replace the single UDP DNS diagnostic with a post-connect health runner.
- [ ] Mark client status as `connected_healthy` only when required checks pass.
- [ ] Mark client status as `connected_degraded` when optional IPv6/MTU checks fail but IPv4 tunnel works.

### Task 3: DNS Leak Guard

**Files:**
- Modify: `omega-client/src/config.rs`
- Modify: `omega-client/src/diagnostics.rs`
- Modify: `omega-client/src/network.rs`

- [ ] Add `OMEGA_DNS_LEAK_GUARD=off|warn|strict`.
- [ ] In tunnel DNS mode, verify configured tunnel DNS servers are assigned to the tunnel interface.
- [ ] In strict mode, fail startup if tunnel DNS cannot be set.
- [ ] In warn mode, continue but mark diagnostics degraded.

### Task 4: Self-Heal And Transactional Cleanup

**Files:**
- Modify: `omega-client/src/network.rs`
- Modify: `omega-client/src/main.rs`

- [ ] Add startup stale cleanup for old Omega full/split routes and server host route.
- [ ] Roll back route/DNS changes if client network configuration fails halfway.
- [ ] Keep existing Ctrl+C cleanup and make it reuse the same cleanup path.

### Task 5: Kill Switch Policy

**Files:**
- Modify: `omega-client/src/config.rs`
- Modify: `omega-client/src/network.rs`
- Modify: `omega-client/src/diagnostics.rs`

- [ ] Add `OMEGA_KILL_SWITCH=off|soft|strict`.
- [ ] Default to `soft`: self-heal stale routes and fail startup instead of silently running half-configured.
- [ ] Implement `strict` as opt-in platform firewall/route blocking only after tunnel routes are installed.
- [ ] Always clean strict rules during normal shutdown and stale cleanup.

### Task 6: IPv6 E2E Validation

**Files:**
- Modify: `omega-client/src/main.rs`
- Modify: `omega-client/src/diagnostics.rs`
- Modify: `deploy/diagnose_server.sh`

- [ ] If `OMEGA_IPV6_POLICY=tunnel`, run an IPv6 DNS/UDP egress probe through the tunnel.
- [ ] Mark IPv6 as passed, skipped, or failed with an explicit reason.
- [ ] Extend server diagnostics to report whether NAT66/forwarding/runtime snapshot all agree.

### Task 7: Deploy Gate

**Files:**
- Modify: `deploy/update_server.sh`
- Modify: `.github/workflows/deploy.yml` if present
- Modify: `docs/OPERATIONS.md`

- [ ] Run `deploy/diagnose_server.sh` after restart when available.
- [ ] Fail and rollback deploy when server diagnostics reports failed checks.
- [ ] Print admin/UDP/listener/runtime summary at the end of deployment.

### Task 8: Verification

**Files:**
- Modify docs as needed.

- [ ] Run focused tests for each new unit.
- [ ] Run `cargo fmt --all --check`.
- [ ] Run `cargo test --workspace`.
- [ ] Run shell syntax checks for changed deploy scripts.
