# IPv6 Dual-Stack Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn Omega from IPv4-only tunneling into a working dual-stack inner tunnel with deployable NAT66 server support.

**Architecture:** Extend the handshake/session contract to lease IPv4 and optional IPv6 tunnel addresses, route both families through the same UDP datapath, and teach the client/server TUN bootstrap plus deploy scripts to operate in dual-stack mode. Keep the outer transport UDP-only and keep the first pass conservative: NAT66 on the server, dual-stack TUN on the client, and explicit documentation of the remaining Windows outer-IPv6 gap.

**Tech Stack:** Rust workspace (`omega-core`, `omega-server`, `omega-client`), `tun-rs`, Windows PowerShell routing commands, `nftables`, Bash deploy scripts.

---

### Task 1: Lock the protocol contract

**Files:**
- Modify: `omega-core/src/protocol.rs`
- Test: `omega-core/src/protocol.rs`

- [x] Add `tunnel_ipv6: Option<Ipv6Addr>` to `ServerHello`.
- [x] Keep deserialize backward-compatible with old IPv4-only `ServerHello`.
- [x] Add red/green tests for dual-stack and IPv4-only handshake decoding.

### Task 2: Extend session leases and datapath lookup

**Files:**
- Modify: `omega-server/src/session.rs`
- Modify: `omega-server/src/handshake.rs`
- Modify: `omega-server/src/datapath.rs`
- Test: `omega-server/src/session.rs`
- Test: `omega-server/src/datapath.rs`

- [x] Replace single IPv4 lease allocation with `TunnelAddrs { ipv4, ipv6 }`.
- [x] Make session lookup accept `IpAddr` so tunneled IPv6 packets map to the same flow.
- [x] Add tests for dual-stack lease allocation and IPv6 destination extraction.

### Task 3: Boot dual-stack TUN devices

**Files:**
- Modify: `omega-server/src/main.rs`
- Modify: `omega-server/src/runtime.rs`
- Modify: `omega-client/src/main.rs`
- Modify: `omega-client/src/config.rs`
- Modify: `omega-client/src/diagnostics.rs`

- [x] Add `OMEGA_IPV6_MODE=nat66|disabled` on the server and expose it in runtime snapshots.
- [x] Add `OMEGA_IPV6_POLICY=tunnel` on the client and propagate IPv6 tunnel state into diagnostics.
- [x] Build dual-stack TUN devices when the handshake/runtime enables IPv6.
- [x] Let the client bind UDP sockets for IPv4 or IPv6 server endpoints.

### Task 4: Make deploy and admin surfaces truthful

**Files:**
- Modify: `omega-server/src/web_admin.rs`
- Modify: `deploy/setup_nat.sh`
- Modify: `deploy/diagnose_server.sh`
- Modify: `README.md`
- Modify: `docs/CONFIG_REFERENCE.md`
- Modify: `docs/GAMING_NETWORKING.md`
- Modify: `docs/PROJECT_CONTEXT.md`

- [x] Show IPv6 tunnel leases in the built-in admin UI.
- [x] Teach bootstrap/diagnostics scripts to support NAT66 mode and `fd70:7::/64`.
- [x] Update docs so they describe dual-stack inner tunneling instead of IPv4-only behavior.

### Task 5: Verify and capture follow-ups

**Files:**
- Verify: workspace formatting and tests

- [ ] Run `cargo fmt --all`
- [ ] Run `cargo test --workspace`
- [ ] Record any remaining follow-ups:
  Windows full-tunnel still assumes an IPv4 outer server endpoint, Linux/macOS route orchestration still needs a dedicated pass, and routed-prefix IPv6 is not implemented yet.
