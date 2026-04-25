# Production Network Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Harden Omega's production networking so deploys fail on broken IPv6/NAT state, strict DNS leak guard verifies real DNS ownership, Windows strict kill switch blocks fallback leakage during a session, and TCP fallback can be introduced without weakening UDP.

**Architecture:** Keep the working UDP datapath as the default. Add deploy/runtime consistency checks in Bash, platform policy helpers in `omega-client/src/network.rs`, and a conservative transport policy in config/docs. TCP is implemented as a framed transport only after the safety gates are in place; HTTPS/TLS camouflage remains a follow-up layer.

**As-built scope note:** Strict kill switch is a production-safe first pass, not a full WFP/global outbound policy. It is fail-fast outside Windows full-tunnel and blocks DNS leakage on physical adapters when strict DNS/kill switch is enabled.

**Tech Stack:** Rust workspace, Tokio networking, Windows PowerShell/NetSecurity, Linux/macOS route/DNS tools, Bash deploy diagnostics, GitHub Actions.

---

### Task 1: Deploy Gate Consistency

**Files:**
- Modify: `deploy/diagnose_server.sh`
- Test: PowerShell guard over `deploy/diagnose_server.sh`

- [x] Add a failing guard that expects diagnostics to fail when runtime `ipv6_mode=nat66` does not match expected mode or NAT66 state.
- [x] Add `runtime_contains` checks that treat runtime mismatch as `[FAIL]` instead of `[WARN]`.
- [x] Add IPv6 route/egress checks for `OMEGA_VPN_IPV6_MODE=nat66`: `ip -6 route get 2606:4700:4700::1111` must pass; `ping -6` passes when available.
- [x] Add `nft -c -f /etc/nftables.d/omega-vpn.nft` validation when the generated config exists.
- [x] Run the guard and `git diff --check`.

### Task 2: DNS Leak Strict Verification

**Files:**
- Modify: `omega-client/src/network.rs`
- Modify: `omega-client/src/config.rs` only if enum/config surface needs extension
- Test: `omega-client/src/network.rs`

- [x] Add tests for DNS server normalization and subset matching.
- [x] Add Windows DNS readback using `Get-DnsClientServerAddress -InterfaceAlias`.
- [x] After setting tunnel DNS, verify configured DNS appears on the tunnel interface. In `strict`, fail; in `warn`, log and continue.
- [x] On Linux and macOS, verify readback through `resolvectl dns` or `networksetup -getdnsservers` after configuration where tooling is available.

### Task 3: Windows Strict Kill Switch

**Files:**
- Modify: `omega-client/src/network.rs`
- Test: `omega-client/src/network.rs`

- [x] Add tests for strict policy support decisions: Windows full-tunnel is supported; split-tunnel strict is rejected; Linux/macOS strict fail fast.
- [x] Add Windows stale cleanup for Omega firewall rules.
- [x] Keep full-tunnel `/1` routes under Omega ownership and stale cleanup so old route state cannot survive retries.
- [x] Add strict DNS firewall block rules for physical adapters on TCP/UDP 53, scoped to Omega display group, and clean them on normal shutdown/stale cleanup.
- [x] Roll back strict policy if later route/DNS configuration fails.

### Task 4: TCP Fallback First Pass

**Files:**
- Modify: `omega-client/src/config.rs`
- Modify: `omega-client/src/main.rs`
- Modify: `omega-server/src/main.rs`
- Modify: `omega-server/src/datapath.rs`
- Modify: `omega-server/src/session.rs`
- Test: focused Rust unit tests where possible

- [x] Add `OMEGA_TRANSPORT=udp|tcp|auto` to client config and runtime docs.
- [x] Add server `OMEGA_TCP_BIND`/`OMEGA_TCP_ENABLE` config without changing UDP default.
- [x] Implement framed packet helpers: 2-byte big-endian length + Omega packet bytes.
- [x] Add TCP listener and per-connection writer queue.
- [x] Register TCP session egress in session state so TUN-to-client packets can be written to TCP instead of UDP.
- [x] Add client TCP handshake/data loops and `auto` fallback from UDP handshake failure to TCP.
- [x] Keep UDP path untouched and default.

### Task 5: Docs And Verification

**Files:**
- Modify: `docs/CONFIG_REFERENCE.md`
- Modify: `docs/OPERATIONS.md`
- Modify: `docs/PROJECT_CONTEXT.md`

- [x] Document deploy gate expectations and recovery commands.
- [x] Document strict kill switch limitations and platform support.
- [x] Document DNS leak guard behavior.
- [x] Document TCP fallback as framed TCP, with HTTPS/TLS camouflage deferred.
- [x] Run `cargo fmt --all --check`.
- [x] Run `cargo test --workspace`.
- [x] Run `git diff --check`.
