# IPv6 Completion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Finish Omega's IPv6 implementation across Windows, Linux, and macOS client networking.

**Architecture:** Extend client config to understand IPv6 split routes and generic DNS resolvers, move route/DNS lifecycle into a dedicated client network module, and complete platform-specific orchestration for Windows, Linux, and macOS. Keep the server-side dual-stack handshake and NAT66 model from phase 1.

**Tech Stack:** Rust workspace, `std::process::Command`, `tun-rs`, PowerShell, Linux `ip`/`resolvectl`, macOS `route`/`networksetup`.

---

### Task 1: Add failing config tests for IPv6 completion

**Files:**
- Modify: `omega-client/src/config.rs`
- Test: `omega-client/src/config.rs`

- [ ] Add failing tests for IPv6 split-route parsing and IP-agnostic DNS parsing.
- [ ] Run the focused config tests and confirm they fail for the expected reason.
- [ ] Implement the minimal parsing changes.
- [ ] Re-run the focused config tests until they pass.

### Task 2: Add failing network orchestration tests

**Files:**
- Create: `omega-client/src/network.rs`
- Modify: `omega-client/src/main.rs`
- Test: `omega-client/src/network.rs`

- [ ] Add failing tests for route-discovery parsing helpers for Windows, Linux, and macOS.
- [ ] Add failing tests for command-building behavior for full-tunnel dual-stack routing.
- [ ] Run the focused network tests and confirm they fail before implementation.
- [ ] Implement the network module and wire it into `main.rs`.
- [ ] Re-run the focused network tests until they pass.

### Task 3: Finish Windows outer IPv6 endpoint handling

**Files:**
- Modify: `omega-client/src/network.rs`
- Modify: `omega-client/src/main.rs`
- Test: `omega-client/src/network.rs`

- [ ] Add a failing Windows test that expects preserved outer IPv6 server routing.
- [ ] Implement IPv6 outer-route preservation and symmetric cleanup.
- [ ] Re-run the Windows-focused tests until they pass.

### Task 4: Finish Linux and macOS route/DNS lifecycle

**Files:**
- Modify: `omega-client/src/network.rs`
- Modify: `omega-client/src/diagnostics.rs`
- Test: `omega-client/src/network.rs`

- [ ] Add failing tests for Linux/macOS route discovery and DNS state parsing helpers.
- [ ] Implement Linux route and DNS orchestration.
- [ ] Implement macOS route and DNS orchestration.
- [ ] Re-run the focused tests until they pass.

### Task 5: Sync docs and run full verification

**Files:**
- Modify: `README.md`
- Modify: `docs/CONFIG_REFERENCE.md`
- Modify: `docs/GAMING_NETWORKING.md`
- Modify: `docs/PROJECT_CONTEXT.md`
- Verify: full workspace

- [ ] Update docs to describe IPv6 split routes and platform routing ownership.
- [ ] Run `cargo fmt --all`.
- [ ] Run `cargo test --workspace`.
- [ ] Report any residual limits that are still intentionally out of scope.
