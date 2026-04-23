# IPv6 Completion Design

## Goal

Finish Omega's IPv6 implementation so the client and server can run a dual-stack inner tunnel end-to-end across the platforms the client already advertises: Windows, Linux, and macOS.

## Scope

This design closes the remaining gaps after the first dual-stack phase:

1. Windows must support an IPv6 outer server endpoint instead of rejecting it.
2. Linux and macOS must perform real route and DNS orchestration for full-tunnel and split-tunnel operation.
3. Client configuration must support IPv6 split routes and IP-agnostic DNS server parsing.
4. Diagnostics and docs must describe the real behavior.

## Approach Options

### Option A: Command-driven platform orchestration in the existing client

Use platform-native tools from the client process:

- Windows: PowerShell `Get-NetRoute`, `New-NetRoute`, `Remove-NetRoute`, `Set-DnsClientServerAddress`
- Linux: `ip`, `ip -6`, `resolvectl` when available
- macOS: `route`, `networksetup`, `scutil`-style service discovery via shell commands

Pros:

- Fits the current codebase style, which already uses `Command` on Windows
- No new Rust dependency graph
- Easier to reason about cleanup because the client owns every route/DNS change explicitly

Cons:

- More platform shell parsing
- Runtime depends on the platform utilities being present

### Option B: Introduce Rust networking crates for each platform

Wrap route/DNS changes in dedicated crates or OS APIs.

Pros:

- Cleaner long-term abstraction
- Less shell parsing

Cons:

- Much larger dependency and maintenance cost
- Slower to ship, riskier in an existing codebase that already uses shell commands

### Option C: Leave DNS/routing partially manual outside Windows

Keep dual-stack TUN and handshake support but document that Linux/macOS operators must install routes and DNS themselves.

Pros:

- Smallest code delta

Cons:

- Does not satisfy "ready" IPv6
- Leaves the user-facing product incomplete

## Recommendation

Use Option A.

It matches the current codebase, keeps changes local to `omega-client`, and lets the VPN runtime fully own the network state it creates.

## Design

### 1. Client config contract

`omega-client/src/config.rs` will be extended so the client can express both IPv4 and IPv6 split routes and accept DNS servers as generic `IpAddr` values.

New behavior:

- keep `OMEGA_SPLIT_ROUTES` for IPv4 CIDRs
- add `OMEGA_SPLIT_ROUTES_V6` for IPv6 CIDRs
- parse `OMEGA_DNS_SERVERS` as IPv4 and IPv6 addresses
- keep current defaults, but allow `OMEGA_IPV6_POLICY=tunnel` to drive full dual-stack routing

### 2. Shared client network orchestration

Move route/DNS lifecycle into a dedicated `omega-client/src/network.rs` module.

That module will:

- own a platform-specific `NetworkState`
- apply route and DNS changes after TUN creation
- clean them up on shutdown
- keep the platform command parsing and command construction out of `main.rs`

### 3. Windows completion

Windows orchestration will become dual-stack for both the inner tunnel and the outer server endpoint.

New behavior:

- preserve IPv4 or IPv6 reachability to the Omega server before installing full-tunnel routes
- install IPv6 `::/1` and `8000::/1` routes when `OMEGA_IPV6_POLICY=tunnel`
- keep cleanup symmetric for both families

### 4. Linux completion

Linux orchestration will:

- preserve a host route to the server endpoint using `ip route get` / `ip -6 route get`
- install full-tunnel or split routes for IPv4 and IPv6
- configure DNS with `resolvectl` when tunnel DNS is requested
- revert DNS with `resolvectl revert` during cleanup

### 5. macOS completion

macOS orchestration will:

- preserve the outer server route using `route -n get`
- install full-tunnel or split routes with `route`
- update DNS on the active primary network service using `networksetup`
- restore previous DNS settings on cleanup

For full-tunnel mode this changes system DNS on the active service, which is acceptable because the client already owns connect/disconnect lifecycle and will restore the prior state.

### 6. Diagnostics and verification

Diagnostics will remain JSON-first, but now the config/runtime values they report will represent actual dual-stack behavior rather than Windows-only routing.

Tests will cover:

- IPv6 split route parsing
- generic DNS parsing
- command-output parsing for Linux/macOS/Windows route discovery helpers
- existing protocol/session/datapath dual-stack paths

## Error Handling

- If required platform route discovery fails, the client must fail fast in full-tunnel mode instead of silently running half-configured.
- DNS setup failures should also fail fast when `OMEGA_DNS_POLICY=tunnel`.
- Split-tunnel route failures should fail the session startup because partial route ownership is too risky.

## Out of Scope

- Routed-prefix IPv6 or NPTv6 on the server
- TCP outer transport fallback
- Full split-DNS policy beyond "system DNS" vs "tunnel DNS"

## Success Criteria

IPv6 is considered complete for this pass when:

1. The inner tunnel is dual-stack end-to-end.
2. Windows no longer rejects IPv6 outer server endpoints.
3. Linux and macOS install and clean up the routes required for dual-stack full/split tunnel operation.
4. DNS can be configured for tunnel mode with IPv4 or IPv6 resolvers.
5. `cargo test --workspace` remains green after the change.
