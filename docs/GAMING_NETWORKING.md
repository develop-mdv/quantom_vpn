# Gaming Networking Notes

This repository now ships a gaming-oriented runtime profile and a server bootstrap that is closer
to the "UDP-first, MTU-aware, diagnosable" target from the Dota/Steam VPN spec.

## What Was Added

- `OMEGA_PROFILE=gaming|general|restricted`
- `OMEGA_MORPHING=balanced|full|off`
- `OMEGA_TUNNEL_MODE=full|split`
- `OMEGA_SPLIT_ROUTES_V6` for IPv6 split-tunnel destinations
- `OMEGA_TUN_MTU` for explicit tunnel MTU selection
- `OMEGA_DNS_POLICY=tunnel|system`
- `OMEGA_IPV6_POLICY=disabled|passthrough|tunnel`
- `OMEGA_DIAGNOSTICS_PATH` client runtime snapshot JSON
- `OMEGA_RUNTIME_SNAPSHOT` server runtime snapshot JSON
- `deploy/setup_nat.sh` now configures `nftables`, `MASQUERADE`, MSS clamping, loose `rp_filter`,
  and longer UDP conntrack timeouts
- `deploy/diagnose_server.sh` now validates the `nftables` and runtime snapshot state

## Recommended Gaming Defaults

Client:

```env
OMEGA_PROFILE=gaming
OMEGA_MORPHING=off
OMEGA_TUNNEL_MODE=full
OMEGA_TUN_MTU=1380
OMEGA_KEEPALIVE_SECS=25
OMEGA_DNS_POLICY=tunnel
OMEGA_IPV6_POLICY=tunnel
OMEGA_NETWORK_DIAG=1
```

Server:

```env
OMEGA_PROFILE=gaming
OMEGA_MORPHING=off
OMEGA_TUN_MTU=1380
OMEGA_BIND=[::]:443
OMEGA_IPV6_MODE=nat66
OMEGA_RUNTIME_SNAPSHOT=/opt/omega/state/runtime.json
```

Then bootstrap the server networking as root:

```bash
sudo OMEGA_VPN_PORT=443 OMEGA_VPN_IPV6_MODE=nat66 bash deploy/setup_nat.sh
sudo OMEGA_VPN_IPV6_MODE=nat66 bash deploy/diagnose_server.sh
```

## Diagnostics Files

Client runtime snapshot:

- `omega-client/state/diagnostics.json` by default

Server runtime snapshot:

- `state/runtime.json` by default
- `/opt/omega/state/runtime.json` in the provided systemd service

These snapshots are intended to answer "what MTU, DNS policy, tunnel mode, keepalive, and session
health are active right now?" without guessing from logs.

## Interpreting Very High In-Game Ping

If the client diagnostics show a moderate handshake RTT to the VPN server (for example ~100-200 ms)
but the game reports ~1s+ latency to every region, the bottleneck is usually not just "server is
far away". That pattern more often points to one of these issues:

- heavy packet loss and retransmits on the UDP relay path;
- provider/security-group egress filtering for game UDP traffic;
- an MTU/path issue that causes bursts of loss and recovery.

For maximum throughput, keep `OMEGA_MORPHING=off` first. If the line is still unstable, test
a smaller `OMEGA_TUN_MTU` such as `1320` or `1280`. If you explicitly need more traffic cover,
step back up to `OMEGA_MORPHING=balanced`.

## Important Current Limitations

The repository still does **not** meet the spec completely:

- The datapath is still a custom Omega UDP tunnel, not WireGuard.
- There is no real OpenVPN TCP fallback implementation.
- IPv6 now works as an inner dual-stack tunnel, but the current server deploy model is still NAT66 rather than routed-prefix IPv6.
- Split tunnel route selection exists for both IPv4 and IPv6 on the client, but true split-DNS behavior is still intentionally limited.

So the project is now much closer to the operational requirements for Steam/Dota troubleshooting,
but it has not yet completed the protocol-level migration required by the spec.
