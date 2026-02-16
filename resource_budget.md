# Omega VPN — Resource Budget

Target: 1-2 vCPU (e.g. AMD EPYC @ 2.5 GHz), 1-2 GB RAM, 10-50 clients, >300 Mbps aggregate.

## Per-Packet CPU Cost

| Operation | Cost / 1400B pkt | Notes |
|---|---|---|
| ChaCha20-Poly1305 encrypt | ~0.5 µs | ring, AVX2/NEON SIMD |
| ChaCha20-Poly1305 decrypt | ~0.5 µs | same |
| ChaosPrng iteration | ~5 ns | 2× u128 multiply |
| RTP header generation | ~10 ns | 12 bytes memcpy |
| Replay filter check | ~5 ns | bitmap lookup |
| TUN read/write | ~1 µs | kernel copy |
| UDP sendto/recvfrom | ~1 µs | kernel syscall |
| **Total (no FEC)** | **~3 µs** | |
| RaptorQ encode (K=32) | ~15 µs | only when active |
| ARQ NACK processing | ~100 ns | rare |

## Throughput Estimates (2 vCPU @ 2.5 GHz)

| Scenario | PPS | CPU/core | Aggregate CPU |
|---|---|---|---|
| 300 Mbps, 1400B pkts, no FEC | ~27k | ~8% | ~4% (2 cores) |
| 500 Mbps, 1400B pkts, no FEC | ~45k | ~14% | ~7% |
| 300 Mbps + RaptorQ (all pkts) | ~27k | ~48% | ~24% |
| 500 Mbps + RaptorQ (all pkts) | ~45k | ~80% | ~40% |
| 300 Mbps + RaptorQ (5% of pkts) | ~27k | ~10% | ~5% |

**Conclusion**: Without FEC, CPU stays well under 15% at 500 Mbps. With adaptive
FEC (only on lossy paths), CPU remains under 10% for typical conditions.

## Per-Connection Memory

| Component | Size | Notes |
|---|---|---|
| SessionKeys | 80 B | 2×32B keys + 2×u64 nonces |
| ChaosPrng state | 16 B | seed + x |
| ReplayFilter | 24 B | u128 bitmap + u64 window_top |
| ARQ retransmit buf | ~2 KB max | 32 slots × 64B header |
| RaptorQ decoder | ~4 KB | when active |
| Metadata (timers etc) | ~100 B | |
| **Total (no FEC)** | **~220 B** | |
| **Total (with FEC)** | **~6.3 KB** | |

50 connections × 6.3 KB = **315 KB**. Negligible.

## System Memory Budget

| Component | Size |
|---|---|
| Binary (omega-server) | ~5-10 MB |
| tokio runtime | ~2-5 MB |
| TUN buffers | ~256 KB |
| UDP socket buffers | ~512 KB |
| Session state (50 conn) | ~315 KB |
| Prometheus metrics | ~1 MB |
| **Total** | **~15-20 MB** |

On a 1 GB VPS, this leaves >95% for the OS and other services.

## Scaling Limits

| Resource | Limit | Bottleneck |
|---|---|---|
| Connections | ~1024 | DashMap + hashmap entries |
| Throughput | ~1 Gbps | Single UDP socket + TUN |
| PPS | ~200k | Syscall overhead (recvmmsg helps) |
| eBPF maps | 1024 entries | max_entries config |
