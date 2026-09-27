# Isolated BLAKE3 throughput and commitment geometry

ReleaseFast on the same ARM host. Each case has one explicit warmup and six measured samples, alternating scalar/SIMD order. Inputs change each iteration and outputs are consumed; scalar/SIMD checksums agree. This is a single-thread, hot-data microbenchmark, not a proving-time result. The imported `batch.zig` is the preceding unpromoted expanded candidate.

| Operation | Bytes or columns | Scalar / SIMD median time |
| --- | ---: | ---: |
| bytes | 64 | 1.288× |
| bytes | 256 | 1.436× |
| bytes | 1024 | 1.404× |
| bytes | 8192 | 1.441× |
| columns | 4 | 1.330× |
| columns | 64 | 2.340× |
| columns | 275 | 2.483× |
| columns | 1024 | 2.609× |
| nodes | 64 | 1.198× |

Build: `/opt/homebrew/opt/zig@0.15/bin/zig build-exe -OReleaseFast --dep stwo_core -Mroot=autoresearch/notes/2026-09-23-blake3-throughput/main.zig -Mstwo_core=src/core/mod.zig -femit-bin=autoresearch/notes/2026-09-23-blake3-throughput/bench`. Run `bench` with stdout redirected to a new JSONL output.

The one-sample canonical Keccak geometry diagnostic used the frozen preceding tiled-witness CPU binary and `STWO_ZIG_PCS_COLUMN_HISTOGRAM=1`, 16 workers. It verified in process and matched the preceding proof hash. These instrumented timings are not performance evidence.

The receipts show log-21 final leaves with log-14 prefix states (30,932,992 bytes / 16,384 states = 1,888 bytes per BLAKE3 hasher). The 96 MiB state cap cannot admit the next available height group. Fixed/main/interaction tails report 124,452,864 / 52,756,480 / 68,419,584 repeated column absorptions, respectively. Tail-cache bytes are zero.

Source inspection establishes that the dominant bounded tail builder was untouched by the rejected SIMD integration. Its default path independently replays the remaining columns at final-domain multiplicity. The existing `commitColumnsWithReusedBoundedPrefix` retains two parity states per height and eliminates most repeated absorptions. It was enabled explicitly by recursion but ordinary BLAKE3 schemes defaulted to false. This is a stronger next experiment than expanding the SIMD code: qualify BLAKE3 layer parity and enable the existing shared reuse policy, with a same-binary replay control.
