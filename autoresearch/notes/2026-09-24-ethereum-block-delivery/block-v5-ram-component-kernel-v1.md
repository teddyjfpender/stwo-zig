# Two-event RAM witness and interaction comparison

ReleaseFast CPU comparison on the same 32,768 sorted writable-memory events, with 16 accesses per address and full-u64 clocks. A shared sealed 65,536-value inverse table is prepared before either measurement. One warm pair precedes four ABBA samples. No commitment, STARK, FRI, recursion, guest execution or GPU is invoked.

| Measurement | Word v4 | Two-event lanes |
|---|---:|---:|
| Physical rows | 32,768 | 16,384 |
| Median interaction generation | 32.327 ms | 21.500 ms |
| Fixed/main/interaction value arrays | 14,024,704 bytes | 11,141,120 bytes |

Interaction generation is 1.50x faster (33.5% less time). Arrays use 20.6% fewer bytes. Witness allocation/fill/seal is about 4.8–5.0 ms for each path; see the raw samples. Array bytes exclude counters, shared inverses, temporary scratch, metadata and allocator overhead: this is not process peak memory.

Every sample compares exact transition, link, initial and endpoint buses, endpoint/range census, aggregate range sum and complete counter digest. Word batches neighboring limb requests while lanes batch corresponding positions across events; their individual range planes intentionally differ. Register endpoints are absent.

No whole-proof or block speedup is established. Canonical lifecycle/transport codegen and fresh proof verification require separate qualification. Segment runs remain stopped.

Evidence: [raw samples](cpu-performance-gates-v1/ram-two-event-witness-interaction-kernel-v1.log), [source hashes and scope](cpu-performance-gates-v1/ram-two-event-witness-interaction-kernel-source-v1.json). Reproduce with the focused helper and root `src/frontends/riscv/block_v5_ram_lanes_kernel_bench_root.zig`, filter `block-v5 RAM component benchmark`.
