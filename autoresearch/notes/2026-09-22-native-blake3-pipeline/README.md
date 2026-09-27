# Admitted native BLAKE3 preparation/proving overlap

The local pipeline runs one serial preparation coordinator alongside one persistent
proving worker group, with a one-item bounded handoff. It validates the existing
PolicyV2 before allocating/spawning and checks both total and per-node CPU/memory
allowances. Worker count and allocation cap must match the admitted worker.
Every prepared job must match the worker's exact key context before proving.

Reservation arithmetic includes the preparation cap, worker cap, two queue byte
limits (ready storage and the consumer's current prepared input), explicit producer
and helper stacks, bounded result/control metadata and caller-declared external
memory. At most 64 jobs are accepted. Returned proof allocations remain charged
to the retained worker budget. No unbounded output payload allocator was added.

Failures cancel/drain the queue and join the producer before returning, releasing
prepared owners and any partial outputs. The caller retains worker ownership.
The pipeline reuses canonical prepareBounded and Worker.prove; it has no separate
witness or proof implementation. Reports retain monotonic per-job intervals and
compute preparation/proving overlap, excluding time blocked on queue send.

This is admission for one pipeline node. The caller's higher-level scheduler must
limit simultaneous pipeline nodes. External-memory reservations remain a caller
obligation; this is not a measured process RSS ceiling. The local runner validates
a policy but does not mint/forward a production ExecutionKey or activate the
production worker wire.

## Qualification

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-native-segment -Doptimize=ReleaseSafe --summary all
```

Final exit 0: 4/4 steps, 3/3 tests, 41 s / 2 GiB; compile 1 min / 5 GiB.
Initial compile failed on a test variable shadowing an existing job binding;
renamed it before the passing run. No allocator leaks reported.

The gate uses the real execution PolicyV2 and covers insufficient CPU/memory
reservation, preparation failure at a 64 MiB cap, and consumer rejection while
the proving worker is busy. Both failed runs join/clean up, followed by a successful
two-job run on the same worker. The successful run proves two freshly prepared
owners, verifies both via the canonical codec and independent verifier, and
retains the existing proof/capture lifetime check after worker destruction.

| Observed/configured item | Value |
| --- | ---: |
| Jobs | 2 |
| Reserved CPU tokens | 3 (serial preparation + two proving workers) |
| Combined reservation | 11,836,342,192 bytes |
| Policy allowance | 12 GiB |
| Preparation cap | 2 GiB |
| Worker cap | 4 GiB |
| Ready queue limit | 512 MiB / one item |
| External reservation | 4 GiB |
| Measured stage overlap | 1,343,412,708 ns (~1.34 s) |
| Peak tracked worker allocations | 1,632,926,982 bytes |

These are local diagnostic allocations/reservations and execution overlap, not
production sizing or an end-to-end speedup measurement. No serial A/B benchmark
ran. The two jobs repeat the same verified native child and admitted key. This
does not qualify distinct-child aggregation, statement-independent keys, or
parent-of-parent recursion.

Artifacts remain 111,428 bytes with diagnostic key
`f76d51b30dce850ad74060c42808bed2f4dd5bee6cc5705673f00b4754d3c976`.
Child q1/PoW0 and parent q8/PoW0 remain unchanged. Production profile/key integration,
binary/parent-of-parent and Metal qualification remain unfinished. The original
fused PCS/DEEP and final-layout witness optimization objectives remain active.

Logs and source snapshots are pinned by relative SHA256SUMS.
