# M8 GPU-native piece "d-wire" (codex/rv64-m8-gpu-d-wire)

Design: `design/riscv-proving-stack/rv64-m8-gpu-native.md` §1, §2 H1/H8/H13/H27/H28, §3.4–3.8, §6.3 D4/D5. Flag: `STWO_RV64_M8_GPU_NATIVE=1`, which requires `STWO_RV64_M8_JOBS=1`. It is default off; the default and feeder paths are byte-unchanged.

## What landed

| piece | file | evidence |
|---|---|---|
| Contract additions (additive, slab layout unchanged): `CapturedSegment`, `CaptureEnd`, `ChunkWriter`, `WarmBlock`, `BlockShape`, `RecursionShape`, `Publication`; optional `NativeFactory.{shape,pack,captured,publish}`, `RecursionFactory.{shape,captured,publish,truth_stage2}`; `ClassEntry.{stage_one_bytes,needs_capture_end}`; `Exchange.{truths,capacity_truths,truthRoot}` (r-truth's layout, word for word) | `rv64/jobs/gpu_native.zig` | host |
| Streaming capture feed (H1): per captured segment, `native.pack` writes pinned ring chunks, then the segment is sealed so its Stage1 stages while capture continues; `captured` hooks; `done` exactly once on every path; an end gate for truths whose inputs are final only at capture end | `rv64/m8_capture_stream.zig` (`Feed`, `Stream.endGate`) | host |
| Driver: the request pseudo-proof carries `stage-one.bin` (native seal job encodes it; an unfilled region refuses publication), end-gated truths, two-stage truths (stage 1 framed by the seal, stage 2 after it on the same GPU), factories' publish hooks after the single wait | `rv64/jobs/driver_request.zig`, `driver_dag.zig` | host D1 + pod D3 |
| Legacy recursion tree port (`ready_dag.Plan.initArity`) pinned to the D2 golden names (4-ary: folds 4,9,13,14 for 4+7 leaves; 4,9,14,17,18 for 7+7) | `driver_dag.zig Topology.carry` | host |
| Resident service: warm one capture per block -> shapes (rows, truths, arity) -> `Driver.install` -> ring + 2 capture streams; `begin`/`finish` (two in flight); spool loop (READY/inbox/out/done, `out/<stem>/m8-jobs.json` receipt) | `rv64/jobs/driver_serve.zig` | host (fake device) |
| GE direct capture as the service's capture source (config/image/program built once per block; `Ready.call` + `native_segment` -> `Feed`), the `combined-serve` request switch | `rv64/jobs/driver_ge.zig`, `rv64_combined_ethereum_main.zig`; exports in `riscv_cpu/mod.zig` | pod build (gate) |
| Merged siblings: n-stage1 (54623155a), n-stage2 (c76da4a37), r-truth (0756c32e0) | merge commits | host 499/509 (10 skips) |

## Evidence

**Host (laptop, Debug, memguard 6 GB), `zig build test-rv64-jobs`: 499/509 passed, 10 pre-existing skips [M]** (after the sibling merges; 334/339 before them). New D1/serve cases: a Feed-streamed request (1 host wait, 2 D2H, artifacts written by both publish hooks, native first), an empty stage-one region refused, a capture that dies after segment 0 fails the remaining Stage1s and the gated truth, two-stage truths (roots exchanged before the seal, proofs after, 1 wait), the service pipelining two requests (2 waits, 4 D2H total), install refusals (missing shape hook, failed warm capture, duplicate block, too many segments), and the spool (FIFO answers, malformed / reused / unwarmed requests refused, STOP).

**D3 rerun on both RTX 5090s with this driver (ReleaseSafe, addon-8), `d3-probe.json` [M]:** 7 segments, 2 truths, 17 nodes, 34 device jobs, 26 proofs per request.
- Positive 6/6 byte-exact, `host_waits = 1`, `d2h = 2` each. CUDA-event GPU span 0.99–1.22 ms per device. Request wall 1.26–1.64 ms.
- Host per request (warm, requests 2–6): plan 65–73 µs, make 22–25 µs, enqueue 1.04–1.25 ms (both GPUs in parallel; it overlaps device work), wait ≤ 2 µs after enqueue, finish 42–53 µs, publish 53–69 µs.
- Negative: a withheld claims publish is rejected by the seal's device check (`global_seal` word `0x0103000a`) and the request is refused.
- Peer ping-pong 26.8–27.3 µs per hop (no P2P on this pod: copies stage through the host).

**Gate default:** see `gate-1.json` (pod `/workspace/m3/runs/m8-gpu-d-wire/gate-1`).

## Not done (blocked on the sibling factories)

D4 and D5 need the factories' new hooks implemented: `NativeFactory.shape/pack/captured/publish` (n-stage1/n-stage2: block class mix from a warm capture, TraceChunk v1 packing from GE `Prepared`, `cpu-N.bin`/`stage-one.bin`/`cells.bin`/`bundle.json`/`report.json` writers) and `RecursionFactory.shape/captured/publish` plus the node job (r-node, r-truth). Until then `combined-serve` under the flag fails closed at install (`GpuNativeNativeShapeHookMissing`). Measured numbers above are probe-factory numbers, not proving numbers.
