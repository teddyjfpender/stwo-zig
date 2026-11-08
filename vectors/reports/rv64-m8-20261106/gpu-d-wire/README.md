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

**Gate default (`rv64_gate.sh --stream m8-gpu-d-wire`, 26235156, source 5063fa785, sibling merges included): PASS [M]** (`gate-2.json`): build, Zig + Python unit tests, cold and warm proofs byte-identical to the frozen D2 golden (32/32 and 32/32), 2 fresh CPU receivers accepted, 19 corpus cases. gate-1 (649d35088) failed at build: a shadowed `run` in driver_ge.zig, fixed in 5063fa785.

**Request switch smoke (pod, `smoke-1.json`) [M]:** `combined-serve` with `STWO_RV64_M8_JOBS=1 STWO_RV64_M8_GPU_NATIVE=1` on the gate manifest parses the manifest, builds the per-block config/image/capture program, then refuses at install with `GpuNativeNativeShapeHookMissing` (exit 1, no READY, no proof): it fails closed, never falls back to the feeder or legacy path.

## Not done (blocked on the sibling factories)

D4 and D5 need the factories' new hooks implemented: `NativeFactory.shape/pack/captured/publish` (n-stage1/n-stage2: block class mix from a warm capture, TraceChunk v1 packing from GE `Prepared`, `cpu-N.bin`/`stage-one.bin`/`cells.bin`/`bundle.json`/`report.json` writers) and `RecursionFactory.shape/captured/publish` plus the node job (r-node, r-truth). Until then `combined-serve` under the flag fails closed at install (`GpuNativeNativeShapeHookMissing`). Measured numbers above are probe-factory numbers, not proving numbers.

## Review pass (b65fbae54)

Each finding was checked against the code. Fixed:
- **Late capture failure published proofs (fail-closed hole).** GE runs its final checks after the last segment seals: terminal state, collector equivalence, segment count, and the `captured` hooks. A failure there failed no Stage1 gate. Without a `needs_capture_end` truth, every device job succeeded and the request published. Fix: after the single device wait and before `G.publish`, `Driver.finish` calls `Stream.awaitCaptured()`. That call is a host sync with the capture thread, with no device wait. It passes only if `done` was clean and the end gate opened. The same call also orders the factories' `publish` hooks after their `captured` hooks, which could otherwise race. The receipt field is `capture_wait_ns`.
- **A clean `Feed.finish` without `end` opened the end gate.** It now fails with `GpuNativeCaptureEndMissing`.
- **GE adapter event-mismatch and cancel paths failed the stream but not the Feed.** They now go through `Feed.abort`, which records the first error.
- Tests: `capture feed: a clean finish without end, or a capture error after the last seal, fails awaitCaptured` and `D1: a capture that fails after its last seal (no end-gated job) refuses publication`. Host `test-rv64-jobs` 501/511 (10 pre-existing skips) [M].

Open, not fixed here:
- `driver_ge.serve` builds `ND.Native{}` without `stage1_hooks` or `stage2_hooks`. `OD.Recursion` has no truth seam, so the n-stage1 Registry, the n-stage2 Factory and the r-truth Factory are merged but not bound. Binding them needs per-block class registration from the `shape` hooks, which do not exist yet. Install still fails closed at `GpuNativeNativeShapeHookMissing`.
- `Driver.begin` returns only after every GPU's batch is enqueued, and gated Stage1s are staged on the worker thread. Begin therefore blocks for about the capture duration. In `serveSpool` (two deep), `finish(N)` waits behind `begin(N+1)`, so request N's publication can slip by up to capture(N+1) when proving after capture is shorter than capture [D]. A dedicated enqueue thread per in-flight request would remove this.

**Gate after the review fix (`gate-3.json`, source b65fbae54, 26235156): PASS [M].** The build includes driver_ge in the combined exe. Cold and warm proofs are byte-identical to the frozen D2 golden (32/32 each), both fresh CPU receivers accept, and the corpus passes. The default path is unchanged; the fix touches only the flag-gated GPU-native driver.
