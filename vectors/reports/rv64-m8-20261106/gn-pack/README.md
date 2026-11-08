# m8-gn-pack: compact TraceChunk v2 + Stage-1 device witness (IO lever L0)

Branch `codex/rv64-m8-gn-pack` (from `codex/rv64-m8-gpu` @ b289b021f). Code at 2abac0259. Pod 2x RTX 5090.
Labels: [M] measured, [D] derived, [E] estimate. Raw logs stay on the pod (paths below); `gn-pack.json` holds every per-segment number.

## What landed
| piece | file | status |
|---|---|---|
| TraceChunk v2 format (compact records + launch program; declare/data/launch/status/end records, `Ref` = buffer<<48 \| offset) | `rv64/jobs/native_pack.zig` | done, host tests |
| Stage-1 device witness program: zero/h2d/launch of the EXISTING base-library `*_witness_on` kernels on lane 0 into the arena MAIN image; ledgers + status words stay on device | `native_pack.zig` `Program`/`Bound` | done, GPU parity [M] |
| Stage-1 witness step: `Witness.compact`, v2 dispatch in `Registry.chunk/stage1`, `witness_status` also requires every program status word == 0, `Spec.compact_words`, `Registry.roms` | `rv64/jobs/native_device_stage1.zig` | done, GPU glue test [M] |
| capture-side serializer: port of `cpu_projection` + `core_witness` (BuildJob + Finish) + `bridge_witness` + `bulk_sponge` + `device_source` extensions, incl. their host validations; LS events routed straight into the ring | `rv64/jobs/native_pack_capture.zig` | done |
| `NativeFactory.pack` adapter (`Packer.hook`, exact VTable signature) over a `RequestSource` | `native_pack_capture.zig` | done; RequestSource is the class owner's (see below) |
| legacy recorder (env `STWO_RV64_M8_GN_PACK_RECORD=<dir>`, default off): v2 stream from the real source request + SHA-256 of every legacy MAIN column | `rv64/gn_pack_record.zig`, 2-line hook in `device_source.zig` | done |
| piece-only GPU harness on recorded real segments + negatives | `rv64/jobs/native_pack_gpu_test.zig` | done |

No CUDA change (no new image): the program runs the kernels already in `libstwo-rv64-native.so` 25d0e62f; addon `addon-1` built against it.

## Acceptance [M]
**MAIN byte identity, every segment of both blocks** (final source, `p3-f`): 26235156 4/4 segments, 13,375/13,375 MAIN columns;
24628607 7/7 segments, 21,413/21,413 columns (`GN_PACK_PARITY_TOTAL columns=34788 equal=34788`). Per column the SHA-256 of the
device image equals the legacy device MAIN column recorded from the same request; every program status word is 0.
Stage-1 glue: `enqueuePrologue(.compact)` vs `.device` of the verified image: MAIN root and post-MAIN channel equal, witness_status
0 (`GN_PACK_STAGE1_GLUE root_equal=true channel_equal=true`, both blocks).

**Negatives (fail closed)**: ALU fact result flipped -> ledger status word 1 (witness_status rejects); CPU record rom_row out of the
program -> CPU status 3; a dropped chunk and a corrupted record tag -> refused at parse (nothing enqueued); host tests: truncation,
coverage hole, column overlap, upload gap/overlap, ref out of range / undeclared buffer, bad magic.

**Gates**: `rv64_gate.sh` PASS with the recorder ON: gate-rec-26235156 (32/32 byte-identical to frozen D2, receivers 2/2, corpus),
gate-rec-24628607 (39/39), gate-rec2-24628607 at 2abac0259 (39/39). **Default gate (no env) 26235156 at 2abac0259: PASS** (32/32, receivers 2/2, corpus).
`zig build test-rv64-jobs` with GPU: 531/532 passed, 1 skipped.

| per request | 26235156 | 24628607 |
|---|---|---|
| H2D bytes, v2 chunk stream [M] | 821.4 MB | **1,375.9 MB** |
| v1 MAIN images it replaces [M, sum of image bytes] | 4,724.9 MB | 7,375.6 MB (5.36x more) |
| design estimate for v2 | — | ~2.3 GB [D, io-streaming §4.2] |
| Stage-1 witness GPU time, CUDA events, h2d + kernels, summed over segments [M] | 93.2 ms | **149.4 ms** (12.5–30.1 ms/segment) |
| Stage-1 host time for the witness step (parse + stage + enqueue), summed [M] | 2.8 ms | 4.2 ms |
| capture-thread pack, wall [M] | — | 807 ms total; **median 88 ms/segment** (segments 1–6: 77–104 ms); segment 0 275 ms = 87 ms one-time ROM reconstruction + first-touch of the chunk pool |
| largest segment chunk stream [M] | 237.6 MB | 258.2 MB |
| largest Stage-1 program arena (inputs + CPU scratch + ledgers) [M] | 483.5 MB | 505.5 MB |

Pack phases, 24628607 segments 1–6 [M]: CPU (CompactRecord/seed pack 11–32 ms, threaded) 15–41 ms; core roles 25–35 ms; service
bridges + bulk/sponge 5–28 ms; Zbb/LS-D64/tables 10–24 ms. Data per segment (26235156 seg 0) [M]: LS events 97 MB, CPU records+seeds
73 MB, public RAM cells 22 MB, family facts 18 MB, bulk/sponge 24 MB, bridges 1 MB. Arena: the CPU metadata scratch (14 words/row,
236 MB) dominates, as in the legacy path.

## Remaining host work (what is still NOT GPU-native or not wired)
1. **RequestSource** (gn-shape / gn-bind): CapturedSegment -> legacy `DeviceSourceStage.Request` (class `R.CpuSetup` from the class
   cache, `Coordinator.requestView` + `routeDword` + sponge first id, first_ids). `pack` is read-only on it. Until then the pack hook
   is exercised through the legacy recorder only.
2. **Ring sizing** (driver): a segment holds up to 258 MB of chunks [M] but the default ring is 128 MiB; the ring must hold one
   segment per in-flight Stage 1 (pinned host is plentiful) or chunks must upload before the seal (L3).
3. **ROM** (32 MiB, reconstructed in 87 ms [M]) should be put into `Roms` at warm, not on the first request's capture thread.
4. **Capture-thread pack ~88 ms/segment** [M] is real CPU on the capture thread (~0.6 s/request [D]); next cuts: encode family facts
   and cells straight into the ring (as LS events now are), reuse the Compact arrays.
5. The chunk h2d still rides the exec stream (as v1); moving it to the h2d stream is L3 (M9).
6. Not produced by pack: the legacy narrow host `Headers` (call lists, function masses) the legacy CPU worker reads; GPU-native
   Stage 2 must derive what it needs on device.

## Pod paths (raw, not in git)
Logs `/workspace/m3/runs/m8-gn-pack/{p3-f,p3-e,p3-c,p2,p4}/`, gates `/workspace/m3/runs/m8-gn-pack/gate-rec-*`, `gate-rec2-24628607`,
recordings kept for re-runs in RAM: `/dev/shm/m8-gn-pack/{rec-26235156,rec2-24628607}` (2.2 GB tmpfs, not pod disk; harness: `STWO_RV64_M8_GN_PACK_RECORDS=<dir>[:<dir>]`).

## Review 1 (ded04d1c2)
Findings confirmed against the code and fixed (`native_pack.zig`, `native_device_stage1.zig`):
1. **Unchecked status word**: parse accepted a launch whose `status` ref was not a listed status word, so a kernel's failure verdict could
   go unchecked and the proof would publish. Now every kernel status ref must be a listed status word (`GnPackStatusUnchecked`), and each
   status word must sit in a `.zero` buffer (`GnPackStatusNotZeroed`). Before, an upload or scratch word could hold a host or stale value.
2. **CheckSpec overflow**: `max_status` was 8, but `witness_status` holds 8 zero words and uses 1 for ingress, so an 8-word program failed
   at enqueue rather than at parse. Now `max_status` = 7.
3. **MAIN log vs class**: no check tied a launch's `log` to its columns' class logs, and a mismatch writes past the column span in the image.
   New `Program.checkMainLogs`, plus a bridge `main_words` check. Stage 1 runs it at init and so does the GPU harness: all real launches pass.
4. **Arena double count**: `Spec.compact_words` goes into `jobWords()`, and the footprint added the program arena on top, so once a binder
   sets the bound each job asks for up to ~506 MB/segment more than the plan. Now a planned class does not add the arena again; a program
   above the bound is refused at init (`GnPackArenaExceedsPlan`). With an unplanned class (0) the behaviour is the same as before.
5. `Roms.put` leaked the words when the map insert failed (non-pinned).

Re-test [M], `/workspace/m3/runs/m8-gn-pack/rv1/`: `zig build test-rv64-jobs` with GPU 532/533 (1 skipped), plus new host tests (status
unchecked / not zeroed, MAIN log mismatch). GPU parity is unchanged: `GN_PACK_PARITY_TOTAL columns=34788 equal=34788`, with checkMainLogs
on both blocks. Glue root and channel are equal on both blocks, and all 4 negatives fire on both.

Measurement notes: "capture-thread pack" [M] was timed inside the legacy source build (the recorder), not on the GPU-native capture
thread. The ring is plain pageable memory that is pre-faulted after segment 0. Treat it as an estimate of the capture-thread cost until
Packer.hook runs in a driver request.

Gate [M]: `rv64_gate.sh` default (no env), 26235156, source ded04d1c2: **PASS** (`/workspace/m3/runs/m8-gn-pack/gate-rv1-26235156`): build, unit zig + python, small-block cold and warm byte-identical to the frozen D2 golden, fresh CPU receivers, negative corpus.
