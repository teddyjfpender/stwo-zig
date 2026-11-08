# gn-bind review (2026-11-07)

Branch `codex/rv64-m8-gn-bind`, reviewed from 226f210c9. Labels: [M] measured, [D] derived, [E] estimate.
Raw logs are on the pod under `/workspace/m3/runs/m8-gn-bind/rev/` (r1..r7 repro logs plus nvidia-smi samples; sha256 in
`review-r7-install.txt`). The repro is `review-run.sh`: the gate-6 GPU-native env with addon-4.

## Findings (confirmed, fixed)

| # | finding | fix |
|---|---|---|
| 1 | **Warm-capture `FileNotFound` (the builder's open blocker).** `Source.init` parsed each request config with `parseFromSlice(.., .{})`. The default `alloc_if_needed` makes every string (elf, input, output_directory) a slice of the request text, and that text was freed at the end of the loop iteration. The warm capture's boot then opened a freed path in `Walk.create`. [M] r2 (`STWO_RV64_CAPTURE_ASYNC_START=0`) fails at `capture_stage=start`. The gn-shape harness kept its text alive, which is why it passed. | `.allocate = .alloc_always` (8622d353e). [M] r3: `warm_capture block=26235156 segments=4`, then the class build and recursion shape run. |
| 2 | **Stale sibling heads, including a known race.** gn-bind carried gn-shape 65966f11c/3c9f368b0, which still has shallow Stage-2 framing pool copies (the race fixed in gn-shape 7fc107c95). It also lacked the gn-truth review (unanchored-role anchor read of uninitialized shared memory), the gn-node node-job lifetime fix (use-after-free with two requests in flight), the gn-s2 review, and gn-pack. | Merged gn-shape b638c6592, gn-s2 8adc06362, gn-truth dd3ac53db, gn-node cb410ff73 (incl. the 383e51e6d lifetime fix), gn-pack 533226abe. All merges were clean. addon-4 was rebuilt for the changed `truth_oods.cu`; `runtime-addon-4.json` has the sha256s. |
| 3 | **A refused `Driver.begin` released the in-flight request's Stage-1 state.** `Service.begin` passed `driver.generation` to the end hook even when `begin` failed before taking a generation (pipeline full, poisoned, stream in flight). `Registry.release` then freed the previous request's pending Stage-1 records while that request was still in flight. | Generation 0 = none taken. `endRequest` skips `Registry.release` for it. |
| 4 | **main_resident sized for 64 segments.** The driver planned main_resident as ceil(64 / GPUs) x the largest class. [M] r3/r4: 13.87G words per GPU, `GpuNativeMemoryPlanExceedsDevice`. | `Service.install` sizes `max_segments` / `max_truths` from the installed shapes. [M] r5/r6: 866.7M words (2 x 433M). |
| 5 | **Plan capacity ignored the device arena.** With `STWO_RV64_DEVICE_ARENA=auto` (gate env), the carve leaves `cudaMemGetInfo` about 0 free while every allocation of the process is served from the carve. [M] r4: capacity 0.82G words, and nvidia-smi shows the service itself holding 30,044 MiB per GPU. | `measuredCapacity` adds the unused part of `stwo_exec_context_pool_current` (`Config.pool_current`). [M] r6: capacity = the 7.516G-word cap. |

The install now also prints each class's arena peak and the Stage-1 `jobWords` terms (`reportStage1`).

## Where GPU-native 26235156 stops now [M, r7]

The warm capture, the class build (8 classes: 4 Stage-1 + 4 Stage-2 entries), the recursion-shape fallback and the capacity
measurement all pass. The install then fails on **`GpuNativeMemoryPlanPhaseA`**: the phase-A peak is 6.365G words (25.5 GB),
against a 7.516G-word cap with class cache 0.28G + main_resident 0.87G + slab, graph and reserve. The peak is
`native_device_stage1.Class.jobWords` (n-stage1), which **sums** phases that run one after another:

| class | job_words | gkr_enqueue | main_device (LDE) | image | resident |
|---|---|---|---|---|---|
| 8519d3b3 | 6.365G | 3.812G | 2.213G | 0.307G | 0.420G |
| d2728a50 | 5.478G | 2.888G | 2.243G | 0.313G | 0.433G |
| c4b47cf0 | 5.384G | 2.957G | 2.108G | 0.286G | 0.406G |
| 2e359c6f | 5.094G | 2.724G | 2.060G | 0.276G | 0.392G |

[D] max(gkr_enqueue, main_device) + image + resident is about 4.5G words, which would fit. `gkr_enqueue` is the GKR traversal
workspace under `byte_cap = gkr_bytes` (32 GiB, the same cap the legacy worker passes). This needs n-stage1 / gn-pack: a
LIFO-true `jobWords` (and the v1 `image_words` term dropped for v2 compact witnesses, `Spec.compact_words` instead), or a measured
peak like truth_factory's `measured_peak_words`.

## Still unbound after the memory plan (not reachable yet; in order)

1. `NativeFactory.pack`: gn-pack `Packer` + a `RequestSource`. The legacy `early_segments.build` needs the segment-0 initial RAM,
   the last segment's terminal RAM and the block keccak total (sponge first ids). With `STWO_RV64_FIRST_PASS_RAM=0` none of these
   exist before the capture ends. A per-block install-time copy from the warm capture, checked against the request at `captured`,
   is the minimal route. It also needs `Registry.setRequest` (seed / prefix / publics: `binding.begin(config, localCpuExpected)`,
   `childPrefix`) and `Registry.roms`.
2. Stage-2 `Factory.beginRequest` (roster, flat entries incl. truth statements, per-segment boundary tuples / public). NOTE:
   `Factory.segment_class` is keyed by segment only, so two in-flight requests of different blocks would collide (gn-s2).
3. Truth `Factory.begin`; recursion `shape` / authority registration / `NodeClasses`; non-proof publish files.

## Gates

See `gates.json` (gate-7 default 26235156; gate-8 JOBS=1 26235156; gate-9 JOBS=1 24628607; runtime addon-4).
