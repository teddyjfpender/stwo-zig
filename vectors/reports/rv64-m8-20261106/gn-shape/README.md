# gn-shape: install-time native class builder + NativeFactory shape hook

Branch `codex/rv64-m8-gn-shape` (from `codex/rv64-m8-gpu` @ b289b021f). Labels [M] measured / [D] derived / [E] estimate.
Base image `/workspace/m3/build/m8-opt-combined/img` (lib 25d0e62f), jobs addon `m8-gn-bind/addon-1` (3bfd1840); no CUDA
change, no image built. Hashes of the binaries / logs / env: `artifacts.sha256`.

## What landed
- `rv64/jobs/native_class_build.zig` (new): per native segment class, ONCE at install, with NO CpuWorker:
  - inventory from the warm capture exactly as gkr_main builds it: `Plan.cpus` (+ canonical rungs when the policy says so),
    `requestView` / `routeDword` / `assignSpongeIds`, first ids; per segment (in parallel) its setup keys (`Keys` over the one
    declaration, as early_segments.zig) and FIXED authority (`FixedSet`), `localCpuExpected`, FIXED coefficients via the
    authority binding into a throwaway scheme (= CpuWorker.prepareMain's append);
  - Stage 1 `native_device_stage1.Spec`: the hybrid prove()'s `NG.Plan.init` + `NB.Plan` (native_hybrid.zig l.589) on the
    class's OWN FIXED copy (the plan keeps host-column views), FIXED authority root, MAIN shapes, beta;
  - Stage 2 `native_device_stage2.ClassFraming`: the hybrid stageTwoInner component set + buildFraming verbatim (l.834-922:
    global plans, INTER shapes/plan, composition plan, mask points -> `PcsJob.prepare`) plus what n-stage2 defined but nobody
    built: the encode `Program` (`NE.Program.build(pcs shape)`) and the device patch tables (each global plan's artifact
    parameter slots; each composition role's parameter slots at `t_params` + every hc role's rows from the semantic handoff);
  - `Fingerprint`: SHA-256 per field, class fields vs per-request fields; class key = digest over the class fields;
  - `Builder`: `NativeFactory.shape` (via `hooks()`), registers each class once (`Registry.register`, `Factory.register` x
    framing instances), resolves classes by (block, segment, rows); `missBlock` = the same build on the miss path (receipted).
- `rv64/jobs/native_device.zig`: `ShapeHooks` + `Native.shape_hooks`; vtable `.shape`, `.class_of_block` (unbound shape still
  fails closed with `GpuNativeNativeShapeHookMissing`).
- `rv64/jobs/gpu_native.zig` (additive, defaulted null): `NativeFactory.VTable.class_of_block(block, segment, rows)`.
- `rv64/m8_class_build_composition.zig` (new, outside jobs/ for the sync lint): composition roles + artifact slots, host-only
  `HostArtifacts` (no GPU service).
- `rv64_m8_class_build_parity_main.zig` + step `build-rv64-m8-class-build-parity`: real-block parity harness.
- `riscv_cpu/mod.zig`: additive exports only.

## Evidence (real blocks, pod 2x5090; `parity-26235156.json`, `parity-24628607.json`)
Harness: the unchanged legacy resident pipeline (GPU0) with pass-through recorders on the numerical stage (the exact request
the hybrid prove() receives) and on native_stage_two (the stage-two CpuWorker + pending manifest: real local GKR artifact and
shared challenges); then the GPU-native install of the same block from ONE warm capture through `ND.Native.factory().shape`,
the factory's `warm` / `installed` hooks on the job GPU (GPU1), and negatives.

- [M] **Specs equal field by field: 4/4 segments of 26235156, 7/7 of 24628607** (install-built Stage-1 fields vs the class built
  from the legacy numerical request: 29 Stage-1 class fields incl. the full GKR plan, FIXED host coefficients, FIXED root).
- [M] **Framings equal field by field: 4/4 and 7/7** (install-built vs built from the legacy stage-two worker: 64-68 class
  fields per segment incl. slots, global plans, INTER, composition key + table, every PCS section but 15, PCS plan / columns /
  shape, encode program, patch tables); class keys equal. The per-request fields DO differ (16-25 of 17-26 per segment: GKR prefix,
  patched global-parameter and composition-table words, PCS section 15 + scope), i.e. every value that differs between
  placeholder and real inputs sits under a device patch or a per-request rebind; the unpatched words are identical.
- [M] install with the hook succeeds on the GPU: shape -> Registry/Factory warm (8 / 14 ClassCache entries) -> `installed`
  (one WarmJob per class on GPU1: device FIXED commit, device root == class authority root) -> cache sealed.
- [M] cold WarmJob per class (fresh persistent region: full device FIXED commit + root copy), CUDA events: 5.30-5.67 ms
  (26235156), 3.77-5.51 ms (24628607); steady (region warm) 0.006-0.014 ms.
- [M] negatives, each fails closed with exactly its error (both blocks): tampered class root -> `NativeStage1FixedRootMismatch`
  on the GPU; register after seal -> `GpuNativeClassBuildOnRequestPath`; unknown block / wrong rows -> `GpuNativeClassNotWarmed`;
  out-of-bounds patch table -> `NativeStage2PatchTable`; one flipped FIXED word -> exactly field `s1.fixed_host` differs.
  Miss path: a new block after the seal builds (no fail-closed), receipted (`misses=1`), its class keys equal the warm ones.
- [M] class miss on a genuinely new block (`miss-26235156-then-24628607.json`): 26235156 installed and sealed, then 24628607
  (never warmed) through the same shape hook: 7 new classes built, registry + class cache reopened, registered, host-warmed and
  device-warmed (WarmJob per class: FIXED commit + root check), resealed; 17.80 s wall after its 4.20 s capture (classes
  15.31 s, register + warm 2.16 s); every segment resolves by `class_of_block`, registry and cache hold all 14 classes.
- [M] host (unit) `zig build test-rv64-jobs`: 520/530 (10 skipped GPU), incl. the sync lint and 6 new gn-shape tests.
- [M] `rv64_gate.sh --stream m8-gn-shape` default: **PASS** at 277fd08dd (`gate-2.json`: 26235156 cold + warm 32/32 artifacts
  byte-identical to the frozen D2 golden, 2/2 fresh CPU receivers accepted, negative corpus). The later commits touch only
  native_class_build.zig and the harness (default path unchanged); gate-3 on the head: see `gate-3.json` when present.

| install, host wall [M] | 26235156 (4 seg) | 24628607 (7 seg) |
|---|---|---|
| warm capture (GE direct) | 3.07 s | 3.90 s |
| shape hook (inventory + classes, threads = segments) | 11.08 s | 15.38 s |
|  of which per-segment setup keys + CPU FIXED authority | 4.31-9.64 s | 3.02-13.75 s |
|  of which per-class build (plans, PCS framing, program, patches) | 1.24-1.43 s | 0.69-1.34 s |
| factory warm (S1 Class.init + S2 cache insert) | 1.17 s | 2.18 s |
| installed (device WarmJobs, host wall) | 0.17 s | 0.29 s |
| miss path, same block again (build only, no new class) | 12.13 s | 15.06 s |

Sequential shape before the per-segment parallel setup: 17.98 / 34.50 s [M] (inventory alone 16.06 s on 26235156).

## Findings
- `class_of(segment, rows)` is ambiguous [M]: every 26235156 segment and 6/7 of 24628607 have 4,194,304 rows with distinct
  classes, and no class is shared between the two blocks. Hence the additive `class_of_block`; the registry's rows map is
  bypassed (`rowsToken`). Driver / gn-bind: call `class_of_block` with `Request.block` (driver_request ~l.541) and in the
  install loop (driver_serve ~l.122); n-stage2's `Factory.segment_class` is per ordinal, so it must be re-bound per request
  with `Class.framingKey(class_of_block(...))`.
- bench15 (15 new blocks): no class reuse across blocks under the D2 v1-flat profile, so every new block is a miss costing
  12-15 s host [M], dominated by setup keys + the CPU FIXED authority commit.

## Remaining host work
- Per request: none from this piece (class resolution is a map lookup). The per-request words this class leaves open are
  produced elsewhere: `RequestWords{seed, prefix, publics}` (n-stage1/gn-pack: a few Blake2s on the capture thread), the
  patch sources (shared draws on device; public namespace + RAM boundary tuples from the capture), PCS section 15/scope.
- Install / miss path: per-segment setup keys + CPU FIXED authority (3-14 s/segment [M]) is the cost; the device commits the
  same FIXED tree in 3.8-5.7 ms [M]. Levers: a resident setup cache across blocks (the legacy SetupCache), or canonical rungs
  (strict roster) so classes repeat across blocks.
- Not done here: `ClassFraming.oods` (gn-s2's `NO.fromPlan`, not on this base), `capture_words` (gn-pack's ring format), the
  driver calling the shape hook for an unknown block at request time (today Service.begin refuses GpuNativeBlockNotWarmed;
  with `Builder.miss_cache` bound the hook does the whole miss path). The miss path writes `Registry.sealed` directly (no
  unseal API in native_device_stage1.zig) and must not run while a request of the same service is mid-enqueue.
