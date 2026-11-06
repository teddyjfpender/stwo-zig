# gpu-native / native stream: step 1 (2026-11-07)

Branch `codex/rv64-m8-gpu-native` @ fc1e79226 (on contract 065e248e6). Not integrated.

## Landed (default off: `STWO_RV64_M8_NATIVE_FRAMING_CACHE=1|check`)
- Per-class Stage-2 framing cache (H9): global plans, INTER plan, composition plan, mask points and
  PcsJob framing (incl. the host FFT/FRI coordinate sections, rebuilt per segment today because the
  hybrid passes no geometry cache) are built once per class and checked out exclusively per job.
- Request words rebound on a hit: composition parameters + hc rows (`Plan.rebind`), global shared
  challenges + sponge first id (`native_global.Plan.rebind`), PCS section 15 (expected roots) and scope identity.
- `check` mode rebuilds fresh on every hit and compares every word (N1 acceptance on real blocks).
- Global stage builds its twiddle tower only for a fresh persistent region (was every slot of every stage).
- Host split timers in `m8-native-hybrid.json` v2: restore / set / framing / decode / oods / encode.

## Evidence
- [M] pod `zig build` of the driver: EXIT=0; `zig build test-rv64-jobs` (ReleaseSafe): EXIT=0, which covers
  the new host tests (rebind == fresh init, fail-closed geometry, pool exclusivity/LRU/seal, key hashing).
- NOT measured: GPU parity, gate proof step, host-time savings. The pod GPUs are held by orphan pid 3302210
  (30.1 GB per GPU, m8-native-hybrid combined-serve), so nothing on the GPU can start.

## Next, once the GPUs are free
1. `rv64_gate.sh --stream m8-gpu-native` default (must stay unchanged), then the same with
   `--env STWO_RV64_M8_JOBS=1 --env STWO_RV64_M8_NATIVE_JOBS=1 --env STWO_RV64_M8_NATIVE_FRAMING_CACHE=check`
   on 26235156 and 24628607 (byte identity + N1 on the warm request), then `=1` for the timings.

## Review 1 (2026-11-07)
Fixes in 4af2df716 (see `review-1.json`): cached PCS framing restores placeholder column bindings on
checkout (no stale job-arena addresses), `Plan.detach` OOM double free, `create` env-parse leak.
Gate gate-review1: build / unit-zig / unit-python PASS [M]; proof step still blocked by orphan pid 3302210.
