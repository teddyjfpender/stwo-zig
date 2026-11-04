# RV64 M3 stream `host`: the request path outside recursion

Branch `codex/rv64-m3-host` (from `fbb6c6c76`). Review-plan M1a/M1b/M1c/M1d plus capture.
Labels: **[M]** measured (receipt in this directory), **[E]** estimate.

## Changes (all scheduling/allocation only; no proof byte may change)

| # | Change | Where |
|---|---|---|
| 1 | `SharedHostBudget`: lock-free atomic admission on one heap+external total (`total <= limit` invariant, CAS reserve, rollback on child failure). The global `ThreadSafeAllocator` mutex is gone; the child must be thread-safe. | `src/prover/host_budget_allocator.zig` |
| 2 | Combined batch budget child `page_allocator` -> `smp_allocator` (revert of the `bd9ae4247` regression). | `src/integrations/riscv_cuda/rv64/resident_batch.zig` |
| 3 | Same-process native verification runs on a side thread with its own 8-worker pool, overlapped with recursion; `report.json` and `combined-report.json` are written only after a successful join. `STWO_RV64_SERIAL_NATIVE_VERIFY=1` restores the old order (A/B). | `ethereum/native_verify_overlap.zig`, `ethereum/gkr_main.zig` |
| 4 | CPU leaf capture verifies each native proof once: `admitCpuBeforeCoreVerify` runs every non-core check of `verifyCpuWithAuthority` in the same order, then the identical core verifier runs once with proof capture. Previously it ran twice. | `gkr_local/cpu_worker.zig`, `om31_native/cpu_capture.zig` |
| 5 | Warm resident service: the `ResidentSession` owns one PR #320 `SetupCache` for its lifetime when `STWO_ZIG_RV64_SETUP_CACHE` is set (removes the `session == null` gate). Empty value = in-process residency; a directory = also seed from / persist to disk. Batch manifest `warm_order` pre-warms setup (`inputs-candidate`: capture, plan, keys, FIXED; no proof) before timed requests. New artifacts persist between requests, outside the request timer. Resident CPU setups take custody of their raw ROM arrays (`retainRawAuthority`), as the session key cache already did. | `ethereum/resident_session.zig`, `ethereum/gkr_main.zig`, `ethereum/keys.zig`, `rv64/resident_batch.zig` |

## Soundness argument

- **1, 2**: allocator mechanics. The budget is still a hard cap (admission is a single atomic reserve against
  the same limit, charged at requested length as before); it only refuses more often transiently, never less.
  No allocator choice reaches a transcript.
- **3**: the verifier code, inputs and decision are unchanged; only *when* it runs moves. All inputs are
  `*const` for the whole request and were already read concurrently by recursion lanes. Acceptance markers
  (`report.json`, `combined-report.json`, the batch `combined-entry.json`) are written only after the join
  returns success; a rejection fails the request before any of them exists. The recursive proofs written
  meanwhile are not acceptance artifacts (and are themselves proofs that the native proofs verify). What is
  lost is fail-fast before recursion starts; `native_verified_before_recursion` is therefore not claimed for
  this route; the report records `native_verify_overlapped_with_recursion=true`.
- **4**: `verifyBorrowedWithProofCapture` and `verify` are the same `verifyImpl` (`src/core/verifier_family.zig`);
  the capture path already builds the identical component set, transcript (`fixed.begin`, two tree commits,
  `mixManifestAndClaims`, INTER commit) and receiver. Every remaining check of `verifyCpuWithAuthority`
  (`validate`, `checkManifest`, proof shape/config/revision, `checkPhysicalRoots`, `publicClaims`, local
  entry present) runs first, in the same order. Same accept set, one verification instead of two.
- **5**: #320's cache keys are derived from receiver-owned identity (code SHA, pinned program fields, suite,
  rung). Artifacts are SHA-sealed; prover bulk data cannot affect soundness (a wrong coefficient yields a
  transcript an independent receiver rejects). Receivers still refuse the cache
  (`PersistedSetupCacheForbiddenForReceiver`). The session binds each request's program identity
  (`bindRequest`) before any lookup.

## Correctness test

Byte parity of every native `*.bin`, `bundle.json` and the recursive snapshot against the accepted controls
(`/workspace/m3/runs/host/controls/controls.json`, copied from the accepted harnesses' `source-authority.json`)
for 26235156 and 24628607, plus a fresh cache-disabled independent receiver.

## Results on 2x RTX 5090 [M] (`gpu-runs-v1.json`; single observations)

Driver `0ccf7519c` (this branch) + accepted runtime `library.so` 25295868. Every row: all native `*.bin`,
`bundle.json` and the full recursive snapshot are **byte-identical** to the accepted controls.
Independent receiver (pristine `fbb6c6c76` receiver d4d9d7fe, separate process, GPU disabled, setup cache
unset): **26235156 accepted, 24628607 accepted** (run r2).

| Block | Run | Request wall | Capture | Setup | Native prove | Native verify on path | Recursion |
|---|---|---:|---:|---:|---:|---:|---:|
| 26235156 | infra pristine fbb6c6c76 (control) | 65.37 | 3.28 | 9.30 | 6.07 | 3.62 | 42.93 |
| 26235156 | r1: this branch, no setup cache | 50.95 | 2.55 | 9.41 | 4.50 | 0 (1.12 s side thread) | 34.30 |
| 26235156 | r2: session SetupCache, empty disk | 46.27 | 2.45 | 4.97 | 4.16 | 0 (1.07) | 34.54 |
| 24628607 | accepted a8f4e643 (control) | 98.92 | 6.17 | 13.06 | 10.33 | 5.54 | 63.62 |
| 24628607 | r2: same process after 26235156 (3/28 classes shared) | 69.37 | 3.27 | 5.88 | 5.72 | 0 (1.66) | 54.23 |
| 24628607 | r3 trial 0: new process seeded from disk | 62.91 | 3.27 | 0.69 | 5.71 | 0 (1.63) | 53.05 |
| 24628607 | r3 trial 1: warm, same process | 64.37 | 3.34 | 0.16 | 5.73 | 0 (1.59) | 54.79 |
| 24628607 | r4: `warm_order` startup pre-warm (residency only), then timed; CPU build ran concurrently | 67.95 | 3.86 | 1.09 | 6.12 | 0 (1.60) | 56.66 |
| 24628607 | r5: lean `warm-setup-candidate` pre-warm (residency only), then timed (driver 4be54de25) | 65.66 | 3.33 | 0.94 | 5.77 | 0 (1.59) | 55.33 |

Non-recursion time of 24628607 (capture + setup + native prove + publish): 35.3 s -> 9.4 s (disk-seeded
cold) / 9.5 s (warm). Native verify join wait is ~70 us: it is fully hidden behind recursion.
The allocator fix also shortens recursion (63.6 -> ~53-55 s on 24628607; 42.9 -> 34.3 s on 26235156),
and native proving (10.3 -> 5.7 s).

Not reached: the <= 6 s warm non-recursion target. What remains on 24628607 warm: native prove 5.7 s
(GPU, pipe stream), capture 3.3 s (serial ordered memory ledger ~1.1-1.3 s, first-packet capture ~0.65 s,
image/ROM authority 0.55 s), publish 0.2 s.

## Receipts

- `allocator-ab-v1.json` [M]: 8 threads x 200k alloc/free 16 B..32 KiB. Old mutex+page_allocator 16.0-18.4 s
  wall, 21.7-25.0 s sys, 1.0M minor faults; atomic+smp 0.19-0.34 s, ~0.1 s sys, ~11k faults.
- `capture-attribution-v1.json` [M]: block 24628607, same capture options. smp-allocator CPU product:
  execution 0.58 s (accepted combined route: 4.28 s), first pass 0.24 s (1.79 s), all inputs 3.72 s (6.17 s).
  Execution workers 8 vs 16 and inflight 4 vs 8: no change (3.35 vs 3.33 s); capture is not thread-bound.
- `receiver-r2-26235156.json`, `receiver-r2-24628607.json` [M]: independent receiver stdout (accepted,
  complete block, expected outputs 9661a4e4... and e63d2797...; 11+10 and 17+16 recursive proofs verified).
- `gpu-runs-v1.json` [M]: the table above, with parity verdicts, setup-cache stats and markers.

## Next (not done)

- Capture: shard the ordered memory ledger (`services/collector.zig` `one`) by address so segments build
  their ledger slices in parallel and only a cheap boundary stitch stays serial; cache the ELF-only ROM
  authority (`ProgramAuthority.initWithRom`) in the session. Together ~1.5-2 s [E].
- Disk-seeded load is 2.3 s summed (1.34 GB) but overlapped: 0.69 s on the wall. Warm 0.16 s.
- Startup pre-warm: `inputs-candidate` (r4) cost 37 s; the lean `warm-setup-candidate` (r5) costs 10.6 s.
  Both still leave ~0.8 s of FIXED work on the first timed request, whereas a request after a real
  produce (r3 trial 1) leaves 0.017 s. Not yet explained (open). Disk seeding (r3 trial 0, setup 0.69 s)
  is the better cold path today.
- Pre-existing failure, not from this branch: `test-riscv64-om31-native-pcs` panics (integer overflow in
  `captured.deinit`, `om31_native/test.zig:124`) identically on pristine `fbb6c6c76`; 23/23 other tests
  pass on both. `test-rv64-recursion-ready` passes; allocator unit tests (8 + 19 incl. external-memory
  root, Debug and ReleaseSafe) pass.
- `warm_order` lets a service pre-warm setup at startup; per-block geometry classes are data-dependent
  (ALU/binary rungs), so pre-warming from representative blocks plus the persisted disk cache is the
  practical way to cover distinct blocks.
