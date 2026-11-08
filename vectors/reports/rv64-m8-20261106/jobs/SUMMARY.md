# M8 job architecture: integrate step (2026-11-06)

Integrate head: `codex/rv64-m7-integrate @ 78e871d48`, fast-forward under `integrate.lock`. Compact data: `summary.json`.
Raw receipts stay on the pod under `/workspace/m3/runs/m8-integrate/`, with their SHA-256s listed in `summary.json`.

The pod runs used the stream name `m8-integrate` (src/build/runs under `/workspace/m3/*/m8-integrate`). `build/m7-integrate`
and `runs/m7-integrate` are frozen assets, so the gate did not rebuild into them.

## What is on integrate

| stream | commits | how |
|---|---|---|
| runtime | 6b7864839 .. 929b54eea | landed by runtime (gates 1-4 PASS) |
| native-job | e991419df .. 577433230 | landed by native-job (gate-6 PASS) |
| outer-job | 40f811a18 .. 52f6c4c0c (6) + 78e871d48 | rebased here from `-r2` da93d0e76. Only build.zig conflicted (union of both test steps). 78e871d48 points the fixture at `ops.Libraries.open`, because the raw draw is now in the addon |

## Results

| check | result |
|---|---|
| host tests (`test-rv64-jobs`, `test-rv64-jobs-outer`) | [M] 115/120 pass, 5 GPU-only skips. The outer fixture build and `check-rv64-ethereum-gpu-combined` are OK |
| gate, default path, 26235156 | [M] **PASS**: 2/2 proofs byte-identical to the frozen D2 golden (32 artifacts each), 2/2 fresh CPU receivers, 19/19 corpus |
| gate `--env STWO_RV64_M8_JOBS=1`, 26235156 | [M] **FAIL**: service exited before READY. Both workers booted and passed the boot parity self-test (1 host wait each), then `M8RequestProviderNotLanded` |
| gate `--env STWO_RV64_M8_JOBS=1`, 24628607 | not run: it fails closed the same way regardless of block |
| channel parity (`rv64-jobs-channel-parity 0,1 4`, both 5090s) | [M] PASS: 24 jobs, 896/896 boundary snapshots, 1 host wait per job |
| outer-job fixture on the integrated head | [M] PASS: prefix 4/4, and 5/5 whole-node proofs wire-byte identical to legacy (632624 B, `d6e67853…`), one of them with a device-precommitted FIXED authority |

Fixture per node [M]: 1 host wait; 1,554,264 B slab D2H; 453 host-API launches direct vs 1 graph launch (1070 kernel nodes) captured;
arena peak 609-614 M words. The timings are a diagnostic from one process with no quiet gate, so there is no speed claim.

## Measurement and promotion

- **Not measured.** The candidate arm (`STWO_RV64_M8_JOBS=1`) produces no proofs, so the canonical 3+3 interleaved runner has nothing to compare.
  No job-path number is claimed for request time, capture, native window, recursion after native, tail, kernel GPU-s, GPU busy, launches or per-node peak.
- **Not promoted.** The default stays on the legacy path.

## Where the job path stops (no byte divergence: no request reaches it)

The boundary is `jobs/mod.zig provider()`. The runtime, channel and recursion node are proven up to that boundary. No `request.Provider` exists past it.
One of these is needed:

1. **Stage A** (legacy native + job-path recursion): one default-null hook in a legacy file, e.g. `Factory.whole_node` checked first in
   `circuit_cpu/om31/device_prove.zig proveFromCircuit`, filled by `rv64/outer_job_factory.zig Prover.prove`. This is outside every
   stream's ownership and needs an **owner decision**. Runtime and outer-job are ready to wire and gate it.
2. **Stage B** (native on the job path): the NativeStage1/2/Truth producers still need porting: witness source, binding finalize,
   global interaction + publicClaims device reduction, native composition kernels, and an enqueue-only local GKR (salt/rejection retry
   policy). After that, compose `request.Provider`.

Once either stage exists: run the gate with `--env STWO_RV64_M8_JOBS=1` on 26235156 and then 24628607, run the real-block channel parity
(legacy vs job on the same block), then the 3+3 measurement.
