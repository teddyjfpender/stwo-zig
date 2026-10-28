---
title: Joint native companion STARK: exact relation parity and measured limits
author: Teddy Pender
created_utc: 2026-10-28T14:51:41Z
---

# Native execution and companion equations in one STARK

Implemented on `codex/ethereum-block-fast-lab` at `4af0abbba`: the new
`block_v6_joint_native_proof_v1.zig` proves native execution, native request
projections and ordinary-memory constraints with **one composition and FRI
proof**. Previously they required separate native and companion STARKs.
Fixed/main commitments are shared. With RAM, total commitment trees including
composition fall from nine across two proofs to six in one; without RAM they
fall from eight to five. Global provider closure and recursion remain open.

This is a real proof implementation with an independent verifier, not a
concatenated artifact or a host receipt. It is **not yet integrated into the
complete-bundle driver or its recursive verifier**, and no block improvement
is claimed from these measurements.

## Correctness boundary

The B6JP v1 domain separates the joint transcript. Both native physical claims
and companion physical claims are absorbed before either interaction root.
Native template, public admission, source seal, exact projection/memory rosters,
witness root, event count and fixed columns are independently checked. Native
fixed columns are reconstructed through the original verifier's shared helper.

Two integration details were caught and fixed by real-proof tests:

- Non-fixed component columns are concatenated by Stwo's collector. Shared
  main columns must be declared once. Before suppressing a companion's duplicate
  declaration, the adapter checks that every required sample is present at the
  same index in the native openings; extra or different openings fail closed.
- Native q1 quotients cannot simply be relabeled q2 to match companion AIRs.
  The adapter invokes the existing checked polynomial-extension transform.
  Unsupported larger lifts or preexisting conflicting overrides are rejected.

All 15 selected tests pass for each of three transcript seeds. The tests compare
**every exported native and companion relation**, including all lookup/range
claims, against fresh verification of the separate proofs. Cases cover real
load/store execution under both register-custody modes and a register-local
case with no RAM events. Cancelling native claims and cancelling companion
claims both fail verification. Existing four-tree companion mask/domain tests
and concrete producer/receiver code-generation checks also pass.

The joint route still needs a bounded artifact codec, independently keyed
recursive capture/AIR, complete driver integration, broader instruction and
precompile qualification, and closed global providers. The existing native
recursive key cannot admit this new five-trace-tree layout. No default receiver
has been changed to accept the joint artifact.

## Measurements

Apple M5, eight CPU workers, ReleaseFast. Each case runs a 1,024-iteration loop
(5,123 cycles). Three different job/transcript seeds, one run per seed. Table
entries are medians across those seeds.

| Security / case | Separate proof phase | Joint proof phase | Separate verify | Joint verify | Separate STARK bytes | Joint STARK bytes |
|---|---:|---:|---:|---:|---:|---:|
| q8/0, global registers + RAM | 0.200 s | 0.191 s | 0.055 s | 0.047 s | 104,807 | 81,289 |
| q8/0, local registers + RAM | 0.135 s | 0.127 s | 0.039 s | 0.031 s | 81,414 | 57,427 |
| q8/0, local registers, no RAM | 0.092 s | 0.086 s | 0.031 s | 0.024 s | 68,498 | 43,958 |
| q70/26, global registers + RAM | 0.650 s | 0.829 s | 0.074 s | 0.059 s | 515,469 | 402,087 |
| q70/26, local registers + RAM | 0.521 s | 0.198 s | 0.056 s | 0.041 s | 404,453 | 281,503 |
| q70/26, local registers, no RAM | 0.435 s | 0.169 s | 0.048 s | 0.033 s | 332,284 | 218,050 |

**Interpretation:** proof bytes and verification improve across these cases.
The diagnostic proof-phase improvement is only 4–7%. Canonical timing is heavily
affected by the different PoW transcripts: the global-register case regresses
in this three-seed sample. Do not promote the local-register 2.6× median as a
stable general speedup. Fewer independent PoW jobs is structural, but individual
grinding times are variable. A larger workload and stage-level breakdown are
required to establish the runtime tradeoff of the q1-to-q2 extension.

Proof timing excludes runner execution, initial witness/commitment preparation,
serialization and hostile probes. Verification is timed separately. Bytes count
Postcard STARK bodies, excluding claim transport. Peak memory was not measured
in this experiment. No timings here represent a complete block or recursive
root. Raw measurements and log hashes are retained in
[JSON](block-v6-joint-native-m5-20261028.json) and
[CSV](block-v6-joint-native-m5-20261028.csv).

```sh
STWO_JOINT_ITERATIONS=1024 STWO_JOINT_SEED=1 \
  python3 scripts/zig_protocol_test.py \
  src/frontends/riscv/block_v6_joint_native_test_root.zig -OReleaseFast \
  --test-filter 'block-v6 joint native and companion' \
  --test-filter 'block-v5 full fused' > joint-seed-1.log 2>&1
# Repeat with seeds 2 and 3, using separate log names.
python3 design/riscv-proving-stack/performance/joint-native-results.py \
  joint-seed-1.log joint-seed-2.log joint-seed-3.log
```

The parser requires all matched arms and successful qualification, rejects
mixed workloads, duplicate seeds and incorrect scope, and retains all samples.
Seven malformed/duplicate log controls were checked.

## Decision

Joint proving establishes the correct common commitment boundary, but merging
two proofs alone does not remove their equations. Before expanding this into a
large recursive tree, quantify the joined verifier's openings and BLAKE3 work.
Also examine whether the next native protocol can export the exact global
memory/program/lookup interfaces directly, eliminating companion projections
rather than merely proving them in the same STARK. This requires a new global
closure argument; aggregated claim arithmetic alone is not sufficient evidence.
The proof-once event bridge remains the other major work-removal target.
