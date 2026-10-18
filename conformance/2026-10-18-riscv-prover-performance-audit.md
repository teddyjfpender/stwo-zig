# RISC-V prover performance audit (October 2026)

**Captured:** 2026-10-18

**Implementation:** `f8b64e96b` plus the changes recorded in this audit

**Host:** Apple M5 Max, 18 logical CPUs, 64 GiB, macOS, AC power

**Mode:** `zig build stwo-zig-riscv-cpu -Doptimize=ReleaseFast`, BLAKE3 proof
suite (the Blake2s suite is verify-only: proving returns
`LegacyProofGenerationRemoved`), secure profile (pow 26 bits, 70 FRI queries,
blowup log 1), `bench --warmups 1 --samples 5 --profiled`.

This is local diagnostic evidence for engineering decisions. It is not a
locked-host judged receipt and makes no cross-implementation claim. Absolute
times are valid only on this host; attribute by phase, since witness and
admission phases are unaffected by backend changes and reveal host drift.

## Baseline (clean `f8b64e96b`, quiet host; median / min of 5)

| Guest | Cycles | Total | Witness | Admission | Proving | In-proc verify | Proof bytes | Peak RSS |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| sha256 128 B | 14,056 | 601.9 / 593.9 ms | 94.0 | 60.5 | 368.8 / 363.1 | 73.3 | 837,493 | 668 MB |
| sha256 2048 B | 145,696 | 1690.2 / 1684.1 | 302.2 | 147.9 | 1068.6 / 1062.6 | 158.0 | 940,453 | 1,888 MB |
| keccak 2048 B | 285,456 | 2022.3 / 1988.1 | 391.5 | 178.5 | 1244.1 / 1217.7 | 181.5 | 926,803 | 2,233 MB |

Guest execution 1 to 17 ms; artifact encoding about 6 ms. Standalone `verify`
of the sha256-128 artifact: 80 ms wall, 250 ms CPU, 140 MB. Average pool
utilisation during a proof is about 5.7 of 18 cores.

## Stage profile (product path, sha256 128 B, `STWO_RISCV_EXECUTION_PROFILE=1`)

| Stage | ms |
| --- | ---: |
| fixed commit | 22.1 |
| main commit | 33.1 |
| native interaction | 16.4 |
| hash interaction | 53.4 |
| interaction commit | 35.1 |
| composition evaluation | 69.2 |
| composition commit | 7.1 |
| sampled values | 8.0 |
| FRI quotient build and commit | 32.9 |
| proof of work | 17.3 |
| decommitments | 1.5 |
| outside the prover: witness 94, PreparedVerifier admission 55, fresh verification 67 | |

`riscv-bench --profile` drives an older pipeline (2.29 MB proofs) and must not
be used for product attribution.

## Hot spots (CPU samples, sha256 128 B; keccak 2048 B in brackets)

1. `src/prover/vcs_lifted/streaming_committer.zig:424-499`
   `finalizeBoundedTailRangeReusing`: 25% [29%]. Scalar std Blake3 per lifted
   leaf row (17% [20%]) plus a memmove of the 1.9 KB std hasher state per row
   (5%). Only Blake2s had 4-lane tail kernels. Fixed below.
2. `compress4` 19%: proof of work (`pcs/blake3_proof_of_work.zig`, 11%,
   protocol-inherent), Merkle inner layers (`core/vcs_lifted/blake3_merkle.zig`,
   6%), batched leaves (1%).
3. Blake3-AIR constraint evaluation
   (`recursion/air/universal_typed_component_component_for_manifest.zig`
   `RangeWorker.run`) 9%, plus the interpreted
   `direct_constraint_program.zig` evaluator 2%.
4. Circle FFT (`poly/circle/fft_radix8.zig`, `transforms.zig`) 8% [13%];
   already SIMD radix-8.
5. FRI quotients (`pcs/quotient_tile_executor.zig`) 5% plus batch inverses 1.4%.
6. Hash LogUp interaction (`recursion/air/framework_interaction.zig`
   `TileWorker.run`) 5%; `framework_device_interaction.zig`
   `writeColumnsAtSerial` 1.4%, a main-thread serial section of about 27 ms.
7. memmove 13% in total: the committer above, an unresolved pool closure that
   is pure memmove plus `PageAllocator.free` (4%), and the serial phase-1
   extension coefficient copy in `pcs/columns/circle_transforms.zig` (fixed
   below).

Main-thread serial sections per sha256-128 proof: `munmap` churn about 25 ms
(phase-end frees of large buffers), witness `Owner.init` zeroing about 18 ms,
PreparedVerifier admission 55 ms, fresh verification 67 ms,
`DomainEvaluationAccumulator.finalizeInto` about 13 ms, twiddle precompute
about 9 ms (once per log size per proof).

Composition task graph (sha256 128 B, 87.9 ms): one `pool_exclusive`
component runs alone for 55 ms at about 53% pool utilisation, then three large
serial fallback leaves (17 to 25 ms each) run on single workers while about 15
workers idle. On keccak 2048 B the exclusive component runs 230 ms of a 278 ms
graph.

## Changes landed (proof, statement and transcript bytes identical)

Identity was checked by SHA-256 of the retained `--proof-out` artifacts and
the report's statement and transcript digests on all three guests.

1. **4-lane Blake3 bounded-tail kernel.** `src/prover/vcs_lifted/bounded_blake3_tail.zig`
   (new, with tests in `vcs_lifted/tests/bounded_blake3_tail.zig`), hooked at
   `streaming_committer.zig:401-434`. Lockstep 4-lane streams on the existing
   canonical `compress4`, mirroring `std.crypto.hash.Blake3` exactly; a
   compact lane state replaces the per-row std-state copy; a preflight
   declines to the scalar path on any keyed, misaligned or oversized leaf.
   `STWO_ZIG_SCALAR_TAIL_UPDATES` still forces the old path. Scalar compress
   samples fell from 8707 to 398. Same-window A/B: about −7% wall, −13 to
   −15% CPU.
2. **Worker-side extension coefficient copy.** `src/prover/pcs/columns/circle_transforms.zig`
   (`FftEvalWorkItem.sources`, `materializeSources`): the serial phase-1 copy
   now runs inside the FFT workers. Interleaved A/B: −2 to −5% wall, larger on
   bigger traces.
3. **Environment-lookup hoist.** `src/frontends/riscv/recursion/air/framework_device_interaction.zig:17-31`:
   two per-call `hasEnvVarConstant` lookups replaced by a once-resolved policy.
   Noise-level gain; behaviour identical.

Tests on the final tree: `src/prover` package 754 of 754; `test-merkle` 36 of
36 (four new); `test-stwo-prover` and `test-riscv-blake3-memory-path`
(ReleaseFast) pass; RISC-V inventory gate passes.

## Measured result

| Guest | Baseline total | Final total (quiet window) | Proving | Verify |
| --- | ---: | ---: | ---: | ---: |
| sha256 128 B | 601.9 / 593.9 ms | 475.2 / 473.1 ms | 368.8 → 279.0 | 73.3 → 57.7 |
| sha256 2048 B | 1690.2 / 1684.1 | about 1540 (measured at load 3) | 1068.6 → 969.8 | 158.0 → 134.6 |
| keccak 2048 B | 2022.3 / 1988.1 | 1559.8 / 1549.4 | 1244.1 → 959.8 | 181.5 → 133.8 |

The quiet-window host was about 10% faster than the baseline session on the
untouched witness phase, so the headline totals overstate the gain. The
same-window interleaved A/B evidence attributes about −7% to change 1 and −3
to −5% to change 2, roughly −12% end to end. CPU-user per six-proof bench run
fell from 20.5 s to 17.0 s (sha256 128 B) and from 71.6 s to 57.4 s (keccak
2048 B).

## Candidates not implemented (ranked by expected gain)

| # | Candidate | Expected gain | Notes |
| --- | --- | --- | --- |
| 5 | Preprocessed tree built three times (PreparedVerifier admission, prover fixed stage, fresh verification). Adopt the prover's fixed-stage root in the PreparedVerifier, fail closed on mismatch. | admission 54 → 20 ms (sha256 128 B), 140 → 89 ms (keccak 2048 B) | Implemented, tested with a wrong-root negative test, digest-identical, then reverted on request. Design below. |
| 3 | Composition graph: the `pool_exclusive` component runs at about 50% utilisation and three large serial fallback leaves run alone. | about −25 ms (sha256 128 B), more on keccak | Mixing leaves into exclusive waves was tried and reverted: keccak proving got 4 to 5% slower because the exclusive component's wall time scales with helpers lost and work estimates are not comparable across task kinds. Real fix below. |
| 6 | Verifier recomputes the preprocessed columns and Blake3 root on every verify (most of the 67 to 80 ms). | about −50 ms per verify | Per-program cache keyed by the full statement shape, ELF hash, plan identity, PCS config and implementation commit; recompute on any miss; opt-in and off for conformance receipts; test that a mismatched key recomputes. |
| 4 | Hash LogUp interaction: the parallel `writeColumnsAt` path requires at least 64 destination columns, so Blake3 AIRs (4 to 71 columns) run serially. | about −20 ms proving | A row-range split was tried and reverted: witness time rose 25 to 30 ms on keccak from per-chunk lease acquisition and parallel first-touch page faults. Needs a chunking strategy that amortises both. |
| 7 | `munmap` churn from phase-end frees of large buffers. | −10 to −25 ms | Per-proof slab or arena reuse across prover phases. Twiddles are already cached per proof. |
| 9 | Interpreted constraint program for the Blake3 G-call component. | −15 to −25 ms | Specialised code generation; larger refactor. |
| 8 | Proof-of-work 8-lane ILP in `compress4`. | about −5 ms | Nonce unchanged (lowest valid nonce). |
| — | Proof of work and FRI queries | — | Protocol-inherent. |

### Design for candidate 5 (adopt the prover's preprocessed tree)

`blake3_execution_prepared.zig:57-68` generates the native preprocessed
columns and commits a Blake3 tree into a throw-away scheme only to derive
`key.preprocessed_root`; `blake3_execution_proof.zig` `proveInternal` rebuilds
the same tree into the real scheme; `Artifact.verifyPublic` rebuilds it again.
Smallest change that keeps admission semantics:

1. `blake3_execution_proof.zig`: a `proveCompactAdmitting` entry that returns
   the fixed stage's root and column logs alongside the proof.
2. `blake3_execution_prepared.zig`: an `initCompactAdopting` mode that skips
   its own preprocessed generation and commit, sets the key from the adopted
   root and logs, and fails closed with `UntrustedExecutionKey` if the derived
   key id differs from the proof's key id.
3. `blake3_execution_request.zig`: for the base profile, prove first, then
   build the adopting PreparedVerifier; extended profiles keep
   prepare-before-prove. Report `proving_ns` and `admission_ns` partition
   accordingly and update `verified_request_binding_test.zig` token order.
4. Negative test: adopted root with one flipped bit and adopted root with an
   altered key id both reject; the adopting verifier reproduces id, root and
   logs; `verifyPreparedCaptureOwned` passes.

Alternative if admission must stay independent in-process: add
`adoptCommittedTree` on `src/prover/pcs/scheme.zig` that moves tree 0 from
the admission scheme into the prover's scheme and mixes the root exactly as
`commitBorrowedStreaming` does. This saves only the prover's 22 ms and retains
about 77 MB between admission and proving.

### Design for candidate 3 (composition graph)

Inside the `pool_exclusive` component
(`universal_typed_component_component_for_manifest.zig` `prepareRanges` is a
single child wave; `air/accumulation.zig` `finalizeInto` is serial), split into
at least four times more ranges than workers over several child waves and
parallelise `finalizeInto` over column chunks. Expect 55 → about 35 ms on
sha256 128 B and 230 → about 140 ms on keccak 2048 B for that task. Give the
three large serial fallback leaves a domain-parallel evaluator so they run as
exclusives after the main component rather than as a tail wave. Do not mix
leaves into exclusive waves with a fixed per-wave budget.

## Reproduction

```sh
zig build stwo-zig-riscv-cpu -Doptimize=ReleaseFast
./zig-out/bin/stwo-zig-riscv-cpu bench --elf vectors/riscv_csp/guests/sha256.elf \
  --input vectors/riscv_csp/inputs/msg_128.bin --backend cpu \
  --warmups 1 --samples 5 --profiled --report-out sha128.json --proof-out sha128.bin
STWO_RISCV_EXECUTION_PROFILE=1 ./zig-out/bin/stwo-zig-riscv-cpu bench ... --warmups 1 --samples 1
./zig-out/bin/stwo-zig-riscv-cpu verify --artifact sha128.bin --elf ... --input ... \
  --expect-statement-digest <statement_blake3 from the report>
shasum -a 256 sha128.bin
```

Report fields used: `timings[]` (execution, witness, admission, proving,
artifact_encoding, fresh_verification), `proof_sha256`, `statement_blake3`,
`transcript_digest_blake3`, and the lifetime maximum physical footprint under
`resources`. CPU profiles were taken with `sample` on a long `--samples 21`
run. Timing discipline: sample only when `uptime` load is low and no other
`zig` build or test process is running; keep both binaries and run interleaved
A/B with at least two repetitions; report median and minimum of five.
