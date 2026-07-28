# RISC-V pull-request proof gate

**Status:** NORMATIVE

**Owner:** `riscv_cpu` in `conformance/ci-touchpoints-v1.json`

**Entrypoint:** `scripts/riscv_pr_proof_smoke.py`

## Purpose

Every change that can alter the RISC-V proof path must demonstrate that the
production focused CLI can still produce real proof artifacts and that a fresh,
separate verifier process accepts them. Compilation, field unit tests, trace
parity, and one synthetic AIR test are not substitutes for this gate.

This is the bounded pull-request prevention gate. It complements the live
Sail/Spike differential and strict release runner; it is not itself a
universal refinement proof or an independent proof-system verifier.

## Trigger contract

The gate is blocking whenever the product-scope planner selects `riscv_cpu`.
That includes changes owned by:

- `src/core/`;
- `src/backend/` and the CPU backend;
- `src/prover/`;
- `src/frontends/riscv/`;
- `src/integrations/riscv_cpu/`;
- the RISC-V product/build graph; and
- the CI policy or this gate itself.

Shared arithmetic and prover optimizations are therefore RISC-V changes even
when their motivating benchmark is Native CPU or Metal.

## Required execution

The focused lane must, in order:

1. build and test `test-riscv-cpu-product` in `ReleaseFast`;
2. build the focused `stwo-zig-riscv-cpu` executable from the same checkout;
3. execute `scripts/riscv_pr_proof_smoke.py` with that executable;
4. retain the smoke summary, proof artifacts, prove reports, and independent
   verify receipts in the focused-lane artifact directory; and
5. run the committed RISC-V trace-vector parity gate.

No command may select a fallback backend. The focused binary is CPU-only by
construction, and every proof report and receipt must be bound to the exact CI
commit and a clean tree.

## Structural corpus

The PR corpus is deliberately small but not trivial:

| Workload | Required property |
|---|---|
| `branch_fib` | Branch control flow and multi-family composition |
| `memcpy_loop` | Load/store behavior and memory-commitment composition |
| `multi_shard_addi` | Cross-shard state and LogUp placement |
| `sha2_input_128B` | Wide crypto execution and high-log polynomial evaluation |

Each workload has a pinned VM-step count. The gate rejects execution drift,
missing components, missing artifacts, schema drift, statement/transcript
disagreement, an empty proof, or any failed verification.

Removing a workload, lowering a structural assertion, changing a pinned input,
or weakening receipt validation requires all of:

- a design note explaining the lost coverage;
- a replacement workload that preserves the structural property;
- a regression test for the policy change; and
- successful exhaustive RISC-V release evidence on the replacement corpus.

Runtime alone is not grounds to weaken correctness coverage. Optimize or cache
the build before reducing the proof corpus.

## Verification boundary

For every workload, the gate requires two acceptance events:

1. the prover completes its internal verification and writes a schema-v3 proof
   artifact plus a machine-readable `riscv_prove_v1` report; and
2. a new CLI process reads that artifact and emits a bound, successful
   `riscv_verify_v1` receipt under the same functional protocol.

The receipt must agree with the prove report on statement digest, transcript
state, executable identity, implementation commit, release status, and protocol.
Artifacts and receipts are retained so a green check is auditable.

Pinned Sail is the semantic authority, with Spike as the independent execution
cross-check. Ordinary PR CI uses committed Sail/Spike trace-vector evidence so
it can remain fast; the live differential re-derives that evidence whenever
its meaning changes and on schedule. Strict release execution also runs the
formal workspace and the full adversarial suite. Zig prove/verify agreement
alone cannot establish AIR-to-Sail refinement or independent proof-system
soundness.

## Failure policy

Any nonzero prover/verifier exit, timeout, malformed output, missing output,
identity mismatch, or semantic mismatch fails `riscv_cpu` and blocks the PR.
There is no skip, warning-only mode, zero-throughput substitution, or
performance-promotion exception.

A failure during proof construction is a correctness failure. It must not be
reported as a benchmark result because no verified proof exists.

## Runtime contract

The proof portion targets less than one minute on a warm hosted runner and must
remain comfortably within the focused job's ten-minute fail-safe. It performs
one proof per workload, no performance warmups, no repeated sampling, no Metal
work, and no live Rust build.

Performance evidence uses the separate benchmark and autoresearch protocols.
This gate answers only whether the production RISC-V proof path is still valid.

## Regression provenance

This contract was introduced after shared `QM31` vectorization in `61f233bd`
passed the existing focused RISC-V lane but caused 13 of 20 production corpus
proofs to fail with `ConstraintsNotSatisfied`. The old lane selected the correct
product but did not execute its production prover corpus; the exhaustive jobs
were manual and skipped on the pull request. `branch_fib` in this gate reproduces
that failure before the field fix and verifies after it.
