# RV32IM zkVM soundness roadmap

This roadmap tracks assurance beyond ordinary feature completeness. The
normative architectural model is pinned Sail RISC-V; Spike is an independent
executor, and the pinned RISC-V Architectural Tests provide the standards
corpus. Stark-V is retained only for legacy proof-layout lineage.

The two obligations stay separate:

1. **Semantic refinement:** every admitted retirement has the Sail-defined
   decode, state transition, memory effect, and next PC.
2. **Computational integrity:** an accepting proof forces that retirement
   sequence and its public program, input, output, roots, and completion state.

## Current assurance baseline — 2026-07-26

- [x] Exact Sail model, compiler, configuration, and transport patch are
      machine-pinned and reproducibly verified.
- [x] Exact Spike and architectural-test revisions are machine-pinned.
- [x] Canonical retirement comparison covers PC, word, register write, next PC,
      and memory effect with no PC normalization.
- [x] The deterministic positive/negative corpus passes live Sail and Spike
      comparison, including strict illegal/reserved/misaligned rejection.
- [x] All applicable upstream RV32I and RV32M architectural tests use
      Sail-generated signatures and pass the zkVM executor.
- [x] Every applicable architectural test follows execute → secure prove →
      separate-process verify in the formal audit.
- [x] MULH, MULHSU, and MULHU are admitted. Signed high multiplication binds
      both operand sign bits and the complete byte/carry recurrence.
- [x] MULH malicious-witness mutations are rejected at proof admission.
- [x] FENCE is admitted for the single-hart zkVM; FENCE.I remains an explicit,
      conservative profile exclusion.
- [x] Misaligned instruction targets and data accesses reject before state
      mutation and are constrained at the AIR boundary.
- [x] CPU/SIMD and Metal consume the same backend-neutral witness/AIR; Metal has
      no CPU fallback.
- [x] Completion is a public relation event, artifact schema v4 binds protocol
      and exact PCS geometry, and independent verification recomputes the
      decoded-program root from the supplied ELF.

The reproducible commands and evidence schemas live in
`scripts/riscv_formal_tools.py`, `scripts/riscv_trace_vectors.py`,
`scripts/riscv_arch_tests.py`, and `conformance/riscv/`.

## Continuing adversarial work

- [ ] Expand committed-witness mutation coverage from the highest-risk MULH and
      program/memory boundaries to every opcode family.
- [ ] Add a deliberately malicious prover harness for skipped instructions,
      stale reads, forged outputs, and altered completion.
- [ ] Exhaustively check small-limb component domains where enumeration is
      feasible, with Sail transitions as the reference relation.
- [ ] Maintain serialized-proof bit-flip, truncation, splice, and wrong-statement
      rejection corpora as the wire evolves.
- [ ] Increase deterministic differential generation beyond the current
      checked corpus and record seed ranges and retirement counts.

## Independent verification and accounting

- [x] Proof artifacts are serialized and accepted only by a separate verifier
      invocation bound to an externally supplied statement digest.
- [x] Statement mutation and malformed-proof tests cover the public artifact
      boundary.
- [ ] Add a second independently implemented verifier for the RISC-V proof
      protocol. Sail and Spike independently validate execution semantics, not
      the repository-specific PCS/FRI proof wire.
- [x] Publish the current conjectural security-bit accounting for every exposed
      PCS profile, explicitly separating it from a reviewed reduction.
- [ ] Obtain independent review of the FRI/list-decoding security accounting.
- [ ] Keep the Fiat–Shamir schedule and all domain-separated extensions in the
      conformance ledger with mutation coverage.

## Formal and external assurance

- [ ] Machine-check that AIR satisfaction refines the pinned Sail transition
      relation, beginning with instruction decode and memory consistency.
- [ ] Obtain independent AIR and protocol audits.
- [ ] Maintain a public bug-bounty scope for witness construction, statement
      binding, serialization, and verification.

Feature completion does not imply these longer-horizon audit items are done.
Conversely, they must not be represented as missing RV32IM instructions or as
authority for reintroducing a second semantic oracle.
