# Session 16: Authenticated SN2 CUDA transcript schedule

Date: 2026-07-25

## Scope

This session closes the semantic scheduling layer for the resident Cairo CUDA
Fiat-Shamir transcript. It does not claim a complete SN2 proof.

The authority is the existing Cairo Metal `TranscriptRecipe` order together
with the canonical statement bootstrap ordinals and the backend-neutral CUDA
transcript kernels. The resulting CUDA schedule binds:

- the Cairo AIR identity;
- the compact statement identity;
- the compact protocol identity and encoded protocol header;
- the backend-neutral semantic proof identity;
- the complete executable `ProofProgram` identity;
- every fine-grained transcript operation and FRI round.

The coarse `ProofProgram.transcript` barriers are checked first. They remain a
portable semantic description, while the CUDA schedule expands them into the
exact resident device calls.

## Exact SN2 order

SN2 has 39 transcript operations:

1. Eleven bootstrap mixes at input ordinals
   `1, 2, 3, 10, 11, 12, 13, 14, 15, 16, 20`.
2. Interaction PoW at input 21, then one two-QM31 relation draw at output 1.
3. Interaction claims at input 22, interaction root at input 23, then the
   composition challenge at output 2.
4. Composition root at input 24, then the OODS point at output 3.
5. The 24,440 sampled-value words at input 25, then the quotient challenge at
   output 4.
6. Eight alternating FRI root/challenge pairs at input/output ordinals
   `65536 + 4 * round` and `65537 + 4 * round`.
7. Final-line coefficients at input 30.
8. Query PoW at input 31 and 70 query positions at output 5.

The controller enforces the next operation, owning stage, ordinal, payload
extent, schedule chain, and challenge cardinality before dispatch.

## Device-only challenge and PoW path

Challenges are written only by CUDA transcript draws into resident secure-field
buffers. The controller has no API for host-provided challenge values.

Cairo has two PoW boundaries. Interaction PoW belongs to `trace_commit`; query
PoW belongs to the later `pow` stage. The common CUDA runtime now exposes
`Fri.grindPowAtStage` and `Transcript.absorbPowAtStage`, and the Cairo
controller always combines those calls. There is no host-nonce absorption
entry point in this controller.

Input snapshots alias their immutable resident sources and challenge/query
snapshots alias their resident destinations. The CUDA kernels copy identical
words onto the same addresses, so evidence is preserved without allocating a
24,440-word sampled-value scratch buffer. The 64-word transcript slot needs
only the 16-word channel state and a disjoint 16-word boundary snapshot.

## Fail-closed evidence

Terminal transcript evidence binds the schedule, semantic proof, executable
program, authenticated AOT manifest, and authenticated AOT binary identities.
It is sealable only after all operations complete and measured counters report:

- zero runtime compilation attempts;
- zero CPU fallback attempts;
- non-empty AOT manifest and binary identities.

Mutation tests cover program/proof/protocol identity drift, coarse barrier
drift, ordinal drift, stage drift, payload drift, incomplete execution, runtime
compilation, fallback, and forged evidence.

## Verification

Focused ReleaseSafe result from an isolated source-root import:

```text
zig test ... -OReleaseSafe
All 32 tests passed.
```

The closure includes the nine new Cairo transcript tests plus the imported
protocol, telemetry, ABI, and module tests. An aggregate transcript-filtered
run also passed 35/35 before concurrent executor work resumed. All new Zig
files remain below the repository's 850-line hard cap.

## Remaining boundary

This work authenticates and checks the transcript schedule and its device
execution contract. A complete SN2 proof still requires the root executor to
connect the admitted bootstrap inputs, commitment roots, claimed sums, sampled
values, FRI roots, terminal coefficients, and resident PoW workspaces to these
operations in the full stage pipeline. Exact SIMD/CUDA proof-byte equality and
the pinned Rust verifier remain the acceptance gate.
