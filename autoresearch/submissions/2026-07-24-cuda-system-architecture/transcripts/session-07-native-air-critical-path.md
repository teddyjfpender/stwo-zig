# Session 07: Native AIR Correctness Critical Path

Date: 2026-07-24

This session moved the CUDA program from wide-trace evidence toward exact,
lookup-heavy Native AIR coverage. It does not claim CUDA activation or a
portfolio performance promotion.

## Landed Milestones

### Exact Plonk/LogUp CPU and Rust authority

- The Zig Native CPU prover commits the exact upstream three trace trees:
  preprocessed, main, and interaction.
- The interaction uses two secure LogUp columns, represented by eight M31
  coordinates.
- The component evaluates the three upstream Plonk constraints with degree
  bound `log_n_rows + 1`.
- Canonical proof size is 10,090 bytes.
- Canonical proof SHA-256 is
  `2f204c0b5b63e0b8196562402a43e2ee08f6f4c9b419e183a6c77dfb03d928a4`.
- Pinned Rust Stwo commit
  `a8fcf4bdde3778ae72f1e6cfe61a38e2911648d2` independently accepts the
  Zig proof and rejects claimed-sum, log-size, statement-shape, and commitment
  mutations.

The full integration exchange gate passed 13/13 exchange cases and 208/208
tamper cases. Its local content-addressed receipt was
`1b7a7eb27e5d8791bd857723e471f24fe2d29470900618c03ab65a528e5cefea`.

### Exact XOR/lookup CPU and Rust authority

- The exact trace contains seven preprocessed columns, four main columns, and
  one secure interaction column represented by four M31 coordinates.
- Fourteen constraints bind selector bits, XOR truth-table rows,
  multiplicities, and the LogUp recurrence.
- The public claimed sum is zero.
- Pinned Rust implements an independent component over Stwo rather than
  invoking the Zig verifier.
- Zig-to-Rust and Rust-to-Zig proof exchange passes.
- The integration run passed 3/3 cases, including the exact Plonk/LogUp oracle,
  and rejected 38/38 tamper cases.
- The integration receipt was
  `81c1fd2e3b3aa233be26c0481adc93163baf16de5b0eeac7e95e4846d16da831`.

CUDA remains blocked for XOR because the resident product still exposes the
former two-preprocessed/one-main, zero-interaction route. CPU correctness is
not being used as evidence for CUDA correctness.

## Generic Resident Relation Stage

The first generic CUDA relation wrapper now exposes the copied global
relation schedule:

1. Expand transcript-derived `z` and alpha powers.
2. Generate all proof-wide numerator/denominator pairs.
3. Run ragged batch inversion.
4. Construct fraction chains.
5. Reduce each claimed sum.
6. Apply the exact claimed-sum shift.
7. Run the circle-order prefix scan.

The schedule is nine ordinary kernel launches on one proof-owned stream. The
host validates exact M31 row inverses, small-row ragged-inverse transitions,
signed CUDA extent limits, pointer-table alignment, cumulative geometry
offsets, scratch capacities, and all mutable range aliasing before launch.

The relation IR is being extended generically after exact Plonk exposed two
missing forms:

- projected tuples that do not inject a relation identifier;
- multiplicities sourced from an explicit column.

These are relation-graph capabilities, not Plonk-specific shader branches.

## Adversarial Review Findings

The first relation stage was not accepted as complete. Independent review
found two high-severity architecture defects:

1. The product selected whole copied translation units that also contain
   allocation, copy, synchronization, default-stream, and environment-driven
   legacy paths. Even if the exact relation entrypoints did not call those
   paths, they remained linked into the product.
2. The execute wrapper validated device pointer-table storage but could not
   prove the ownership, generation, capacity, disjointness, or descriptor
   semantics of the indirect pointees.

The correction is structural:

- split the smallest resident-only relation and ragged-inverse translation
  units;
- scan every admitted product source for forbidden runtime surfaces;
- compile relation instances at ingress into an opaque prepared plan;
- retain every typed source/output/slab/sum slice in that plan;
- upload exact descriptor, pointer, and geometry tables from the validated
  plan;
- remove the public raw-pointer-table execution boundary.

CUDA Plonk/LogUp cannot be declared resident or exact before this plan is the
only route.

## Activation Authority

`core_cuda` remains disabled and promotion-ineligible. Only wide Fibonacci is
currently release-ready, so the family count is 1/6.

Positive global activation gates now require parsed receipts. A boolean plus a
repository path is rejected. The current candidate dry run must parse as a
clean strict-AOT structural-screen receipt with all artifacts accepted by the
pinned Rust oracle. The predecessor rehearsal must parse as a seven-round
paired counterbalanced A-B-B-A verdict with valid confidence bounds and no
regressing workload.

Future gates have explicit schemas for structural coverage, sustained judging,
host authority, A/A calibration, mutation evidence, and full repository
release evidence. Every release receipt must bind the candidate commit and
binary digest.

## Cairo Boundary

The four SN PIE source-coverage record now pins the exact normalized geometry
of each PIE and a 57-component union. It remains deliberately inadmissible:

- the decoder Stwo revision differs from the manifest pin;
- the decoder Cairo checkout has two dirty Cargo files;
- three source writers are missing;
- 24 active writers are not safely rewritable;
- 56 source semantic packs are missing.

This record preserves the Cairo path without treating decoded structure as
proof semantics.

## Next Gates

1. Complete the resident-only CUDA relation object split and forbidden-source
   closure gate.
2. Complete the opaque prepared relation plan.
3. Produce exact resident CUDA Plonk/LogUp bytes and obtain pinned Rust
   acceptance with zero fallback and complete stage telemetry.
4. Wire the same relation plan into exact XOR/lookup CUDA.
5. Replace the provisional state-machine component with the upstream
   two-component LogUp AIR on CPU and pinned Rust, then CUDA.
6. Port the exact Poseidon relation/AIR and the multi-component Blake AIR.
7. Only after six-family correctness, run locked-host A/A, ABBA, portfolio,
   memory, and sustained-service evidence.
8. Start profiler-directed 2-5x optimization only from that exact baseline.
