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
- The hardened integration run passed 3/3 cases, including the exact
  Plonk/LogUp oracle, and rejected 48/48 example-specific tamper cases.
- Both verifiers require exactly four XOR proof commitments. Missing and extra
  commitment mutations are now mandatory verifier-semantic rejections.
- The hardened integration receipt was
  `0f37094ae1f64d94177ea62d38fc2cf98f06e20767d5542a59fd10e242301247`.

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

The source-closure correction is now integrated. The Native product selects
zero copied ordinary CUDA translation units. `cuda_mem_pool.cu`,
`prefix_sum.cu`, and `utils.cu` are quarantined, and every Native CUDA source
is scanned for forbidden allocation, copy, synchronization, default-stream,
environment, and legacy ABI surfaces. The resident relation graph is compiled
from two allocation-free Native translation units whose output hashes and
pinned authority inputs are recorded in the product manifest.

The Zig constraint framework also now lowers symbolic AIR expressions into an
owned, canonical, topologically ordered instruction program. The program
inlines named intermediates, retains explicit column/parameter bindings,
validates every operand and root, has deterministic semantic identity, and is
differential-tested against the symbolic evaluator including exhaustive
allocation-failure cleanup. This is the backend-neutral input needed to
compile future Poseidon, Blake, state-machine, RISC-V, and Cairo constraints
without adding workload names to the CUDA runtime.

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

1. Complete and integrate the opaque prepared relation plan.
2. Produce exact resident CUDA Plonk/LogUp bytes and obtain pinned Rust
   acceptance with zero fallback and complete stage telemetry.
3. Wire the same relation plan into exact XOR/lookup CUDA.
4. Replace the provisional state-machine component with the upstream
   two-component LogUp AIR on CPU and pinned Rust, then CUDA.
5. Port the exact Poseidon relation/AIR and the multi-component Blake AIR.
6. Only after six-family correctness, run locked-host A/A, ABBA, portfolio,
   memory, and sustained-service evidence.
7. Start profiler-directed 2-5x optimization only from that exact baseline.

## 2026-07-24 Exactness Review Checkpoint

The next Native AIR implementations remain unmerged while three review
findings are closed:

- State Machine must reject `log_n_rows < 5`. The pinned SIMD authority
  requires its shorter `log_n_rows - 1` axis to contain at least one full
  16-lane pack. Zig request validation, the Rust adapter, verifier statement
  validation, and adversarial mutations must enforce the same boundary.
- Poseidon must prove all 1,144 constraints and use the pinned
  `log_n_rows + 2` composition degree. A temporary one-constraint diagnostic
  and an incorrect `+3` degree were found before commit and are not eligible
  evidence.
- The resident Plonk composition kernel must be compared coordinate-for-
  coordinate with the exact CPU/Rust AIR over multiple shapes. A hard-coded
  CUDA smoke vector is useful lifecycle coverage, but it is not an
  independent correctness oracle.

The shared lifted PCS is also being corrected symmetrically. Query positions
must be folded for every commitment tree according to that tree's maximum
column degree, not only for the preprocessed tree. The acceptance gate is a
heterogeneous-tree regression plus unchanged exact Plonk/XOR proof bytes and
pinned-Rust acceptance.

## Exact State Machine And Accounting Checkpoint

The exact upstream State Machine protocol is now integrated on Native CPU and
the pinned Rust oracle:

- three trace trees are committed: one preprocessed, one main, and one
  interaction tree;
- two components use different trace heights, with the shorter component at
  `log_n_rows - 1`;
- the interaction contains eight secure columns, represented by 32 M31
  coordinate columns across the two heights;
- both components consume their own random-coefficient powers and claimed
  sums;
- `log_n_rows < 5` is rejected at request, statement, Zig verifier, and Rust
  oracle boundaries.

The formal bidirectional exchange produced a 10,145-byte proof with SHA-256
`cb870f4e3b1380212890ac9aff7edd6cf11a25214d2705dc61e2e582cf4f1b1b`.
Its content-addressed receipt is
`bf5696348a06b5535841b094d18295f220741a84cb064a8807764f55cb33783d`.
All 52 State-specific tamper mutations were rejected: 46 by verifier
semantics and six at the artifact metadata boundary.

The prior CUDA State route remains the simplified
`raw-stwo-state-machine-v1` protocol. It is not relabelled as exact. CLI,
direct-route, verification, artifact, benchmark, parity, diagnostic, and
sustained-service entry points now fail closed until the resident CUDA path
implements `raw-stwo-state-machine-v2`. The exact `sm_v2_log14` and
`sm_v2_log16` portfolio guards remain registered so the eventual CUDA
implementation must improve the real protocol rather than remove the family
from the score.

Benchmark geometry is now protocol-bound rather than inferred from the old
CUDA-shaped stubs:

- exact XOR has three trace commitments, 15 logical columns, and a
  `raw-stwo-xor-lookup-v2` descriptor identity;
- exact State Machine has three trace commitments, 12 logical columns,
  `9 * rows` committed cells across its mixed-height main and interaction
  trees, and a `raw-stwo-state-machine-v2` descriptor identity;
- resource admission accepts explicit mixed-height committed-cell geometry;
- product receipts reject a workload whose tree count, logical-column count,
  committed-cell count, or AIR protocol identity disagrees with its exact
  descriptor.

This correction is performance-critical evidence hygiene. It prevents a fast
legacy CUDA route from being compared with a materially different exact CPU
AIR, and it prevents cells-per-second or memory-admission claims from using
columns that the proof never committed.
