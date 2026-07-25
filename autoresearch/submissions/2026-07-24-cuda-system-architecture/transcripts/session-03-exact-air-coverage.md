# CUDA System Extraction: Session 03

## Record

- Date: 2026-07-25
- Model: GPT-5 Codex with three parallel implementation/review agents
- Integration branch: `feature/cuda-system-architecture`
- Local host: Apple M5 Max; no NVIDIA device is present
- Method: exact CPU/Rust semantics, host AOT differentials, product-route
  instantiation, then locked-SM89 measurement

This record separates host-proven schedule changes from CUDA performance
claims. No RTX timing, zero-fallback result, or proof-parity result is inferred
from a non-CUDA host.

## Objective

Close exact Native Poseidon and Blake semantics before returning to kernel
tuning. The accepted architecture must keep witness, relation, constraint,
commitment, transcript, quotient, FRI, decommitment, and terminal assembly
resident. Provisional constant constraints, synthetic traces, hidden CPU
fallbacks, and AIR-name benchmark shortcuts remain inadmissible.

## Accepted Host-Proven Schedule Reductions

### Direct depth-two composition split

Poseidon's exact constraint domain is `4N`, while the committed composition
tree contains 16 degree-`<N` base-field columns. The first implementation ran
the shared B2N transform into an `8 x 2N` temporary and queued 16 D2D copies to
partition those coefficients into canonical order.

Commit `bf0ddd47` extends the shared compact B2N continuation with an explicit
split depth. The final transform interval now writes:

```text
[LL c0..c3, LR c0..c3, RL c0..c3, RR c0..c3]
```

directly into the `16 x N` commitment slab. It removes the proof-sized
temporary and all 16 reorder copies without adding a transform launch.
ReleaseFast closure, CUDA runtime, exact Poseidon arena, authenticated build
plan, and source-conformance gates pass. RTX measurement remains pending.

### Witness-owned relation projection

The first exact Poseidon executor generated 1,264 main columns, then queued
256 D2D copies to preserve the 16 initial and 16 final state columns for each
of eight relation instances before destructive interpolation.

Commit `0702fae8` versions the generic 16-lane M31 permutation AOT schema and
makes relation projection an explicit second output of the witness program.
The same trace launch now writes the immutable `256 x N` relation slab while
the states are register-resident. This removes 256 host API operations and the
later reread of those main columns. An independent scalar C++ differential
checks the complete trace, initial/final relation order, non-target shapes,
and padding canaries. The old AOT identity remains historical; the changed
program has a new schema, semantic hash, source hash, cache key, and pack
identity.

These changes are general mechanisms, not measured promotions. Direct compact
split depth applies to any degree-two composition bound. Witness-owned
relation emission is the required pattern for exact Blake and future
lookup-heavy AIRs where the relation projection is known during trace
construction.

## Exact Blake Integration

The pinned CPU/Rust Blake AIR has eight mixed-height components, four
commitments, 15 preprocessed columns, 1,457 main columns, 1,156 interaction
base columns, 417 constraints, and 2,668 OODS samples. The minimum log-4 proof
commits 51,736,576 trace cells, so uniform max-height padding is both
semantically wrong and memory-prohibitive.

The first integrated slices establish:

- component-local packed views and exact tree geometry;
- a single lifetime-checked arena for all four trees and terminal output;
- strict eight-slab constraint descriptors with the exact lift map;
- reversed 417-power intervals and component-specific relation/claim indices;
- fail-closed separation from the retired three-tree seeded Blake experiment.

### Review correction: FRI cardinality and transcript barriers

Adversarial integration review found an off-by-one in the initial structural
model. With default blowup log one and last-layer degree log zero, the final
domain has log one. A first FRI circle domain at log 17 therefore commits:

```text
first circle layer: log 17
inner line layers:  log 16 through log 2
last polynomial:    log 1, not committed
```

That is 16 committed FRI trees, not 15. Each committed root must be mixed
before its folding alpha is drawn; a combined `fri_commit_and_fold` metadata
operation hides a real Fiat-Shamir dependency. The exact executor cannot land
until geometry, arena, transcript, decommitment, and tests all encode 16 trees
and distinct root/alpha barriers.

## Remaining Critical Path

1. Land exact Blake witness AOT with compact mixed-height outputs, bounded XOR
   multiplicity accumulation, and witness-owned relation sources.
2. Land the independent exact constraint AOT differential across all eight
   components and mutation-sensitive lift/power/relation tests.
3. Route the exact four-tree executor through authenticated descriptors, not
   caller-provided callback authority.
4. Instantiate the full terminal executor in a dedicated host gate so Zig
   generic-function laziness cannot hide an uncompiled path.
5. On the locked RTX 4090, require exact CPU/CUDA proof bytes, pinned Rust
   acceptance, strict AOT, zero fallback, one terminal D2H, and complete stage
   telemetry for all six Native families.
6. Only then measure the two pass reductions and resume Nsight-led
   coefficient/evaluation representation work toward the portfolio 2x target.
