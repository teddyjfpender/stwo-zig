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

The exact witness is now an authenticated AOT program rather than a host
facade. At log four, the complete preprocessed and main slabs match the Zig
CPU oracle digests:

```text
preprocessed 80ce951a14d3a4fd55cbafe281d3da5b1017d1da3acbdfdb91fab3d4e0f3cefe
main         314a97333fae566653f7e9623eef1dda309e0f4891f9117d5b63fb299321165e
```

The same launch emits an immutable preprocessed-plus-main relation mirror.
The differential also replays the launch without clearing ordinary columns
and verifies that only the bounded XOR multiplicity ranges double. The binding
selects fixed arena slots and an AOT-manifest source identity; it has no
caller-selected callback identity, host readback, or fallback.

The exact constraint AOT has an independent all-eight-component scalar
differential. Its scheduler, two round shards, five XOR tables, lift mapping,
and reverse power intervals match the Zig AIR on the host fixture. This is
semantic evidence, not a claim that an NVIDIA device has compiled or executed
the program.

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

The corrected structural transaction now carries 16 FRI roots at logs 17
through 2, 20 total decommitment trees, a separate last-layer mix, and explicit
PoW and query barriers. Its executor policy is compile-time typed. Product
activation still fails closed because exact paired-LogUp interaction
generation is a distinct third authenticated authority.

### Review correction: interaction workspaces and public claim order

The first interaction arena draft sized batch-inversion workspaces by
individual relation entries (`2 * secure_columns - 1`). The CPU oracle
constructs paired fractions first and batch-inverts one denominator per
secure column. Correcting the arena to widths:

```text
[6, 65, 65, 128, 8, 8, 8, 1]
```

halves each log-four workspace from 68,569,408 to 34,285,568 M31 words. The
denominator and prefix workspaces together therefore occupy about 261.6 MiB,
not 523 MiB. An authenticated future kernel may reuse or remove these slots
only with an exact differential.

The public Statement1 order is:

```text
[scheduler, xor12, xor9, xor8, xor7, xor4, round_split3, round_split1]
```

Execution component order differs. Review found that the initial constraint
descriptor read claims as if both orders were identical. The required claim
indices in execution order are `[0, 6, 7, 1, 2, 3, 4, 5]`. The constraint AOT
must be corrected and its independent differential must consume the public
order directly; a private uncommitted mirror would conceal protocol drift.

### Review correction: spill-prone constraint evaluation

The first exact constraint source materializes `RoundReader.batches[65]`,
`tuple[96]`, three `Fu32[16]` arrays, and `batches[128]` for the largest XOR
component. Although the host semantic differential passes, these dynamic
thread-local arrays imply roughly 4-5 KiB of local storage per thread and are
expected to spill to device local/global memory.

This source is not performance-qualified. The replacement must stream
relation pairs directly into their weighted constraints, combine tuple values
incrementally, preserve exact public-claim indexing, and record or gate
`cudaFuncAttributes.localSizeBytes` on the locked device. The rejected layout
will not be benchmarked as if its arithmetic correctness implied an acceptable
CUDA architecture.

## Remaining Critical Path

1. Implement the authenticated exact paired-LogUp interaction AOT: fraction
   generation, batch inversion, cumulative interaction columns, claimed-sum
   reduction, shift, and exact circle-order inclusive prefix.
2. Replace the spill-prone constraint source with streaming evaluation and
   correct public Statement1 claim indexing.
3. Bind witness, interaction, and constraint identities into the concrete
   four-tree product route and retain fail-closed activation until all three
   descriptors are authenticated.
4. Run the full independent interaction and composition differentials plus
   mutation probes for claim order, relation order, power interval, lift
   direction, batch inversion, and prefix ordering.
5. On the locked RTX 4090, require exact CPU/CUDA proof bytes, pinned Rust
   acceptance, strict AOT, zero fallback, one terminal D2H, and complete stage
   telemetry for all six Native families.
6. Only then measure the two pass reductions and resume Nsight-led
   coefficient/evaluation representation work toward the portfolio 2x target.
