# 2026-08-15 — A1 receipt measurement infrastructure

## Outcome

A1 now has a checked, allocation-free ingestion boundary for exact leaf and
binary-outer proof observations. The implementation lives in
`src/frontends/riscv/recursion/fri_profile_frontier.zig`; its focused tests live
in `fri_profile_frontier_measurement_test.zig` behind the standalone
`fri_profile_frontier_measurement_test_root.zig`.

This is measurement infrastructure only. It does not change `protocol.zig`,
does not activate a V1.1 profile, and does not reinterpret the repository's
query-plus-PoW ledger as an end-to-end soundness theorem. The checked constants
remain:

```text
PROTOCOL_ACTIVATION = false
FROZEN_V1_MUTATED = false
```

No speedup is asserted. A comparison records exact integer pairs and their
direction; it never produces a percentage, weighted score, or extrapolated
runtime.

## Why the adapter is value-only

The real leaf driver and binary outer driver sit above the frontend module.
Importing either receipt type into `recursion/fri_profile_frontier.zig` would
reverse the dependency direction and create an integration/frontend cycle.
`ObservationInputV1` is therefore the root adapter ABI. It is pointer-free and
contains no proof, capture, allocator, timer, slice, or receipt reference.

The proof root copies the following accepted values into the adapter only after
successful independent verification:

| Field | Unit | Authority |
| --- | --- | --- |
| source | enum | leaf or binary proof root |
| profile | exact configured integers | checked FRI frontier derivation |
| canonical proof bytes | bytes | canonical serializer receipt |
| fixed wire bytes | optional bytes | fixed-wire serializer, when that source has one |
| query count | queries | derived and checked in `MeasuredProfileV1` |
| commitment-tree depths | digest edges per path | accepted verifier capture |
| FRI fold widths and path depths | field values / digest edges per query | accepted verifier capture |
| terminal values | field values | accepted verifier capture |
| verifier work | graph nodes or AIR constraints | unit-tagged compiled receipt |
| native verification time | nanoseconds | proof transaction timer |
| Poseidon2 provider calls | calls | sealed provider-call ledger |
| receipt identity | SHA-256 bytes | canonical proof/receipt digest |

Leaf compiled graph nodes and binary AIR constraints are different units. The
model rejects an observation whose source carries the wrong unit and never
adds or ranks those units across sources.

## Exact path arithmetic

The adapter retains per-tree path depths and every active FRI layer's fold
width and authentication depth in fixed-capacity arrays. Redundant totals are
re-derived and checked:

```text
tree_path_count = tree_count * query_count
trace_authentication_digests = query_count * sum(tree_path_depths)
fri_authentication_digests = query_count * sum(fri_path_depths)
fri_fold_values = query_count * sum(fri_fold_widths)
```

Every sum and product is checked `u64` arithmetic. Inactive array tails must be
zero, active tree depths must be nonzero, active fold widths must be powers of
two, and a terminal value count must be present. Overflow rejects before an
observation can be sealed. The derived tree-path count, FRI layer count,
authentication total, fold total, and terminal total must also equal the
checked candidate model; a receipt cannot name one profile while carrying
another profile's geometry.

## Deterministic comparison semantics

`ObservationV1.seal` binds the complete value payload and upstream receipt SHA
to a domain-separated observation ID. `ObservationSetV1.ingest` validates first
and then inserts into a fixed 32-entry array sorted by source and profile. A
duplicate source/profile is rejected: this V1 schema deliberately represents
one selected exact receipt per profile rather than hiding sample aggregation.

`ObservationSetV1.comparisons` emits one source-local comparison for every
non-V1 observation. It requires a matching frozen-V1 baseline with the same
column degree, security floor, and PoW setting. Fixed-wire coverage must match
on both sides. `ComparisonSetV1.validateAgainst` then reconstructs every row
from the sealed observations and proves exact coverage.

The reported cost dimensions are:

- query count;
- canonical proof bytes;
- optional fixed-wire bytes;
- tree path count and authentication digests;
- FRI authentication digests, fold values, and terminal values;
- unit-tagged verifier work;
- native verification nanoseconds; and
- Poseidon2 provider calls.

Lower is treated as lower cost only for Pareto direction. If some dimensions
fall and others rise, the result is `tradeoff`; the model does not choose a
winner. Observation and comparison sets have domain-separated SHA-256
identities and are invariant to receipt completion/ingestion order.

The current storage bounds are compile-time constants derived with `@sizeOf`.
Construction, ingestion, validation, comparison, and hashing allocate no heap
memory. The focused gate additionally holds both fixed-capacity sets below 64
KiB each.

## Proof-root wiring

No shared build or driver file was changed in this lane. The intended one-way
wiring is:

```text
successful verifier receipt + accepted capture + provider ledger
    -> local proof-root adapter
    -> ObservationInputV1
    -> ObservationV1.seal
    -> ObservationSetV1.ingest
```

For the native leaf root:

1. use the exact postcard byte count and SHA from the serialized proof;
2. use fixed-wire bytes from `serializedByteCountRuntime` / the encoded wire;
3. copy trace-tree depths and FRI layer dimensions from the successful proof
   capture;
4. tag the compiled FRI verifier graph's node count as
   `compiled_graph_nodes`;
5. copy native `verify_ns`; and
6. copy the exact active outer receipt's `poseidon2_call_count` (or the
   equivalent sealed provider ledger), never a path-count estimate.

For the binary outer root:

1. use `Receipt.canonical_proof_bytes` and
   `Receipt.canonical_proof_sha256` from the successful transaction;
2. copy query/tree/FRI dimensions from its accepted `OuterProofCapture`;
3. tag the sealed complete-gate constraint count as `air_constraints`;
4. copy `Receipt.verify_ns`; and
5. copy the cohort's exact Poseidon2 provider-call count from the same sealed
   generated interaction authority.

The binary publication is already written only after successful verification,
so its proof/cohort/closure identities are suitable cross-checks at this root.
The adapter should be constructed before those verifier-owned values are
released, then retained only by value.

## Historical measurements and evidence boundary

The 2026-08-13 A1 note contains real proof bytes, wire bytes, graph schedules,
and native times for six leaf profiles. It does not record every new required
field—most importantly a per-receipt SHA and exact provider-call ledger—for all
six runs. This implementation does not invent or backfill those values.

The focused tests use explicitly labelled fixture observations, including the
published byte/work magnitudes where useful. They prove schema behavior, not
benchmark results. New proof roots can now emit complete sealed observations;
only those complete observations may become a reviewed V1.1 receipt.

## Focused validation

No proof is generated by these commands:

```text
zig test -ODebug --dep stwo_core \
  -Mroot=src/frontends/riscv/fri_profile_frontier_measurement_test_root.zig \
  -Mstwo_core=src/core/mod.zig

zig test -OReleaseFast --dep stwo_core \
  -Mroot=src/frontends/riscv/fri_profile_frontier_measurement_test_root.zig \
  -Mstwo_core=src/core/mod.zig
```

The gates cover source-local comparison output, order invariance, mutation and
coverage rejection, fail-atomic ingestion, exact replay against observations,
and arithmetic overflow.
