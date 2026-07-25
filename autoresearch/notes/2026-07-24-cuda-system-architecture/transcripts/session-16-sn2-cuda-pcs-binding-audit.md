# Session 16: SN2 CUDA PCS Binding Audit

Date: 2026-07-25

## Question

Which post-trace stages of the existing Native CUDA prover can the Cairo
resident plan reuse directly, and which exact product contracts still prevent
an honest SN PIE 2 proof?

## Result

The Cairo executor now has allocation-free typed bindings for:

- four compact mixed-height trace trees;
- the uniform eight-column composition tree;
- the full OODS working set;
- quotient preparation, group, partial and result storage;
- every FRI coordinate, Merkle and terminal slot;
- the resident PoW working set;
- all trace/FRI decommitment scratch and column-log ranges; and
- the canonical SWPC terminal bundle.

Every binding checks the plan-assigned slot identifier and exact word extent.
It performs no allocation, upload, dispatch, synchronization, host read,
runtime compilation or fallback.

The exact SN2 protocol cardinalities flow through these bindings:

- 24,440 sampled-value words, or 6,110 secure-field samples;
- 2,077,800 terminal decommitment words;
- four trace commitments;
- eight FRI commitments; and
- 58 four-coordinate interaction claims.

This is a binding result, not an executed proof or performance claim.
`production_ready` remains false.

## Reusable Native CUDA Stages

The following implementation is AIR-neutral and remains the correct execution
base:

| Stage | Existing reusable implementation | Cairo-specific contract still required |
| --- | --- | --- |
| Composition transform/commit | `runtime/stages/composition_split.zig`, `transform.zig`, `commitment.zig`, `native_cuda/common/commit_tree.zig` | Exact four-coordinate aggregate layout and transcript/root schedule |
| OODS | `runtime/stages/oods.zig`, `native_cuda/common/oods_executor.zig` | Authenticated mixed-height sample/mask cohorts |
| Quotient term preparation | `runtime/stages/quotient.zig::prepareTerms/finalizeGroups` | Exact sample-to-constraint descriptors and structural groups |
| Quotient numerator | `runtime/stages/quotient.zig::accumulateCompact` | Compact source descriptor product and device slot |
| FRI | `runtime/stages/fri.zig`, `native_cuda/common/fri_executor.zig` | Transcript operations, inverse-twiddle offsets and exact final folded extent |
| PoW | `runtime/stages/fri.zig::grindPow` | Authenticated transcript state/sub-layout and Cairo PoW boundary |
| Decommitment | `runtime/stages/decommit.zig`, `native_cuda/common/pow_decommit_executor.zig` | Mixed-height opening groups, tree record offsets and terminal compaction |
| Terminal sections | `native_cuda/common/resident_proof_binding.zig` | Copy-free or bounded device compaction from working assembly to SWPC |

No new Cairo-specific CUDA math kernel is justified for OODS, FRI, PoW or
Merkle/decommit operations. The remaining work is product topology and two
mixed-height quotient contracts.

## Concrete ABI And Slot Gaps

### 1. Transcript sub-layout

`resident_plan` currently exposes one 64-word transcript slot. The common
executors require identity-bound state, input snapshot, output snapshot,
boundary snapshot and static-input views, plus the exact ordered operation
schedule. Guessing subranges would make Fiat-Shamir parity unauditable.

This blocks composition-root mixing, OODS challenge/sample boundaries, FRI
root/alpha boundaries, PoW absorption and query derivation.

### 2. Composition coordinate layout

The plan authenticates the final eight composition coefficient columns, but it
does not yet describe the intermediate four secure-coordinate evaluation
matrix emitted by the 279 constraint placements. The common split kernel
requires exactly four coordinates at the unsplit domain followed by eight
degree-halved columns.

This blocks the shared composition split, LDE and commitment sequence.

### 3. Mixed-height OODS schedule

The full OODS buffers now bind at all 6,110 samples. Cairo still needs an
authenticated schedule mapping every current/previous mask point to a compact
source range, coefficient log, factor range, scratch range and output index.
The common explicit/compact OODS batch engine can execute that schedule once
it exists.

### 4. Compact quotient source descriptors

The common CUDA quotient stage already supports
`CompactSourceDescriptor` and `accumulateCompact`. The Cairo resident plan has
no device slot for those descriptors. Its current prepared-term and batch-term
slots do not describe byte offsets and strides into the concatenated
mixed-height evaluation arenas.

This is a concrete missing product slot, not a missing arithmetic kernel.

### 5. Compact quotient combination

The plan correctly sizes four partial-coordinate slabs by the sum of the 58
component evaluation heights. The current common combine ABI instead treats
each coordinate as a fixed-stride matrix with
`group_count * max_output_size` words. It therefore cannot consume the compact
layout.

The product must choose one of:

1. add a compact offset-aware combine ABI and kernel; or
2. allocate the much larger dense fixed-stride partial matrix.

The compact combine is the resident architecture-compatible choice.

### 6. Quotient-to-FRI ownership

`quotient_result_coordinates` and FRI layer zero are distinct live slots. The
shared Native executor requires them to alias exactly so quotient output
becomes FRI input without a transfer. Cairo must either make them one
identity-bound slot or add an explicit resident device-copy node. Aliasing is
preferred.

### 7. Final FRI extent

The resident plan sizes `fri_last_evaluation` from the proof's final
coefficient count. The common executor needs the evaluation extent produced by
the final fold, then separately emits the bounded last-layer coefficients.
The adapter checks this relationship and refuses FRI execution when they
differ.

### 8. Mixed-height decommit topology

The device scratch, column logs, retained trees and 2,077,800-word terminal
capacity bind exactly. The missing authority is the ordered grouping of
same-height columns within each trace tree, the opening geometry for each
group, and the canonical per-tree assembly offsets. A single uniform
`WordMatrix` cannot represent the compact Cairo trees.

### 9. Terminal assembly route

The working decommit assembly is a separate resident slot. Even though the
corrected SN2 terminal capacity is large enough, no authenticated device-side
route currently compacts its used words into the SWPC decommitment section.
No host-side stitching is admitted.

## Gates

Focused binder compilation and fail-closed tests:

```text
zig test ... -OReleaseSafe --test-filter 'Cairo PCS'
All 22 tests passed.

zig test ... -OReleaseSafe --test-filter 'Cairo OODS'
All 20 tests passed.
```

Repository guards:

```text
zig build test -Doptimize=ReleaseSafe
stwo-zig closure: PASS

source conformance: 5 explained legacy findings
(5 active_native_backend, 0 deferred_todo), no new violations

zig fmt --check: clean
git diff --check: clean
```

## Next Product Boundary

The shortest path to the first exact proof is:

1. define and authenticate the Cairo transcript sub-layout and operations;
2. bind the four-coordinate constraint output into composition split/commit;
3. emit mixed-height OODS cohorts and compact quotient source descriptors;
4. add compact quotient combination and alias its result to FRI layer zero;
5. derive the final FRI evaluation extent from the last fold;
6. compile mixed-height opening groups and terminal record offsets; and
7. execute the whole schedule in one proof-owned session with one final read.

Only after that sequence matches Zig SIMD proof bytes, passes the pinned Rust
CPU verifier, and reports zero JIT/fallback is an H100 SN PIE benchmark
admissible.
