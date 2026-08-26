# A-014 degree-aware lookup batching

**Date:** 2026-08-12
**Status:** explicit authenticated V2 proof path and real 17-family CPU proof
are complete; compatibility V1 remains the default and native Metal execution
remains open

## Question

Can the compiler choose singleton versus adjacent-pair LogUp batches without
raising the proof-wide quotient domain, while preserving relation order and
making the choice part of an authenticated plan?

## Implemented substrate

[`lookup_batch_planner.zig`](../../../src/frontends/riscv/air/lang/lookup_batch_planner.zig)
implements a bounded dynamic program over the typed relation effects in their
declared order. Version 1 deliberately supports only the two recurrence forms
already implemented by the prover: a singleton and a pair of adjacent events.
It never reorders or groups non-adjacent effects.

[`lookup_batch_execution.zig`](../../../src/frontends/riscv/air/lang/lookup_batch_execution.zig)
adds the allocation-free row execution seam. It separates a fixed
`FamilyAuthority`—the intended generated compiler artifact—from fallible
retained-plan construction. The current shadow compiler can discover that
authority, while the runtime-shaped constructor consumes it without rebuilding
a symbolic arena and releases every partial allocation on failure. A selected
row pair is then reconstructed from the exact production entry list with no
allocation, reordering, string dispatch, or hash lookup.

The fixed authority does not trust a caller-supplied family label. It checks the
native typed-program digest against the P-002 registry and checks a separately
domain-separated digest of the family, program identity, event count, and every
ordered `(ordinal, numerator degree, denominator degree)` triple. All seventeen
authority digests and resulting V1 plan digests are pinned. The native retained
constructor rejects drift before allocating; custom research policies remain
explicitly unpinned.

The policy is lexicographic and intentionally avoids an invented timing scalar:

1. minimize proof-wide quotient-expansion bits;
2. minimize committed interaction columns (four M31 columns per batch);
3. minimize maximum interaction degree;
4. minimize pair cross-multiplications, with the earliest legal pair as the
   deterministic structural tie-break.

The first coordinate uses an explicit `ambient_constraint_degree`. This is the
maximum degree imposed by the rest of the proof, not the local direct degree of
the component being planned. The distinction is essential: treating a locally
quadratic family as an isolated proof can make a legal cubic pair look like a
domain expansion even when another native component already fixes the whole
proof at degree three.

The SHA-256 plan identity binds the domain and format version, semantic program
digest, policy, ambient degree, ordered event ordinals and numerator/denominator
degrees, complete score, and every selected batch with all derived recurrence
degrees. Validation recomputes the partition algebra and identity. Selection is
`O(N * D)` time and `O(N)` temporary memory, where `D` is statically bounded by
16; it runs during planning, never in a row-generation hot loop.

## Complete native-family audit

The shadow audit derives event degrees from every production family and pins
the following proof-wide cubic candidate:

| Metric | Current compatibility layout | Selected shadow layout |
| --- | ---: | ---: |
| LogUp batches | 155 | 137 |
| Interaction M31 columns | 620 | 548 |
| Maximum interaction degree | 3 | 3 |
| Families with changed batching | 0 | 3 |

Only three families change:

| Family | Current batches | Candidate batches |
| --- | ---: | ---: |
| `mul` | 16 | 11 |
| `mulh` | 22 | 16 |
| `div` | 25 | 18 |

All other families retain their current count. No family increases the
proof-wide quotient expansion. The deterministic five-event fixture pins plan
digest
`6c26c035b31e80cae8082a78947fb1d4d7eec7faaf20e03c32d7d5948536fffc`.

The tests cover malformed policies and event order, semantic and plan mutation,
zero-denominator rejection, complete allocation-failure cleanup, a case where
the optimal legal pair occurs after a forced singleton, and 1,024 randomized
QM31 algebra differentials between two singleton fractions and their paired
form. A second differential constructs every family plan, replays 64 concrete
rows per family through the production relation-entry builders, and proves the
sum of all singleton fractions equals the compiler-selected batch sum. It also
forces a real relation-denominator collision through the selected execution
primitive and requires inversion to reject.

The existing sequential interaction generator first gained a separate
`generateSelected` entry point, monomorphised over the selected plan rather
than branching on policy inside the row loop. Across all seventeen families,
random 32-row committed inputs produce the same total claim and the same
aggregate cumulative value at every committed row as compatibility batching.
The candidate owns only its active 137-batch output geometry, and exhaustive
allocation injection proves partially allocated candidate columns are released.
The compatibility `generate` entry point, statement geometry, verifier, and
proof bytes remain unchanged.

The normal opcode LogUp component also accepts an authenticated selected-plan
constructor. It copies the authenticated batch descriptors and plan digest,
derives its interaction masks and constraint count from the selected geometry,
and evaluates the same recurrence through the selected entry ranges. Generated
selected traces satisfy every component constraint for `mul`, `mulh`, and
`div`; changing a cumulative value is rejected. Its V2 backend capability binds
the exact variable partition, degree schedule, program identity, and physical
placement. The CPU backend admits it only when the proof transaction presents
the statement-scoped V2 activation; a V2 capability in an ordinary
compatibility proof remains inert.

## Paired local performance evidence

The focused ReleaseFast test alternates baseline/candidate order, takes seven
samples per arm, consumes the complete claimed sum, and reports the median for
16,384 rows. The timed interval includes output allocation, relation replay,
batch inversion, cumulative-column construction, and cleanup. The first
isolated run reported:

| Family | Current | Selected | Current median | Selected median | Speedup |
| --- | ---: | ---: | ---: | ---: | ---: |
| `mul` | 16 batches | 11 batches | 9,825,750 ns | 8,097,334 ns | 1.2135x |
| `mulh` | 22 batches | 16 batches | 13,660,625 ns | 11,426,708 ns | 1.1955x |
| `div` | 25 batches | 18 batches | 15,690,125 ns | 12,772,542 ns | 1.2284x |

A second cached-binary run, while an unrelated Debug suite was compiling,
reproduced 1.2092x, 1.2010x, and 1.2291x respectively. These are promising
local interaction-generation measurements, not a whole-proof speedup claim.
The test deliberately reports rather than promotes: P-004 still requires an
A/A-calibrated end-to-end budget.

## Authenticated production path and real-proof evidence

The selected layout is now an explicit, append-only protocol path. The prover
derives one `AuthenticatedStatement` from the exact native statement and
static 17-family manifest, mixes its activation identity before Tree 0, writes
and commits the selected Tree 2, and assembles the selected components through
the shared prover/verifier registry. The ordinary SegmentV2 entry point remains
compatibility-only and cannot activate the layout accidentally.

One repository-owned ELF retires at least one instruction from every canonical
opcode family. Its production-derived statement contains all 17 families.
Holding that execution, public statement, PCS profile, and engine fixed gives:

| Metric | Compatibility V1 | Authenticated V2 | Exact change |
| --- | ---: | ---: | ---: |
| Opcode Tree-2 M31 columns | 620 | 548 | -72 (-11.61%) |
| Infrastructure Tree-2 M31 columns | 68 | 68 | unchanged |
| Total Tree-2 M31 columns | 688 | 616 | -72 (-10.47%) |
| Canonical proof bytes | 51,863 | 50,256 | -1,607 (-3.10%) |

Both proofs independently verify. Reciprocal replay is rejected: the selected
proof is not accepted by the compatibility verifier and the compatibility
proof is not accepted by the selected verifier. The admitted identities are:

- manifest: `f205a9fb631bbab2b93efbb961fe662c5a2c0ee55d7d60d606d49d030a2de849`;
- statement: `8b1b08f4635daa583a55d91914103c49ad15a7db996a4290e23b6686109eeff0`;
- activation: `d5771e0a86bb81a25f4e6d0a3b52e6a88766c3be3c1115d39f9846443a50fd51`.

Single-sample elapsed times are retained only for attribution. Debug observed
33,869.979 ms versus 31,100.957 ms proving and 6,663.241 ms versus 6,633.311 ms
verification. ReleaseFast observed 2,032.799 ms versus 2,047.789 ms proving and
562.661 ms versus 552.205 ms verification. The opposite proving directions
across build modes are the reason neither observation is promoted to a speed
claim; the exact column and byte reductions above do not depend on timing.

The same V2 proof is backend-generic for correctness, but it is not yet a
native-Metal/no-fallback path. The first missing boundary is
`src/backends/metal/runtime/base_polynomial_composition.zig::lookupCapability`:
it recognizes `lookup_polynomial_v1` only, so V2 is evaluated by the prepared
CPU host worker. Honest Metal closure requires a V2 program/job owner,
variable-batch code generation or AOT kernels, cache identity, dispatch, and a
no-CPU-fallback receipt; merely admitting the enum variant would be unsound.

## Validation

```text
zig build --build-file src/frontends/riscv/build.zig test-lookup-batching -Doptimize=Debug --summary all
Build Summary: 3/3 steps succeeded; 228/228 tests passed

zig build --build-file src/frontends/riscv/build.zig test-lookup-batching -Doptimize=ReleaseSafe --summary all
Build Summary: 3/3 steps succeeded; 228/228 tests passed

zig build --build-file src/frontends/riscv/build.zig test-lookup-batching -Doptimize=ReleaseFast --summary all
Build Summary: 3/3 steps succeeded; 228/228 tests passed

zig build --build-file src/frontends/riscv/build.zig test-air-semantics -Doptimize=Debug --summary all
Build Summary: 3/3 steps succeeded; 611/611 tests passed

python3 scripts/typed_air_zig_lane.py --label a014-full-cohort-real-proof-final -- \
  /usr/bin/time -l zig build --build-file src/integrations/riscv_cpu/build.zig \
  test-riscv-lookup-v2-native-proof -Doptimize=Debug -j1 --summary all
Build Summary: 1/1 steps succeeded

python3 scripts/typed_air_zig_lane.py --label a014-releasefast-real-proof -- \
  /usr/bin/time -l zig build --build-file src/integrations/riscv_cpu/build.zig \
  test-riscv-lookup-v2-native-proof -Doptimize=ReleaseFast -j1 --summary all
Build Summary: 1/1 steps succeeded

python3 scripts/typed_air_zig_lane.py --label a014-full-lookup-debug -- \
  /usr/bin/time -l zig build --build-file src/frontends/riscv/build.zig \
  test-lookup-batching -Doptimize=Debug -j1 --summary all
Build Summary: 3/3 steps succeeded; 326/326 tests passed
```

## What this does not establish

The exact CPU structural and proof-size reductions do not establish a proving-
throughput win, a peak-memory win, or native Metal acceleration. A production
promotion decision still requires the P-004 A/A measurement protocol, exact
work and peak-memory receipts, and the Metal closure described above. The
compatibility protocol remains the default; callers must select and authenticate
V2 deliberately.

## Decisions and tasks affected

- A-014 remains `active`: CPU production lowering and real-proof evidence are
  complete; native Metal/no-fallback and normative performance evidence remain.
- P-003 must join this static candidate with runtime proof telemetry before any
  performance conclusion.
- E-022 can consume the explicit V2 path where protocol selection is deliberate;
  compatibility V1 remains the default.
