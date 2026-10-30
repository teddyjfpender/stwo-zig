# One authoritative native relation basis

Task: prove native semantics, clock constraints, all typed lookup requests and
ordinary-memory byte/integer transitions once under a single STARK transcript.
Current joint B6JP still generates original mixed native lookup batches and a
second partitioned copy for global accounting. Exact batch aliases remove only
2–8% of measured joint proof time and cannot resolve the layout mismatch.

This is exact sparse relation partitioning, not sampled-value deduplication.
The typed native lookup program is the source of every relation entry, sign,
tuple and weight. A new independently derived layout groups entries by global
relation. All entries occur exactly once, except conditional memory entries
which split algebraically into space and (1-space) parts. Their weights sum to
one at arbitrary field points. Native semantic constraints and the three
clock direct constraints remain; original mixed lookup columns are replaced.
Ordinary access byte/integer and opposite-memory bridge equations remain in
this first version. No provider, initial/final binding or claim is omitted.

| Candidate | Relationship | Decision and risk |
|---|---|---|
| Existing whole-batch aliases | Exact common subexpression elimination | Already measured; cannot reconcile mixed versus typed partitions |
| One typed partition basis | Exact re-partition of signed rational terms | Selected; requires coverage certification and a new transcript/codec/capture |
| Drop native memory terms together with opposite bridge terms | Cancellation after a separate identity proof | Deferred; demands a stronger conditional-selector and integer-bridge argument |

Source mechanism: [Stwo's multi-component prover](https://github.com/starkware-libs/stwo/blob/dev/crates/stwo/src/prover/mod.rs)
forms one composition and PCS proof from component handles. The independently
sized [ZisK topology](https://github.com/0xPolygonHermez/zisk/blob/1e22630bb7e143c30705a1603ed87cfd3da8c6ec/pil/zisk.pil)
motivates explicit relation/provider boundaries, not a transferable speedup.
No external implementation is copied.

Required interface: a new B6JP-v3 protocol with a layout digest, complete
physical-claim transcript binding and independently derived geometry. One
interaction tree replaces native-plus-companion interaction trees. The open
receipt contains the freshly verified typed partition totals and native
accounting total derived from those totals. It must not fabricate NativeV3
physical claims. A proof capture and admitted verifier component roster feed
actual recursion; an old host receipt cannot stand in for these equations.

Prediction: remove every original native interaction column, adding only the
ordinary-memory partitions absent from the companion schedule. Shared
fixed/main roots and the global prechallenge seal stay unchanged. Measure
total columns, proof count and complete assembled runtime, not aliases alone.
The global program-request instance must bind the new complete roster before
challenge derivation. Reject if any original typed entry lacks coverage or if
layout transport can change entry order/weight/domain without rejection.

Tests: derive coverage from every admitted opcode family and clock component;
check duplicate/omitted/wrong-partition entries, both register modes and
conditional RAM/register splits. Real native RAM/no-RAM proofs must match old
fresh accounting receipts, reject cancelling physical-claim modifications,
wrong layout/protocol and changed independent public pins. Canonical q70/26
qualification follows focused checks. Benchmark timings remain unqualified
until run on an idle host. Caller-only and local-x0 shapes must either be
supported exactly or rejected explicitly, never interpreted as legacy shapes.

## Implementation and current evidence

The implementation is `prover/block_v6_partitioned_native_proof_v1.zig` with
`block_v6_relation_layout_v1.zig`. It retains the unchanged NativeV3 first-round
fixed/main trees and optional retained access tree. It creates one partitioned
interaction tree. Roots therefore fall from five/six in the old joint proof to
four/five without/with ordinary accesses. Original native interaction columns
are never generated in this route.

Focused ReleaseSafe checks establish all-family symbolic coverage, including
local-x0 recipe entry expressions and both clock partitions. Arbitrary extension
field evaluation checks the exact rational equality, including nonboolean
conditional-space values. Mutations of missing/duplicated entries, wrong
partition weight, and inner slot geometry fail. Genuine old-recipe RAM/no-RAM
proofs in both admitted register modes freshly verify, and their open totals
match independently proved NativeV3 totals under the same source seal.
Cancelling two physical claims while preserving their aggregate is rejected.
A genuine caller-only physical frame with no opcode relation claims also proves,
verifies, and survives the bounded codec roundtrip.

`block_v6_partitioned_recursive_admission_v1.zig` reconstructs the source layout,
geometry, and key authority. Capture is produced only by fresh base verification;
`recursion/block_v6_partitioned_public_bus_v1.zig` exports the actual symbolic
verifier rows and typed public supply. `exportsFromValues` reconstructs original
physical claims and every canonical frame offset/step before deriving accounting.
`block_v6_partitioned_accounting_v1.zig` maps these new typed exports into the
original global algebra without inventing a NativeV3 physical-claim receipt.
Caller equivalents live in `block_v6_caller_public_exports_v1.zig`.

The real two-segment publisher now passes its complete ReleaseSafe gate (12/12).
The mixed SHA/Keccak guest executes 20,494 cycles with 8,293 memory events;
it produces exactly two partitioned proofs, with no separate native or companion
artifacts. Original native and access trees are retained and reused for both
segments; caller and external-memory checkpoint reuse is also asserted. All
wide producer owners are destroyed before canonical decoding and fresh native
verification. This is base publication evidence, not complete recursive closure.

Three integration boundaries needed explicit layout selection: the assembly's
prechallenge ROM request roster, the producer's independent replay admission,
and the warm stage's receiver admission. `Assembly.assemblePartitioned` seals the
complete partition before drawing challenges. `Policy.buildProvidersForPartitioned`
independently admits that layout and builds only actual provider/caller transport
policies. It does not create or filter fictitious legacy native proof policies.
The gate also rejects legacy projection admission against the partitioned seal.

A genuine partitioned native RAM proof now passes recursive preparation,
complete recursive parent proving, byte codec roundtrip, and fresh parent
verification. Changing an authenticated physical public claim rejects. The
caller accounting extraction gate also checks exact regenerated frames and
rejects a changed root-routing offset. The complete global accounting helper
is implemented against the original per-window, per-table-kind, program,
byte-demand, transition and source-PAGE equations; assembled root execution
remains a separate qualification obligation.

`block_v6_complete_public_inputs_v1.zig` converts the one reconstructed mixed
public roster into that global algebra's typed operands. Its bounded arrays
borrow exactly the reconstructed Values, retain independently admitted native,
caller and PAGE policies, and pair PAGE semantic claims with the decoded claim
records. Missing, duplicate, extra, wrong-family or wrong-index children reject.
The adapter's focused ReleaseSafe gate passes 10/10, including generated code
for its complete constructor; genuine all-family root integration remains the
end-to-end gate. No native proof receipts or second public frames are invented.

Qualification still in progress: actual local-x0 native proof OODS failure is
not resolved. The independent original NativeV3 local-x0 control on the same
small geometry also fails (InvalidProofShape). The default custody_v2 recipe
passes; local-x0 is an explicit experimental recipe, not the default. The new
producer, independent admission, and bounded decoder explicitly reject this
unqualified recipe in either register mode. Symbolic coverage does not grant
proof acceptance. The final focused partitioned gate passed 13/13 tests with
both actual recursive preparation and fresh parent proof verification enabled;
the caller export gate passed 4/4. Canonical q70/26
complete-bundle closure and idle-host end-to-end timing are still required. This
is not a published soundness qualification or a measured order-of-magnitude
speedup.

### Independent native recursive setup (2026-10-28 follow-up)

Implemented a capture-free original B6JP setup chain:
`block_v6_partitioned_recursive_fixed_v1` (canonical mask/degree geometry and
symbolic original composition/DEEP/FRI graphs),
`block_v6_partitioned_fixed_transcript_v1` (shared live/fixed framing),
`block_v6_partitioned_fixed_profile_v1` (explicit original four/five-tree PCS),
and `block_v6_partitioned_fixed_roster_v1` (original source/PCS/fixed assembly,
public schedule, context and namespace). The namespace includes original
arithmetic MAIN identifier ports reconstructed from lowering, not supplied
private rows. Public claim proposals remain symbolic equation inputs.

Focused metadata-only runtime qualification: 11/11 pass, with ordinary-access
four-trace/five-commitment shape in modes 0 and 1, plus no-access
three-trace/four-commitment shape. The test creates first commitments for genuine
admission but does not produce a STARK proof. Independent reconstruction and
changed-template rejection pass; changing a proposed public claim preserves
original equation and DEEP graph identity. Full fixed roster generation also
passes for all three shapes. No benchmark speedup is claimed from this test.

Remaining authority qualification: exact every-row/context/wire/namespace parity
against a genuine original live preparation and the complete independently
compiled mixed root setup. The existing live native gate now has the explicit
`STWO_B6_PARTITIONED_FIXED_PARITY=1` opt-in for that comparison. It has not been
run in this metadata-only window. Detailed factory coverage and authority
boundaries are recorded in
`mixed-root-independent-key-admission-20261028.md`.

The subsequent authorized native proof-backed parity gate passed **10/10** in
ReleaseSafe with `STWO_B6_PARTITIONED_RECURSION=1` and
`STWO_B6_PARTITIONED_FIXED_PARITY=1`. The genuine RAM mode-1 diagnostic shape
matched every cold/live fixed row, context, public wire and namespace identifier,
including original arithmetic MAIN identifier ports. No discrepancies required
fixes and no equality checks were relaxed. Broader shape/security and complete
mixed-root setup qualification remain separate obligations.
