# Mixed root authority and the next batching boundary

Status: source audit, 2026-10-28. The complete all-family proof gate now passes
its diagnostic q8/PoW0 fixture (see `complete-mixed-root-qualification-20261028.json`).
This note records the receiver boundary and a scale-up design, not canonical
security, Ethereum qualification or a measured speedup.

## What the complete receiver authenticates

`src/frontends/riscv/prover/block_v6_complete_root_receiver_v1.zig` receives an
independently selected key, wire schedule, typed roster, `Global.Pins`, PAGE
context, and expected public-input bytes. It checks security configuration,
key/roster identity and input length/hash, projects the closure operands onto
the exact mixed public bus, verifies one parent STARK, and only then runs the
original global algebra on those same operands. There is no second set of
unauthenticated closure claims or a producer-success receipt.

The source audit found no missing-authority bypass in this boundary:

| Obligation | Source of authority |
|---|---|
| Complete family/index roster | `block_v6_complete_public_inputs_v1.zig` checks exact cardinality and canonical order against independent native/provider/caller/PAGE admissions. |
| Public claim interpretation | `recursion/block_v6_mixed_claim_reconstruct_v1.zig` recreates frames from admitted geometry and claim proposals; serialized offsets and schedules cannot select interpretation. |
| Original verifier equations | `recursion/block_v6_mixed_direct_fixed_v1.zig` compiles all original families and namespaces without captures or MAIN witness input. Its key must be independently selected, not copied from a proof. |
| PC/clock continuity and exact execution span | Original `Global.Pins.validate()` calls `blockSpan` in `block_v5_global_receiver_impl_v1.zig`; native public shapes are tied to those pins. |
| State, register-window compensation, caller census, ROM fetches, lookup requests | `block_v6_global_public_closure_v1.zig` retains separate typed residuals and original equations, including terminal program-boundary fetches. |
| Initial/final RAM, source records and range counts | `block_v6_source_public_closure_v1.zig` reconstructs exact PAGE frames and runs original PAGE/RAM/range algebra. PAGE inventories are bounded and checked against their original geometry and inventory identities. |

This remains an **O(roster) public-metadata receiver**. Its public metadata and
fixed setup are not constant-size merely because there is one final proof.
The expected manifest is an out-of-band authority: the final receiver does not
load an ELF and independently derive its image/program roots, nor interpret
the final guest output as an Ethereum success statement. The complete fixture
gets that manifest through the original admitted runner/source route, deletes
intermediate proof and operand files, and reconstructs fresh admission owners.
The fixture currently uses an empty public input because its release ELF has
an empty input region. Separate input-binding regressions cover nonempty input;
that must not be described as nonempty-input qualification of this fixture.

## Beyond the direct 64-child bound

Keep the current direct verifier as the bottom layer. Partition the canonical
original family/index roster into bounded batches, prepare original verifier
rows for each batch, and prove one STARK per batch. Batch admission must consider
actual per-cohort row counts and memory, not only the 64-child transport limit.
This avoids creating a recursive wrapper for every original proof.

The next layer should verify these batch STARKs using a new mixed-batch public
protocol. Every child must bind its exact batch ordinal, contiguous original
roster interval, roster digest, shared source seal/configuration, independent
key/schedule and full public-input identity. Carry all canonical transcript
frames and wire supplies; do not collapse state, RAM, source, lookup or caller
claims into a single scalar. Final closure can initially retain the existing
O(roster) public claims and run the same original global algebra.

Reuse the exact radix-four topology in
`prover/block_v5_open_exact_forest_plan_v1.zig`: aligned quartets, residual pairs,
no dummy leaves, and an exact final residual-root fold. Reuse the transcript
frame replay and original parent verifier machinery in
`recursion/block_v5_open_child_frames_v2.zig`. Do **not** directly instantiate
the existing native-only `ForLeafAdapter`: its receiver assumes one execution
per leaf, execution PC/clock spans, `policy.native` and `native_open_sum`.
Provider/PAGE batches do not satisfy that interface. A typed mixed-batch
normalization and range protocol are required before those mechanisms confer
authority. Independently compiled parent keys must bind that new protocol.

Only after the complete public-metadata route works should a compact summary
replace those claims. Such a summary needs proved typed accumulators, census,
roster coverage and source/endpoint commitments; a host-computed digest is not
a replacement for those constraints.

Implemented groundwork: `recursion/block_v6_mixed_batch_ranges_v1.zig` now
admits a whole-job roster separately from its bounded direct batches. It uses
the original direct-bus roster parser for canonical order, binds the shared
seal/profile/request identity, rejects gaps, duplicate ordinals, omitted or
padded children, and compares batch key/public-input identities with independent
pins. Three ReleaseSafe tests pass, including a 137-child roster split 64/64/9
and source/config/key/request mutations. This is host metadata admission only.

The next implementation layer now lives in
`block_v6_mixed_batch_capture_v1.zig`, `block_v6_mixed_batch_public_v1.zig`,
`block_v6_mixed_batch_protocol_v1.zig` and
`block_v6_mixed_batch_prepare_v1.zig`. It decodes and freshly verifies the
original mixed STARK against independently selected policy, retains every
original typed public frame and packed wire-supply term, compiles the original
parent-verifier equations, and joins those rows through one n-ary drain. The
new outer public bus binds adjacent original roster ranges and exact child
key/public identities. It does not invent native spans or native open sums.

Nine focused ReleaseSafe tests pass for exact transcript replay, typed-frame
mutation, allocation rollback, range/schedule mutation, and implementation
instantiation. These metadata tests are separate from the genuine nested proof gate.

The subsequent nested fixture passes five ReleaseSafe tests: genuine range16
and ROM originals become two direct mixed proofs (129,927 and 129,052 bytes),
then one 141,368-byte batch-verifier STARK. Its joined fixed roster, wire
schedule and context match the capture-free compiler exactly. The verifier
uses that independently derived key after all producer captures and wide
rows have been destroyed, reconstructing source metadata from independent
policy. A well-formed changed composition OODS is rejected by the original
cryptographic verifier as `OodsNotMatching`; range/key negatives also pass.
Evidence is in `mixed-batch-reduction-qualification-20261028.json`.

This is diagnostic q8/PoW0 protocol qualification, not a full block closure or
canonical security claim. Recursively normalizing further reduction layers,
a final complete-coverage/global receiver, and canonical footprint-driven
batching remain outstanding. Sources borrow the capture owners during row and
public-bus construction; the API documents those lifetimes. Metadata still
grows with the original roster.

`block_v6_mixed_batch_fixed_v1.zig` adds a capture-free compiler for one
original mixed-batch verifier. It derives original composition, DEEP, FRI,
transcript, PCS paths/openings, packed supplies, fusion and arithmetic namespace
from independently supplied key/range policy. It explicitly substitutes the
original mixed protocol's claim-frame domain/version into the otherwise
unchanged original PCS operation schema. This matters: copying the older
closed-parent claim tag would compile a different transcript. It exports fixed
rows, public wires, context and namespace for subsequent cold/live parity; it
does not yet provide an admitted complete reduction-root key.

## Canonical geometry without proving every original

The current q8 and canonical q70 profiles have the same blowup (1), FRI fold
step (1) and terminal degree, but different query count and PoW. Therefore raw
AIR shapes and commitment heights do not inherently require new original
proofs for a geometry census. Query-dependent DEEP, FRI, Merkle paths, public
wires and transcript work do change; multiplying the whole q8 size by 70/8
would be inaccurate, and power-of-two padding makes peak changes discontinuous.

The existing independent factories already provide the right census seam:
`block_v6_partitioned_fixed_roster_v1.zig`,
`block_v6_provider_fixed_singletons_v1.zig`,
`block_v6_caller_fused_auxiliary_fixed_v1.zig`, and
`block_v6_page_auxiliary_fixed_v1.zig`. Starting from a newly admitted canonical
manifest, derive and discard one family's fixed roster at a time; collect exact
cohort row counts, fixed/main/interaction column counts, padded row logs,
namespace extent, public wires and measured setup allocation peak. No original
proof, private witness or PoW search is needed by these factories. Public
claims are proposals used by the original verifier equations, not success
authority.

The manifest must be canonically re-admitted with its config-dependent seals,
identities and roots. Mutating a q8 admission's config in place or passing q8
captured metadata to a q70 key compiler is invalid. A diagnostic shape-only
estimator can use the same original shape builders with explicitly labeled
non-authoritative headers, but its output must not be accepted as a key or
receipt. Prefer an exact canonical metadata census before estimating budget.

Sum unpadded cohorts across the proposed batch, apply the same G partition and
power-of-two row rules as the live n-ary join, and calculate memory by phase
(fixed setup, joined witness, interaction, FFT/commitment, recursive verification).
This produces a geometry/memory admission estimate; it is not a proving-time
measurement and still needs a live canonical proof qualification.
