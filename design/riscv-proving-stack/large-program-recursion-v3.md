# RISC-V long-execution proof boundary

The released SegmentV2 statement uses one global clock and admits at most
2^24 retired instructions. Splitting an execution into more SegmentV2 leaves
does not remove that global limit. A long execution needs bounded leaf-local
clocks and a recursively verified 64-bit global span.

## Implemented ingress

`recursion/segment_execution_campaign_v3.zig` executes a real ELF in leaf-local,
segment-owned chunks. A consumer receives the complete profile-specific leaf
before that leaf's trace is released. Continuation capabilities, segment order,
global cycle continuity, the V3 leaf budget, and a finite leaf limit are
checked. This is an execution source, not proof acceptance.

`integrations/riscv_cpu/recursive_segment_v3_native_ingress.zig` takes an
admitted V3 source for one leaf, projects it into the bounded V2 AIR, creates
and serializes its Poseidon2 proof, destroys the producer, freshly verifies the
decoded proof, and joins the verifier-owned receipt to the V3 metadata. Its
`VerifiedLinkV3` is checked by the host. It is not yet a recursive proof of
the global position. Its public constructor now takes one native verifier
capture instead of a detachable wire/receipt pair. This narrows accidental
misuse but is not an adversarial proof capability: the final V3 verifier must
re-establish child authority from the committed proof and admitted key.

`recursion/segment_execution_plan_v3.zig` runs the ELF once to size every
leaf, records the exact total, ELF/input hashes, guest policy, and compact
per-leaf CPU, sparse-memory, clock and I/O boundary records. Replay checks
these records before exposing a leaf to the proof consumer, so equal-sized but
different executions cannot silently reuse a plan. Replay also passes each
measured leaf count as that leaf's reservation budget, avoiding an oversized
terminal-leaf trace allocation. It rejects host and
retirement callbacks until their behavior has an authenticated replay
contract. Planning is advisory and does not authenticate a proof.

`recursion/temporal_pair_candidate_v3.zig` checks the exact two-child V3
metadata preimages and the folded parent statement, including 64-bit positions
past the V2 clock cap. It is a native preflight for a future parent AIR, with
mutation gates; it does not accept either child as a recursive proof.

`recursion/temporal_interval_v3.zig` extends that preflight to arbitrary
contiguous intervals. It retains first/last leaf identities and sparse-memory
boundaries, checks the common job and 64-bit cycle/CPU/snapshot joins, and
produces a canonical 412-word statement for each aligned tree node. Its
left-to-right reducer carries an odd child unchanged, as the Starknet circuit
recursion tree does; a three-leaf tree needs two actual parent proofs and no
fabricated empty proof. The reducer returns only a native witness, and its
proof-publication API fails closed. A future parent AIR must authenticate the
two child proof families and all interval fields, then freshly verify its own
proof before exposing the resulting node. The legacy `SpanStatement.fold`
requires equal child heights, so the V3 relation uses height-independent
`foldExecuted` and validates the resulting aligned canonical parent statement.
The pinned row-11 statement-semantics graph also enforces equal child heights.
`statement_semantics_circuit_temporal_v3.zig` now builds the separate pinned
graph for unequal-height pairs (2,244 inputs, 17,304 nodes, 2,910 zero
constraints). It derives each child and parent slot from the 32-bit executed
segment count and first segment with bit-constrained 16-bit words, while the
existing body-fold equations constrain order, 64-bit cycle addition and CPU
state continuity. A three-leaf `2+1` fold satisfies it; mutations to child or
parent height, slot index, ordering and CPU boundary fail. The old row-11
program identity remains unchanged. The V3 graph still has to be installed
as a committed component in a new parent roster, joined to verifier-owned
child proof publications, the sparse-memory sidecar and final-only completion
flag, and independently
verified before a parent can be published. Host preflight alone cannot grant
that authority.
Its 2,244 input bindings require a 4,096-row (log-12) statement input trace;
the legacy parent roster fixes this row at log 11 and cannot be reused for V3.
`temporal_parent_row11_session_v3.zig` now initializes the pinned graph and
log-12 preprocessed binding once, reuses fixed-size scratch across pairs, and
materializes the actual typed row-11 preprocessed/main columns for each
validated pair. It checks the complete binding against the pinned graph on
session admission and rejects changed pair preimages before any trace write.
These are staging columns, not a committed parent proof. The parent transaction
still needs a genuine V3 wrapper proof for each leaf, a verified parent proof
for each internal child, a typed join from those verifier publications to the
pair words and boundaries, and a fresh parent PCS verifier. No host-only
metadata or staged 39-row local V2 proof may fill that child-verifier slot.

`integrations/riscv_cpu/recursive_segment_v3_outer_stage.zig` can now prove
and freshly verify the actual 39-component local V2 outer transaction for a
projected V3 leaf, then bind its verifier publication to the host-checked V3
link. The staged manifest has no V3 publication capability: the local proof
still does not constrain global position, so a temporal candidate cannot use
this stage as a verified recursive child.
The current V2 outer-child profile is explicitly developmental: three FRI
queries and zero interaction/PCS PoW bits. A production V3 wrapper must pin a
distinct security profile and upgrade the local outer prover and its recursive
verifier together; wrapping a weak local outer proof does not strengthen it.
The present native `SECURE_PCS_CONFIG` is a different 70-query/26-PoW preset;
its configured query-plus-PoW ledger is 96 bits under this repository's
`PcsConfig.securityBits()` calculation. A fail-closed V3 policy now rejects
both current presets against the existing recursion target profile
(193 queries, 16 PCS PoW, 10 interaction PoW). This policy specifies required
configuration; it does not prove that a future transaction actually used it.

The base RV32 SegmentV2 transcript ProgramV2 has an exact canonical M31
preimage with Poseidon identity parity and a pinned typed word-source AIR.
The 39-row outer shared providers have a field envelope over their sealed
manifest, claims, challenges, geometry and split sums. These are inputs for a
future wrapper cohort; neither field authority is yet consumed by a V3 proof.
The staged `BundleV3` takes the freshly verified native V2 child and the
separately verified 39-row outer publication, requires that they name the same
local leaf, and derives their canonical ProgramV2/provider word rows and
Poseidon hash calls. It checks exact word-to-hash lookup tuples and binds the
native Tree0 root to the captured FRI root. These are verifier-owned witness
inputs, not a proof that a V3 wrapper committed them.
The typed Tree0 link now emits the verified native root as verifier-input
words, consumes the matching transcript root, and consumes the transcript
frame coordinates. Its focused relation gate rejects changed limbs and frame
coordinates. The V3 wrapper still has to commit the link rows, constrain
their active/limb schedule against independently admitted verifier rows, and
close their transcript-word lookups; the host `BundleV3` cannot grant that
authority on its own.

The V3 leaf-wrapper roster fixes all 49 rows: the 39 local verifier rows,
typed link source/projection/arithmetic at 39–41, ProgramV2 and provider
word/hash rows at 42–45, the Tree0 link at 46, and metadata/link hash callers
at 47–48. Row 34 must be rebuilt as one enlarged Poseidon provider for every
caller; copying the 39-row V2 proof would leave the added rows outside its
commitment and lookup closure. The roster and exact-row claim gate pin geometry
and reject incomplete assemblies, but cannot themselves prove anything. The
new V3 protocol/key identity includes the roster, relation registry, strong
security profile and preprocessed root; the future verifier must recompute that
root from pinned sources rather than trust a caller-supplied digest. Publication
remains disabled until the verifier-owned source/interaction cohort, combined
hash-call witness, exact global lookup closure and PCS transaction are built
and freshly verified. The separate partial manifests remain useful as focused
typed-component tests; they are not proof publications.
For the base RV32 leaf, the child verifier authority is the freshly verified
native SegmentV2 capture inside `PreparedNativeV2LeafOuter`; the detached
39-component recursive-child loader belongs to a later parent and cannot
stand in for this native child.

The Starknet circuit recursion session provides the right reuse boundary for
eventual throughput: keep immutable, verifier-checked AIR tables, canonical
programs, PCS plans and worker pools live across leaves or parent nodes, while
allocating witness/proof data from request-local scratch that is reset after
verification. The RISC-V detached-parent workspace already reuses PCS plans
and bounded scratch; a future V3 campaign session should extend that pattern
to its fixed wrapper roster and ProgramV2 without reusing a previous leaf's
input, transcript or public-I/O state.

## Proof path still required

1. Connect the two-pass plan/replay to proof publication. The first pass now
   establishes exact total cycles, completion and per-leaf sizes without
   retaining traces; replay checks ELF/input identity and the leaf sizes.
   Construct one immutable `JobContext` from that total, then bind each replay
   leaf's actual execution and boundary identities to its V3 proof. Do not
   treat the planning receipt as a proof.
2. Complete the recursive leaf wrapper to constrain every V3 metadata word to
   the verified local V2 wire. The Ethereum leaf-link schedule now routes the
   base span, directly equal boundary words, and redundant position/completion
   fields. Separate typed AIR constrains canonical continuation-root limbs,
   completion tags, and 64-bit position arithmetic. These pieces are not yet
   one proof transaction: proof identity, verifier key, ProgramV2/provider
   authority and shared lookup closure still need integration. Make the
   wrapper available to the base RV32 profile as well.
3. Prove global position and length arithmetic with canonical 16-bit limbs:
   `end = start + local_count`, no overflow, exact segment order and bounded
   local count. The transcript must commit the complete V3 statement, local
   proof identity, security configuration and recursive verifier key.
4. Implement a verified temporal parent over two V3 publications. It must
   enforce common job/program/input identity, adjacent global ranges, equal
   CPU and sparse-memory boundary commitments, and exactly one terminal leaf.
   Support odd tails without inventing a dummy proof; mixed leaf/parent inputs
   need explicit family tags and verifier-key admission.
5. Publish a root only after all native leaves, leaf wrappers and temporal
   parents have been freshly verified. Detached loading must bind canonical
   proof bytes to verifier-owned metadata rather than accepting host assertions.
6. Bind public input/output claims to canonical guest I/O bytes through a
   versioned verifier-owned input and AIR relation. Existing SegmentV2 edge
   digests and `MachineState.public_io_state` are copied from the span
   statement, and custody checks only establish first/last placement; they do
   not prove that those digests represent the runner's actual input/output.
   The V2 canonical wire retains sparse `(address, value)` snapshots but drops
   the runner's I/O word-role bits and I/O address/length metadata, so the
   verifier cannot reconstruct the byte relation from that wire alone. The V3
   wrapper must not inherit that unbound claim. The minimal repro and
   acceptance criteria are tracked in [issue #228](https://github.com/teddyjfpender/stwo-zig/issues/228).
   An opt-in native capture check now defines a versioned I/O digest and
   compares trusted ABI bytes with authenticated sparse snapshots. It remains
   experimental: the V3 wrapper still needs the corresponding verifier-input
   and AIR relation before it can assert application I/O.

The first normal gate should prove a real two-leaf program, verify both local
proofs, both wrapper proofs and their parent, then reject mutations to global
position, local count, boundary clocks, memory snapshot, completion and child
order. A separate large gate should cross 2^24 total retired instructions with
each leaf below the V3 cap. Until those gates pass, no long-execution root is
claimed.

The public iadd256 experiment in [PR #223](https://github.com/teddyjfpender/stwo-zig/pull/223)
is a useful large-program gate: its
61-repetition first batch retired more than 2^24 instructions across bounded
leaf-local segments, but that capture is execution-only. The same experiment
shows that repeatedly regenerating earlier SHAKE inputs makes late batches
much larger than early ones. A full quantum-circuit proof therefore needs the
sound V3 leaf/parent path here **and** proof-bound SHAKE checkpoints and exact
batch/repetition coverage; merely raising a row cap or adding more leaves is
not sufficient.
The experimental V2 I/O capture check accepts verifier-known public bytes;
it does not meet the quantum fixture's private-circuit input contract. That
route needs an in-proof private-input commitment and parsing relation rather
than handing the circuit bytes to the verifier as an expected public value.
