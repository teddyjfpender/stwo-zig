# Genuine two-event RAM lifecycle source handoff

Status: root's initial AIR gate passed6/6 and its initial lifecycle nonproving
gate passed7/7. The bounded follow-up review below adds formatted source fixes
and two focused source fixtures; this agent has not built or run them. No STARK,
segment proof, block run or benchmark was launched. A full fresh lane proof
remains unqualified. Canonical integration
belongs to block_relation/root and uses an explicit sorted-memory tagged union:
register custody mode1 selects lanes; mode0 keeps explicit word compatibility.

## Proof custody

`block_v5_ram_lanes_proof_v1.zig` uses the existing
`block_v5_word_pcs_v1.For(Backend,Lanes.Spec)` implementation. It adds no fork of
backend proof machinery. The trace tree recipe is fixed24/main54/interaction92,
then genuine composition/FRI through the existing engine. Every PCS column,
fixed-row reconstruction and component domain uses **actual Claim.row_log**.
The legacy `row_log+1` event conversion remains only an algebra/range-planner
oracle. Retained coefficients have log `row_log`; committed LDE columns include
the independently pinned FRI blowup, exactly as other PCS families.

The independently pinned proposal is
`Proof.Pin{claim,index,roots[2],request_count,counter_digest,config}`. The first
channel binds lane ABI, exact geometry/event boundaries/index and PCS security.
The memory SourceSeal entry ID additionally binds physical roots, exact local
counter digest and request count. The proof channel replays the unchanged
universal47 plus word suffix linearly from B5SS, then binds the lane domain,
independent Pin identity and every secure interaction/census claim. No channel
reset occurs after drawing challenges. Old v4 instance IDs are rejected.

`commitFirstRoundWithCounter` emits a genuine two-root PCS plus the exact local
histogram in one range scan. Roots-only collection releases that PCS.
Pass2 commits the immutable trace once, checks actual roots and the exact
collected Pin, then `provePrepared` consumes this original warm PCS without a
second local fixed/main commitment. It requires ownership, exactly two actual
trees, retained coefficients, same config/index/geometry, and matching roots.
Generated range counts and histogram digest must match the independent Pin.
Caller-owned local counters are discarded on errors, never merged prematurely.
One shared range16 inverse table serves the entire memory/range proof pass.

Fresh `verifyOwned` consumes proof ownership on every success/error path. It
reconstructs fixed24 alone with the shared canonical `fillFixed` routine, checks
the actual fixed root using existing PCS, admits both roots/config under B5SS,
and verifies the new AIR, transcript, composition, Merkle openings and FRI.
Returned OpenReceipt remains an open lane receipt. Strict space1 gives an
explicit zero register endpoint sum/count; no producer-carried register scalar
or fake v4 proof receipt is constructed.

## Bounded stage and transport

`Stage.ForBackend.collect(a,Source,claims,total,config,limits)` owns claims, Pins,
the exact Range.Plan, range roots, provider counters, plan digest and config.
Source.load returns one owned sealed lane Trace at a time. It must replay the
same immutable sorted source and exact claimed event boundaries. Source and
its backing Replay remain owned by the driver until proving completes.
`collectEmpty` creates actual typed zero-requester metadata only after the
driver has checked EOF and its independent RW census. It consumes no source
loader and creates no PCS/STARK. Its plan digest is lane-ABI separated.

Plan reconstruction checks ordered indices, exact contiguous event census,
public predecessor/first/last, range request bounds and greedy field-safe
provider shards. The lane memory-plan digest binds all Pins, exact range-plan
digest and provider roots. It cannot be replaced with an old word plan. The
stage revalidates the complete plan and every memory/provider seal entry before
emitting the first proof. It retains at most one memory witness/PCS/proof, then
one provider PCS/proof; success transfers proof ownership to the sink and every
error retains producer cleanup responsibility.

Defaults are explicit: proof maximum rowlog22, fixed reconstruction1GiB,
interaction output-plus-scratch4GiB; plan maximum4096 instances/shards,
metadata32MiB; retained provider counters64MiB. The plan metadata cap uses a
conservative concurrent stage/reconstruction estimate. The trace has its own
owned-byte cap. Generic PCS allocations still use the driver's freeing bounded
host allocator, as other families do; these limits are not a measured total
RSS guarantee or a substitute for the aggregate host budget.

The follow-up security review moved the exact derived shard cap ahead of all
temporary claim/provider-plan allocations. Fixed and interaction byte caps are
also checked before a first commitment. Impossible physical LDE or FRI folding
geometry is rejected before scanning counters or constructing a PCS.

`block_v5_ram_lanes_artifact_v1.zig` provides independently supplied
`Expected{pin,expected_seal_digest}` plus bounded encode/decode and file Entry.
Magic `B5RAM2A1`, lane ABI, expected policy/seal/instance/index and a fixed-size
canonical360-byte interaction claim envelope precede the STARK bytes. Security,
actual row geometry, roots and query masks come from Expected, never artifact
metadata. Allocation-free shape preflight precedes proof decoding. Default caps
are artifact128MiB, proof64MiB,1024 queries and rowlog22. Encoding counts bytes
before allocating one bounded output buffer. Loading checks exact independently
pinned length and SHA before decode. Exclusive file output does not overwrite
existing files and removes a newly created partial file on ordinary errors.
Proof decode uses the caller's bounded freeing allocator for aggregate memory.

Artifact preflight uses actual physical row_log for both FRI and Merkle bounds.
The shared PCS derives its final domain from committed column logs;
PcsConfig.lifting_log_size remains exactly config/transcript-bound metadata and
cannot enlarge those actual lane domains. The earlier max(row_log,lifting)
preflight mismatch was corrected in this source review. Degree4 splitting
leaves16 composition columns, with sample bounds1/2/2/1; the actual AIR verifier
still enforces exact masks, fixed reconstruction, config and roots.

## Fresh global closure

`Receiver.Pins{seal,expected_seal_digest,first_round,pins,range_roots,
expected_total_events,source,limits}` is independent receiver policy. The
explicit verify/admit limit argument must equal that policy. `verify` freshly
checks every typed lane proof, every shared range provider, and the existing
canonical initial/final source files under the same B5SS. It requires complete
final-root policy, no register touches, exact local request counts, closed
cross-shard links, initial values, final values and endpoint census.

`Join.buses` only regroups17 lane range planes into the existing nine pair
positions associatively; it has no standalone proof/closure authority.
Transition/initial/endpoint tuples and challenge semantics are unchanged. The
receiver returns the common existing WordReceiver.Scoped only after all these
new proofs and source checks have actually succeeded internally. It never
promotes an arbitrary scalar or labels lane roots as an old word OpenReceipt.
That common result's transition bus remains open for the fresh opcode/caller
execution join; registers remain with the separately proved window policy.
For zero RAM the receiver authenticates empty touch/endpoints and unchanged
full-image roots, takes no memory/range proofs, and relies on the enclosing
fresh execution/register join to prove every RW requester is absent.

## Deferred focused gate

Root: `src/frontends/riscv/block_v5_ram_lanes_lifecycle_unit_test_root.zig`.
Filter: `block-v5 ram lifecycle`. Seven source tests include genuine tiny
physical first commitments but never call a STARK/FRI or guest prover:

1. Warm root/config/index/counter/phase custody, actual row versus LDE logs,
   exact fixed reconstruction and independent local histogram parity.
2. Linear transcript replay, stale seal, root/geometry/counter mutations,
   repeated old-v4 ID rejection, pure bus conversion and receiver-plan pins.
3. Field-safe multi-shard count planning without giant witnesses, changed
   shard/order/resource bounds and genuine zero-requester metadata.
4. Canonical claim envelope roundtrip and ABI/policy/index/row/census swaps;
   a deliberately invalid one-byte STARK is rejected by the real decoder.
5. Concrete producer/receiver/stage/codec/file API code generation. Functions
   are retained for compilation; proving and complete verification are not run.
6. Exact physical FRI/sample/composition shape despite optional lifting
   metadata, and impossible FRI/LDE/resource admission with a zero-byte allocator.
7. Actual empty-RAM source reception retains a nonzero untouched RW leaf and
   nonzero public input, consumes no proof loaders, and rejects a digest-consistent
   independently wrong final root or changed untouched source bytes.

Remaining required evidence: semantic/codegen qualification of the review batch;
actual tiny fresh lane+range+initial/final proof and negative gates when root
authorizes proof execution; independently reconstructed fixed-root rejection;
tagged production planner/replay/Store/policy/MemoryJoin wiring; detached
roundtrip and complete-join qualification; then isolated performance evidence.
block_relation owns canonical integration and root/exact owns resident backend
qualification. No segment runs are enabled by this source handoff.
