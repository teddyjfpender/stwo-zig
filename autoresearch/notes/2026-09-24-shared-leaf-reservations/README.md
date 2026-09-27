# Reserved hash rows for execution-leaf shared emission

This is the storage prerequisite for extending shared final-layout hash emission
from recursive-node pairs to execution-leaf pairs. It does not yet switch the leaf
orchestration path or claim a performance improvement.

`Shared.initReserved` adds checked per-child G/XOR custody counts to the allocation
layout. Native emission retains its exact original layout and metadata slice; the
second child starts after the first child's entire reservation. Ordinary shared
construction delegates with zero extra rows. Partitions carry their capacities,
and final shared joining rejects unfilled reservations.

Parent append now accepts assembly partitions. It validates hash capacity and shared
column geometry, allocates only replacement fixed metadata for G/XOR, and writes
new main values directly into the reserved suffix. All cohort checks and allocations
finish before any shared value is written. Non-hash cohorts and ordinary prepared
parents retain the existing transactional replacement behavior.

The focused test injects allocation failures into append storage independently of
shared backing. It checks late-cohort rejection leaves hash data unchanged, main
pointers are retained, nonzero-offset append writes exactly its suffix, sibling and
padding values are preserved, and excess rows cannot spill into available padding.
The existing join tests continue covering ordinary/shared parity and ownership.

An initial test run exposed allocation-before-capacity-check error precedence:
injected OOM masked rejection of an over-capacity append. Capacity and geometry
checks now precede replacement allocation. The failed run is retained in
`join-initial.log`; final qualification is recorded separately.

Remaining integration: size custody rows from admitted conversions, retain stable
verified captures through deferred emission, emit both execution children into the
reserved layout, attach their custody rows, and use checked shared aggregation.
Canonical tree timing is required after that path is enabled. No CSP, protocol,
AIR, shader, or proof-parameter change is claimed here.

## Integration lifetime constraint

`State.plan` borrows the verified capture's proof pointer. Leaf pairing must retain
captures at stable addresses until both partition emissions and span attachments
finish. Both execution/ Ethereum proof modules expose their `Verified` type, so a
small owned capture-and-plan helper can encode this lifetime without type reflection.
Execution owners can still be destroyed after proving; custody conversions must
remain alive until direct suffix append completes. Existing pair admission of both
children before consuming either interaction must be preserved.

## Focused qualification

`join.log`: six ReleaseSafe checks passed (38 seconds testing, seven seconds
compilation), including the new allocation-failure and reserved-suffix check.

`tree.log`: seven canonical Metal tree checks passed. All three aggregate
artifacts independently verified at 70 queries/26 PoW bits with unchanged
845993/849496/889364-byte artifacts. Routed peak remains 26,459,992,736 bytes.
This is a regression qualification run, not an interleaved performance comparison.
No new speedup is claimed. Source snapshots and `change.patch` record this step
relative to the preceding dirty-worktree checkpoint.
