# Separate memory cohorts through recursive verification

The architectural change bounds wide RAM witness lifetimes before proving.
Each cohort is proved using the original RAM AIR and the shared execution epoch;
initialization intervals, range16 and terminal reads remain separate original
provider proofs. The job does not retain a monolithic RAM witness or require
another pass to reconstruct it. More original proofs are the explicit tradeoff.

## Problem match and reuse boundary

This is bounded external-memory execution with an authenticated reduction. The
recursive layer must retain the exact original equations and public operands
while permitting cohorts to be prepared and reduced in bounded windows. It is
not permissible to label a separate RAM proof as the heterogeneous joint proof,
or to treat a host verification receipt as a recursive child.

`block_v7_memory_component_recursive_v1.For` exposes exactly four families:
RAM, interval, range16 and terminal. Their profiles admit the independently
selected execution policy, complete epoch and roster, family/index, row domain,
first-round roots and physical claims. RAM also binds the original geometry.
The existing `block_v7_memory_shape_composition_v1` supplies the original symbolic
equations, including first-halt constraints. No second AIR implementation is used.

Cold and live parent preparation share the extracted four-tree plumbing in
`block_v7_word_family_*`. The original joint-memory facade uses the same plumbing
with its unchanged joint equations and framing. Each separate family's public
circuit and transcript domains remain distinct. Both routes reuse the exact
53-pair epoch draw, original PCS/DEEP/FRI and fixed-column compilation. The source
channel's framing is extracted once as `recordAfterChallenges` for native and
recursive recorders.

## Complete closure

The complete mixed roster supports either one joint-memory child or every RAM
cohort plus exactly one interval, range16 and terminal child. The epoch rejects
mixed modes. Canonical reconstruction checks the whole RAM geometry sequence,
including exact count, indices, adjacency, preceding endpoint and total events.

Every physical claim is authenticated by its actual original verifier rows:
29 claims per RAM cohort, two interval claims, two range16 claims and one
terminal claim. Complete closure checks the RAM link sum, initialization sum,
range sum and both exact census totals. Terminal reads contribute to the same
execution transition bus. Only after native and caller transitions close that
bus can the final receiver return a complete execution result.

A direct batch remains open. Bounded windows can cross memory-family boundaries;
reduction preserves every canonical public frame, exact roster ranges and the
whole-job epoch. The final root receiver needs neither original proof files nor
producer traces. Metadata remains O(number of original proofs).

## Qualification status

The genuine two-segment SHA+Keccak fixture passed all 11 checks. Both RAM
cohorts and the interval, range16 and terminal providers pass fresh original
verification, exact independent cold/live fixed-row and wire comparison, and
real parent proof verification. The five parents are recorded in
`performance/v7-separate-memory-parent-qualification-20261029.json`.

The whole qualification took 23.43 seconds with 1.204 GB maximum RSS, under
concurrent compilation. This includes original proofs, five parent proofs and
all differential checks; it is not production throughput. The typed Receiver independently verifies each parent, and a well-formed
changed physical claim is rejected under the unchanged roots and key. Integrated
complete-root qualification is pending.
No canonical security, Ethereum-block completion, or end-to-end speedup is
claimed by this gate.

## Complete execution-root qualification

On 2026-10-29 the complete CPU producer passed the genuine 20-cycle segmented
execution fixture with bounded external sorting, four RAM cohorts, all three
memory providers, two native segments, one caller, ROM and lookup. The twelve
original proofs reduce to one 159,188-byte root. Original proofs/checkpoints
are destroyed before independent final verification. Missing RAM coverage and
compensated changes to RAM/interval physical claims reject.

The diagnostic execution-to-verified-root interval was 68.330 s with a tracked
allocation peak of 7,999,930,428 bytes. This uses q8/PoW0, is not an Ethereum
block, and ran alongside compiler activity. It establishes complete closure,
not canonical security or a controlled performance improvement. The tested
binary predates the later receiver matrix-allocation-cap hardening. Binary and
log hashes are retained in
`performance/v7-cohort-complete-qualification-20261029.json`.
