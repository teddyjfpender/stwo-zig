# Bounded v7 mixed batches and final closure

Status: genuine two-window diagnostic root qualified; >64 original proofs and canonical security remain unqualified.

## Problem-match brief

- Task and semantics: authenticate a complete ordered original-proof roster using bounded recursive batches, retaining every typed public operand until the independently verified final root closes the original global equations.
- Inputs and scale: the direct v7 route permits 64 children. Canonical q70 geometry can require batching even below that count. The complete roster contains native segments, caller windows, ROM, six compact lookup claims, and joint memory; counts and roots are bound by the v7 epoch.
- Invariants: no padding/dummy proofs, no missing/duplicated/reordered original child, one request and security configuration, independent verifier keys, original claim frames preserved. A batch is open and cannot claim global closure.
- Canonical match: exact contiguous sequence partition and bounded fan-in tree reduction. The batch sizes are independently selected by geometry planning; this layer verifies coverage, not optimal bin packing.
- Prior implementation: the local v6 mixed-batch capture compiles the original parent verifier (public transcript plus packed public supply, DEEP, FRI and Merkle openings). It does not use the native-only leaf adapter. This is the finite protocol to transfer to v7.
- Mapping: original ordinal -> sequence position; each direct batch -> a nonempty interval of at most 64 originals; each reduction child -> an authenticated interval. Adjacent intervals concatenate; the final interval must equal the full independently reconstructed roster.
- Complexity (derived): O(N) whole-job metadata and coverage work, O(N) original verification work, O(log_f B) reduction depth for B batches and fan-in f. Recursive verification is real additional work, so no end-to-end speedup is claimed merely from batching.
- Integration boundary: direct batches use original v7 mixed public frames; reduction captures verify the original parent STARK under an independently compiled key. Only the final receiver performs complete global algebra. Reject using a host success flag, a digest without proof authentication, or a partial input passed to the complete receiver.
- Prediction/falsifier: bounded batches should lower peak retained recursive witness memory, at the cost of more STARKs and reduction work. Actual geometry and peak measurements can falsify usefulness; this document contains no timing result.
- Correctness plan: >64 metadata coverage with cross-boundary duplicate/gap/order/epoch/root/key mutations; genuine proof-of-batch proof with cold/live key parity; final detached verification after all original proofs disappear; then >64 complete-root fixture. Tests of metadata alone are not proof qualification.
- Open uncertainty: optimal footprint-based batch sizes, canonical q70 parent capacity, and multi-level reduction costs remain unmeasured.

## Authority boundaries

The whole-job owner validates the full epoch and reconstructs all canonical family frames from independently selected admission metadata plus proposed physical claims. It exposes bounded windows without calling any global closure. A direct batch proof authenticates its own window. A reduction proof authenticates those proofs and exports their original frames; final metadata remains O(roster), not constant size.

The final receiver must independently reconstruct the entire roster, require the exact contiguous range cover, derive each key/supply schedule, verify the reduction root, and only then close the original native/caller/program/lookup/memory equations and independently selected ELF/output policy. No child batch is required to have zero global residual by itself.

## Implemented interfaces and present qualification

`block_v7_mixed_inputs_v1.Owned.init` preserves the 64-child direct limit.
`initWhole(..., max_entries)` admits the complete roster under an explicit
receiver limit; `window(first,count)` exposes an open slice of at most 64.
`requireSameWhole` checks every canonical frame, exact total length, and
cross-window family/index order. The original global algebra is shared by
`closePublic` and `closeWholePublic`; no equations were copied or omitted.

`block_v7_mixed_fixed_v1.Owned.deriveWindow` compiles only selected original
verifiers under the complete epoch. `block_v7_mixed_collection_v1.prepareWindow`
freshly verifies the corresponding originals, prepares their original verifier
rows and drains them into a direct batch. A singleton moves its rows and retains
the family allocator lease; it adds no padding proof.

The explicit v7 `mixed_batch_*` capture, fixed, preparation, public, protocol,
producer and receiver modules implement one reduction layer with 32 direct
batches. This bounds the present structure at 2,048 originals, even though the
metadata range validator itself permits larger jobs. Further levels are not yet
implemented. Direct batch keys and the final reduction key are independently
compiled. The final receiver receives only the final proof plus O(roster)
admission metadata and independently selected key/schedule pins, never child
proof files or a host success receipt.

The genuine one-child nested test passed 12 checks: six actual originals were
proved into a complete direct root, used as one open child, then reduced into a
131,684-byte proof. Fresh final verification ran after original/direct proof
bytes, captures, wide producer rows and cold rows were destroyed. OODS, range
and key mutations were rejected. This is diagnostic q8/pow0, not canonical
security, a multi-window proof, or a >64-original proof. The exact binary/log
receipt is `performance/v7-nested-root-qualification-20261029.json`.

A 137-original metadata coverage test passes, including provider omission,
changed epoch/root/key, overlap, duplicate ordinal, incomplete coverage,
overlarge/zero batches and resource limits. This is metadata evidence only.
The genuine two-window {5,1} gate passed 12 checks. It produced 156,945-byte
and 128,975-byte independently keyed open direct proofs, then a 141,280-byte
root. Only the final receiver closes the complete global equations; the first
window contains no memory provider. The singleton window proved successfully
after its family owner was destroyed, exercising the retained allocation lease.
Fresh final verification receives no original or intermediate proof files.

The full qualification process took 68.04s and peaked at 6,171,377,664 bytes RSS.
This includes original proofs, independent cold setup, every direct/reduction
proof, detached verification and negatives. It is diagnostic/unranked and is
not a production latency or controlled A/B benchmark. Exact stage data and
binary/log hashes are saved in
`performance/v7-split-root-qualification-20261029.json`.

The one-layer implementation accepts at most 32 direct batches. No >64-original
proof has yet been run, and no arbitrary-depth reduction is claimed. A future
large fixture must be sized from original-family geometry before launching a
canonical-security job.
