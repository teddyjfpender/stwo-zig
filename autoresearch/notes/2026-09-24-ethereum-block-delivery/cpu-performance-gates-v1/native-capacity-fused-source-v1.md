Capacity-native projection and ordinary-memory fusion, B5CF v1

Source-only candidate, 2026-09-27. No builds, tests, commitments, STARK/FRI,
guest/segment, device or benchmark jobs were executed for this batch. The
fresh fused proof and full block composition remain unqualified.

The new `block_v5_native_capacity_fused_*` modules implement one local fused
proof alongside a separately mandatory, genuinely verified B5CT native proof.
They have distinct nominal native/projection receipts, first-round identity,
linear B5SS/word challenge replay and proof transcript. B5CF uses fixed/main/
access-witness/interaction trace trees (five commitments including composition)
when ordinary access slots exist. Register-only ordinary geometry uses a real
projection proof with three trace trees/four commitments. Caller-only geometry
has the real B5CT native frame proof and typed projection/access absences;
there is no fused file, invented STARK, or fabricated zero receipt.

`Source.binding` identifies each component by its true original main offset
and independently pinned logical count. `Component` aliases old fixed active
views to the current appended committed-main selector; its old delegate sees
only the original native-main prefix. The authentic opcode fetch numerator or
clock enabler must equal that selector through an additional degree-one AIR
equation. Existing tuple signs, access ordinals, program/table/state/register/
clock projections, packed/universal memory equations and byte requests are
preserved. The base B5CT proof supplies prefix boolean/order/count authority;
the fused proof supplies this same-root selector link and its original buses.
There is one union main-opening owner, with selector openings and no duplicated
count ownership. Capacity fixed placeholders are not activity authority.

Production API:

- `Stage.ForBackend.collect(a, owner, capacity_proposal, frame, counters, limits)`
  constructs actual ordinary witnesses, commits their physical root and merges
  exact byte counters transactionally. It retains small owned slot/root/census/
  digest proposals, with late binding through `Proposal.memoryEntry` and
  `Proposal.projectionEntry` using the genuine capacity proposal/context.
- `Stage.produce(a, capacity_first_round, sealed, pins, entries, catalog)` borrows
  the real immutable fixed/main tree owners, reconstructs/recommits the access
  witness and checks the collection snapshot. Native ownership remains live
  for its own subsequent proof. `Sink.put_fused` consumes the fused proof only
  on successful publication. `requireFinished` checks exact execution order.
- `Receiver.verifyOwned` consumes a genuine `Capacity.Proof` and an optional
  B5CF proof on every path. It freshly verifies B5CT first. The private hook
  `verifyAfterFreshNative` accepts the distinct just-verified capacity receipt
  and still freshly verifies B5CF. Independent shape/public/frame/template/
  catalog/source-seal/mode/access-root/event pins reconstruct both schedules.
- `Artifact.Policy.expected` re-admits independent source authority. `Codec`
  uses separate `B5CFART1` grammar, exact row/capacity identities, native/fused
  IDs, B5SS digest and word ABI. Both claim arrays and four/five-tree postcard
  shape are bounded and canonical before received sequence allocation.
- `Store` uses `block-v5-native-capacity-fused-{index}.proof` and separate
  `B5CFFLS1` manifest. Shared `block_v5_artifact_files_v1` supplies exclusive,
  synced publication and pinned bounded reads. Source policies are immutable
  borrowed authority for the store lifetime; slots, manifests, decoded claims
  and proofs have explicit owned teardown. `take` is structural only;
  `verifyOwned` performs both fresh typed verifications.

Qualification root:
`src/frontends/riscv/block_v5_native_capacity_fused_unit_test_root.zig`.
Safe filter: `capacity fused`. Seventeen authored checks cover mixed-log source/
ordinal/mask/resource parity, original point/domain equations at nonzero points,
all native recipe activity linearity (including x0 envelopes), every source/
mask and codec/store-initialization allocation failure, frame/root/count/mode/
seal/protocol swaps, genuine typed absence, separately owned literal envelopes,
exclusive file publication/one-shot loads, and retained actual producer/fresh
receiver/stage/store function bodies. Fixtures execute field/FFT algebra,
literal postcard serialization and bounded file I/O only; they never invoke
the retained proof, stage or verifier bodies.

Remaining integration and qualification: root's versioned capacity program
loop and final global private joins must consume the distinct capacity/fused
receipts; driver, detached policy/loader and recursive capacity path must select
this version coherently before canonical activation. GPU executable export for
the new selector-link component needs its own typed capability. No old default
driver/global/transport activation was changed by this batch. A genuinely fresh
capacity plus fused proof and complete-bus gate are still required. This source
implementation alone does not complete capacity-template performance work.

Revision 2 source correction: the first safe compiler attempt exited 1 before
any tests executed (native-capacity-fused-unit-v1.log). Policy.expected now uses
a nonshadowing derived local; receipt accumulation iterates the mutable optional
range allocation only when present, preserving genuine zero-memory absence.
The original failed source hashes are retained in native-capacity-fused-source-
original-v1.json; the current manifest pins revision 2 and remains unqualified.
No compiler/test/proof job was launched by the source owner for this revision.

Revision 3 corrects the real shared runtime allocation failure observed in
native-capacity-fused-unit-v2.log: compilation passed and six test records
completed before the symbolic arena OOM abort. All four production runtime
scalar extraction factories now latch/propagate allocation failure; symbolic
column declaration checks it before node dereference/naming, and owned program
adapters check before copying or publishing the graph. Existing deferred arena
cleanup and symbolic.end run on every error. No equations or successful graph
order changed. New bounded tests retain the old successful extraction as a
parity oracle for every opcode family and inject every allocation failure into
direct/lookup/authority factories, including the failed-column ownership seam.
No failure indices are skipped. Revision 2 hashes and its failure result are
retained separately; revision 3 also pins the changed runtime/model sources and
the unchanged symbolic helper dependency. Root qualification remains pending.

Root revision3 qualification passes24/24 (17 named checks plus7 imports),
retained in `native-capacity-fused-qualified-v1.json` and
`native-capacity-fused-unit-v3.log`. All15 source and one symbolic dependency
pins matched. The shared extraction OOM fix preserves successful DAG/event
parity for every opcode family and rejects incomplete graphs with rollback.
Actual producer/receiver/stage/store bodies compile without proof invocation.
No PCS, STARK, FRI, guest, segment or device was executed. Native/fused fresh
proof, complete bundle and canonical driver activation remain unqualified.
