# Endpoint root: measured memory and next composition boundary

The canonical two-cohort, eight-instruction root is qualified. The saved4M
window's eight-local flat root failed before emitting a proof under its48GiB
budget. No complete266-cohort root currently exists.

## Exact4M retained representation

The cold-key census predicts exactly the failed live retained count:
26,422,967,500bytes. It requires no native witness reconstruction or parent
MAIN allocation. See `native-4194304-local-compact-8x524288-memory-census/`.

| Storage | Bytes |
|---|---:|
| Dense padded MAIN, already M31 |21,703,901,184|
| Joined compact M31 fixed rows |4,719,039,636|
| Child cold fixed duplicates |4,718,848,340|
| Aggregate cold fixed duplicate |4,719,039,636|
| Closure cold fixed duplicate |191,296|
| Four G-shard MAIN matrices |19,260,243,968|
| Padding within those G matrices |7,521,034,752|
| Byte-route fixed metadata |1,463,110,200|

The26.42GB live count includes its MAIN/fixed rows and small column headers;
it excludes the additional cold copies. A universal QM31-to-M31 conversion
cannot save4x here: storage already uses native4-byte M31 cells. QM31 graph
evaluations are transient and released by `finishReleasingRows` before joining.

The failed cold stages were53.168s fixed compilation,36.373s fixed commitment,
115.849s source witness construction,12.196s plan admission. Source witnesses
were built serially. The attempt also overlapped an unrelated Python process;
its timings are not an isolated performance result.

V2 implements cold compiler-state release after exact fixed/live comparison and
Plan retained-key admission. It drops child/aggregate/closure fixed rows,
namespace maps and compiler graphs while preserving public operands/wires.
Plan retains counts/digests and the independently committed tree, not full
fixed-row copies. Expected fixed-copy release:9,438,079,272bytes plus metadata.

V2 also implements bounded source preparation batches (explicit1/2/4 workers).
Each job owns recorder TLS, a serial private pool and its preparation budget.
Profiles/captures remain immutable and live until every job joins. Transfers,
namespaces and concatenation follow source index, not completion order. Failure
joins every job and frees all completed results before returning. The q70tiny
fixture passes exact serial root SHA parity and a mixed-success/failure job test.

Further candidates require separately qualified layout/storage rules:

* Rebalance the identical G AIRs globally, instead of rounding each concatenated
  shard10M->16M. The current domains16M/16M/16M/8M could become16M/8M/8M/4M,
  saving roughly6.88GB padded MAIN. Cold/live repartition must share the same
  independently reconstructed rule; received geometry cannot silently change.
* Typed byte/bit/halfword column sources may compress specific G/route columns,
  provided exact range contracts are checked and PCS/interaction consumers read
  the same canonical values. General arithmetic columns require full M31.
* Streaming source-to-final-column emission avoids retaining all child padded
  columns, but every fixed and wire namespace must be known/admitted first.

##266cohorts: actual hierarchy, not a larger flat roster

The present Source union supports local/bridge/compact-global originals only;
its bounded flat roster supports at most62 local cohorts plus two providers.
It must not be advertised as closing266cohorts.

1. Prove conditional local-group roots, for example17 groups of at most16
   consecutive cohorts. Each verifies complete Local11 bodies, native/halt,
   ROM/lookups/range closure and internal CPU adjacency. Global RAM stays OPEN.
   Export exact coverage, first/final CPU boundaries and an authenticated ordered
   endpoint-root roster. Never add local transition sums drawn under different
   local epochs as though they were one global relation.
2. Derive ONE late epoch from all266 endpoint-root identities and the independently
   admitted compact-global first commitments. Reopen the same23-column endpoint
   roots in3 bridge batches127/127/12. Each batch preserves the full266-source
   epoch/roster, even though it opens only its slice.
3. A final root verifies the17 actual group-parent STARK bodies, the3 bridge
   original bodies and one compact-global body:21 child verifier machines.
   It proves ordered complete coverage, CPU/group adjacency, exact endpoint-root
   rebinding, common ELF/program/security/epoch and transition-sum closure.
   Compact global separately closes initial/final/ranges/counts against externally
   pinned complete snapshots. Intermediate complete RAM snapshots are absent.

The missing implementation is an actual parent-group source adapter: independently
rebuild its canonical fixed geometry/key from the admitted group rule and local
metadata, replay its own parent protocol exactly, and prove its complete typed
AIR/public-supply/PCS/transcript equations in the top DAG. The source union has no
such adapter yet. A host `Verified`, key hash or summary is not an authority.
Any reusable cached group key must be independently authorized by the exact
structural compiler/rule, not accepted from a producer proof envelope.

## Structural key versus request data

Original source fixed roots already enter the joined verifier as public root
ports, with keys independently rebuilt from metadata. However current profile
seals/context IDs include request epoch/root identities, and protocol key roster
digests include all request operands. Closure circuits also bake values such as
endpoint/fetch census, source ordinal and ELF halt policy into constants.

A reusable canonical parent plan needs two identities:

* Structural identity: exact kernel authorities, component order, source family,
  all column/mask/log/FRI geometry, public-wire schedule, transcript operation
  grammar/capacity, partition rule and security parameters.
* Request identity: independently admitted original fixed roots, epochs, CPU
  boundaries, policies, roots and physical claims, authenticated by public
  transcript/recursion-wire supply under that structural plan.

Move policy/census constants to authenticated public operands, preserving their
binding to independently reconstructed ELF/window metadata. Then cache fixed
rows and the actual fixed commitment by structural identity; a request may still
have a distinct protocol/public-input digest. A cache hit must prove exact
structural compatibility, not simply trust a supplied root/key label. Report
cold compile/commit separately from warm emission/proving and receiver setup.

## V2 failure and V3 qualified storage rule

V2 released9,442,205,512bytes of cold compiler state and reduced source witness
construction115.849s->99.925s with two independent jobs. It still failed during
parent proving under the same48GiB cap (OS peak footprint44.333GB); no4M root
was emitted. A2s authorized sample makes these timings diagnostic.

The sample identified `stark_paths.Builder.opening` / Merkle-frame construction,
with many small frame-route allocations through `std.testing.allocator`'s
DebugAllocator (ten stack frames per allocation). Active samples included
`collectStackTrace -> MemoryAccessor -> __msync`; the second job often waited on
allocator locks. Native hash column writing was also substantial. Test fixtures
retain their testing allocator; the V3 production benchmark uses the SAME
bounded SharedHostBudget backed by `std.heap.smp_allocator`, records that choice,
and makes no claim that removing debug instrumentation is a pure AIR speedup.

V3's explicit globalG rule has passed cell/fixed/order/padding and allocation
failure tests, plus an actual q70two-cohort root/fresh receiver gate. It changes
only physical grouping among the identical G AIRs, keeps all wire/circuit IDs,
and binds the independently reconstructed partition plan into the root context.
Legacy/default layout remains available with its exact original proof SHA.

For the measured4Mfull-ROM shape the canonical counts reduce G padded rows
56Mi->36Mi, MAIN padding7,521,034,752->642,376,192bytes. MAIN decreases by
6,878,658,560bytes; logical LDE cells decrease by twice that at blowup2. Those
are exact layout counts, not a measured physical allocation saving. Live
relocation precomputes one144MB permutation and drains one physical column at a
time, so it never needs a second full12.38GB G MAIN matrix concurrently.

Sparse local ROM is supported by replaying the same canonical6-fixed-column
program AIR at the actual admitted dispatch log, not the legacy full-image log.
Root keys remain rebuilt from the externally pinned ELF and metadata. No4M
root result is implied by these smaller qualification gates.
