# V3 bulk services: authenticated GKR foundation

Foundation snapshot: the nine bulk-memory/JUMPDEST components at PR308 snapshot
`2490495dd16a35a2961cd113870a0a490ff36018`. This is a qualified component
foundation, **not production v3 GKR admission**. `v2_scope.zig`, CPU roster
admission and the retention planner continue to reject v3 requests.

## One tuple authority

`bulk_memory/equations.zig:emitQueries` emits the original ordered raw
RAM14, OWNER19 and U16 tuples and weights. The classic fraction evaluator
compresses that emitter; the local GKR projection selects OWNER/U16, and
the global projection selects RAM. Zero-weight and padded queries remain.
No compressed denominator is substituted for authenticated MAIN expressions.

Before the refactor, nine classic QM31 fraction digests were recorded and are
pinned in the bulk AIR suite. Full OM31 challenge-law tests preserve those
digests and verify both independent QM31 halves. Additional tests compare
local numerator/denominator marginals and every global RAM fraction to that
classic authority, including padding. Counts are generated from the emitter,
not repeated manually in a schema.

`bulk_role.zig` joins original MAIN constraints, sixteen local Eq/prefix
binding columns, and the global RAM inverse/prefix columns in one physical
role. It reuses the existing packed domain, OODS, mask and geometry adapters.
It does not copy MAIN or introduce a proof per bulk component. The intended
production integration is the existing single CPU proof and batched local
child. Degree-three and globally lifted-mask conventions remain unchanged.
JUMPDEST scan is the largest global adapter: eighteen RAM queries, nine
paired inverses and one prefix, or eighty global columns; with local binding
its interaction width is ninety-six. The local term cap remains 128.

## Custody and worker boundary

Stage one must seal the physical MAIN root before drawing local challenges.
The verified local child still returns pending terminal marginals. Eta is
drawn after those marginals; physical Eq/prefix constraints authenticate them.
A local child alone never accepts an execution.

The native local provider reconstructs rows from call/word/index metadata.
After the child and durable binding exist, `bulk_metadata.retireLocal` removes
MAIN, fixed columns, range histograms and table multiplicities. Calls, word
predecessors, index maps and JUMPDEST pending counters survive whenever the
role owes RAM. Table-only roles can retire all of that metadata. Retirement
is idempotent; source destruction remains safe. Subsequent local replay
returns `LocalGkrMetadataRetired` rather than indexing released fixed data.

Global metadata generation uses no retained fixed columns or MAIN: it
reconstructs the exact RAM tuples from durable metadata and the shared
manifest challenge. The physical set fixture retires these wide buffers,
then generates a **nonzero** RAM claim and proves/ freshly verifies it against
the authenticated MAIN root. This does not close the RAM claim; the aggregate
execution must still close every physical participant against INIT/TEARDOWN.
The CPU worker retirement/destruction hooks know how to preserve and release
these bulk obligations, but production worker admission is intentionally shut.

`retainedBytes` records exact retained payload bytes for existing sources.
It is not a request-derived admission upper bound, RSS, or a reason to open
production admission. The latter is still a required integration gate.

## Receiver framing

Origin tags are stable pairs: core `(0,role)`, bridge `(1,family)`, bulk
`(2,kind)`. Existing v2 child transcript and receipt bytes remain unchanged.
A roster containing bulk or a new v3 bridge selects a distinct child domain
and canonical receipt domain. Its child wire magic is `RV64LGK3`, selected
from the receiver's roster; it is not a producer-selected downgrade flag.
V2 stays `RV64LGKO`. The codec rejects cross-profile replay before decoding.

Framing tests freshly verify a synthetic balanced child and reject altered
role, height, term count, fixed offset, MAIN offset and instance order. These
synthetic rows test framing only; they do not constitute an admitted roster.
The physical bulk fixture separately tests MAIN, target, Eq, prefix and
published global-claim tampering. A full v3 execution identity and receiver
are still pending; this child frame does not substitute for them.

## Gates before v3 promotion

1. Add the bulk roster, physical component dispatch and complete worker plan
   through the services coordinator, with exact request/shape matching and
   request-derived retention/task admission. Preserve failure-atomic custody.
2. Qualify the two-shard bulk/LS fixture with cross-epoch memory closure and
   balanced corruption tests, including all descriptor/body/JUMPDEST joins.
3. Extend the source-support analysis. OWNER19 now mixes unit consistency
   with weighted JUMPDEST transition-table membership. The latter is **not**
   ordinary signed unit mass. Establish disjoint slot-zero tags (trusted CPU
   opcodes versus fixed bulk tokens), Boolean consumer weights, fixed table
   support, consumer mass below M31 characteristic and all padded denominator
   slots. `source_bounds` must explicitly model that partition before use.
4. Recompute shape, global mass, algebraic and transcript budgets for the
   admitted v3 roster. The reviewed v2 security envelope excludes this work.
5. Integrate the other v3 bridges/truths, sponge, LS-D64, U8 pairs and
   throughput Keccak; give each physical/receiver/closure tests. The benchmark
   block alone cannot qualify curve families it does not call.
6. Run a complete v3 OM/GKR block under the documented 128-bit target profile
   and a fresh complete receiver. Retain classic QM31/q70/P26 as a distinct
   benchmark control. No v3 128-bit or recursion claim is made here.

PR308 subsequently advanced to `10c6a084a1af3692077f1081f7c7892250defc30`
(secp row truth, planning and EEST updates). That delta was fetched separately;
this foundation's receipts stay pinned to the earlier integrated snapshot.

## Worker-gate completion

The follow-on [bounded review](rv64-bulk-weighted-owner-review.md) records the
complete bulk-only worker plan, fresh transport receiver, cross-shard closure,
request-derived retention bounds and weighted JUMPDEST support partition.
Those gates supersede items1–3 above for the bulk extension. The full Ethereum
v3 route, other service adapters, and full-v3 security-budget/benchmark gates
remain separate; their production admission is still closed.
