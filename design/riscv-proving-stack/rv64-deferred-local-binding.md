# Optional projected local binding retention

Status: software/lifetime/physical-fixture and complete K18 control qualification.
K16 checkpoint and candidate-profile complete-block runs also pass independent fresh
verification and exact same-profile/geometry artifact comparisons. Resource option `defer_local_binding` defaults
false and is omitted from default resource JSON. Candidate operational resources
forward the same flag. It does not select a proof or security construction.

## Exact lifecycle and transcript authority

The local numerical child already produces proof, artifact, canonical receipt
digest and eta before constructing its binding. Stage one exports only MAIN and
the numerical child. It needs no committed Eq/prefix columns at that barrier.
Retaining all original local metadata for a later replay would preserve5.838GB
of CPU metadata alone (56bytes *104,253,913 retirements), plus ALU54/BINARY46/
SHIFT30-byte padded-row caches, arithmetic metadata, count ledgers and owned
fixed buffers. The existing narrow global metadata would not suffice. That
larger dependency-preserving design is not implemented here.

Instead, stage one uses the ORIGINAL provider and prepared projection authority
to construct just P(row)=N(row)+eta*D(row), including unused fact-lane weights.
It retains8 column-major M31 planes per physical row, all8 OM31 coordinates.
No Eq is generated, no prefix is generated, and no provider/source pointer is
retained in this object. Original local source metadata is retired on exactly
the existing schedule. The child owns the original proof/artifact, receipt and
eta until final binding and verification obligations close.

Stage two first checks the complete manifest, statement and physical MAIN/FIXED
roots. It reconstructs Eq from the SAME artifact row-point suffix, multiplies
by immutable P, subtracts the SAME terminal target/row count, and constructs the
SAME logical cyclic prefix into a newly allocated16-plane witness. It does not
re-expand MAIN, reconstruct N/D planes, rerun the guest or replay tuple metadata.
The physical AIR still recomputes N/D from authenticated original MAIN, so an
uncommitted projected cache alone never establishes lookup validity.

Every finalization allocation and validation precedes releasing the old projected
owner. Failure leaves projection, reservation and artifact intact and retryable.
Success swaps once, releases the old32-byte/row reservation, and retains the
new64-byte/row reservation until ordinary INTER ownership transfer. Both transfer
APIs reject a pending projection under ReleaseFast. Deinit handles projected-only
abort and completed ownership. No allocation/budget failure changes the policy.

## Explicit admission and observations

The physical INTER width remains64bytes/row. Barrier retained binding payload
becomes32bytes/row. Finalization owns old32 +new64 =96bytes/row, plus both slice
header arrays simultaneously. The optional hard numerical plan conservatively
adds32bytes/row and a second header array to the complete existing peak, covering
that overlap plus the original metadata/scratch allowance. Selected policy and
configured GKR cap are preserved; exceeding the adjusted cap fails admission.

Retention replaces64 by32 only in pending inventory, keeps MAIN/global obligations,
and charges stage-two resident32 plus new64, global output and scratch. Host
requested allocation bounds remain distinct from RSS, recycler cache, allocator
rounding, setup, capture, PCS, stacks and kernel memory. The full-block binding
payload projection13.086GB ->6.543GB is deterministic layout arithmetic, not a
measured process-memory claim or a throughput improvement.

Reports expose actual retained local binding/projection bytes, final binding bytes,
the96-byte/row overlap including headers, admission/hard-cap values and cumulative
GKR requested peak through completion. Truths have no CPU projection values.
Native profile stage `binding_finalize` records the deferred Eq/prefix work
separately before `interaction_generation`; stage-two native completion includes
this work. Moving work out of stage-one binding time is not an algorithm speedup.

## Qualification

Core helper289ee4aef reuses the original tuple/padding/projection authority and
checks every projection shape/point before finalization allocation. Mixed-height,
padded-lane and all-coordinate reference, immutable source/provider failure and
allocation-failure tests pass Safe/Fast. Lifecycle qualification additionally checks:

- Same child proof, artifact/receipt and final binding values as immediate binding.
- Finalization OOM retry, unchanged pending owners/reservations, malformed shape,
  and ReleaseFast pending-transfer refusal; every lifecycle allocation failure.
- Real CPU Keccak proofs with beta1 and beta2 independent fixed authority: exact
  physical proof bytes before/after original metadata retirement and complete
  MAIN coefficient/Merkle parking/restoration, with fresh receivers.
- Projected-only parked abort and later-worker OOM teardown.
- Complete two-CPU plus Keccak/ADD/DOUBLE execution under two2-worker lanes:
  all physical proof bytes/claims and stage-one bytes exact, independent fresh
  complete receiver accepted, actual retained bytes halved and admission/peak
  counters checked. A deliberately interleaved stage-two order is retained.

Whole128 construction and GPU execution remain independently unqualified. The
complete-block benchmark and fresh receiver under both control/candidate profiles
are still required before promoting this optional operational mode.

## First complete-block measurement

The frozen final CLI (`f35c350d3`, SHA256
`02195aee6a1c9fea3deef751bf4088189dcb28b107c6c4d19d7af6c9df406c53`)
proves the entire pinned block under q70/P26, streamed dense-upper K18 and the
same2x8 schedule/resources with only the deferred flag enabled. All33 durable
artifacts match immediate binding; a fresh complete receiver accepts.

| K18 storage | Proving | Wall | Peak RSS |
| --- | ---: | ---: | ---: |
| Earlier immediate binding |231.55s|250.25s|38.07GB|
| Deferred projection |227.20s|245.92s|38.03GB|

These are individual observations using different frozen binaries of equivalent
physical protocol, not repeated same-binary causal latency evidence. Projection
retention across all25 CPUs is6,542,893,520 bytes including headers, against
13,085,779,408 final binding bytes including headers. Every completed child stays
within its exact admitted requested-byte limit and clears its pending flag.

**There is no meaningful whole-process RSS reduction in this K18 observation.**
The maximum recorded process peak occurs in physical worker25, a Keccak truth
proof, in both runs. Those counters cover concurrent whole-process activity;
they are not isolated component allocation costs. Halving barrier storage does
not remove the widest service-proof allocation regime. Smaller independently
sized truth instances must be measured before a whole-prover memory claim.

Receipt: `vectors/reports/rv64-deferred-local-binding-20261102/fullblock-deferred80-k18-v1/`.
The balanced-cache adversarial physical proof separately reaches a fresh receiver
and fails `OodsNotMatching` under both Safe/Fast, even though its modified
projection preserves the exact weighted sum and final prefix. Its numerical
closure is deliberately valid; the original authenticated MAIN remains authority.

## Complete K16 and candidate measurements

| Profile / geometry | Immediate binding proving / RSS | Deferred projection proving / RSS | Exact artifacts / fresh acceptance |
| --- | ---: | ---: | --- |
| q70 checkpoint68 K16 |254.66s /30.17GB|238.91s /26.79GB|39 /yes|
| beta2 source80 K18 |303.92s /39.95GB|305.85s /39.96GB|33 /yes|

The K16 observation reduces RSS by3.38GB (11.2%) compared with its earlier
checkpointed reference. Relative to the older tight-dense K18 control's42.49GB,
the combined smaller-instance/stream/checkpoint/deferred policy uses1.59x less
peak memory, with238.91s versus242.44s proving. That cumulative comparison changes
geometry and storage together and adds six service proofs; it is not an isolated
GKR or deferral speedup. K16 total proof bytes remain43.44MB versus27.07MB atK18.

The candidate K18 pair shows no time or RSS improvement. The option therefore
remains defaultfalse. Select the profile, service geometry and retention policy
from complete latency/memory/proof/receiver measurements, rather than assuming
that a smaller retained payload improves every workload's process peak.

Full receipts under `vectors/reports/rv64-deferred-local-binding-20261102/` record
actual96-byte overlap, all completed children under their admitted hard caps,
profile, frozen binary, resources, process usage and every authoritative hash.
Whole128 and accepting OM/GKR recursion remain independently unqualified.

## Schedule observation and independent ISA qualification

The same frozen CLI, K18 geometry, resource caps and deferred mode ran under
three6-worker lanes. All33 artifacts match two8-worker lanes and the fresh
complete receiver accepts. Three lanes measured230.39s proving (92.19s stage
one,138.01s stage two), versus227.20s (89.66s,137.36s) with two lanes. Peak RSS
was37.92GB versus38.03GB. One pair establishes no schedule speedup; the existing
2x8 selection remains. It does not justify a larger-memory-cap production policy.

The optional producer flag is also exposed by the existing pinned OM Sail
qualification adapter, without changing its independently expected image or
receiver. Both profiles compare every one of1,032,240 retirements across12,903
cases/all63 ordinary opcodes before advice construction. All four authoritative
artifacts are byte-identical to the already accepted streamed80 Sail runs.
Fresh receivers accept and wrong endpoints/cross-profile reception reject.
Control proving is2.829s and candidate3.654s in single functional observations,
not a causal performance A/B. See `vectors/reports/rv64-deferred-sail-20261102/`.
Previously Rust-replayed numerical contexts retain identical child proof bytes;
no new Rust physical PCS/whole-execution qualification is implied.

## K17 geometry midpoint

An explicit K17/source80/deferred run proves the full pinned block in225.72s
(244.08s process wall), with35.35GB peak RSS and32,559,576 physical proof bytes.
An independent complete receiver accepts all25 CPU and7 truth proofs. The four
Keccak truth intervals are1..9038,9039..18076,18077..27114,27115..32835. Public
RAM cell bytes and expected output match K18. Shared challenges and proof
inventory legitimately change with geometry; cross-geometry proof-byte parity
is neither expected nor claimed.

| Qualified control policy | Proving | RSS | Physical proof bytes |
| --- | ---: | ---: | ---: |
| K18/source80/deferred |227.20s|38.03GB|27.07MB|
| K17/source80/deferred |225.72s|35.35GB|32.56MB|
| K16/checkpoint68/deferred |238.91s|26.79GB|43.44MB|

Each row is a single complete-block observation, rather than an isolated
repeated comparison. K17 offers an intermediate memory/proof-volume choice.
Keep geometry explicit, preserve independent receiver authority, and include
the added proof-opening/recursion cost when selecting a production instance
class. No automatic geometry/default-policy promotion is made here.

Evidence: `vectors/reports/rv64-deferred-local-binding-20261102/fullblock-deferred80-k17-v1/`.
