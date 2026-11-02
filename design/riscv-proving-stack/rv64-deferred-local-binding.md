# Optional projected local binding retention

Status: software/lifetime/physical-fixture qualification; complete-block RSS and
latency qualification pending. Resource option `defer_local_binding` defaults
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
