# Cost and ownership review of sealed MAIN spill

Read-only review of `39a17bcf5`/`77c6d5ac5`; no new storage mode is implemented.
Prefetch changes later access and cannot remove the synchronous stage-one copy,
flush and discard path. The current combined-source full A/B remains the next
measurement gate before choosing another implementation.

## What the current path does

`services/worker.zig:128` consumes owned MAIN/backings into the streaming PCS,
checks actual roots, then calls `Store.spill` before publishing a sealed worker.
`retained_main_store.zig:125` validates compact ownership and native views,
reserves backing storage, allocates one mapped arena, copies every native
coefficient, performs `msync(SYNC)` and then `madvise(DONTNEED)`. Only after all
fallible work succeeds does it replace both polynomial/column views, release the
old native owners and publish the teardown token. Original bytes remain owned
and retryable on pre-transfer failure. Parking changes mapping custody but still
streams the same bytes and synchronously syncs its unlinked file.

The underlying CPU PCS already transforms eligible owned source arenas in place
(`src/prover/pcs/commit_ops.zig:526` onward), retaining their complete backing
allocations only once after every bounded batch joins. Spill therefore adds a
second full native-coefficient copy after an otherwise reusable owner. The
existing `retained_column_allocator` is not a drop-in coefficient solution:
`commit_ops.zig:484` rejects it with coefficient retention enabled; its separate
LDE/column-storage role must not be confused with native compact storage.

The earlier LS7 A1 manifest receipt records 40,922,791,936 bytes of retained MAIN
backing across 30 workers and 11.211363 additive spill seconds. Its stage-one lanes
account for 5.630504 and 5.580859 spill seconds respectively. These are historical
measurements before the newly combined secp/boundary changes, not predictions
for that source. Additive stage time is not block wall time. Removing all spill
work has a first-order balanced-lane ceiling near 5.6s in this particular run,
subject to changed scheduling/contention; it is not an 11.2s wall-speedup claim.

## A bounded resident-first tranche

This is the smaller ownership change: keep an explicitly capped set of original
coefficient owners rather than copying them into files. Charge **actual retained
allocations**, including arena padding and any independent coefficients; logical
column cells alone are insufficient. Reserve the tranche before admission, with
no oversubscription exception. Hold the original allocator/budget lease and let
the ordinary PCS teardown free each native buffer exactly once. A separate
teardown lease releases only tranche accounting after native backing is freed;
`commitment_tree.zig:404` through444 defines that destruction order.

Select eligible ordinals deterministically from validated geometry/actual owner
sizes rather than whichever lane happens to finish first. Fall back atomically
to the existing spill path when the tranche cannot admit the complete owner.
Restore/prefetch must recognize resident custody explicitly: native resident
pages are already readable and should not be mislabeled as mapped file bytes or
passed through an unvalidated mapped-owner token. Failed/abandoned workers return
the same lease through the existing joined cleanup barrier.

A 4GiB tranche is only about 10.5% of the historical 40.9GB backing volume. Under a
uniform per-byte cost model that avoids roughly 1.18 additive spill seconds
(~0.6s on two balanced lanes), while retaining up to 4GiB of less-evictable native
memory. Whole-worker packing, allocator retention and nonuniform sync costs can
change that result. This is a bounded traffic/memory trade, not a plausible
standalone multiplier or a promised host-memory reduction. It should not be
built solely from an optimistic percentage of the 11s additive number.

## Direct file-backed native commitment

The larger change is to arrange final coefficient custody at the owned source/
PCS preparation boundary. Preserve the current in-place transform and complete
backing owner; replacing the global allocator would map scratch/LDE/metadata as
well and is the wrong abstraction. Merely copying each prepared batch to a file
sink still copies all native bytes. Out-of-place mapped FFTs can also introduce
extra copies or dirty-page writeback; they are not automatically less traffic.
A mapped source arena can avoid the post-commit copy, but writes during witness
construction/FFT and later reuse must be measured separately.

Ownership requirements are concrete: reserve disk capacity before writing,
transfer a move-only mapped owner on every success/error path, retain allocator
and FD/mapping leases, keep every compact view tied to the same final owner, and
publish no sealed receipt until all fallible owner publication is complete.
The complete manifest still precedes stage-two challenges. Neither file layout
nor host disk durability substitutes for root/shape validation, and late I/O
errors must stop production rather than manufacture missing coefficient data.
Scratch files are unlinked process-local custody, not crash-recoverable jobs.

Removing or deferring `SYNC` is a separate platform-semantics change. Do not
assume that keeping/discarding dirty mappings is equivalent on every supported
OS, and do not silently reuse a checkpoint durability contract for ephemeral
scratch. Qualify coherence, failure/cancellation and final unmap/close semantics
before implementing such a policy. This review does not authorize an unsafe
flush/discard substitution or background owner release.

## Decision gate

First use the combined queue/prefetch measurements. If spill remains material,
separate reserve/map, copy, sync and discard scopes before choosing a mode;
the existing aggregate stage cannot attribute its cost among them. Compare
additive work, critical-path time, actual allocation/mapping lifetimes and total
traffic together. Require exact roots/proofs/public requests, fresh verification,
OOM/FD refusal and partial-worker teardown parity for either implementation.
The device-resident path should keep native owners on the executing device under
an explicit whole-manifest retention budget rather than inherit this host-file
spill architecture by default.
