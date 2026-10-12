# Metal FRI ownership under the shared host/external budget

The budgeted ownership scope passes 16 device-free fixtures; actual Metal
allocation/conversion/fold/cascade/fused-quotient/drain/teardown bodies compile
to an object, and the actual Objective-C runtime passes syntax checking. No
device, STARK, execution segment, or benchmark has been run for this revision. Proof
encodings, FRI equations, transcript framing, and CPU verification are unchanged.
The subsequent ordinary-allocator compatibility revision now passes 23 focused
device-free fixtures and actual strict/ordinary production body compilation,
including backend shutdown. This does not qualify an executed Metal proof.
The immutable inverse-lease revision passed 11 new fixtures and the 23 existing
ownership checks, plus actual production body compilation. Its subsequent
multi-geometry LRU revision passes18 lease/LRU fixtures and23 ownership regressions plus actual production body compilation; each
receipt describes its own frozen source snapshot.

The canonical allocator-bearing Metal FRI path requires the same
`SharedHostBudget` allocator as the producer. Its cap covers logical owned heap
bytes plus explicitly reserved Metal buffer bytes. It does not measure or cap
whole-process RSS, stack memory, Metal framework overhead, or physical allocation
rounding.

| Factory/path | Charge and durable owner | Release boundary |
| --- | --- | --- |
| Secure column, line evaluation, coordinate conversion | Exact `count * 16` reservation in a local owner context; the resident handle remains the actual MTLBuffer | Device buffer, context heap, then reservation |
| Circle and line inverse generation | Bounded immutable entries per runtime/budget; exact public-domain key, pole admission, old/new overlap reserved before allocation | Checked completion precedes publication; failed/cancelled proposals are destroyed; active reader entries cannot be evicted |
| FRI cascade, including fused opening-quotient → FRI | Padded transcript/hash arena charged once through explicit shared references; temporary folded outputs and seed buffers reserved until joined | Each tree releases its reference; the final reference destroys the heap control before the last budget lease |
| Separate fold-and-commit transaction | Exact hash layers plus inverse/alpha/seed/intermediate buffers | Joined result retains only tree-layer bytes |
| Enclosing FRI prover/cascade result | Temporary allocator lease acquired before any resident token is dropped | Outer heap arrays and terminal polynomial are freed before the temporary lease |

`MetalCommitBackend.allocateSecureColumnWithAllocator`,
`allocateLineEvaluationWithAllocator`, and `secureColumnFromLineWithAllocator`
are the canonical factories. Generic FRI call sites prefer these explicit
capabilities. Canonical circle/line folds use resident inverse buffers, including
small admitted cascades; they do not silently prepare a host inverse table.

The source now bounds the actual inverse cache to four runtime/budget slots,
eight immutable entries and sixteen concurrent transactions per slot. Completed
geometries share an exact least-recently-used order across circle and line kinds.
A hit refreshes that order; idle old geometries remain reusable instead of being
removed whenever proof heights alternate. A request cannot borrow another budget
or runtime. The
key binds kind, count, layer count, initial point and step. Public circle/line
domains are checked analytically for active poles before GPU inverse allocation.

Bank and entry locks protect only slot admission, reader counts and publication.
They are released before resource factories, dispatch and checked completion, so
multiple same-budget proofs can borrow an admitted inverse concurrently. Misses
are private and charge old/new overlap before allocation. Only successful checked
completion can publish them. Racing exact-key proposals are deduplicated after
completion; a full set of leased entries keeps the checked proposal private and
releases it instead of evicting a live reader. Failed/cancelled work destroys its
private proposals and preserves all non-evicted admitted entries. This removes the prior completion-held global lock in
source; it does not qualify actual parallel GPU execution or a speedup.

Idle inverse bytes per bank are limited to `min(256 MiB, owner.limit / 8)`.
Four banks together therefore retain at most 1 GiB and at most half the same
owner's cap as idle inverses. The ceiling admits a roughly 128 MiB log-25 fused
circle/line pair and a roughly 256 MiB log-26 pair when the owner-relative bound
also permits them. Publication and the last-reader release evict the least
recently used idle entries until that byte bound is met. Active readers are
excluded from idle eviction but remain fully charged to the same combined cap.
An individual inverse larger than the idle bound may still prove successfully;
it stays private and is released at completion rather than cached.

Before a miss reserves bytes, known capacity pressure can reclaim idle entries.
The shared synchronized reservation remains authoritative, including races with
other allocations. If admission still fails, eligible idle entries are evicted
and admission retried; live entries and private proposals are never reclaimed.
These pressure evictions are permanent even if the subsequent factory fails or
work is cancelled. There is no promise to restore evicted resources or retain
every geometry. Existing active old/new overlap is charged before allocation,
and oversized requests never evict idle entries when they cannot fit the owner
cap at all. Idle bounds leave substantial room for other proving allocations,
but callers needing the entire cap must drain caches after joining users; this
is not a whole-process RSS guarantee.

Historical general Metal APIs accept ordinary caller allocators such as
`c_allocator` and testing allocators. Their policy is explicitly uncapped:
owned contexts bind the original allocator and exact extent, and inverse buffers
are temporary for each dispatch, released after checked completion. They never
enter the persistent shared-budget cache. A supplied `SharedHostBudget` always
selects strict same-owner charging, even when the general API requests ordinary
compatibility. Canonical RAM/block entrypoints require the shared allocator
before resident work and cannot use compatibility to bypass their cap. Neither
proof outputs nor existing source arrays are moved to an allocator wrapper.
Allocator-less legacy column factories now use explicit uncapped page-allocator
contexts. Their owned sources can be borrowed only by the uncapped route; strict
requests reject their uncharged ownership.
Ordinary direct FRI calls with host coordinate columns use explicitly uncapped
resident ingress: four coordinate copies into an owned Metal buffer, followed by
the same checked GPU fold. The original source stays borrowed and unchanged.
This path performs no CPU inverse, transform, AIR, or proof computation and is
rejected for shared-budget canonical requests requiring resident source owners.

Producer teardown can call `MetalCommitBackend.drainBudgetedFriCaches(a)` after
all FRI work is joined and before releasing the shared runtime. Both producer and
shutdown drains return `RuntimeBusy` if a factory, reader or private proposal is
active; they do not wait or release a partially drained active bank. Each buffer
is destroyed before its reservation. Reader transactions and bank slots retain
the budget if its original owner was released, and each slot retains a runtime
resource lease even during cold factory work.
Outstanding cache buffers retain the shared runtime's resident-resource count,
so runtime shutdown rejects incomplete teardown rather than discarding them.
Actual backend shutdown now calls `drainAllForShutdown` before pooled scratch
and runtime teardown. That boundary uses `tryLock` and returns `RuntimeBusy`
rather than deadlocking if its caller holds a pending transaction. The slot's retained budget lease
survives destruction of the cache's last token. Root owns shutdown
and any producer-level drain integration.

Consuming owners expose explicit `take`, `retain`, completion, and destruction
operations. Raw struct copying does not acquire a lease and is outside their
contract; Zig does not enforce move-only types. The old raw C inverse-cache
entrypoints remain separate diagnostics. They are
not an uncharged fallback for canonical allocator-bearing calls.

The device-free fixture root is `src/metal_fri_budget_test_root.zig`, filtered by
`FRI budget:`. It covers exact framing/geometry, cache hits and contention,
replacement overlap, allocation/factory failure, checked completion failure,
cancel/drain, foreign allocator/runtime rejection, active poles, explicit moves,
and release after the original budget owner. Its enclosing-prover teardown test
uses the real `FRIProver.deinit` with a device-free local tree destructor.
`src/metal_fri_budget_codegen.zig` retains actual production factory, fold,
cascade, fused quotient/FRI, drain, and teardown bodies in an object without
executing them.

The subsequent [quotient allocation batch](metal-quotient-allocation-budget-v1.md)
charges the opening-quotient hash arena, numerator/domain scratch and private
quotient metadata buffers at their actual constructors, including the fused
path. Generic copied Merkle/FFT staging and plan metadata, sampled
OODS/barycentric scratch and decommitment readback remain outside these batches. Existing no-copy host
aliases are already heap-charged and must not receive a second external charge.
Those broader ownership migrations remain explicit follow-up work; this source
batch does not claim that every Metal allocation or a complete GPU proof is
covered or executed.

The source snapshot and logs are retained in
`autoresearch/notes/2026-09-24-ethereum-block-delivery/cpu-performance-gates-v1/metal-fri-shared-budget-qualified-source-v1.json`.
That snapshot qualifies the strict budgeted path, not the subsequent compatibility
revision. The current source includes explicit allocator policy, ephemeral
ordinary inverses, allocator-bound contexts, and actual shutdown drain. Its
device-free root now also covers policy normalization, original source/output
ownership, foreign allocator/extent rejection, and transient failure/cancel.
The root now passes 23 device-free fixtures, with actual ordinary/strict production
bodies compiled. The snapshot is `metal-fri-ordinary-compatibility-qualified-source-v2.json`
in the same evidence directory. A factory-failure test exposed partial optional
owner publication; construction now succeeds before publication, so rollback
never visits an uninitialized resource. The related cache and fused-owner
publication paths were repaired together. No general Metal proof was executed.


The new source-only concurrency root is
`src/metal_fri_inverse_lease_test_root.zig`, filtered by `FRI leases:`. It adds
same-buffer concurrent checked-completion coverage, busy drain, immutable old
readers during replacement, private proposal deduplication, factory/status
failure, cancellation, moves, exact overlap caps, bounded users/full entry sets,
and original-owner release. The existing production body root continues to
retain real fold, cascade, fused quotient, drain and shutdown implementations.
Those 11 lease fixtures passed on their frozen revision. The explicit uncapped route keeps
its per-dispatch ephemeral inverse ownership and does not use this cache.

The immutable inverse revision passes 11 new lease/concurrency fixtures and 23 existing ownership checks, with actual production bank/fold/cascade/fused/shutdown bodies compiled. Source hashes and logs are `metal-fri-inverse-leases-qualified-source-v1.json` in the same evidence directory. No GPU, STARK, guest or segment ran.


The source-only LRU additions in the same root are filtered by `FRI LRU:` (7
fixtures). They cover alternating paired geometries, exact LRU eviction, charged
working-memory pressure, failure after an explicitly permanent eviction,
concurrent-reader immutability during pressure publication, uncached oversized
inverses, and mathematical log-25/log-26 pair bounds without allocating large
buffers. The existing lease/ownership fixtures were adjusted only for the new
idle limit and intentional multi-geometry retention. These LRU changes pass18 lease/LRU checks and23 ownership regressions; actual production fold/cascade/fused/shutdown bodies compile without invocation. Receipt: `metal-fri-inverse-lru-qualified-v1.json`. No device execution or speedup is claimed.
