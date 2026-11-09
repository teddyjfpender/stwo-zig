# Pure-P2 MAIN custody review

The retained object is the existing compact coefficient tree and its existing Merkle layers. Parking does not regenerate a witness, change a transcript or recompute the commitment. The file is private, preallocated and immediately unlinked; its descriptor remains owned until the tree teardown token releases it.

The initial store (312bd2a0e) preserved all nine M31 root coordinates and exact coefficient bytes. Independent review found four missing boundaries: restored mappings bypassed the shared heap budget; writable mappings allowed accidental mutation; file length was not checked before mmap (a truncated file could cause SIGBUS during hashing); and restore did not authenticate ordered native/column logs or source setup/statement identity.

Commit fedba22ae closes these boundaries. OP producers use `parkBound` and `restoreBound` with independently admitted worker fixed identity and statement. Restoration checks the actual teardown token, exact descriptor addresses and lengths, native and column logs, complete 36-byte root, ownership flags, contiguous payload geometry and file length. It reserves external mapped bytes in the original allocator's SharedHostBudget before creating a read-only mapping. Any failure before publication leaves the safely empty parked descriptors and counters retryable. Already-restored trees are revalidated before an idempotent return.

The owner retains the original budget until the detached tree and mapping are released. The owner callback does not dereference a live worker or tree. The Store itself must remain at a stable address and outlive its tree tokens; whole workers and schemes must retain their ordinary allocator lifetime through teardown. This is ephemeral same-process custody, not a cross-process restart format. The private writable file descriptor and owner metadata remain trusted process state.

Focused ReleaseSafe tests pass for exact coefficients/root, disk/mapped caps, wrong setup and statement, changed native/column logs, changed ninth root word, malformed token size, payload corruption, truncated and extended files, combined heap/mapping budget refusal, successful external reservation, and moved-tree teardown after releasing the caller's budget lease. The independently rerun two-CPU/two-truth physical inventory test passes with bound identities: 19 retirements, two SHA calls, two ARITH calls, two bulk calls, 3,915,744 native proof bytes (unchanged), fresh durable receiver acceptance and exact RAM/Wire closure. All four parked mappings and file reservations return to zero. Three filtered physical tests pass in ReleaseSafe.

This host custody improvement does not change the protocol security claim: 128-bit security target under documented assumptions; security_qualified=false.

## Immutable FIXED templates and request leases

The store additionally supports an exclusively parked immutable template.
`shapeBound` copies only root/column/coefficient/layer descriptors for stage one;
it maps no data. `leaseBound` creates independent read-only descriptors and a
mapping for a worker's physical proof. Both bind the complete source identity,
ordered logs and all nine root coordinates. No shared tree is mutated and no
commitment is rebuilt or remixed. Caller code must validate a pending shape and
acquire its full replacement before releasing the shape or starting evaluation.

Each request view retains the file owner. A shape retains its request allocator
through a zero-byte external reservation; a mapped lease reserves its complete
rounded payload in that request's SharedHostBudget and the shared mapped cap.
Destroying the original template leaves existing views valid. The file, disk
reservation and original budget survive until the last view releases. Store
address/lifetime and exclusive-template-acquisition requirements remain explicit.

Independent source review found no ownership defect. Focused ReleaseSafe tests
pass for separate request budgets, two mappings, descriptor separation, exact
coefficients and roots, template-before-view teardown, caller-budget-before-view
teardown, mapped/disk/budget refusal, and every descriptor-allocation failure.
The shape test also checks zero mapped bytes and rejects opening before any
allocation. PCS decommit now refuses parked trees before coefficient-opening
scratch construction. The prior MAIN restore/custody regression passes.

This is the storage primitive qualification. Complete parked-FIXED worker proof
parity and the heavy-block memory qualification are separate integration gates.

An enclosing service cache can register `ViewLifetime` at Store construction.
Only successfully published request shapes/maps retain that cache, with one
release after descriptor, mapping and allocator-reservation teardown. Templates
do not retain it, avoiding an ownership cycle. Retain is atomic and non-reentrant
under the Store mutex; release runs outside it so the final cache destructor can
release templates and the Store safely. The focused lease/allocation-failure
gate confirms balanced callbacks, including zero callbacks from template
custody and refusal paths. Cache integration separately tests derived views
surviving release of all request and cache handles.
