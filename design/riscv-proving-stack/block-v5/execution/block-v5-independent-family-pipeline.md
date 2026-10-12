# Independent block-v5 proof families

The CPU driver now schedules caller witnesses, sorted word memory and range providers, the ROM table and native lookup providers independently after the common first-round seal. Native execution and its fused local projections retain one live staged native witness. All jobs must join successfully before publishing the bundle manifest. Segment proving remains stopped; assembled proof acceptance and performance are not yet measured.

`block_v5_cpu_family_queue_v1.zig` uses a fixed-capacity FIFO and a bounded number of coordinator threads. The default is two coordinators, four queued descriptors, a 16 GiB simultaneous reservation limit and an 8 GiB reservation per family. Reservations are admission estimates, not per-family allocation quotas. Every allocation still uses the same synchronized 40 GiB aggregate heap budget, including nested recursive budgets. The allocation limit is enforced even if an estimate is wrong. Thread stacks, allocator overhead and backend/device storage are not included in that heap number. These defaults need real workload qualification before claiming improved peak RSS.

Each descriptor borrows immutable source/seal/catalog metadata for the joined lifetime. Caller proving reconstructs its own staged columns and recommits against its independently pinned physical roots. Sorted-memory proving opens its own reader over the finalized sorted file and initial image, retaining one trace/PCS at a time. ROM proving reconstructs its fixed/main commitments and compares them with the retained roots. Lookup proving opens the group's hash-pinned counter file and retains one counter/PCS at a time. None of these jobs borrows the live native PCS or replay owner.

The execution-only producer returns execution coverage, with no memory/provider coverage fields. Global jobs must separately finish and publish their artifacts. The canonical warm stage produces one version2 local projection/access proof, preserving separately authenticated program, table, register, clock, packed-memory and byte-range obligations. Global closure and independent final verification still run after all required artifacts are staged.

## Workers and lifetime

Whole proof jobs run on coordinator threads, never on helper-pool threads. Each binds the driver's existing `WorkPool`; nested helpers retain the pool's structured lease and fallback behavior. The recursive leaf cache borrows this same pool, as do incremental forest lanes and the final outer coordinator. Standalone recursive worker/forest APIs retain owned pools when no shared pool is supplied. Borrowed pool pointers must outlive every worker/cache and all joined requests.

`ScopedPoolBinding.initIfNeeded` reuses an identical binding without acquiring its ownership, rejects a different nested pool and never discovers or creates the legacy global pool. Shared recursive workers therefore leave the caller's binding intact. Worker workspace, authenticated setup, public-admission rebind and host-budget ownership remain exclusive to the existing worker lease.

Queue failure preserves the first error and cancels queued descriptors. Foreground native callbacks, caller instance boundaries, sorted memory/range instance boundaries and lookup-group boundaries check that shared failure state. Abort joins active readers before releasing the store, staged source, collected metadata, recursive cache or seal roster. Cancellation is cooperative between owned proofs; a proof already inside a STARK call must unwind or return before its coordinator can join.

The bundle store serializes checked publication. Producer and store use the same allocator, so successful publication can consume a proof without freeing through a different nested allocator. Durable partial files on a failed attempt do not become a completed manifest or verified block.

## Evidence and reporting

The nonproving queue gate exercises actual concurrent allocations and bindings, reservation serialization, first-error cancellation, foreground abort/join, invalid admission and hard parent-allocation failure. Assembled driver/CLI tests take concrete function addresses to generate their bodies without calling them. These checks establish source/custody behavior, not complete proof acceptance.

The assembled driver/CLI and queue/shared-pool gate passed 19/19, including transitive tests. The separate fusion-equation gate passed 11/11 and transport/custody gate passed 15/15. [Passing logs and source hashes](../../../../autoresearch/notes/2026-09-24-ethereum-block-delivery/cpu-performance-gates-v1/fusion-pipeline-qualified-source-manifest.json) retain the exact scopes. No execution or proof job ran in these gates.

The CPU report records peak simultaneous independent families and admitted reservation bytes separately from the actual aggregate heap peak and process RSS. Caller, memory/range, ROM and lookup wall times overlap and must not be added as end-to-end time. `proving_ns` remains the common wall interval covering native/sidecars, independent providers and recursive leaf publication; `forest_ns` records the remaining forest wait and staging.

No order-of-magnitude or end-to-end speedup follows from queue tests or source integration. Final acceptance still requires canonical 70-query/26-PoW security, independently complete verification, exact base/recursive counts, isolated proving time and process/device peak memory.
