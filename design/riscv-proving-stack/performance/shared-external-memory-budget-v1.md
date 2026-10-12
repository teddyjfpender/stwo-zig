# Shared heap and external allocation ownership

Root qualified all16 device-free checks (11 shared ownership/admission,2 actual
PCS backing teardown and3 Metal extent/alias checks). Exact evidence is retained
in `autoresearch/notes/2026-09-24-ethereum-block-delivery/cpu-performance-gates-v1/shared-external-memory-device-free-qualified-source-v1.json`.
The subsequent RAM CPU metadata gate passed4/4. Actual RAM producer/replay,
requester/range/original-STARK and typed secure quotient/PCS bodies compile with
the regenerated real Metal library and Objective-C runtime. The separate
`ram-lanes-shared-external-budget-qualified-source-v1.json` pins that scope.
Hardware execution and generic device FRI accounting remain unqualified. This does not run a
device, make a proof, restart segments, or measure GPU speed.

`SharedHostBudget` now admits heap growth and external reservations under the
same mutex and the same configured limit. `snapshot().live_bytes` and
`peak_live_bytes` describe the combined logical envelope. `host_live_bytes`,
`external_live_bytes`, `peak_host_bytes` and `peak_external_bytes` break out
the terms; the independent peaks need not occur at the same instant. External
peaks include a factory's admitted temporary envelope until checked command
completion shrinks it to retained buffers. These are allocator/reservation
counters, not process RSS. Thread stacks, the budget control object, Objective-C
objects, catalog/command/framework overhead and unrelated allocators are outside
this accounting.

`reserveExternal(bytes)` admits before allocation and retains the owner's
lifetime. `ExternalReservation.take()` consumes and clears the original;
`resize()` changes the charge under the same mutex; `deinit()` drops bytes and
then the lease. Repeating `deinit` on the same cleared object is harmless.
Raw Zig struct copies do not acquire leases and are outside this ownership
contract. The language does not enforce move-only structs. Release of a copied
charged token detects count underflow, but arbitrary use-after-release of raw
copies cannot be made safe by that check.

`shared_external_memory_v1.createPrivate` reserves a factory envelope before
calling the factory. Factory errors must have joined and destroyed unpublished
resources, after which the wrapper rolls back the reservation. Pending owners
cannot expose a checked resource or transfer it. Completion/status errors
permanently deny checked admission. Cancellation and destruction join before
resource release. Successful completion shrinks temporary scratch to the
factory's bounded retained extent. Explicit transfer keeps exactly one owner.

`createAlias` takes a typed actual host owner, retains it before creating a
no-copy resource, and reserves zero external bytes. Its host backing remains
heap charged once. Resource destruction and host release precede release of
the budget lease, so the original root owner may be released first. Join
callbacks must be terminal even when reporting errors. These are local memory
contracts, not proof receipts or authority derived from received metadata.

Canonical Metal RAM sessions require the actual shared allocator and reject
foreign allocators before allocation. They retain a zero-charge session lease,
and charge record/histogram uploads, the shared range inverse table, witness
outputs/status metadata, interaction outputs/scan scratch/descriptors and
uniform commitment private Merkle/descriptor/twiddle copies. Resident inputs
must match the session's local owning budget; allocated output tokens travel
with `ResidentBuffer` and `Tree`. No-copy aligned PCS coefficient/evaluation
arenas retain their existing heap charge. Exact uniform Merkle extents preserve
the runtime's layer alignment and shrink to the retained hash arena after the
synchronous command and autorelease boundary.

The typed secure quotient path charges its gathered device output, quotient
output, equation descriptors and resident FFT copied metadata. The final
quotient reservation remains with its output ownership slot until actual
destruction. PCS teardown temporarily retains the budget before destroying
device views, then frees host backing and any shared wrapper before dropping
that temporary lease. Sorted-source and gathered-input metadata likewise free
their heap owners before releasing the final resident token.

Legacy raw device APIs retain default-empty or explicitly unbudgeted tokens.
Generic device FRI and other allocations outside these canonical entrypoints
have not been migrated by this revision. The shared cap must not be advertised
as accounting for every GPU operation or whole-process memory.

Device-free fixtures are `src/shared_external_memory_test_root.zig` (boundary,
heap resize, contention, overflow, factory rollback, failed status, cancellation,
transfer, foreign allocator and alias lifetime),
`src/shared_external_pcs_budget_test_root.zig` (actual PCS backing/shared-wrapper
teardown after root release using a resource-only backend that cannot commit a
proof), and `src/metal_resident_budget_test_root.zig` (exact private Merkle and
interaction extents plus alias/copy alignment). Actual Metal production bodies
remain retained by `src/block_v5_ram_lanes_metal_producer_codegen.zig`.
