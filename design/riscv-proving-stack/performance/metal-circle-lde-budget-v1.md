# Shared-budget circle LDE scratch

The generic PCS preparation path now prefers the backend's allocator-bearing
`CircleLdeBatch.initWithAllocator`. Each actual runtime batch binds its runtime
and allocator, and retains a zero-byte shared-budget lease from construction
through command destruction and outer-owner cleanup.

All seven private constructor sites in the actual circle LDE implementation
call admission before allocation: copied coefficients, copied extended values,
inverse and forward twiddles, two routing arrays, and copied source runs. The
three no-copy aliases borrow the original caller-owned heap arenas and receive
no second external charge. This scope measures logical allocation bytes, not
Metal framework overhead, physical allocation rounding or process RSS.

The C dispatch returns an explicit queued-operation receipt. Buffered direct
groups genuinely coexist in the batch command and remain charged until its
checked completion or unsubmitted cancellation. Groups that execute
synchronously release their destroyed scratch immediately, preserving any
earlier queued charge. Constructor rejection is sticky. A partially encoded
failed group poisons the batch; it cannot subsequently submit that command.
Destruction cancels the unsubmitted command before releasing its reservations.

Allocator-less ordinary entrypoints retain their explicit uncapped policy.
They can borrow ordinary allocator inputs, but cannot accept a supplied shared
budget as an uncapped fallback. Allocator-bearing batches require exact owner
identity. Legacy diagnostic C symbols retain their original signatures;
production calls use the new budgeted symbols and actual queued receipt.

Seven device-free checks cover pre-factory failure, combined heap/private-copy
caps, 128 joined waves under a constant cap, original-owner release, allocator
identity, overflow and ordinary compatibility. The full real generic PCS
`commitOwned` body plus batched/standalone LDE and batch lifecycle bodies compile
without being invoked. The literal assembled Objective-C runtime prefix ending
at circle LDE passes syntax checking; it deliberately excludes the later OODS
batch still under development. The existing `fastMathEnabled` deprecation
warning remains.

Evidence is retained in
`autoresearch/notes/2026-09-24-ethereum-block-delivery/cpu-performance-gates-v1/metal-circle-lde-budget-qualified-v1.json`.
No GPU, guest, segment, STARK or performance run was executed. These checks do
not qualify actual device parity, every other private Metal constructor, or
complete proof throughput. Borrowed input custody remains the original PCS
owner's responsibility.
