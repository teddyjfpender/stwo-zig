# Quotient dispatch allocation admission

The direct opening-quotient dispatch and fused quotient-to-FRI dispatch use one
synchronous admission callback for private Metal buffers. Every copied input,
view/partial metadata buffer, numerator, generated domain grid, private output,
hash arena, root readback and local transcript buffer is reserved before its
device constructor runs. The parent plan's private node seed is also admitted.
The two remaining raw constructors are no-copy input/output aliases whose
backing heap or resident allocation is already owned by the caller.

The callback grows one reservation from the original allocator's shared
heap/external budget. Competing proof jobs use the same cap. A rejected growth
is sticky and prevents later constructors from slipping through after failure.
The synchronous dispatch joins before returning, including its existing
submitted-command failure path. Cleanup destroys published handles before the
reservation can be released. OutOfMemory is preserved at the Zig boundary.

Successful dispatch drops temporary charges and transfers the returned hash
arena's charge into the actual runtime Tree. Its extent uses the ABI's64-word
layer alignment; discrete devices additionally retain32 bytes for root readback.
Malformed, undersized or unadmitted retention fails before transfer. The scope
also retains the allocator while outer heap arrays are being freed.

The old Objective-C domain cache is uncapped and lacks an owner identity. It
remains available to explicit ordinary allocator APIs. Supplied shared budgets
generate a proof-local GPU grid and cannot borrow or publish that global cache.
This does not use a CPU domain fallback. A future budget-bound immutable domain
cache can recover cross-proof reuse without releasing the charge while cached.

Eight device-free checks pass for admission-before-construction, sticky failure,
retained-tree transfer, malformed retention, discrete versus unified readback,
large-domain padding, original-owner teardown, uncapped overflow and concurrent
competition. Actual bare/committed/fused and profiled/unprofiled dispatch bodies
compile into an object without execution, and production Objective-C syntax
passes. A source audit finds25 private helper sites plus the parent seed
admission; only the two no-copy aliases bypass private admission. Evidence is
retained in
`autoresearch/notes/2026-09-24-ethereum-block-delivery/cpu-performance-gates-v1/metal-quotient-allocation-budget-qualified-v1.json`.

Reservations conservatively retain the dispatch's admitted envelope until the
synchronous call returns. This is logical ownership accounting, not a measured
RSS limit or GPU speedup. Objective-C host metadata/framework overhead, physical
rounding, sampled OODS, generic FFT/commitment staging and decommitment readback
remain outside this receipt. No device, guest, STARK, segment or performance
benchmark was run.

## Direct BLAKE3 commitment routing

Ordinary lazy quotient commitment formerly queried the staged hash interface.
BLAKE3 has direct full-tree support, but deliberately lacks that staged-state
contract. The selection therefore missed its direct quotient+Merkle path. Its
runtime ForHash guards also admitted only families1/2 despite the actual C
runtime implementing canonical BLAKE3 family3.

The ordinary lazy quotient path now selects typed direct hash parameters,
matching the existing fused quotient-to-FRI path. Direct ForHash entrypoints
admit BLAKE3 only with its actual zero seeds and zero prefix. They do not change
staged hash admission. This keeps the quotient output resident for the direct
commitment rather than reentering a separate commitment path. CPU proof format,
FRI equations and BLAKE3 framing remain unchanged.

Ten device-free allocation/framing/admission checks pass. The actual
Backend.commitLazyMerkle(BLAKE3) body and the six direct/fused/profile dispatch
bodies compile. Source and object hashes are retained in
`metal-quotient-direct-blake3-qualified-v1.json` in the same evidence directory.
No device or proof was executed for this routing revision, so hardware parity
and end-to-end performance remain required.

## Result rejection and consuming tree adoption

The profiled direct and fused routes now consume runtime results at the execution-receipt boundary. If receipt admission fails after device handles have been published, the initial tree, every fused FRI tree, and the raw array are destroyed. A temporary shared-budget lease keeps the outer array allocator alive until cleanup completes.

`fromSharedRuntime` consumes its raw tree on success and error. The fused adoption batch removes each tree from its own ownership before calling that constructor and releases only untouched tails on failure. This fixes first-tree double destruction plus abandoned FRI tails, and middle-tree double destruction. The batch retains its allocator budget until the raw array is freed.

Six device-free success, rejection, first/middle adoption, exact destruction, and original-owner-release checks pass. Actual full `FriProver.commitLazyWithWorkRecorder` and all direct/fused profiled/unprofiled quotient bodies compile without being invoked. Evidence: `autoresearch/notes/2026-09-24-ethereum-block-delivery/cpu-performance-gates-v1/metal-quotient-result-ownership-qualified-v1.json`. This is source/ownership qualification; no GPU, STARK, segment, or performance run was executed.
