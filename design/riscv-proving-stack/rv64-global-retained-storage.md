# File-retained native coefficients at the global challenge barrier

All fixed/MAIN roots must be sealed before global RAM randomness is derived.
Wide MAIN witnesses are transferred once into PCS ownership and retired. Their
native polynomial coefficients still have to survive until each worker proves
its interaction and quotient obligations. Keeping every worker's coefficients
on the heap limits a single-host execution long before its coordinator's small
manifest does.

The optional worker-local Store preserves these native polynomials in shared,
preallocated, unlinked file mappings. It copies each native coefficient once,
flushes its file pages, advises that clean pages may be reclaimed, and transfers
ownership as a failure-atomic transaction under exclusive worker access. This
is not synchronized concurrent mutation. Both the polynomial descriptor and compact column view
are re-pointed together. There is no witness reconstruction, repeated FFT,
extra commitment or transcript change. The source's narrow relation metadata
stays with its original worker until interaction generation finishes.

A concrete RV64 tree must be exclusively owned, fully compact, have matching
coefficient/column views, and own each old polynomial directly or through known
backing buffers. Shared immutable setup and backend-owned aliases are refused.
The Store reserves a bounded page-rounded byte budget before acquiring disk
storage. The existing allocator reserves real disk blocks before mapping and
unlinks each scratch file immediately. Allocation, writeback and reclaim-advice
failures precede the first ownership change; the sealed worker remains usable.
No fallible allocation follows the successful transfer. An existing move-only
PCS teardown token releases the arena and budget after all tree readers drain.
Store must outlive its workers and tree leases.

This is transient storage in the same live process. It is not a portable worker
checkpoint or restart protocol. Distributed owners can still use the same sealed
root-only manifest; this option supplies a bounded disk policy for retained
native polynomials when workers share one host. It does not spill every other
worker allocation or promise an RSS limit. Source metadata, immutable setup,
Merkle data and temporary evaluation buffers remain separate costs.

The explicit two-packet tool accepts producer-only options:

    --retained-main-dir=/path/to/scratch --retained-main-cap-mib=8192

Without the options it retains the resident behavior. Fresh receivers need no
storage options. Output-directory availability is checked before proving, and
successful completion must leave no mapped disk allocation or named scratch
file. The budget counts reserved mapping bytes, not observed resident memory.

Safe/Fast tests compare complete proofs, claims, sealed roots and manifest
against the ordinary path and verify afresh. They also exercise budget refusal
and ordinary completion, owner-allocation rollback followed by retry, repeated
spill refusal, and abandoning a sealed worker. A real8,388,606-instruction
prefix preserves both complete proofs, the manifest and all712,789 RAM records
byte for byte, then passes a fresh independent receiver. It maps4,621,484,032
bytes at the barrier and releases all of them.

Two exploratory runs had peak RSS about14.77GB, the same as the resident control.
Darwin's separately reported peak memory footprint was about10.15GB versus
14.77GB. Those metrics must not be substituted for each other. Clean mapped
pages can remain resident and transient allocation can determine lifetime RSS.
The source-cost and long-retention benefit still needs qualification over more
shards; no1.45x RSS claim or block-scale extrapolation follows from this probe.
Timing overlapped engineering and is not a controlled speedup measurement.
