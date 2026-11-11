# Pure-P2 native OP truth catalog

The common native worker now covers Keccak permutations, classic secp,
secp row ADD/DOUBLE, SHA-256, arith256 and all seven curve/field providers.
It reuses their existing equations, geometry and narrow witness-generation
metadata. There are two concrete component layouts (classic and delegated),
one source-owned key, one PCS lifecycle and one fresh receiver implementation.
No GPU stages or new service tags are involved.

Immutable key identity binds the provider family, source version/profile,
fixed roots and ordered column geometry. Requests bind first ID and call count
in their statements; the shared manifest supplies execution identity and global
RAM/KIO/Wire challenges. Local challenge draws follow the sealed MAIN and the
manifest. Source MAIN and INTER move into PCS ownership, and generator advice
is released before proving. The source factory is not proof authority: its
returned kind/geometry/allocator are checked, and physical AIR and global debt
closure authenticate its values.

Each worker requires explicit live, MAIN, interaction and advice limits.
Source construction, its retained witnesses, PCS and prover use one stable
synchronized allocator budget. Immutable keys, caller-owned input inventories,
encoded output proofs and thread-pool stacks are outside that budget. The
13-case fixture uses a 1 GiB live cap; observed peaks range from 2.3 MB to
34.4 MB of requested worker-owned allocations. Every case returns to zero live
budget after completion. These observations are not process RSS.

All 13 physical fragments pass under `op_target_b4_q72_p0_fold4_v1` with
freshly reconstructed P2 fixed authority. Changed first IDs, altered physical
claims, insufficient source/MAIN budgets and oversized durable frames reject.
The `OPTRP201` transport bounds lengths and canonical OM encodings; decoding
is never acceptance. The receipt contains individual sizes and requested peaks.

These fragment fixtures deliberately use a synthetic pending scope and do not
claim execution acceptance. Complete OP inventory admission, the actual CPU
and sponge joins, durable block framing, fresh-process reception and recursion
remain distinct gates. Production CLI admission remains closed. The security
label is “128-bit security target under documented assumptions.”
