# Native RAM frontier handoff

The native collector can now prepare a detached RAM transition without building
the 303-column Poseidon witness or retaining the execution `Memory`. The worker
uses that detached graph and the owned before/after chunk words to fill the
existing RAM caller and Poseidon columns once. This is a preparation/ownership
seam for independent workers, not a parallel CLI scheduler or a new proof system.

`memory/native_frontier.zig` reuses `batch.Witness.initPrepared` with a native
recorder whose wide writer is null. It retains the exact before/after roots,
leaves, nodes, frontier sides, sparse cache patch and permutation input/output
pairs. It neither clones the complete sparse cache nor reconstructs a different
root graph. A retained permutation pair occupies 128 bytes; its eventual main
witness has 303 M31 cells, or 1,212 bytes per provider row before domain padding.
The prepared object's `ownedBytes` reports its actual narrow graph/IO payload;
it excludes temporary validation maps which are already freed on return.

The portable graph frame is separately bounded and validated by
`native_frontier_wire.zig`. Its explicit little-endian header and record counts
are checked before allocations, and decoding stops exactly at the frame end.
These native checks establish canonical representation, coverage and ownership.
The existing Poseidon provider still proves every permutation and the existing
RAM/CPU/policy buses still authenticate the values. A native root or portable
packet is never independently accepted as a proof.

The collector's state machine is:

1. `prepared`: graph construction and validation complete; cache unchanged.
2. A caller-supplied durable handoff callback copies or persists the immutable
   packet. Failure leaves `prepared` and the cache unchanged.
3. `durable`: callback succeeded. Sparse patch publication reserves all required
   capacity before mutation. Publication OOM retains `durable`; retry skips the
   callback and publishes the same patch.
4. `published`: native cache advanced to the exact after-root. A worker may take
   the prepared owner. A worker may also take a decoded `prepared` packet, since
   it has no collector cache to update. Taking a `durable` packet is rejected.
5. `consumed`: narrow graph and IO moved into the successful worker trace;
   repeated construction is rejected. Deinitialization remains safe.

`Trace.initFromPreparedGraphOwned` and
`Trace.initFromPreparedGraphBorrowedOwned` use the same core filler as the cache
constructors. Graph coverage, exact IO indices/framing, opening values, allocator
identity and borrowed-main input aliases are validated before wide allocation or
writes. The filler borrows the three narrow owners until all fallible work
finishes. Success moves the prepared graph, preparation grants/edges and opening
owner; failure leaves all three with the caller. The borrowed arena always
remains the outer owner's allocation, and policy/BYTE multiplicity tails are
left for their existing coordinator. The provider expands recorded inputs using
the existing arithmetic kernel and compares its outputs with the recorded pair.
There is no second graph traversal to recompute permutations.

ReleaseSafe and ReleaseFast AIR gates passed with both 512-byte and 4-KiB
geometries. The tests compare every provider/caller cell, roots, all retained IO,
BYTE/policy counts and restored rows against the cache constructor. They destroy
both native `Memory` and `Cache` before detached construction, exercise owned and
borrowed output storage, and exhaust allocation failures. Coverage also includes
consumed reuse, stale before-root, graph orphans, IO/patch substitution, modified
opening values, pre-write alias rejection and durable-publication retry without
repeating the callback. Portable frame tests cover high u64 addresses/words,
24-bit clocks, truncation, malformed/capped counts and crossing 64-KiB I/O blocks.

Gate logs for this change are `/tmp/rv64-native-frontier-air-safe.log` and
`/tmp/rv64-native-frontier-air-fast.log`. Whole-job scheduler throughput and
independent process packet proving remain separate integration qualifications;
these low-level tests do not establish those performance claims.

The prepared-worker integration subsequently passed seven ReleaseSafe and seven
ReleaseFast chain tests, including actual SD17/LD17 RAM events after native
owners were destroyed. Cache/owned, cache/arena, detached/owned and detached/arena
produce identical complete encoded proofs with independently rebuilt receivers.
The 65k-prefix CLI proof and receipt also match the pre-seam reference:
962,896 proof bytes, SHA-256
`7fa69a687e73382c429fbb196333239c6387454744a510a9b9223f4b5cc8ceba`.
Integration logs are
`/tmp/stwo-rv64-delivery/detached-worker-chain-safe.log` and
`/tmp/stwo-rv64-delivery/detached-worker-chain-fast.log`.
The CLI still schedules its cache adapter serially; this is not a measured
detached-process fanout result.
