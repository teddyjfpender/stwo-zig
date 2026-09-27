Register custody source integration and witness staging foundation
================================================================

Status: source engineering only for this batch. No builds, proofs or benchmark
runs were launched by the memory agent. The stopped mainnet benchmark remains
stopped. Root controls qualification. These changes do not establish a measured
speedup or a qualified complete register-custody implementation yet.

The canonical product options select `register_custody_mode=1`. This is a
versioned SourceSeal/native admission policy: legacy mode 0 retains its original
grammar. Mode 1 filters authentic RW accesses into the sorted replay and proves
register claims from the same native and caller execution roots. Load/store
register/RW slots are dynamic and use `(1-space)`/`space` numerator projections;
host zero-row classification cannot decide their space.

`block_v5_register_windows_v1.Plan` binds exact ordered windows, local final
access clocks, independently supplied block initial/final registers and x0.
The private TableJoin closes register opcode, clock-helper, caller and endpoint
compensation **separately for each window**. The seven-field universal memory
tuple has no execution ordinal, so a pooled sum would permit cross-window local
clock cancellation. Existing strict predecessor gap range requests remain in
the actual shared counter census. SHA register accesses preserve their pointer
bytes (`sha256_memory_caller.zig`, consume/emit at lines 143–144).

The genuine zero-RW path validates an empty real sorted stream, commits a
versioned empty plan, and loads no memory or range STARK. It still authenticates
the complete initial/final image (including untouched nonzero and input leaves),
requires their independently pinned roots to match, checks the exact fresh
execution/caller RW census, and requires all proved register windows to close.
It produces no host-fabricated memory receipt. Source tests cover pure-register
production/detached reception, ordered window and endpoint mutations, cross-
window cancellation, forged fresh native/caller claims, and empty RW source/
plan policy mutations. These tests await the root's test lane.

Witness-once staging is a separate, incomplete integration. The new
`block_v5_witness_columns_store_v1` file format is canonical LE, version 1:

* 140-byte header: magic/version, native or caller kind, execution index,
  cycle count, first cycle, descriptor digest, original fixed/main roots,
  column count and total cells.
* Each ordered column has a 12-byte log-size/u64-count descriptor followed by
  exactly `2^log_size` canonical M31 words (four bytes each).
* `bytes = 140 + 12*columns + 4*cells`. I/O buffer is 16 KiB. Loading allocates
  one segment's columns, checks independent geometry/file length/SHA, and
  unwinds every partial allocation. There is no whole-file byte buffer.

`block_v5_native_columns_stage_v1` reconstructs the native owner and aliases
opcode/clock views to those loaded cells. It copies public I/O, reconstructs
signed native counters from authenticated cells, regenerates fixed columns,
and invokes the existing physical commitment kernel. The original retained
template and fixed/main roots must match. `Prepared.takeFirstRound` moves the
real recommitted PCS into the admitted native-v3 producer; it does not invent a
fresh verifier receipt. The first round must be released before its owner.
Column/public caps are explicit; fixed/counter/PCS allocations also require the
driver's tracked host budget. The new tests exercise multi-buffer round trips,
canonical and noncanonical tampering, resource/length/scope negatives, real
native reconstruction/counter parity and a rehashed wrong-root rejection.

Caller staging source was subsequently implemented in
`block_v5_caller_columns_stage_v1`. It includes all nineteen family11 main
blocks: Keccak arithmetic and chi/xor multiplicities, all proved secp private
arithmetic/byte/caller matrices, and SHA source/schedule/round/feed-forward/caller
rows. Mapped 16 KiB I/O writes those cells directly and restores the destination
matrix/row layouts without another full column-major copy. Fixed selectors and
SHA fixed row metadata are regenerated from independently retained statements.
The affine construction tape is not staged or simulated with fake recovery
records; an explicit logical signer count defaults to the original live tape
count in legacy callers.

The restored owner derives the six signed shared-table counters from actual
caller cells and the existing authenticated SHA DAG registration. Physical
recommit must reproduce the collected caller roots and key. The existing warm
proof transaction now accepts that real recommitted first round, preserving
family11/12/13, state/table callbacks and full byte/counter snapshot checks.
`Caller.collectSegmentWithStaging` writes the already-owned first-pass witness;
`Caller.proveStaged` takes no `RawSegment` and performs no guest execution.
The root agent owns driver/source integration and default selection.

Limits cover exact authentic column count, log24, file bytes32GiB, loaded cells
16GiB, and reconstructed matrices/selectors/counters24GiB. These are admission
caps rather than measured runtime peaks; allocator and PCS overhead remains
subject to the tracked host cap. Partial reconstruction/publication failures
release the owner arena and real PCS. A moved first round must be destroyed
before its witness owner. No verifier receipt is fabricated by loading files.

The new caller fixture source uses real SHA+Keccak and genuine nonempty
signer+Keccak witnesses. It compares roots, all SHA main/fixed rows, shape/logical
counts and the complete signed counter arrays against original raw-record
registration; it checks scope/clock/key/hash/resource mutations and a fully
rehashed wrong-root file. These tests perform physical commitments only. The
memory agent has not run them, any build, any proof or any segment benchmark.
Whole witness-once production remains pending the root's integration and
qualification; there is no new measured speedup claim.

The first focused root-run staging gate exposed a genuine buffered codec count
bug: an inferred `@min(..., 4096)` result narrowed the count before multiplication
by four, so full cell buffers produced an incorrect file length. Both mapped
writer and reader now declare those counts `usize`; the log14 round-trip test
exercises four full buffers. Root-run qualification of this correction is
pending. A bounded audit of the source writer, counter spool, sorter chunk I/O,
native/caller staging emitters and direct interaction emitters found no other
concrete instance: multiplied record counts are already explicitly `usize`,
and remaining inferred counts only drive slices or loops. No unrelated codec
or arithmetic changes were made.

Root qualification: the bounded27-test native/caller/direct custody gate passed, including the mapped full-buffer regression in ReleaseFast; its isolated Debug round-trip also passed. The production driver compiles with staged native/caller loading. Actual execution-segment and complete-bundle proving remain stopped and unqualified. Evidence: [custody log](cpu-performance-gates-v1/witness-and-direct-columns-custody.log).
