# Retained full-execution setup ownership

This audit constructs only the independently expected image and immutable setup
keys from the retained schema4 full-block bundle. It executes no VM, decodes no
Tape, constructs no MAIN or interaction witness, and verifies no execution
proof. It independently reconstructs all 30 fixed roots and compares them with
the retained bundle. There are 25 distinct CPU keys, one cached Keccak truth key
used by two truth instances, and three cached secp truth keys.

The live owner ledger records these requested payload bytes:

| Allocation category | CPU 25 | Cached truth 4 | Total |
|---|---:|---:|---:|
| Original fixed vectors | 5,586,719,360 | 77,444,096 | 5,664,163,456 |
| Native coefficient backing | 5,586,728,192 | 77,444,096 | 5,664,172,288 |
| Program feature/row metadata | 773,785,350 | 0 | 773,785,350 |
| Retained Merkle hashes | 838,860,000 | 84,410,240 | 923,270,240 |
| Retained LDE values | 0 | 0 | 0 |
| Auxiliary truth table MAIN | 0 | 39,936 | 39,936 |
| Headers, owners and registry | 269,368 | 13,800 | 283,168 |

The header row includes 896 registry bytes in the truth/other column.
Total requested live payload is 13,025,714,438 bytes. The cost report's CPU fixed
logical area is 5,586,728,192 bytes; original ownership is 8,832 bytes smaller
because equal-height INIT/TERM roles alias their original fixed array. Their
committed polynomial coefficients still occupy separate logical columns.

`Key.seal` borrowed-streams the fixed evaluations, retaining independent native
coefficients and a Merkle tree. Compact storage removes the LDE buffers, not
the native coefficient allocation. Even constant-column preparation retains
native-length coefficients in the current representation. Tree leases share
these arrays through one owner; counting each proof's lease as another key
would be incorrect. The audit checks that every coefficient view is covered by
owned backing storage and counts identical owner ranges once.

Each CPU fixed commitment has log23 including commitment blowup, with the
bottom four Merkle layers pruned. Its retained 20 hash layers contain 33,554,400
bytes. The program cache contains 540,147 raw words and 572,754 logical ROM rows;
each cached feature Entry is 48 bytes. The full Word16 ROM fixed matrix alone
is 134,217,728 bytes per CPU key. Raw words/addresses borrowed from the expected
image authority are excluded from the per-key owner ledger.

The measurement process reported 8,298,905,600 bytes maximum RSS and
14,046,314,168 bytes Darwin peak memory footprint. Neither equals requested
payload. Allocator rounding, cached free blocks, trusted image allocations,
transient FFT/hash buffers, OS residency/compression and mapped advice are
outside this ledger. This tool uses the standard SMP allocator; the full driver
uses a 4 GiB recycler. These observations are not a controlled RSS comparison.

## First change without a protocol change

An explicit `releaseFixedWitness` operation can retire large original fixed
matrices after their complete key has been sealed. The sealed root,
coefficients, Merkle layers, geometry and statement transcript remain intact.
`fixedColumns` must reject a retired owner; logs, shapes and appending a retained
key remain valid. Defaults continue retaining the old buffers.

Most large material buffers are used only to seal the key. Native ALU, BINARY,
SHIFT, JALR, DIV/MUL and memory providers construct their own fixed data. CPU
native projection uses the logical row authority rather than the material's
CPU fixed matrix. Small register-boundary and range vectors and the packed
SHIFT table still supply existing native generators and should initially stay.
Keeping AND/selection fixed data conservatively too leaves 8,396,032 bytes per
CPU key. The original CPU fixed payload eligible for retirement is then
5,376,818,560 bytes across this 25-key run.

`Program.fixed` is the significant dependency: ROM multiplicity admission
reads its validity column and interaction generation reads its 30 tuple columns.
A bounded native `tupleAt(logical)` view can use the existing immutable
`Entry.romTuple` and row/edge maps, returning zero padding. This is the same
program authority used to construct the fixed matrix. It constructs one tuple
at a time, never a replacement wide matrix and never an instruction replay.
Physical placement must use the existing circle permutation; it is not plain
bit reversal. The retired path must be explicit, while malformed empty buffers
on the default path still reject.

Key/root and complete proof bytes must match the old path, including sparse and
high PCs, branch edges, padding, MAIN retirement and cleanup/error cases.
The full retained bundle's keys must be reconstructed and measured again after
retirement. Requested-byte savings do not establish an RSS improvement until a
full equivalent run is measured.

## Larger alternatives remain unimplemented

Sharing immutable program metadata and native coefficient backing between
geometry keys can avoid additional copies while preserving current roots and
proof bytes, but needs explicit refcount/borrow custody. The first CPU/ROM
coefficient-sharing candidates recur identically across all 25 classes. This is
separate from retiring the original fixed witnesses.

A single program-only fixed catalog could include every admitted role/log
combination and select offsets for each request. It changes the fixed-column
layout and transcript and requires a new canonical schema. The receiver must
derive every mapping from trusted program and admitted geometry. Unused catalog
columns still affect commitment height, leaf hashing/decommitment and possibly
PCS quotient/FRI geometry. Their opening and preprocessing costs must be
measured before choosing it. No catalog, weakened geometry admission, arbitrary
fixed-column offsets, or new accepting proof path is introduced by this audit.

## Explicit original-matrix retirement

`Setup.releaseFixedWitness` and the combined-service `CpuSetup` wrapper are
opt-in lifecycle operations after sealing. They preserve the complete fixed
commitment, compact coefficients, Merkle nodes, immutable program identity,
entry cache, topology and per-request transcript leases. They release original
CPU/ROM/provider/LS/boundary matrices. Small register-boundary, range, AND,
SHIFT-table and selection buffers stay live because native generators still
read them. This changes neither geometry nor the proof format.

After retirement, `fixedColumns` and ROM fixed-column export return
`ExecutionFixedWitnessRetired`. They cannot be used to reseal a partial key.
ROM request generation derives each tuple from the same immutable `Entry`
authority used by the original matrix builder, including invalid entries and
zero padding; it constructs no replacement wide matrix. Dictionary validation
uses this authority too. Sealed tree append/log/shape operations remain usable.
Retirement validates every original fixed-column shape before freeing anything;
allocation or shape failure leaves the original owners intact for retry.
Repeated retirement is an explicit phase error. Default construction retains
all original buffers until the caller requests retirement.

This is not a fixed catalog or coefficient-sharing protocol. The native
coefficients and Merkle payload measured above remain owned by each key.
Requested live allocation reduction must be reported separately from allocator
caches, maximum RSS and Darwin peak memory footprint.
