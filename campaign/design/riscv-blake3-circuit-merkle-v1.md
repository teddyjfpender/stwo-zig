# Native BLAKE3 Merkle and authenticated query kernels in the circuit AIR

New module: `src/frontends/circuit/builder/blake3_merkle_reuse_v1.zig`.
Qualification: all 20 focused ReleaseSafe tests pass. No existing verifier,
production registry, proof codec or source layout changed. This is a circuit
kernel gate, not a complete recursive leaf wrapper or original PCS verifier.

The leaf is exactly BLAKE3 of experimental-v1 protocol ID, LEAF domain byte,
then canonical little-endian M31 words. There is no additional leaf-length
field. Columns are ordered by ascending `(column_log_size, original_index)`,
matching `MerkleVerifierLifted.verifyImpl`. The independent structural layout
selects that order; no witness permutation is accepted. Full multi-chunk hashing
supports widened native/group rows, with tests through 1,100 columns and five
BLAKE3 chunks. Parent nodes use the distinct protocol NODE frame, not BLAKE3's
internal PARENT compression flag. Digests retain all 256 bits.

Root words, siblings and queried M31 cells are typed circuit input wires.
Path length must equal the admitted tree height. Direction selection happens
inside the circuit using Boolean bits extracted from a range-constrained query;
no host direction array enters the public API. The recomputed root is constrained
word for word equal to the same root wires the transcript can absorb.

The native PCS projection is unusually important: `prepareTreeQueryPositions`
preserves the circle pair bit 0. Shrinking a tree drops low **coset** bits, not
the pair bit; expanding a tree inserts zero coset bits. The adapter implements
both directions and zero-height nonempty trees, checked against the authoritative
native utility. A plain right shift would authenticate the wrong row.

`drawQueries` derives indices from the constrained BLAKE3 channel's raw U32
blocks. It masks the low domain bits, preserves order and duplicates, and
consumes whole eight-word draws, discarding the final unused words. It does not
apply the secure-field sampler or modulo-M31 reduction. Tests compare domains
0, 3, 17 and 30 and counts 0, 1, 8 and 9 against native. An end-to-end kernel
case absorbs a request root, derives nine query wires, and checks all paths
using those same wires. A host-selected wrong leaf/path fails even if it is a
valid path at another index. This avoids host authorization of a query index.

Physical forests have no four-tree assumption: the finite kernel accepts up
to 256 nonempty trees, with a 135-tree test (the native-only N32 group geometry).
Heights are bounded by the canonical circle maximum 30. An empty tree has no
opening and is rejected by this opening API; an independently rebuilt PCS roster
must explicitly omit it. Its root is not silently declared authenticated.

Native proof bodies contain compressed sorted/deduplicated multiproofs. Expanded
paths may be supplied as untrusted witness material: each path is fully checked
against the constrained index and root. A fixture uses four raw queries with a
duplicate, three compressed sibling hashes and twelve expanded sibling entries;
it matches the native verifier/capture and is checked again inside the circuit.
The malicious controls feed raw invalid paths directly, without native host
verification. Thus a successful host capture grants no recursive authority.
A strict original-proof codec must still consume the exact compressed witness;
this kernel does not pretend to implement that codec or its byte-shape policy.

Other qualified negatives include changed leaf/root/index/sibling, too-short
and too-long paths, wrong row width, invalid layouts, and out-of-domain query
indices. NoValue compilation and gate-free replay match the value topology
exactly. Native/source fixed keys, Fiat–Shamir operation ordering for a complete
original, OODS/DEEP checks, FRI folds/packed leaves and typed AIR verification
remain necessary before any RISC-V circuit leaf wrap can be published.
