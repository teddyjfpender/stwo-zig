# Capacity-native catalog, transport and capture

Capacity-native proofs now have a distinct ordered catalog, bounded owned wire
format and fresh-verifier capture API. These are explicit B5CT entrypoints;
canonical block collection/fusion/forest defaults have not switched to them.

`block_v5_native_capacity_catalog_v1` binds each execution ordinal to its capacity
digest, template identity and fixed root. B5CC/v1 has its own transcript domain,
separate from the old exact-row B5NC catalog. A varied-row pair within one bucket
can share a template record's identity. Exact logical rows and external
retirements remain independently instance-bound. Catalog admission requires the
actual common seal, complete execution census, zero singular-template binding,
matching config and independently pinned catalog digest. Ordered ownership is
bounded before copying records; default limits are65536 records and16 MiB of
record storage.

`block_v5_native_capacity_codec_v1` uses B5CTART1, an explicit protocol version,
template/instance/capacity digests, proof-byte length and redundant claim count.
The receiver supplies the shape and configuration independently. Wire bytes
cannot select a key, count, source roster, capacity or proof geometry. Header and
canonical claim checks precede any allocation. Postcard preflight derives the
real capacity main width and composition log from this shape before allocating
proof vectors. The degree-three prefix constraints require composition columns
at row_log+1 after the fixed split of one; the old native-only maximum can
understate this geometry. Claim count, fixed claim storage and proof/artifact
bytes have separate admission bounds. Decode failures release every partial
owner.

`block_v5_native_capacity_artifact_receiver_v1.Policy` reconstructs expected wire
identity from the independent common seal's execution entry, public admission,
template and optional capacity catalog. Its actual verifier consumes decoded
proofs on both success and error. It rebuilds the deterministic fixed root and
checks the capacity composite AIR through the ordinary STARK verifier.
`VerifiedCapture` is a distinct owned witness for recursion, with owned and
borrowed proof entrypoints. Both check the same composite geometry and B5CT
transcript. Borrowed capture owns independent vectors and cloned claims. Its
mutation seal binds captured PCS data, exact geometry, capacity identity,
claims, universal challenges and final transcript state. This witness alone
does not close global execution obligations.

The shared bounded artifact writer now streams both B5CT and canonical NativeV3
serialization directly into one final envelope buffer. It checks limits before
each capacity growth and backpatches proof length after serialization. This
removes the temporary complete postcard buffer and its final copy. NativeV3 wire
bytes are unchanged. Logical requested allocation limits do not establish a
whole-process RSS limit or an end-to-end speedup.

The focused gate passes10/10: seven named contracts and three import checks.
It checks exact legacy bytes against the prior staged grammar, independent
decode ownership, malformed/old/version/config/count/capacity/trailing wire
rejection, all allocation failures, serializer caps before growth, owned catalog
isolation and actual sealed two-instance policy admission. The actual catalog
producer, artifact verifier and owned/borrowed capture bodies compile without
invocation. Literal structurally valid envelopes are not generated STARKs.

Evidence is retained under the Ethereum block delivery notes in
`cpu-performance-gates-v1/native-capacity-transport-capture-qualified-v1.json` and
`native-capacity-transport-v2.log`, with eighteen pinned source files.
No STARK, segment, FRI, guest, device or benchmark was run. Fresh capacity capture,
fused/recursive receiver integration, canonical activation and complete bundle
performance remain outstanding.
