# Bound four-byte memory word opening

Added one verifier-owned statement deriving the typed memory boundary and four
byte-path statements. Byte i uses address+i and source wire i; every path shares
the same full root and memory domain. Namespace admission checks all four path
ranges. Live preparation derives all byte values/openings from a sparse snapshot
and rejects root mismatch before constructing hash witnesses. Trusted preparation
requires neither snapshot nor byte values.

The focused ReleaseSafe gate passed in 35 seconds (1 GB reported peak RSS).
Checks cover a partially populated aligned word with implicit zero bytes, all
four computed roots, exact path addresses, boundary/leaf byte agreement, trusted
boundary columns, full recursion-wire closure and substituted boundary-byte
rejection. Root mismatch and namespace collision are rejected. The memory-access
relation remains the external provenance obligation; the ledger only closes
recursion wires and does not fabricate a memory-access source.

This is joined witness qualification, not a complete memory-word STARK proof or
runner-owned snapshot admission. Production memory-access/clock provenance,
continuation claims, retained snapshots and artifact/key integration remain
outstanding. Four openings currently traverse the snapshot separately; batching
is an optimization opportunity after production integration.
