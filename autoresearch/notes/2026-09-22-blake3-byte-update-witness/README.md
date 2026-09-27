# Shared-sibling BLAKE3 byte update witness

Added before/after memory-path assembly with one public address/kind, distinct
byte sources and disjoint hash namespaces. Both paths consume one shared sibling
namespace. The duplicate sibling producer is removed and the retained producer
emits the sum of both consumer multiplicities. Its byte-range table requests
remain single, so one constrained sibling value supplies both paths.

The focused ReleaseSafe gate passed in 30 seconds (1 GB reported peak RSS).
The new check compares both roots to independently rebuilt before/after sparse
snapshots, checks one retained set of 240 sibling words with doubled fanout,
compares trusted producer metadata and rejects aliased byte sources. Existing
single-path checks also pass after adding optional shared sibling namespaces.

This is witness assembly qualification; a combined update STARK proof and full
combined wire ledger are not yet qualified. Production byte/address/root source
admission, continuation claims and artifact/key integration remain pending.
No production memory protocol default changes or timing claims are made.
