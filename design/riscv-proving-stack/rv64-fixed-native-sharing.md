# Immutable fixed native coefficient sharing

This opt-in cache reduces retained setup payloads. It does not skip fixed
construction, interpolation, extension or hashing. Defaults use the existing
uncached path. No execution witness, request endpoint, challenge or transcript
is cached, and no proof schema changes.

Each fixed key is independently constructed before interning. The cache hashes
ordered native coefficient logs and values, then compares every actual span
byte-for-byte before sharing. Backing padding is never read. Individual native
owners and complete backing arenas retain their actual source allocator and a
managed-budget lease. Metadata uses the cache allocator. Stateless allocator
context pointers are never compared: Zig leaves the SMP context undefined.

All allocations, alias checks and capacity decisions finish before ownership
changes. Both coefficient descriptors and compact column coefficient views are
repointed together. Uncached arenas remain under their original owner. Cached
owners live through the existing PCS teardown token, including after the cache
manager or original Setup is gone. The cache has a bounded requested-byte limit
and no eviction/global singleton. The native values may be shared across F1/F4;
each key/material still retains its receiver-selected Suite, and append rejects
a mismatched Scheme configuration.

The focused Safe/Fast suite has 14 actual runtime tests. It covers allocation
failure/retry, concurrent owners, SMP and mixed allocators, source-budget lifetime,
full64 sparse/high PCs, malformed/overlapping views, complete native backings,
uncached aliases, and forced digest collisions. Complete q70 proof bytes and
claims match independently rebuilt uncached controls for both F1 and F4; fresh
setups also verify after original fixed matrices are retired.

The real audit reconstructs the original CPU50/LS71 25-CPU-key block and its five
truth keys from the pinned pristine Image, without Tape, VM execution, CPU MAIN
or new proofs. All 30 fixed roots match the retained accepted block. The audit
rejects a requested cache that observes no spans, adopts no payload, or provides
no useful deduplication across multiple keys.

| Requested retained payload | Uncached | Cached |
|---|---:|---:|
| Native coefficients, including private truths | 5,664,172,288 B | 291,137,920 B |
| Program metadata | 773,785,350 B | 773,785,350 B |
| All audited setup payloads after fixed retirement | 7,648,898,438 B | 2,275,890,054 B |

The CPU keys supplied 3,587 independently owned native polynomials. There were
202 unique groups, 3,385 hits, and 5,373,034,368 duplicate native bytes released.
The cache retained 213,693,824 native bytes plus 25,984 metadata bytes under a
1-GiB limit. Truth coefficients remain private. All coefficient views were
covered by exactly accounted owner allocations.

Same-binary key-only maximum RSS observations were 14,210,203,648 B uncached and
8,885,420,032 B cached. These runs overlapped other engineering work and construct
all keys before retiring original fixed matrices. They are not a controlled
setup-speed comparison, a production lifecycle comparison, or full-block peak
memory measurements. Program metadata sharing and a full cached-block proof /
fresh-verifier observation remain separate follow-ups.

Exact source/tool/input pins and logs are in
`vectors/reports/rv64-word16-execution-20261101/fixed-native-sharing-v1.json`.
