# Miller immutable outer source-key cache

The opt-in `miller_local_gkr/outer_key_cache.zig` cache constructs one R6 authority per immutable Miller source class. It keeps each request's span, ordinal, statement, transcript and nine-word expected output separate. The R6 root producer and source receiver can opt in independently. CPU cache generalization remains separate.

`Cache.init(backing, byte_limit, max_entries)` owns a retaining SharedHostBudget. The budget covers cache state, entries, source-only circuit construction scratch, independently constructed fixed keys and retained authority. It enforces the requested byte cap numerically. Caller native keys, actual leaf witness/prover scratch, serialized proofs and pool stacks are outside this cache cap and require the surrounding request budget. There is no global cache or eviction. A full class roster refuses another class before constructing it.

A class fingerprint binds the independently supplied native Miller key identity, full 36-byte fixed root, profile identity, canonical frontier/arithmetic logs, validated GKR coefficient-length advice and concrete semantic source files. Source dimensions and round counts come from the native key's four-instance roster; only the previously legal 0..4 coefficient lengths are advice. There is no API accepting an outer verifying key. The immutable source is built from the source-owned canonical span calls=1, first_id=1. Request words are variables constrained by the complete native verifier circuit, rather than immutable setup constants.

Acquire a linear lease with `acquireForProving(native_key, span, ordinal, lengths)`, validate its `requireView`, and use `proverKey()` for the existing R6 prover. Release the lease after use. `finishProving()` refuses while any lease exists, then retires prover-only buffers once per class. No leaf may retire a shared key individually. Verification leases can continue using the retained source authority. `deinit()` also refuses live leases. Cache acquisition and lifecycle operations are externally serialized; the implementation introduces no shared mutation inside proof workers.

A final receiver must construct a separate `Cache.initForVerification` from its independently rebuilt native source keys and bounded templates. It independently derives the authority and immediately releases prover data. Reusing a producer cache is not independent admission. The nine-word expected output still comes from receiver-owned statement/manifest/span/claims framing and whole-execution closure. A cache hit never establishes execution acceptance.

The small physical qualification builds the cached source with first_id=1 and proves a real native Miller fragment with first_id=7. Its key/root equal those of the independently derived concrete `SourceLeaf.initLocalMiller` factory. Both produce exactly the same 629,628 proof bytes, SHA256 `24f758dfcdb26370e2ebc73a85f166b51cd66018ac65b0db3a6ce5bb69b4931b`. A separately reconstructed native key and fresh verification-only cache accept those bytes; a changed request or ninth expected output is rejected. The earlier source-class gate separately establishes full topology/usage equality for 1023/first1 and 1022/first17 at logs 15/15.

The lifecycle gate records one miss for two distinct request spans, refuses premature retirement/destruction, separates changed coefficient-length classes, and reconstructs the same receiver key independently. Its tiny 8/15 class peaks at 647,619,742 requested bytes while constructing source authority; after retirement the cache retains 47,979 requested bytes. These are memory measurements from the source/lifecycle fixture. Correctness proving overlapped another task, so no wall-time improvement or heavy-block speedup is claimed. Security remains the 128-bit target under documented assumptions, with `security_qualified=false`.

Integration must preserve source-only factories, per-request public framing and independent final receiver authority. The verifier-only ownership adapter and producer class barrier below are qualified. Copying the owned `SourceLeaf.authority` value would double-own its buffers; both adapters instead retain linear leases.


## Verifier-only root integration

`RootRuntime.Limits.miller_cache_bytes` defaults to zero and accepts at most 8 GiB. A nonzero value creates a verification-only child cache charged to the caller's request budget. The cached authority has already released fixed/prover buffers before a `SourceLeaf` may borrow it. The leaf owns only its source binding metadata and a linear lease; `SourceLeaf.key()` provides the shared immutable authority. The legacy `.authority` value is reserved for owned constructors and is never populated by the borrowed constructor.

The root CLI exposes this resource choice as `--miller-cache-mib=N` (0..8192),
only with `--r6 --miller-local-gkr verify`. It rejects the flag on proving or
classic verification rather than silently ignoring it. For example:

```sh
rv64-op-root --r6 --truth-local-gkr --miller-local-gkr --miller-cache-mib=1024 verify CONFIG SOURCE_ONLY ROOT
```

This changes retention within one receiver request, not its statement, suite or
transcript. The default remains zero; the total caller budget still applies.

Root topology construction uses that accessor. It owns any new parent authorities, and never destroys a child cache entry. Cleanup destroys topology parents, releases every source leaf, and then destroys the cache. Source guards and template validation run before acquisition. Only `OutOfMemory` and the cache's entry-cap refusal can fall back to the independently constructed uncached source path; profile, expected-statement, cap-variant, template and class failures propagate. The cache cannot turn a failed policy check into alternate admission.

The retained complete CPU+Miller root is accepted unchanged with a 1 GiB cache cap and with a deliberately insufficient 4 KiB cap that forces uncached fallback. Its 693,812 bytes have SHA256 `edd53de28a56bdb2272f165cb9977a5b658427e82b0082d4d64e72e47fa06c32`. Fresh source-only reception reads no `native-op.bin`; the cached path also passes the existing wrong-VK, balanced service debt, receipt, membership, terminal-policy and corruption controls. Both contexts release all heap/external budget custody. This is a correctness gate, not a cache speed benchmark: the fixture has one Miller leaf and has no repeated-class hit to amortize.

## Producer class barrier

The producer separately enables `native_omul.recursion.Limits.miller_cache_bytes`
(default0, maximum8GiB), or `--miller-prover-cache-mib=N` with
`--r6 --miller-local-gkr prove`. Verification and proving cache flags are
mutually exclusive resource choices. Neither changes the proof protocol.

Each cached source leaf holds a proving lease while generating and proving its
actual assignment. After physical capture/verification it calls
`Lease.releaseProving()`: this irreversibly drops the proving capability but
preserves a read-only key lease. Later leaves may still acquire the same class
for proving. Once every native callback has completed, the Session calls
`finishProvingWithVerificationLeases()`. That barrier refuses any remaining
proving lease, retires large proving data once per class, and closes further
proving acquisition. Read-only leases keep the immutable key alive through the
fold tree. The historical `finishProving()` still refuses every live lease;
destruction also retains that stronger rule.

Pending nodes point into heap-owned cache entries or the preallocated source
leaf array. Cleanup destroys nodes, releases source leaves, then destroys the
cache; topology parents end before their child metadata disappears. Acquisition
errors fall back only for memory/class capacity, never source-policy errors.

The complete synthetic CPU+Miller root was produced with a1GiB cache and with
a4KiB cap forcing uncached fallback. All native proof bytes, three recursive
nodes, the final root and both sidecars match the uncached control exactly.
A separate source-only receiver accepts the cached result and rejects physical,
membership, wrong-key, balanced-debt and terminal substitutions. Lifecycle and
physical tests cover shared-class hits, direct proving-lease release, one-way
downgrade and retained verifier metadata. The fixture has only one Miller leaf:
its47.143s /47.687s qualifications do not establish an amortized speedup. The
[receipt](../../vectors/reports/rv64-opstack-performance-20261109/miller-local-gkr/producer-cache-root-v1.json)
records exact hashes, resource scope and coverage. No heavy block was rerun.
