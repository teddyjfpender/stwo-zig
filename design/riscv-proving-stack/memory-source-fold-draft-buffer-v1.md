# Guarded fold PAGE buffering

This source-only cohort changes draft replay/promotion internals already used
by selected CPU source-PAGE collection. Controller, Job, native driver, setup
kernels, proof grammar, original source admissions, premix roots, and detached
proof verification are unchanged. No compiler, proof, guest, segment, device,
or benchmark is run by the implementing agent.

The old reader and promoter each requested the payload in 64-record chunks.
Draft replay also computed a full draft-envelope SHA that had no consumer.
Promotion decoded every operation again despite the exact same bytes already
having passed original Reader decoder, ordinal, and payload-hash checks.

Owner now lazily allocates one reusable serialization buffer through its
original aggregate allocator. Its capacity is bounded by the configured
`max_buffer_records` (1..4096, default4096) and actual PAGE row capacity.
The largest allocation is1,024,000 bytes. An identifiable shared budget remains
retained by the existing Owner lease; teardown frees buffer and metadata before
releasing it. Buffer allocation failure precedes taking the reader lease.
Rewind and later promotion reuse this allocation. No whole stream or decoded
matrix is added. The existing metadata cap still bounds pin/control metadata;
this single PAGE witness buffer is charged to the caller aggregate heap.

Unpublished draft replay hashes its payload once and retains all original
decoder/order/header/length/hash/tail checks. It no longer hashes an unused
full draft envelope. Published replay still checks both original payload hash
and the canonical full Store.Pin hash. The exact final bytes and pin identity
are unchanged.

Only after complete original Reader checks, a pin records a small checked-
inventory digest. The digest binds original source and admission identities,
exact page tuple and length, full independently admitted FoldPlan identity,
and original collected payload SHA. Promotion reconstructs that binding. If
it matches, duplicate decoding may be omitted; otherwise the original decoder
is used. This cache establishes no source/proof authority and contains no
challenge-dependent acceptance. Promotion always re-reads and hashes EVERY
current payload byte and compares the original payload pin, then computes the
canonical full-envelope SHA. A changed file cannot be accepted using a prior
Reader result. A changed payload pin invalidates the inventory digest and
requires original decoding. No stat/mtime/advisory-lock substitute is used.

The reader owns any unread buffer span. Promotion of an earlier page while a
later page still has buffered unread records uses the original 64-record stack
fallback. This prevents the shared buffer from overwriting the live reader's
next operations. Default sequential Job publication consumes each complete
PAGE before promotion, so it uses the larger owner buffer.

For a full4096-record PAGE, each default replay/promotion payload scan makes
one buffered `preadAll` request instead of64. Short OS reads may require more
underlying syscalls. Physical payload bytes are STILL read twice, preserving
current-file corruption rejection. Across unpublished replay+promotion, full
payload SHA work falls from four passes to three; exact header/inventory hashes
remain. The repeated promotion decode pass is omitted only with the validated
inventory binding. Original collection's payload encoding/writing/hash remains
unchanged. These are structural counts, not measured timing or bandwidth.

Observational Work counters record actual buffered requests, payload SHA input
bytes, and promotion decode attempts. No admission, pin or verifier reads
these counters. Fixtures compare1/64/PAGE buffer configurations with the
original Cursor and final Store.load bytes, assert those actual work counts,
check published SHA, test live unread-byte lifetime, mutate current bytes and
the cache/payload pin, exercise buffer OOM/retry and early capacity denial,
and retain the exhaustive owner/load/transaction allocation-failure suites.
No fixture constructs a cryptographic verification receipt.
