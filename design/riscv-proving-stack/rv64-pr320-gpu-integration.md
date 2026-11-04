# PR320 integration with the resident GPU branch

This merge retains the resident/combined/recursive producer and strict receiver
entrypoints, current input bounds, admission policy, and GPU stage callbacks.
Direct execution now starts before independent expected-image initialization;
`inputs-candidate` and block-to-input timestamps are available for diagnostics.
New coefficient-bearing source objects are revalidated from their actual bodies;
copying a prior root/suite/shape cannot bypass that check. Frozen resident-owner
reuse remains admitted through the existing ValidatedCatalogue.

Persisted setup files are **operator-trusted producer acceleration**. Their
SHA-256 checks detect corruption; they do not establish independent authority
against an attacker able to rewrite a cache and its hashes. Every fresh native,
prefix, recursive receiver and schedule-inspection entrypoint therefore rejects
`STWO_ZIG_RV64_SETUP_CACHE`. Unset it for external verification. No persisted
setup roots are admitted by those entrypoints.

The existing bounded ResidentSession continues to derive its own immutable keys
and bypasses this disk cache, including on a cold miss. PR320 persisted caching
is explicit opt-in for non-session candidate production and input diagnostics;
it does not establish a measured resident-GPU setup speedup. Its setup build
thread count and memory remain subject to the selected allocator/admission.

The imported receipts describe the comparison branch before this merge. They
are historical CPU measurements, not merged-head GPU qualification. GNU semantic
checks cover native GPU, GPU recursion and combined products. Actual merged-head
proof parity, independent receiver acceptance and 2-GPU operation remain pending.
