# Shared CPU BLAKE3 proof-of-work batching

The word-memory CSP checkpoint measured approximately 0.85 seconds in CPU
proof-of-work for the canonical ECDSA case. This experiment changes the shared
CPU prover search, with no workload identifiers, transcript changes, weakened
difficulty, or skipped nonces. Metal retains its backend-owned GPU search.

The CPU pool precomputes the chaining value for the 64-byte public prefix once,
then evaluates four independent nonce candidates with 128-bit SIMD using the
canonical seven-round BLAKE3 G schedule. Workers retain strided deterministic
search and atomic minimum selection; the final nonce is validated by the
canonical channel implementation. Allocation and worker-pool policy are unchanged.

Qualification: the focused `test-pcs-blake3-pow` step passes all four tests,
including streaming-hash word parity at nonce carries and difficulties through
32 bits, lowest-nonce parity across worker counts, and partial batches near
nonce exhaustion. An initial compile error in a test integer annotation was
corrected before this successful run. `zig fmt --check` passes for changed files.

The benchmark uses baseline/candidate/candidate/baseline cold CPU processes,
16 workers, 70 queries, and 26 PoW bits. Both arms enable identical diagnostics.
The baseline is the preserved word-memory candidate binary. Every artifact must
verify independently, and all four deterministic proof hashes must agree.
Results: CPU end-to-end median **3.129957 → 2.503791 seconds (1.25×)**.
PoW-stage median **0.791831 → 0.148075 seconds (5.35×)**. Two cold samples
per arm; raw samples are in `ecdsa-pairs/results.json`. All four proofs freshly
verified and have identical SHA-256
`6c03a7daeac2914fd7ce2f8fc81337986a179c31ed5f27ed5c2b6d8fb9f6d103`.
The baseline is faster in this run than the earlier 3.56-second checkpoint, so
use this matched 3.13-second baseline to attribute the improvement. This does not by itself resolve
the remaining CSP regression or establish a recursion speedup.
