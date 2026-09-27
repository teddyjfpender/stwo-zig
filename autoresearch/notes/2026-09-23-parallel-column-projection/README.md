# Bounded parallel projection into witness columns

The refreshed Keccak profile (`../2026-09-23-post-tail-profile`) still identifies logical-row projection as a substantial serial prepareMain stack after the shared Merkle improvements. The candidate splits independent destination column ranges across at most four explicitly leased pool workers for chunks with at least 64 rows and 64 destination columns. The coordinator writes one partition and joins all helpers before the source rows or stack contexts leave scope. If no pool/capacity is available, projection remains serial. Submission failure computes that partition synchronously while draining any previously submitted jobs. No row layout, padding, proof parameter or hash change is intended.

`STWO_ZIG_SERIAL_COLUMN_PROJECTION=1` selects the preceding serial path. Tiny projections keep the existing path. The focused ReleaseSafe projection tests pass, including independent inverse-domain mapping, partial and full chunks, nonzero offsets, untouched padding, three-worker uneven column splits and a completely occupied pool forcing fallback. Both CPU and Metal ReleaseFast builds passed.

Canonical comparison uses the same binary per backend, 70 queries / 26 PoW bits, 16 workers, ECDSA precompile, three samples per arm and no explicit warmup. Fixed serial/parallel ordering limits confidence in small E2E differences. Complete transaction includes admission, encoding and fresh verification. Proof hashes must match the preceding full-suite artifact and each retained proof is independently verified.


| Workload | CPU serial → parallel s | Metal serial → parallel s |
| --- | ---: | ---: |
| ecdsa_secp256k1-32 | 0.995144 → 1.007585 | 1.104352 → 1.092782 |
| sha256-128 | 2.337734 → 2.290275 | 2.190672 → 2.132204 |
| sha256-2048 | 4.028111 → 3.950977 | 3.787798 → 3.716176 |
| keccak-128 | 4.024792 → 3.941043 | 3.730229 → 3.644266 |

All 48 timed proofs verified in process and all 16 retained artifacts freshly verified with unchanged full-suite proof hashes. ECDSA total differences are small and mixed. Larger cases show consistent witness-stage savings:

| Workload | CPU witness serial → parallel s | Metal witness serial → parallel s |
| --- | ---: | ---: |
| sha256-128 | 0.658819 → 0.593783 | 0.656566 → 0.590262 |
| sha256-2048 | 0.868208 → 0.759406 | 0.849413 → 0.750976 |
| keccak-128 | 0.909676 → 0.788661 | 0.886672 → 0.779430 |

This is a modest shared witness-stage improvement. Total gains are only a few percent; the original large SHA/Keccak performance remains the target, and a 10× recursion improvement remains unproven. This is not a new full-suite result. Canonical parent functional qualification passed (`canonical-parent.log`): child and parent use 70 queries / 26 PoW bits and independently verify; transcript replay, fixed-plan reuse, worker rekey and outputs outliving the worker all pass. Parent artifact is 850,599 bytes, child 494,897 bytes. Peak tracked memory is 15,001,593,034 bytes below the 25,769,803,776-byte cap. This is a functional base-parent check, not all recursion families or a matched latency benchmark.
