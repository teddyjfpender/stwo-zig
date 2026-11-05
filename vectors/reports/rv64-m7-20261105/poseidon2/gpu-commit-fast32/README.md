# Measured 32-bit M31 arithmetic falsifier

[M] Same complete resident slab-to-retained-Merkle-tree benchmark as prototype. The benchmark-only generator replaces canonical M31 add and multiply reductions with32-bit add plus mul_lo32/mul_hi32 and two Mersenne folds. Official parameters, framing and byte results do not change. No production backend selects this generated header.

Independent all-node CPU parity passes at six widths. All nine large geometry P2roots AND Blake roots exactly match the previous GPU implementation. Native Core P2 arithmetic/framing KATs remain the independent reference; this is not a full-proof parity gate.

| columns | log rows | Blake ms | P2 fast32 ms | P2/Blake | P2 GiB/s |
|---:|---:|---:|---:|---:|---:|
| 47 | 14 | 0.039648 | 0.767104 | 19.35 | 3.74 |
| 128 | 14 | 0.047936 | 0.898080 | 18.73 | 8.70 |
| 479 | 14 | 0.080448 | 1.444512 | 17.96 | 20.24 |
| 47 | 17 | 0.067040 | 1.272320 | 18.98 | 18.04 |
| 128 | 17 | 0.095552 | 1.907360 | 19.96 | 32.77 |
| 304 | 17 | 0.169920 | 3.302112 | 19.43 | 44.95 |
| 479 | 17 | 0.236544 | 4.590944 | 19.41 | 50.95 |
| 128 | 20 | 0.439136 | 8.699456 | 19.81 | 57.47 |
| 479 | 20 | 1.364832 | 26.328608 | 19.29 | 71.07 |

P2 is2.4–2.8x faster than the original scalar prototype, but still17.96–19.96x slower than production prefixed Blake at matched geometry. At479columns and2^20rows, actual GPU-s are0.0263286076 versus0.00136483204. This absolute26.33ms may still be acceptable if full recursive-cell savings offset aggregate commitment cost; the ratio alone cannot decide the backbone.

Measured scope excludes FFT/LDE, transfers, allocations, prefix-bank reuse, openings, proof generation, host waiting and end-to-end requests. Same hardware, all tree levels retained, two warmups and five alternating measured repetitions. Receipt pins binary, original/generated header and baseline receipt SHA256. build.log records generated-header metadata and compiler resource diagnostics. GPU lock is held for the complete numerical/timing pass.

For canonical a,b<p, a+b<2p<2^32. Splitting a*b into low32/high32 gives x=(low&0x7fffffff)+(low>>31)+(high<<1), which fitsu32; folding and conditional subtraction gives exactly product modp. Large generated inputs span canonical M31 values; no field-value-dependent lane is dropped. Other prototype code is unchanged.

This is a current-kernel result, not an intrinsic Poseidon lower bound or a complete block/request measurement. A per-block estimate must charge actual widths/heights and shared LDE separately, and distinguish hypothetical native-height prefix reuse from this flat resident slab route.
