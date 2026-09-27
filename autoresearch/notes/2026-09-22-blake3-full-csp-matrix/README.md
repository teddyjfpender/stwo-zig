## Full BLAKE3 CSP matrix — 2026-09-22

Completed all 16 cases on CPU and authenticated-AOT Metal from clean local source
snapshot `348b9a02c2bfc33487a1f653aef7152ce83ae2b0` (not published).
Every retained proof independently verified; both backends also proved and verified
the bad-signature rejection case. All rows use 70 queries and 26 PoW bits, with
recursion disabled. ECDSA uses the typed recovery precompile; other targets execute
software guests, including the intentionally preserved Poseidon guest workload.

Apple M5 Max, 16 workers, ReleaseFast, one sample, no warmups, battery power.
These are local qualification measurements, not a controlled performance comparison.
Prove includes execution, witness and proof generation; verification is separate.

| Workload | Size | CPU prove (s) | CPU verify (s) | Metal prove (s) | Metal verify (s) |
|---|---:|---:|---:|---:|---:|
| sha256 | 128 | 2.074658 | 0.192373 | 0.421341 | 0.094871 |
| sha256 | 256 | 2.206294 | 0.191040 | 0.452077 | 0.096447 |
| sha256 | 512 | 2.295138 | 0.193408 | 0.423100 | 0.093192 |
| sha256 | 1024 | 3.894334 | 0.192097 | 0.508788 | 0.093122 |
| sha256 | 2048 | 2.719380 | 0.196893 | 0.458731 | 0.093496 |
| keccak | 128 | 2.585501 | 0.194410 | 0.413153 | 0.099302 |
| keccak | 256 | 1.805518 | 0.198111 | 0.408048 | 0.095944 |
| keccak | 512 | 3.879529 | 0.257437 | 0.443229 | 0.092867 |
| keccak | 1024 | 3.596645 | 0.225637 | 0.472704 | 0.094817 |
| keccak | 2048 | 3.811401 | 0.267551 | 0.471172 | 0.106059 |
| poseidon2_m31 | 2 | 2.457577 | 0.224616 | 0.479333 | 0.098394 |
| poseidon2_m31 | 4 | 2.285950 | 0.223041 | 0.519534 | 0.098360 |
| poseidon2_m31 | 8 | 1.712028 | 0.217501 | 0.514272 | 0.107732 |
| poseidon2_m31 | 12 | 2.197131 | 0.232287 | 0.551292 | 0.099131 |
| poseidon2_m31 | 16 | 3.596061 | 0.245193 | 0.606420 | 0.098611 |
| ecdsa_secp256k1 | 32 | 1.096581 | 0.166682 | 0.907835 | 0.091660 |

The earlier 2.523295 s BLAKE3 ECDSA CPU result included 1.640898 s of serial
PoW search; profiling attributed 91% of its difference from the paired BLAKE2s
measurement to PoW. Bounded pooled search fixed that regression. Current full-suite
ECDSA measures 1.096581208 s CPU and 0.907834583 s Metal, versus the historical
approximately 0.882 s reference. The separate Metal AOT harness measured
0.881876417 s witness/proving plus 0.000743667 s execution. Do not interchange
harness witness/proving, suite execution-inclusive proving, verification, or process
wall time. Single samples cannot establish a residual regression or its cause.

This qualifies explicit BLAKE3 suite selection; it does not promote defaults or
complete the remaining Poseidon statement-identity and recursion migration.

Raw reports and command logs are retained alongside this note. Full artifact paths
are recorded in the reports and currently reside in the isolated snapshot directory.
