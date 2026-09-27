## Compact-provider CSP results (2026-09-23)

Apple M5 Max / 64 GiB, ReleaseFast, 16 workers. Three samples per positive
workload, zero explicit warmups; the table reports full end-to-end medians.
All use canonical inputs and 70 queries / 26 PoW bits. Timings include execution,
witness generation, key admission, proving, artifact encoding and fresh verification.
All 32 retained positive proofs and both software rejection proofs independently
verify in separate processes. These are source-pinned local dirty-tree results.

The compact range providers are selected by the shared product request path for
base RISC-V and both extension profiles. ECDSA uses the pinned precompile guest
(1,828 RISC-V steps); its result is not an isolated precompile timing.

| Workload | CPU seconds | Metal seconds |
| --- | ---: | ---: |
| sha256-128 | 4.184246 | 4.098316 |
| sha256-256 | 4.267653 | 4.248658 |
| sha256-512 | 4.620403 | 4.484166 |
| sha256-1024 | 4.769043 | 4.652974 |
| sha256-2048 | 9.430245 | 9.424749 |
| keccak-128 | 9.237800 | 9.031566 |
| keccak-256 | 9.318880 | 9.156700 |
| keccak-512 | 9.569116 | 9.512179 |
| keccak-1024 | 9.883510 | 9.799122 |
| keccak-2048 | 10.832139 | 10.638965 |
| poseidon2_m31-2 | 2.178520 | 1.466811 |
| poseidon2_m31-4 | 1.615393 | 1.500965 |
| poseidon2_m31-8 | 1.939909 | 1.824423 |
| poseidon2_m31-12 | 2.057391 | 2.016272 |
| poseidon2_m31-16 | 2.263120 | 2.317605 |
| ecdsa_secp256k1-32 | 1.480730 | 2.195562 |

Metal ECDSA records 1,666 GPU dispatches and
232 CPU fallbacks per proof. This is the Metal backend's
mixed execution path, not an exclusively GPU proof; raw reports retain
the device counts for every workload and sample.

The bad-signature software fallback also proves rejection: CPU **61.889560 s**,
Metal **62.730673 s** (one sample each). These are
separate rejection proofs, not accelerated ECDSA performance rows.

The historical 0.881876-second CPU ECDSA result also used precompiles.
The current CPU result has not recovered that historical latency.
Compact-child recursion is separately qualified at 70 queries / 26 PoW bits
for base RISC-V, Ethereum and guest Poseidon; those tests are not CSP timings.

[Source, qualification and all raw reports/proofs](README.md).
