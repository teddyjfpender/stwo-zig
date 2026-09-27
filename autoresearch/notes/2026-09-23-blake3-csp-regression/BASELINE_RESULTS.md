# Complete pre-architecture CSP baseline

Apple M5 Max / 64 GiB; ReleaseFast; 16 workers; canonical inputs and ELF routes;
70 queries / 26 PoW bits; one cold sample per case. All 32 proofs independently
verified. Source-pinned dirty-tree diagnostics, not clean-source release admission.
These binaries include parallel lookup counts and bounded coefficient retention,
but precede public-program preprocessing and word-memory commitments.

| Workload | CPU complete seconds | Metal complete seconds |
| --- | ---: | ---: |
| sha256-128 | 85.044773 | 92.526896 |
| sha256-256 | 86.553799 | 93.401719 |
| sha256-512 | 82.243874 | 95.538633 |
| sha256-1024 | 89.891422 | 95.626872 |
| sha256-2048 | 86.786921 | 98.325996 |
| keccak-128 | 82.595478 | 88.866426 |
| keccak-256 | 83.396983 | 89.419049 |
| keccak-512 | 83.656043 | 95.091462 |
| keccak-1024 | 80.313545 | 93.597853 |
| keccak-2048 | 90.055408 | 96.531528 |
| poseidon2_m31-2 | 22.306563 | 21.741383 |
| poseidon2_m31-4 | 22.900549 | 22.719878 |
| poseidon2_m31-8 | 24.552476 | 22.807238 |
| poseidon2_m31-12 | 24.074095 | 23.939452 |
| poseidon2_m31-16 | 26.362065 | 25.248587 |
| ecdsa_secp256k1-32 | 6.767174 | 6.901187 |

ECDSA uses the pinned odd-parity precompile ELF, with 1,828 execution steps.
Raw commands, phase reports, process memory, proof hashes and independent
verification outputs are under `suite/`. The previous CPU/Metal products and
matching Metal AOT bundle are preserved under `baseline-products/`.
