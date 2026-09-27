# Partial canonical CSP baseline

Source-pinned dirty-tree diagnostic, ReleaseFast, 16 workers, 70 queries / 26 PoW bits.
One cold sample per case; each recorded success has independent fresh verification.
These use the coefficient-cache binaries, before public-program preprocessing.

| Case | End-to-end seconds | Physical peak GiB |
| --- | ---: | ---: |
| cpu-sha256-128 | 85.044773 | 36.62 |
| cpu-sha256-256 | 86.553799 | 36.63 |
| cpu-sha256-512 | 82.243874 | 36.66 |
| cpu-sha256-1024 | 89.891422 | 36.71 |
| cpu-sha256-2048 | 86.786921 | 36.78 |
| cpu-keccak-128 | 82.595478 | 36.62 |
| cpu-keccak-256 | 83.396983 | 36.63 |
| cpu-keccak-512 | 83.656043 | 36.68 |
| cpu-keccak-1024 | 80.313545 | 36.77 |
| cpu-keccak-2048 | 90.055408 | 36.96 |
| cpu-poseidon2_m31-2 | 22.306563 | 9.60 |
| cpu-poseidon2_m31-4 | 22.900549 | 9.69 |
| cpu-poseidon2_m31-8 | 24.552476 | 9.92 |
| cpu-poseidon2_m31-12 | 24.074095 | 10.02 |
| cpu-poseidon2_m31-16 | 26.362065 | 10.21 |
| cpu-ecdsa_secp256k1-32 | 6.767174 | 3.60 |
| metal-sha256-128 | 92.526896 | 41.23 |

Remaining cases are still running. See suite/results.json and the raw artifacts.
