# Previous complete CSP results (September 8 source checkpoint)

Historical diagnostic measurements; these are not current-source results.
CSP proving time includes execution, witness construction and proving; verification is separate.

| Workload | Size | CPU prove s | Metal prove s | CPU verify ms | Metal verify ms |
| --- | ---: | ---: | ---: | ---: | ---: |
| sha256 | 128 | 1.008 | 0.471 | 121.02 | 69.31 |
| sha256 | 256 | 0.867 | 0.466 | 117.30 | 69.90 |
| sha256 | 512 | 0.727 | 0.454 | 119.39 | 69.64 |
| sha256 | 1024 | 0.858 | 0.496 | 121.25 | 71.03 |
| sha256 | 2048 | 0.826 | 0.492 | 123.04 | 69.29 |
| keccak | 128 | 0.620 | 0.433 | 118.85 | 69.41 |
| keccak | 256 | 0.709 | 0.455 | 118.02 | 69.05 |
| keccak | 512 | 0.677 | 0.469 | 120.97 | 69.67 |
| keccak | 1024 | 0.710 | 0.486 | 119.56 | 69.29 |
| keccak | 2048 | 0.930 | 0.543 | 123.15 | 71.18 |
| poseidon2_m31 | 2 | 0.706 | 0.466 | 120.09 | 70.16 |
| poseidon2_m31 | 4 | 0.781 | 0.497 | 119.36 | 70.12 |
| poseidon2_m31 | 8 | 1.118 | 0.562 | 122.66 | 71.40 |
| poseidon2_m31 | 12 | 0.911 | 0.581 | 138.09 | 72.36 |
| poseidon2_m31 | 16 | 1.430 | 0.680 | 139.45 | 75.34 |
| ecdsa_secp256k1 | 32 | 4.699 | 2.748 | 177.34 | 126.48 |
