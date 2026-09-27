# Canonical CSP word-memory results

Source-pinned dirty-tree diagnostics on Apple M5 Max / 64 GiB, ReleaseFast,
16 workers, canonical inputs and ELF routes, 70 queries / 26 PoW bits. One cold
sample per full-suite case, all 32 independently verified. Baseline and candidate
use the same parallel lookup counting and bounded coefficient retention. Candidate
adds authenticated public-program preprocessing and full-word memory commitments;
this is an architectural comparison across explicitly versioned root contracts,
not an isolated hash-algorithm comparison or clean-source release qualification.

| Workload | CPU seconds | CPU speedup | Metal seconds | Metal speedup |
| --- | ---: | ---: | ---: | ---: |
| sha256-128 | 6.074877 | 14.00x | 5.447985 | 16.98x |
| sha256-256 | 6.082393 | 14.23x | 5.613816 | 16.64x |
| sha256-512 | 5.991633 | 13.73x | 5.755869 | 16.60x |
| sha256-1024 | 6.056150 | 14.84x | 6.005951 | 15.92x |
| sha256-2048 | 11.696571 | 7.42x | 10.994910 | 8.94x |
| keccak-128 | 10.955671 | 7.54x | 10.569008 | 8.41x |
| keccak-256 | 11.044977 | 7.55x | 10.578587 | 8.45x |
| keccak-512 | 12.072798 | 6.93x | 10.872646 | 8.75x |
| keccak-1024 | 11.691241 | 6.87x | 11.072095 | 8.45x |
| keccak-2048 | 13.610164 | 6.62x | 11.999579 | 8.04x |
| poseidon2_m31-2 | 2.523052 | 8.84x | 2.382662 | 9.12x |
| poseidon2_m31-4 | 3.039839 | 7.53x | 2.829680 | 8.03x |
| poseidon2_m31-8 | 3.569993 | 6.88x | 3.578220 | 6.37x |
| poseidon2_m31-12 | 4.227793 | 5.69x | 4.020119 | 5.95x |
| poseidon2_m31-16 | 5.258890 | 5.01x | 4.801477 | 5.26x |
| ecdsa_secp256k1-32 | 3.659416 | 1.85x | 3.783270 | 1.82x |

## Matched ECDSA measurements

Separate baseline/candidate/candidate/baseline runs, two cold processes per arm
and backend, with identical stage diagnostics enabled in both arms and each
artifact freshly verified using its matching CLI. Both
use the pinned odd-parity precompile ELF and 1,828 execution steps. Medians:

| Backend | Baseline seconds | Candidate seconds | Speedup |
| --- | ---: | ---: | ---: |
| cpu | 6.902855 | 3.557679 | 1.94x |
| metal | 7.097355 | 3.822391 | 1.86x |

Raw reports include execution, witness, admission, proving, artifact encoding,
fresh verification and process-lifetime memory. Historical 0.881876 s CPU ECDSA
used an earlier execution-memory contract; these results do not redefine that
historical measurement. Recursive qualification is recorded separately and must
not be presented as a matched recursion speedup.
