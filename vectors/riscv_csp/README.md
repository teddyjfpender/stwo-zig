# RISC-V EthProofs CSP fixtures

This directory contains the self-authenticating workload boundary for the
standard RISC-V client-side proving benchmark. Its authority is
[`manifest-v2.json`](manifest-v2.json), not the filenames alone.

The manifest pins:

- `privacy-ethereum/csp-benchmarks` commit
  `269c43cc32d3127e3d9ce74d20652887d894cca3`;
- the CSP input generators, size metadata, Rust toolchain, and the
  source-isolated adapter used for k256 and M31 values;
- every guest source, manifest, lockfile, target configuration, and linker
  script used by the workload;
- the committed RV32IM ELF bytes;
- deterministic target-specific inputs;
- expected output digests and exact retirement counts; and
- whether each target uses a precompile.

The current matrix has sixteen proof rows:

| Target | Sizes | Input contract | Classification |
| :--- | :--- | :--- | :--- |
| SHA-256 | 128, 256, 512, 1024, 2048 bytes | CSP-seeded bytes | canonical CSP zkVM workload |
| Keccak-256 | 128, 256, 512, 1024, 2048 bytes | CSP-seeded bytes | canonical CSP zkVM workload |
| Poseidon2-M31 | 2, 4, 8, 12, 16 field elements | CSP-seeded canonical M31 elements | field-native extension |
| secp256k1 ECDSA | one 32-byte digest | CSP k256 digest, uncompressed SEC1 key, and `r || s` signature | canonical CSP zkVM workload |

The original manifest describes software RV32IM workloads (`uses_precompile=false`).
The additional authenticated [ECDSA precompile manifest](ecdsa-precompile-v1.json)
provides the accelerated full-guest path selected with `--execution-mode precompile`.
Other targets retain their software guests.
SHA-256 and Keccak inputs are a little-endian `u32` byte length followed by
the shared message. Poseidon2-M31 inputs are a little-endian element count
followed by canonical little-endian M31 elements. ECDSA inputs are
`digest[32] || public_key[65] || signature[64]`.

Poseidon2-M31 is deliberately not called CSP's canonical `poseidon2` target.
The latter is BN254 in the pinned generic CSP generator. This row instead uses
the repository's M31-native Poseidon2 guest with CSP's exact seeded M31 input
convention and is reported as `csp_field_native_extension`. Classic Poseidon,
BN254 Poseidon2, and P-256 ECDSA remain explicitly unsupported rather than
being represented by near-matches.

Ordinary benchmark execution trusts neither an ambient CSP checkout nor an
unrecorded Rust toolchain. The driver authenticates every committed file before
execution, checks the guest output and cycle count through the trace diagnostic,
generates a secure proof, validates the benchmark/report contract, and verifies
the retained proof in a separate process.

The negative fixture changes one byte of the exact k256 signature. The software
guest must return the all-zero rejection value at the pinned retirement count;
the driver proves and independently verifies this rejection separately from the
positive performance rows. In precompile mode it is explicitly recorded as a
software fallback, not a fast rejection proof.

Use the repository build step:

```sh
zig build riscv-csp-bench -Doptimize=ReleaseFast
```

To audit fixture derivation, first build the locked CSP utility in a clean
checkout at the pinned commit, then pass that checkout to:

```sh
python3 scripts/riscv_csp_benchmark.py \
  --audit-csp-source /path/to/csp-benchmarks \
  --targets ecdsa_secp256k1 --sizes 32 --warmups 0 --samples 1
```

The source audit recompiles
[`upstream_fixture_dump.rs`](upstream_fixture_dump.rs) against the pinned CSP
`utils` library and regenerates all eleven distinct inputs plus the invalid
signature fixture. It does not substitute generated values after a mismatch.

The repository-owned guests are reproducible with their checked-in locked
toolchains:

```sh
(cd vectors/riscv_guests/poseidon2_m31 && cargo build --release --locked)
(cd vectors/riscv_guests/ecdsa_secp256k1 && cargo build --release --locked)
```

The resulting release ELFs must be byte-identical to the copies under
`vectors/riscv_csp/guests/`; the manifest authenticates both sources and
committed binaries.

The benchmark driver rejects source-pin drift, dirty upstream state, fixture
mutation, output mismatch, retirement-count drift, dirty prover identity,
unverified proofs, and proof/report/receipt binding mismatches.

`manifest-v1.json` remains only as provenance for the earlier retained
SHA-256/Keccak report. New benchmark runs use v2.

## Latest full suite with ECDSA precompile — 2026-09-21

These are full guest proofs at **70 queries / 26 PoW bits**, on Apple M5 Max,
from clean snapshot `af05b7401a77`. One warmup and ten measured verified samples
per workload/backend; means include execution + witness + proving, with verification
reported separately. **ECDSA now uses the authenticated precompile guest.**

| Backend | Mean prove | Median prove | Sample range | Mean verify |
| :--- | ---: | ---: | ---: | ---: |
| CPU | **881.6 ms** | 877.5 ms | 873.8–899.8 ms | 171.2 ms |
| METAL | **863.7 ms** | 862.6 ms | 855.1–880.3 ms | 100.5 ms |

| Workload | Size | CPU prove (s) | Metal prove (s) |
| :--- | ---: | ---: | ---: |
| sha256 | 128 | 0.776 | 0.442 |
| sha256 | 256 | 0.697 | 0.447 |
| sha256 | 512 | 0.603 | 0.456 |
| sha256 | 1024 | 0.698 | 0.457 |
| sha256 | 2048 | 0.672 | 0.460 |
| keccak | 128 | 0.541 | 0.415 |
| keccak | 256 | 0.614 | 0.424 |
| keccak | 512 | 0.591 | 0.432 |
| keccak | 1024 | 0.633 | 0.442 |
| keccak | 2048 | 0.796 | 0.484 |
| poseidon2_m31 | 2 | 0.617 | 0.511 |
| poseidon2_m31 | 4 | 0.680 | 0.539 |
| poseidon2_m31 | 8 | 0.969 | 0.530 |
| poseidon2_m31 | 12 | 0.805 | 0.556 |
| poseidon2_m31 | 16 | 1.260 | 0.590 |
| ECDSA (precompile) | 32 | 0.882 | 0.864 |

All 320 measured proofs verified. Retained proofs were independently verified
again, and both backends produced matching proof bytes and statements for every
workload. Each backend also proved and independently verified the bad-signature
fixture's software rejection. ECDSA is 1,828 guest instructions, with a 3,748,143-byte
proof; the timings include caller/memory composition and guest checks.

[Detailed results, memory, proof sizes, raw evidence and reproduction](../reports/recursive-product-20260921/csp-accelerated-suite-v1/README.md).
Use `--execution-mode precompile` for these results; software remains an explicit
comparison mode and the default for historical runner consumers.

## Recorded full software suite — 2026-09-21

Measured on Apple M5 Max, ReleaseFast, 70 queries / 26 PoW bits, one warmup
and ten measured verified samples per row. Values are mean execution + witness
+ proving seconds; verification is separate. This table is the software baseline,
not the accelerated ECDSA result. [Raw CPU/Metal reports and provenance](../reports/recursive-product-20260921/csp-current-suite-v1/README.md).

| Workload | Size | CPU prove (s) | Metal prove (s) |
| :--- | ---: | ---: | ---: |
| sha256 | 128 | 0.754 | 0.441 |
| sha256 | 256 | 0.670 | 0.411 |
| sha256 | 512 | 0.582 | 0.403 |
| sha256 | 1024 | 0.668 | 0.428 |
| sha256 | 2048 | 0.640 | 0.429 |
| keccak | 128 | 0.523 | 0.388 |
| keccak | 256 | 0.594 | 0.402 |
| keccak | 512 | 0.574 | 0.418 |
| keccak | 1024 | 0.614 | 0.427 |
| keccak | 2048 | 0.779 | 0.461 |
| poseidon2_m31 | 2 | 0.602 | 0.428 |
| poseidon2_m31 | 4 | 0.660 | 0.448 |
| poseidon2_m31 | 8 | 0.921 | 0.489 |
| poseidon2_m31 | 12 | 0.778 | 0.515 |
| poseidon2_m31 | 16 | 1.217 | 0.572 |
| ecdsa_secp256k1 | 32 | 3.737 | 1.937 |

Poseidon2-M31 rows are the field-native extension described above. These retained
historical reports checked the negative fixture by execution; the current runner
also produces a full rejection proof. Their schemas and original claims remain
unchanged.

## Accelerated ECDSA execution

```sh
python3 scripts/riscv_csp_benchmark.py --backend cpu --execution-mode precompile \
  --targets ecdsa_secp256k1 --sizes 32 --workers 16 --report-out /tmp/csp/cpu.json
python3 scripts/riscv_csp_benchmark.py --backend metal --execution-mode precompile \
  --targets ecdsa_secp256k1 --sizes 32 --workers 16 --report-out /tmp/csp/metal.json
```

Omit `--targets` and `--sizes` to run the complete mixed suite. This mode proves
the RISC-V caller, memory bindings, recovery computation, low-S/key checks and
public output. Host parity selection is not a trusted verdict. Unsupported inputs
receive full software proofs. See the [guest contract](../riscv_guests/ecdsa_secp256k1_precompile/README.md)
and [runner documentation](../../design/riscv-proving-stack/csp-benchmarks.md).
The earlier 228/165 ms figures measured an isolated provider and are not full
CSP guest results.
