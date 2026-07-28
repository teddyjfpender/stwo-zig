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

Every workload is ordinary RV32IM software and `uses_precompile` is false.
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
the driver records this check separately from the positive performance rows.

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
