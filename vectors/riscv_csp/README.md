# RISC-V EthProofs CSP fixtures

This directory contains the self-authenticating workload boundary for the
standard RISC-V client-side proving benchmark. Its authority is
[`manifest-v1.json`](manifest-v1.json), not the filenames alone.

The manifest pins:

- `privacy-ethereum/csp-benchmarks` commit
  `269c43cc32d3127e3d9ce74d20652887d894cca3`;
- the CSP input generator, size metadata, and Rust toolchain;
- the exact SHA-256 and Keccak guest source and lockfile hashes;
- the committed RV32IM ELF bytes;
- deterministic CSP inputs at 128, 256, 512, 1024, and 2048 bytes;
- expected output digests and exact retirement counts; and
- whether each target uses a precompile.

Each input file is encoded as a little-endian `u32` message length followed by
the exact CSP-generated message. SHA-256 and Keccak share those message bytes.
The guests return one raw 32-byte digest through the zkVM output region.

Ordinary benchmark execution trusts neither an ambient CSP checkout nor an
unrecorded Rust toolchain. The driver authenticates every committed file before
execution, checks the guest output and cycle count through the trace diagnostic,
generates a secure proof, validates the benchmark/report contract, and verifies
the retained proof in a separate process.

Use the repository build step:

```sh
zig build riscv-csp-bench -Doptimize=ReleaseFast
```

To audit fixture derivation, first build the locked CSP utility in a clean
checkout at the pinned commit, then pass that checkout to:

```sh
python3 scripts/riscv_csp_benchmark.py \
  --audit-csp-source /path/to/csp-benchmarks \
  --targets sha256 --sizes 128 --warmups 0 --samples 1
```

The benchmark driver rejects source-pin drift, dirty upstream state, fixture
mutation, output mismatch, retirement-count drift, dirty prover identity,
unverified proofs, and proof/report/receipt binding mismatches.

The manifest keeps unsupported workloads explicit. A similarly named local
guest is not enough to remove a row: its curve or field, algorithm parameters,
input generator, serialization, output, and precompile classification must
match the declared CSP workload.
