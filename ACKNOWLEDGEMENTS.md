# Acknowledgements

This repository builds on years of open work by other teams. We port their
protocols, run their programs, vendor their code, test against their
references and learn from their designs. This page credits each of them: what
the project is, where this repository uses it, and under what licence.

Every entry is traceable to the tree: vendored sources and their licence
files, [`third_party/INVENTORY.json`](third_party/INVENTORY.json), the
[upstream pin ledger](conformance/upstream.md), fixture manifests, guest build
scripts and patches, and design notes. Where this repository only reads,
executes or compares against a project and redistributes none of its code, the
entry says so. A licence is stated where the tree records it.

If we have missed or misdescribed your work, please open an issue. We will fix
it.

## Contents

- [StarkWare and the Stwo ecosystem](#starkware-and-the-stwo-ecosystem)
- [Ethereum execution](#ethereum-execution)
- [OP Stack execution](#op-stack-execution)
- [ZisK](#zisk)
- [Cryptography](#cryptography)
- [RISC-V correctness authorities](#risc-v-correctness-authorities)
- [SM83 (Game Boy) authorities](#sm83-game-boy-authorities)
- [Frontier provers we learn from](#frontier-provers-we-learn-from)
- [Tooling](#tooling)
- [Research](#research)

## StarkWare and the Stwo ecosystem

**[Stwo](https://github.com/starkware-libs/stwo)** is StarkWare's circle-STARK
prover over the Mersenne-31 field. This repository is a parity-first Zig port
of it, and Stwo is the final correctness oracle for the Native lane: the
compatibility target is pinned to `a8fcf4bd` in
[`conformance/upstream.md`](conformance/upstream.md). The Rust oracles and
vector generators under [`tools/`](tools/README.md) (`stwo-vector-gen`,
`stwo-interop-rs`, `stwo-air-derive-vector-gen` and others) build against
pinned Stwo revisions. The LogUp-GKR prototype used Stwo's `prover/lookups`
code as its read-only reference
([design note](design/riscv/rv64-logup-gkr-prototype.md)). Licence: Apache-2.0.
This repository uses the same licence, and we are grateful that StarkWare
published such a clear, fast and well-tested prover to port.

**[Stwo-Cairo](https://github.com/starkware-libs/stwo-cairo)**,
**[Cairo](https://github.com/starkware-libs/cairo)** and the **`cairo-vm`**
crate define the Cairo lane. The Zig Cairo AIR, witness generation and proofs
are checked against the official Stwo-Cairo and Stwo pair, and only the
canonical Rust `verify_cairo` accepts a Cairo proof. Used in
`src/frontends/cairo/`, `tools/stwo-cairo-*`, `tools/cairo-witness-compiler`
and `vectors/cairo/`. The tools fetch the upstream sources at pinned revisions
instead of vendoring them.

**[proving](https://github.com/starkware-libs/proving)** is StarkWare's
monorepo for circuit recursion and the Cairo program runner. It is the single
authority for the circuit recursion lane: `tools/stwo-circuit-oracle-rs`
depends on it by pinned revision, and the checkpoints under
`vectors/circuit/` are either that oracle's output or upstream files copied
verbatim, each bound by `provenance.json`. The Cairo lane also uses its `cairo-program-runner-lib` to
execute PIEs. `stwo-circuit-recursion-cpu` is byte-identical to its binaries
on the canonical small registries.

**[sequencer](https://github.com/starkware-libs/sequencer)** supplies the
Starknet OS (`starknet_os`, `apollo_starknet_os_program`) that
`tools/starknet-aggregator-rs` runs to aggregate multi-block proofs.
**[SNOS](https://github.com/keep-starknet-strange/snos)** builds the Starknet
OS input from RPC. `tools/starknet-block-collector` records every RPC response
SNOS needs, so that leaf PIEs can be rebuilt offline.

**[formal-proofs](https://github.com/starkware-libs/formal-proofs)** is
StarkWare's Lean 4 verification of Stwo. Its LogUp result
(`Stwo/Verification/Lookups/Logup.lean`) is the external formal evidence that
[`design/soundness/SAIL_AIR_COMPOSITION.md`](design/soundness/SAIL_AIR_COMPOSITION.md)
and [`TEAM_AB_INTERFACE.md`](design/soundness/TEAM_AB_INTERFACE.md) cite for the
LogUp-to-multiset reduction. It is cited, not imported. Licence: Apache-2.0.

## Ethereum execution

**[stateless](https://github.com/paradigmxyz/stateless)** by Paradigm provides
`stateless-validator-reth`, the stateless block validator built on Reth. The
[RV32IM](guests/ethereum/rv32/README.md) and [RV64IM](guests/ethereum/rv64/README.md)
Ethereum guests run `stateless-validator-reth` **unmodified** at the pinned
revision `a134a621`; the RV64 service profiles patch only its `zeth-mpt`
dependency (below). The host [projection and validation tools](guests/ethereum/README.md)
use `stateless-validator-common` and `stateless-validator-reth`, so the
expected output that every Ethereum guest, the C++ client included, is checked
against also comes from it. It makes a pure-Rust, reproducible Ethereum guest
possible.

**[RISC Zero](https://github.com/risc0)** wrote `zeth-mpt`, the sparse Merkle
Patricia trie used by the stateless validator (source headers: Copyright 2025
RISC Zero, Inc.). A copy of `crates/zeth-mpt` from the pinned stateless
revision, with small RLP decoding changes, is vendored at
[`guests/ethereum/rv64/vendor/zeth-mpt/`](guests/ethereum/rv64/vendor/README.md)
for the RV64 service profiles. Licence: Apache-2.0 per the source headers; the
manifest declares `MIT OR Apache-2.0`.

**[revm](https://github.com/bluealloy/revm)** is the Rust EVM that the Rust
guests execute. `revm-precompile` is a direct dependency. Patched copies of
`revm-interpreter` and `revm-bytecode` 42.0.0 are vendored under
`guests/ethereum/rv64/vendor/` for the RV64 service profiles. The patches add
RV64IM word paths, a table-driven JUMPDEST analysis, the admitted
`arith256_mod` service and execution-only arithmetic candidates. Licence: MIT.

**[Alloy](https://github.com/alloy-rs)** provides the consensus types,
primitives and signer-recovery hook (`alloy-consensus`, `alloy-primitives`)
that the guests and host tools use. The RV32 guest installs its native
secp256k1 recovery through Alloy's crypto-provider interface.

**[evmone](https://github.com/ethereum/evmone)** is a fast C++ EVM
implementation. Its baseline interpreter (v0.24.0) is the EVM of the
[evmone client guest](guests/ethereum/client_evmone/README.md). Its KZG test
vectors feed the client's curve tests. Our RV64IM interpreter work is
carried as patches in `guests/ethereum/client_evmone/patches/`. Licence:
Apache-2.0. The source is fetched at a pinned commit and not committed.

**[intx](https://github.com/chfast/intx)** (v0.15.0, 256-bit integers) and
**[blst](https://github.com/supranational/blst)** (v0.3.17, BLS12-381 by
Supranational) are evmone's dependencies in the client guest. The patches
give blst 64-bit limbs and give intx byte-wise big-endian conversion and
column-wise multiplication on RV64IM. Licence: Apache-2.0 (both). Both are
fetched, not committed.

**The Ethereum execution spec tests** (`tests@v21.0.2` blockchain tests)
exercised the evmone client guest on the host and on RV64. They found two
witness-dependence bugs that are now fixed (see the client's
[known gaps](guests/ethereum/client_evmone/README.md#known-gaps)).

## OP Stack execution

**[Optimism and the OP Stack](https://github.com/ethereum-optimism/optimism)**
provide the rollup protocol and **Kona**, the Rust implementation used by
the OP Stack guest. The pinned Kona host implementation supplies the
independent historical execution fixtures. The guest and its build guide
are under [`guests/opstack/`](guests/opstack/README.md).

**[Mantle](https://github.com/mantle-xyz/mantle-v2)** supplies the chain-specific
execution and protocol dependencies for the separate Mantle pilot.
Its guest and provenance are documented in the
[Mantle guide](guests/opstack/mantle/README.md).

**`op-revm`**, **`kona-mpt`** and **`kona-protocol`** are used for OP
execution, sparse Merkle Patricia trie operations and rollup protocol and
derivation types. The local copies retain upstream licence and provenance
records. See [the vendored dependency guide](guests/opstack/vendor/README.md)
and [licence inventory](third_party/INVENTORY.json).

**[arkworks](https://github.com/arkworks-rs/algebra)** provides **`ark-ff`**,
**`ark-bn254`** and **`ark-bls12-381`** for field arithmetic, BN254 pairing
work and BLS12-381 scalar operations used by the optional blob-derivation
path. The vendored crates retain their MIT and Apache-2.0 licence notices
and [upstream pins](guests/opstack/vendor/).

## ZisK

**[ZisK](https://github.com/0xPolygonHermez/zisk)** is a high-performance
RISC-V zkVM. Its team's public work shaped much of our Ethereum line:

- **ziskethone.** [ziskethone](https://github.com/0xPolygonHermez/ziskethone) is
  ZisK's C++ Ethereum block client. Its block pipeline, state database and
  evmone patch stack form the
  [evmone client guest](guests/ethereum/client_evmone/README.md). The source is
  fetched at a pinned commit and not committed. Licence: `Apache-2.0 OR MIT`.
- **Block fixtures.** [zisk-eth-client](https://github.com/0xPolygonHermez/zisk-eth-client)
  publishes the Reth-guest mainnet block inputs that make up our 15-block
  regression basket ([`tests/fixtures/ethereum/basket.json`](tests/fixtures/ethereum/basket.json))
  and the pinned block manifest
  ([`ethereum_block_mainnet_24628607.json`](tests/fixtures/ethereum/ethereum_block_mainnet_24628607.json)).
  Every fixture is pinned by SHA-256 (the single-block manifest adds byte
  count and Git blob), and the [projection tool](guests/ethereum/README.md)
  converts it to canonical SSZ.
- **Reference measurements.** `ziskemu` step counts and ziskethone's
  performance notes are recorded as reference sources in the basket manifest.
- **Design patterns.** The SHA-256 framing in
  [`guests/ethereum/runtime/sha256_precompile.rs`](guests/ethereum/runtime/sha256_precompile.rs)
  follows ZisK's aligned-block fast path and compression-only syscall. The
  candidate curve services follow ZisK's precompile granularity
  ([`guests/ethereum/abi/candidate-curves-abi.md`](guests/ethereum/abi/candidate-curves-abi.md)).
  Our GPU design notes study ZisK's ProofMan CUDA prover
  ([`rv64-cuda-zisk-review.md`](design/riscv/rv64-cuda-zisk-review.md),
  [`rv64-cuda-resident.md`](design/riscv/rv64-cuda-resident.md)), its
  streaming commit ([`rv64-m8-engineering-scope.md`](design/riscv/rv64-m8-engineering-scope.md))
  and its CUDA graph cache ([`rv64-m8-job-architecture.md`](design/riscv/rv64-m8-job-architecture.md)).
  The CUDA review records that no external implementation was copied.

Thank you to the ZisK team for building in the open and publishing fixtures,
clients and measurements that others can reproduce.

## Cryptography

**[RustCrypto](https://github.com/RustCrypto)** maintains `k256`, `ecdsa` and
`sha2`. Patched copies of `k256` 0.13.4, `ecdsa` 0.16.9 and `sha2` 0.10.9 are
vendored under `guests/ethereum/rv64/vendor/`. The `k256` copy adds the
secp256k1 projective service path and variable-time GLV for public signature
data, the `ecdsa` copy skips the re-verification that recovery already
implies, and the `sha2` copy carries a candidate SHA-256 compression hook.
Unmodified crates.io `sha2` is the differential reference for
[`guests/ethereum/tests/sha256_precompile/`](guests/ethereum/tests/sha256_precompile/)
(0.10.9) and for our own RV64 SHA-256, `vendor/sha2-rv64/` (0.11.0). Licence:
`Apache-2.0 OR MIT`. The upstream licence files are kept beside each copy.

**[Plonky3](https://github.com/Plonky3/Plonky3)** defines the Poseidon2-M31
width-24 permutation that this repository pins. The reference sources are in
[`third_party/poseidon2_plonky3/`](third_party/poseidon2_plonky3/) (reference
only, not compiled). The derived
`src/waist/core/crypto/poseidon2_m31_w24_constants.zig`,
`src/waist/core/crypto/poseidon2_m31_w24.zig` and
`src/backends/cuda/native/rv64/poseidon2_m31.cuh` carry the Plonky3 copyright
notice. Licence: MIT.

**[bzip2](https://sourceware.org/bzip2/)** 1.0.8 provides the compressor for
the official Stwo-Cairo binary proof transport. A minimal closure is vendored
in [`third_party/bzip2/`](third_party/bzip2/README.md). Licence: bzip2-1.0.6
(BSD-style).

## RISC-V correctness authorities

**[Sail RISC-V](https://github.com/riscv/sail-riscv)** and the Sail compiler
(0.20.2) are the normative executable ISA model for RV32IM decode and
retirement ([Sail contract](conformance/2026-07-26-riscv-sail-contract.md)).
The repository carries small patches against the pinned model in
`conformance/riscv/`, and the Sail-derived operand-class corpus is generated
from it. A formal ISA model that a prover can be held to is a gift.

**[Spike](https://github.com/riscv-software-src/riscv-isa-sim)** is the
independent implementation cross-check, and
**[riscv-arch-test](https://github.com/riscv-non-isa/riscv-arch-test)** is the
architectural test corpus (`conformance/riscv/arch-test/`). Both are pinned in
the upstream ledger.

**[Unicorn](https://www.unicorn-engine.org/)** 2.1.4 is the independent RV64
execution oracle in `scripts/rv64/`: differential retirement comparisons,
independent retirement counts, and the optional execution linkage of the
RV64 Ethereum guest. Its agreement is execution evidence,
not ISA conformance.

**[Stark-V](https://github.com/ClementWalter/stark-v)** by Clément Walter is
the historical RISC-V layout and performance reference for this frontend. It
is retained pinned, as a non-normative reference that makes old receipts
reproducible.

**[zkvm-benchmarks](https://github.com/zksecurity/zkvm-benchmarks)** by
zkSecurity is the pinned RV32IM acceptance corpus recorded in
[`vectors/riscv_guests/riscv_program_matrix.json`](vectors/riscv_guests/riscv_program_matrix.json).

## SM83 (Game Boy) authorities

The development SM83 frontend (`src/frontends/sm83/`) is tested against the
Game Boy community's references, all pinned in the
[upstream ledger](conformance/upstream.md#sm83-isa-lane):
[gb-opcodes](https://github.com/gbdev/gb-opcodes) and
[Pan Docs](https://github.com/gbdev/pandocs) for instruction metadata,
[SingleStepTests](https://github.com/SingleStepTests/sm83) for the 500,000
per-opcode transitions, [SameBoy](https://github.com/LIJI32/SameBoy) as the
reference emulator, Blargg's test ROMs (via
[retrio/gb-test-roms](https://github.com/retrio/gb-test-roms)), and the
[Mooneye test suite](https://github.com/Gekkio/mooneye-test-suite) built with
WLA-DX. [pret/pokered](https://github.com/pret/pokered) provided the first
application reproducibility check. None of these is redistributed. Decades of
careful reverse engineering by these communities made a provable Game Boy CPU
possible.

## Frontier provers we learn from

Our RV64 performance design notes study the public source and published
results of other provers. They credit what we learned; none of these
projects' code is in this repository.

- **[Airbender](https://github.com/matter-labs/zksync-airbender)** (ZKsync).
  Its GPU worker loop, device-resident transcript and one-readback proof
  orchestration, together with ZisK's, are the target model of
  [`design/riscv/rv64-m8-job-architecture.md`](design/riscv/rv64-m8-job-architecture.md).
  Its GKR + WHIR design informs the native argument studies in
  [`rv64-m9-frontier-gap.md`](design/riscv/rv64-m9-frontier-gap.md).
- **ZisK**, credited [above](#zisk).
- **[SP1](https://github.com/succinctlabs/sp1)** and
  **[OpenVM](https://github.com/openvm-org/openvm)**, whose published results
  (vendor documentation and Ethproofs) are part of the performance frontier
  that [`rv64-m9-frontier-gap.md`](design/riscv/rv64-m9-frontier-gap.md)
  measures against. The pinned zkvm-benchmarks corpus above uses its `sp1`
  program root.
- **[Ethproofs](https://ethproofs.org)**, for publishing comparable
  block-proving results across provers.

## Tooling

**[Zig](https://ziglang.org/)** is the language of the prover, and `zig c++`
builds the C++ guest. **[Lean 4](https://lean-lang.org/)** checks the
RISC-V refinement proofs in `formal/`. **[Rust](https://www.rust-lang.org/)**
builds the guests and the independent oracles.

**[CuMetal](https://github.com/Lulzx/cuda-metal)** 0.1.3 is an optional
CUDA-to-Metal portability and correctness screen on Apple Silicon
([`src/backends/cuda/README.md`](src/backends/cuda/README.md)). The repository
carries a compatibility patch in `conformance/` and pins the audited commit.

## Research

The protocols implemented here come from published research. The soundness
dossier ([`INDEPENDENT_PROOF_SYSTEM_VALIDATION.md`](design/soundness/INDEPENDENT_PROOF_SYSTEM_VALIDATION.md))
lists its starting literature, and the
[LogUp-GKR design note](design/riscv/rv64-logup-gkr-prototype.md) cites the
paper behind that prototype:

- Haböck, Levit, Papini and Schmid, *Circle STARKs*
  ([ePrint 2024/278](https://eprint.iacr.org/2024/278)).
- Haböck, *Multivariate lookups based on logarithmic derivatives* (LogUp,
  [ePrint 2022/1530](https://eprint.iacr.org/2022/1530)).
- Papini and Haböck, *Improving logarithmic derivative lookups using GKR*
  ([ePrint 2023/1284](https://eprint.iacr.org/2023/1284)), the basis of the
  LogUp-GKR prototype.
- Ben-Sasson et al., *Fast Reed-Solomon Interactive Oracle Proofs of
  Proximity* (FRI, [ICALP 2018](https://drops.dagstuhl.de/entities/document/10.4230/LIPIcs.ICALP.2018.14)).
- Ben-Sasson et al., *DEEP-FRI: Sampling Outside the Box Improves Soundness*
  ([ePrint 2019/336](https://eprint.iacr.org/2019/336)).
- Block et al., *Fiat-Shamir Security of FRI and Related SNARKs*
  ([ePrint 2023/1071](https://eprint.iacr.org/2023/1071)).
- Diamond and Posen, *From List-Decodability to Proximity Gaps: Revisiting
  FRI Soundness* ([ePrint 2025/870](https://eprint.iacr.org/2025/870)).

Thank you to every author, maintainer and contributor above.
