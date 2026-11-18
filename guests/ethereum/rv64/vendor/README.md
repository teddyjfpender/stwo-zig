# Vendored crates

Patched copies of upstream crates used by the RV64IM service guest. `k256`,
`ecdsa`, `revm-interpreter`, `revm-bytecode`, `zeth-mpt` and `sha2-rv64` (as
`sha2`) are wired in by `[patch]` in [`../services/Cargo.toml`](../services/Cargo.toml).
The [projective service test](../projective_service_test/Cargo.toml) also uses
`k256` and `ecdsa`. The `sha2/` copy carries the candidate SHA-256 hook described
in [`candidate-services-abi.md`](../../abi/candidate-services-abi.md); no
current manifest selects it. The copies of crates.io packages keep their upstream
licence files and README. Local changes are gated behind `stwo-*` Cargo features or marked with
a `stwo:` comment.

| Directory | Upstream | Version | Licence | Local changes |
| :--- | :--- | :--- | :--- | :--- |
| [`k256/`](k256/) | [RustCrypto elliptic-curves](https://github.com/RustCrypto/elliptic-curves) (crates.io) | 0.13.4 | Apache-2.0 OR MIT | secp256k1 projective add and double on the admitted word-packet service; variable-time GLV for public signature data. The upstream checksum, unmodified-file hashes and the changed and added files are in [`k256-source.json`](k256-source.json). |
| [`ecdsa/`](ecdsa/) | [RustCrypto signatures](https://github.com/RustCrypto/signatures) (crates.io) | 0.16.9 | Apache-2.0 OR MIT | `stwo-skip-redundant-recovery-verify`: recovery skips the re-verification that the recovery equation already implies (`src/recovery.rs`). |
| [`sha2/`](sha2/) | [RustCrypto hashes](https://github.com/RustCrypto/hashes) (crates.io) | 0.10.9 | MIT OR Apache-2.0 | `stwo-candidate-sha256`: the execution-only candidate SHA-256 compression service. The default build is upstream behaviour. Pinned by [`sha2-source.json`](sha2-source.json). |
| [`revm-interpreter/`](revm-interpreter/) | [bluealloy/revm](https://github.com/bluealloy/revm) (crates.io) | 42.0.0 | MIT | RV64IM word paths for stack swaps and calldata conversion; the admitted `arith256_mod` service (`stwo-arith256-service`) and execution-only arithmetic candidates (`stwo-candidate-arith`). |
| [`revm-bytecode/`](revm-bytecode/) | [bluealloy/revm](https://github.com/bluealloy/revm) (crates.io) | 42.0.0 | MIT | Legacy JUMPDEST analysis uses one table lookup per byte and avoids general bit addressing on RV64IM (`src/legacy/analysis.rs`). |
| [`zeth-mpt/`](zeth-mpt/) | `crates/zeth-mpt` of [paradigmxyz/stateless](https://github.com/paradigmxyz/stateless) `a134a621`; source headers: Copyright 2025 RISC Zero, Inc. | 0.1.0 | Apache-2.0 (file headers); manifest declares MIT OR Apache-2.0 | Workspace fields made concrete, unused optional features removed, and RLP decoding changes in `src/mpt/rlp.rs`. This copy carries no separate licence file; the licence is stated in each source header. |
| [`sha2-rv64/`](sha2-rv64/) | **Original to this repository** | presents as `sha2` 0.10.9 | MIT OR Apache-2.0 | A narrow RV64IM SHA-256 replacement that imports no upstream implementation source; see its README. |

Credit for these projects is in [ACKNOWLEDGEMENTS.md](../../../../ACKNOWLEDGEMENTS.md).
