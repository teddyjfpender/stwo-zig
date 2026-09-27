# Ethereum precompile coverage

Inventory of the compiled guest provider, not a claim that the pinned block
exercises every operation. Sources: the pinned guest `Cargo.lock`,
`ethereum/src/main.rs`, shared SDK modules, and the local locked
`revm-precompile-42.0.1/src/interface.rs` implementation of `Crypto`.

| Operation | Current guest route | Evidence / remaining qualification |
| --- | --- | --- |
| Keccak-256 | Shared Rust sponge over native Keccak-f instruction | Typed memory-bound leaf and recursion integration; 32,835 calls in pinned block execution |
| Transaction signer recovery | Native secp256k1 successful recovery | 66 transactions; combined block has 78 native recoveries including EVM calls |
| EVM ECRECOVER | Native successful path plus guest-side invalid-result handling and checked hints | Existing recovery qualification; hints do not substitute for cryptographic validity |
| EVM SHA-256 | Default shared allocation-free Rust framing over SHA compression instruction | Canonical typed leaf, source artifact, recursive parent and adjacent-segment custody pass; 44 native SDK vectors / 148 compressions pass; pinned block has zero SHA calls |
| Transaction explicit-key signature verification | Guest k256 software | Preserves the provider's error/invalid-signature semantics; not a native verification accelerator |
| RIPEMD-160 | Revm default guest software | No dedicated instruction or typed AIR added |
| Modular exponentiation | Revm default guest software | No dedicated modular-arithmetic accelerator added |
| BN254 add, multiply, pairing | Revm default guest software | No dedicated typed BN254 precompile added |
| BLAKE2 compression | Revm default guest software | Ethereum BLAKE2 semantics are separate from the prover's BLAKE3 commitment choice |
| KZG point evaluation | Revm default guest software | Crypto provider delegates to the locked KZG backend; no dedicated typed KZG accelerator added |
| BLS12-381 add, MSM, pairing, maps | Revm default guest software | No dedicated typed BLS12-381 accelerator added |
| P-256 signature verification | Revm default guest software | No dedicated typed P-256 accelerator added |
| Identity | Revm byte-copy path | Not a cryptographic instruction |

Default software methods execute as ordinary guest instructions when invoked;
they are not trusted host-result shortcuts. Availability in the provider does
not establish native execution vectors, whole-block proof coverage, or useful
performance for every operation. Fork-specific gas and dispatch remain owned by
the pinned validator/Revm, not by the native compression/recovery ABI.

The SHA capability is explicit ELF profile 4, capability bits 14, ABI 1. Old
profiles do not acquire permission to execute SHA. Shared capability-note code
is `guest_runtime/ethereum_admission_v1.rs`; its extraction preserves the measured
Ethereum ELF byte-for-byte. SHA2 calls outside the EVM provider are not silently
replaced by this integration.

The next performance decisions should be based on actual guest-call counts and
cycle profiles from representative blocks. The active 66-transaction block does
not measure dedicated SHA/BN254/BLS/KZG acceleration, and adding unrelated native
operations must not be represented as a speedup for that workload.
