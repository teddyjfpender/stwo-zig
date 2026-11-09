# RV64 software SHA-256

This is an original FIPS 180-4 SHA-256 implementation, with a constant-index
16-word rolling schedule and 64 expanded rounds for RV64IM. It imports no
RustCrypto, evmone or ziskethone implementation source. The existing pinned
`digest = 0.10.7` crate supplies buffering and the public Digest trait API.

It is a **narrow dependency replacement**, not a general implementation of every
API in RustCrypto `sha2 = 0.10.9`. The services workspace alone patches that
version. Its pinned consumers (alloy-eips, k256, p256 and libssz-merkle, including
the latter's build script) use `Sha256` and `Digest`. SHA-224/384/512 and upstream
raw-compression APIs are deliberately absent, so an expanded consumer graph
must be reviewed and will fail to compile if it needs those APIs. The separately
resolved `sha2 = 0.11.0` production dependency is unchanged.

No service or ABI change is involved. The entire digest is computed in guest
instructions. The compressor checks alignment before native u32 loads and reads
only inside the complete 64-byte block. The counter follows SHA-256's 64-bit
bit-length encoding; the arithmetic uses explicit wrapping operations.

Validation includes the published `abc` and million-`a` answers and differential
checks against independently resolved RustCrypto SHA-256 0.11.0 at every length
0..4096, varying alignment, six streaming chunk sizes, cloning and reset. The
latter is a test-only dependency, pinned with its checksum in Cargo.lock.

```sh
cargo +nightly-2026-08-08 test --locked --release --manifest-path \
  autoresearch/benchmarks/guest_runtime/ethereum/rv64/vendor/sha2-rv64/Cargo.toml
```

This patch needs dependency and cryptographic review before promotion. The
frozen basket and targets are unchanged. Execution measurements are not proof
qualification; see the guest-efficiency experiment receipt.
