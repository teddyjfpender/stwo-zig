# Shared guest runtime

Small `no_std` Rust modules shared by the Ethereum guests. They are not a
crate: each guest includes the files it needs with `#[path]`, so every guest
compiles them under its own target, features and profile.

| Module | Used by | Contract |
| :--- | :--- | :--- |
| [`exact_layout_allocator.rs`](exact_layout_allocator.rs) | `rv32`, `rv64` | Global allocator. Exact size and alignment classes hash into 4,096 intrusive free-list buckets: O(1) average with no header on live blocks and no scan over heap addresses. Exposes `ExactLayoutFreeListHeapV2`. |
| [`fast_memory.rs`](fast_memory.rs) | `rv32` | `memcpy` built from bounded, aligned 32-bit loads and stores with exact byte tails. It uses ordinary instructions only: no host memory operation and no overread. |
| [`fast_keccak_sponge_words.rs`](fast_keccak_sponge_words.rs) | `rv32` | Keccak-256 sponge over the authenticated `stwo.keccakf.1600.v1` permutation. Aligned input is absorbed four bytes per load; padding, permutation order and squeeze are byte-identical to the byte-wise sponge. |
| [`sha256_precompile.rs`](sha256_precompile.rs) | `rv32`, `tests/sha256_precompile` | Allocation-free SHA-256 framing over the two-pointer compression instruction. The framing is portable; the native `hash` entry point exists only under the `stwo_sha256_precompile_v1` cfg or `sha256-precompile` feature, which refuse to compile for anything except little-endian RV32. |
| [`ethereum_admission.rs`](ethereum_admission.rs) | `rv32`, `tests/sha256_precompile` | The `.note.stwo.zkvm` ELF capability note. It declares the execution profile, capability mask and semantic digest that the executor admits. |

The SHA-256 framing follows ZisK's aligned-block fast path and its
compression-only syscall pattern. The alignment and instruction ABI are
specific to this prover.

## Versioning

The file names carry no version: Git history records the iterations, and the
versioned contracts are stated in the code where the executor checks them. They
are the capability note's profile, capability mask and semantic digest, the
`stwo.keccakf.1600.v1` permutation name, the `stwo_sha256_precompile_v1` `cfg`
and the `ExactLayoutFreeListHeapV2` type. Changing any of those is a protocol
change. Renaming a file is not.

These files compile into guest ELFs. Any byte change, including a moved
`#[path]`, needs a guest rebuild, and the rebuilt ELF hashes must be checked
against the previous build before they are relied on.
