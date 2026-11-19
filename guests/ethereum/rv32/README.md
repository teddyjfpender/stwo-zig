# RV32IM Ethereum block guest

A Rust guest for RV32IM (ILP32) that validates one Ethereum block statelessly.
It builds the unmodified [`stateless-validator-reth`](https://github.com/paradigmxyz/stateless)
source at `a134a621` and installs Alloy's transaction signer recovery on the
native secp256k1 instruction. Keccak-f[1600] and SHA-256 compression run as
custom-0 instructions. It uses the shared exact-layout allocator and
word-oriented Keccak sponge from [`../runtime/`](../runtime/README.md). The
EVM's `ecrecover` precompile uses the native recovery only when an untrusted
success hint selects it and otherwise runs in software; the SHA-256 precompile
uses the native compression under the default `sha256-precompile` feature.
Other Revm precompiles and verification against a supplied public key keep
their software semantics. A rejected native recovery is fatal.

The [RV64IM guest](../rv64/README.md) runs the same validator and input
contract without custom instructions.

## Build

From this directory:

```sh
rustup component add rust-src --toolchain nightly-2026-08-08
RUSTFLAGS='-C link-arg=-Tlinker.ld' cargo +nightly-2026-08-08 build \
  --locked -j 1 --release --target riscv32i-stwo.json \
  -Z json-target-spec -Z build-std=core,alloc \
  -Z build-std-features=compiler-builtins-mem
```

The linker declares the full DATA region, including the allocator's heap, in
`__data_len`. `__data_end` still marks the end of static sections, so the allocator
starts at the same aligned address. Excluding the heap lets execution run but
makes retained proof capture reject accessed heap words missing from its RW
snapshot. The build script tracks `linker.ld` so layout edits trigger relinking.

The ELF is `target/riscv32i-stwo/release/stwo-ethereum-guest`. Its admission
note selects `rv32im-zkvm-ethereum-v1`. Input is the four-byte length followed
by canonical SSZ produced by [the projection tool](../tools/projection/src/main.rs).
The [host validator](../tools/host_validation/src/main.rs) checks the same input and
retains the expected 43-byte output. See [the archived block benchmark](https://github.com/starknet-innovation/stwo-zig/tree/archive/pre-restructure-20261108/autoresearch/benchmarks/ETHEREUM_BLOCK.md)
for those commands.

The custom target enables M and single-thread atomic lowering, without A or C
instructions. Its `riscv32i` prefix is intentional: radium 0.7 detects targets
by name and otherwise incorrectly assumes 64-bit atomics. Four LLVM libcalls
implement the required operations in an interrupt-free guest. They must never
be used as synchronization primitives in a host or threaded guest. Check them
from the repository root with:

```sh
rustc +1.96.1 --edition 2024 --test \
  guests/ethereum/rv32/src/single_thread_atomics.rs \
  -o /tmp/stwo-guest-atomics-test
/tmp/stwo-guest-atomics-test
```

This is a new guest artifact, not a reconstruction of the historical ELF's
exact bytes. A successful execution does not establish a segment proof,
secure block commitment, or recursive proof. Existing CSP guests and their
protocol identities are unaffected by this independent guest crate.
