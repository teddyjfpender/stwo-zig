# Reproducible RV32 Ethereum guest

This builds the unmodified stateless-validator source at `a134a621`, installs
Alloy's native transaction signer recovery in the entrypoint, and uses the
retained exact-layout allocator and word-oriented Keccak sponge. Revm EVM
precompiles and verification against a supplied public key retain software
semantics. A rejected native recovery is fatal.

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
by canonical SSZ produced by [the projection tool](../projection/src/main.rs).
The [host validator](../host_validation/src/main.rs) checks the same input and
retains the expected 43-byte output. See [the block benchmark](../../ETHEREUM_BLOCK.md)
for those commands.

The custom target enables M and single-thread atomic lowering, without A or C
instructions. Its `riscv32i` prefix is intentional: radium 0.7 detects targets
by name and otherwise incorrectly assumes 64-bit atomics. Four LLVM libcalls
implement the required operations in an interrupt-free guest. They must never
be used as synchronization primitives in a host or threaded guest. Check them
from the repository root with:

```sh
rustc +1.96.1 --edition 2024 --test \
  autoresearch/benchmarks/guest_runtime/ethereum/src/single_thread_atomics.rs \
  -o /tmp/stwo-guest-atomics-test
/tmp/stwo-guest-atomics-test
```

This is a new guest artifact, not a reconstruction of the historical ELF's
exact bytes. A successful execution does not establish a segment proof,
secure block commitment, or recursive proof. Existing CSP guests and their
protocol identities are unaffected by this independent guest crate.
