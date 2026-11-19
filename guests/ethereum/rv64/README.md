# RV64IM Ethereum block guest

A Rust guest for RV64IM (LP64) that validates one Ethereum block statelessly.
It runs the same pinned [`stateless-validator-reth`](https://github.com/paradigmxyz/stateless)
`a134a621` and canonical SSZ contract as the [RV32IM guest](../rv32/README.md).
The default **software** profile computes Keccak, transaction signature recovery
and Revm precompiles in ordinary instructions. It uses no custom operation,
SP1 syscall, host cryptographic hook or externally supplied success hint.
The **service** profiles (below) reach the admitted Keccak-f and secp256k1
services through `ECALL`. The RV32 guest and target keep their own
native-operation semantics.

Patched copies of RustCrypto `k256`, `ecdsa` and `sha2`, Revm's interpreter and
bytecode crates and `zeth-mpt` live in [`vendor/`](vendor/README.md). The
allocator is shared from [`../runtime/`](../runtime/README.md).

## Build

```sh
python3 guests/ethereum/rv64/build.py \
  --artifacts /tmp/stwo-rv64-ethereum --prepare-fixture
```

The script pins `nightly-2026-08-08`, uses the lockfile, downloads at most the
manifest fixture size plus one byte, checks its byte count, SHA256 and Git blob,
then runs the existing canonical projection and independent host validator.
`--offline` requires cached Rust dependencies and a preexisting verified
`zisk-input.bin`. Build artifacts live under the crate's ignored `target/`;
published ELF/input/output/report files live at the explicit artifact path.

**Known gap.** The `--prepare-fixture` comparison step still imports
`autoresearch.benchmarks.ethereum_block_comparison`, which was retired from
`main`. Fixture download, authentication, projection and host validation run;
the comparison then fails on the missing module. Building without
`--prepare-fixture` is unaffected.

Runtime is one interrupt-free thread. A custom Rust target enables LLVM's
forced atomic libcalls without the RISC-V A extension. Local 1/2/4/8-byte
CAS/add/sub functions use volatile reads/writes plus compiler ordering fences.
These are single-thread guest semantics, **not synchronization primitives** for
threads or a host. The LP64 allocator uses native-width metadata. The linker
keeps aligned mapped heap/input/output/stack ranges and the original u32 length
and halt fields. Input is u32 little-endian canonical payload length followed by
SSZ; successful output is exactly 43 bytes: request root 32, success 1, chain ID 8
little-endian and schema ID2 little-endian. Panic executes an illegal instruction
without publishing successful completion.

Test the 64-bit atomic lowering helpers on the host:

```sh
rustc +nightly-2026-08-08 --edition 2024 --test \
  guests/ethereum/rv64/src/single_thread_atomics.rs \
  -o /tmp/stwo-rv64-atomics-test
/tmp/stwo-rv64-atomics-test
```

Building and host validation are preparation evidence. They do not establish
RV64 block execution or a STARK proof. The CSP-only loader's 4KiB input and
32-byte output contract does not admit this guest. The separate `ethereum-run` adapter now validates the much larger input and
43-byte expected output; its completed real-block execution and independent
oracle receipts are archived in [`rv64-ethereum-20261030`](https://github.com/starknet-innovation/stwo-zig/tree/archive/pre-restructure-20261108/vectors/reports/rv64-ethereum-20261030/README.md).

An optional independent execution linkage is available after native and Unicorn
execution reports exist: pass `--execution-report` and `--oracle-report` together
with `--prepare-fixture`. The script checks freshly built ELF/source identity,
validated input/output, exact instruction count, all registers, PC and the oracle
report's native-report hash before publishing execution status. Proof status
always remains false. See the archived [oracle note](https://github.com/starknet-innovation/stwo-zig/tree/archive/pre-restructure-20261108/vectors/reports/rv64-ethereum-20261030/ORACLE.md).

## Lean services profile (`ethereum-services-v2-lean`)

`build.py --guest-profile ethereum-services-v2-lean` builds the same Keccak and
secp256k1 word-service guest with two guest-side changes and no change to the
execution profile, ECALL tags, packet layouts or AIR: ECDSA recovery no longer
re-verifies the recovered key (the check is algebraically implied; see
`vendor/ecdsa/src/recovery.rs`), and the GLV scalar multiplication runs on
service word packets in variable time (`k256` feature `stwo-vartime`; public
signature data only). On block 24,628,607 this executes 104,253,913 instead of
213,659,488 instructions with half the secp256k1 service calls (rounds 1–5:
lean recovery, aligned-only memory functions in `mem/`, variable-time
inversion, word-wise Keccak absorption, and patched `vendor/` copies of
revm-interpreter, revm-bytecode and zeth-mpt for the EVM and MPT paths). Receipts and the
independent services oracle are archived in [`rv64-guest-lean-20261031`](https://github.com/starknet-innovation/stwo-zig/tree/archive/pre-restructure-20261108/vectors/reports/rv64-guest-lean-20261031/README.md).
The `heap_start` ABI symbol differs between the two ELFs; always derive
execution and proving request symbols from the ELF being run.
