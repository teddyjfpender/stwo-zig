# Software RV64 Ethereum execution guest

This independent RV64IM/LP64 target runs the same pinned `stateless-validator-reth`
`a134a621` and canonical SSZ contract as the adjacent RV32 guest. It uses software
Keccak, transaction signature recovery and Revm precompiles. No custom operation,
SP1 syscall, host cryptographic hook or externally supplied success hint is used.
The existing RV32 guest/target retain their separate native-operation semantics.

```sh
python3 autoresearch/benchmarks/guest_runtime/ethereum/rv64/build.py \
  --artifacts /tmp/stwo-rv64-ethereum --prepare-fixture
```

The script pins `nightly-2026-08-08`, uses the lockfile, downloads at most the
manifest fixture size plus one byte, checks its byte count, SHA256 and Git blob,
then runs the existing canonical projection and independent host validator.
`--offline` requires cached Rust dependencies and a preexisting verified
`zisk-input.bin`. Build artifacts live under the crate's ignored `target/`;
published ELF/input/output/report files live at the explicit artifact path.

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
  autoresearch/benchmarks/guest_runtime/ethereum/rv64/src/single_thread_atomics.rs \
  -o /tmp/stwo-rv64-atomics-test
/tmp/stwo-rv64-atomics-test
```

Building and host validation are preparation evidence. They do not establish
RV64 block execution or a STARK proof. The CSP-only loader's 4KiB input and
32-byte output contract does not admit this guest. The separate `ethereum-run` adapter now validates the much larger input and
43-byte expected output; its completed real-block execution and independent
oracle receipts are in `vectors/reports/rv64-ethereum-20261030/README.md`.

An optional independent execution linkage is available after native and Unicorn
execution reports exist: pass `--execution-report` and `--oracle-report` together
with `--prepare-fixture`. The script checks freshly built ELF/source identity,
validated input/output, exact instruction count, all registers, PC and the oracle
report's native-report hash before publishing execution status. Proof status
always remains false. See `vectors/reports/rv64-ethereum-20261030/ORACLE.md`.
