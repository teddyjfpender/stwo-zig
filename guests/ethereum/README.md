# Ethereum block guests

These guests validate one Ethereum mainnet block statelessly. The input is the
block's canonical SSZ `StatelessInput`: the execution payload plus the witness
of trie nodes it touches. The guest re-executes every transaction, checks the
resulting state root and header, and publishes a 43-byte output (request root,
success flag, chain ID, schema ID). The [guest ABI](../README.md#the-guest-abi)
fixes the memory map and the I/O contract.

| Directory | What it is |
| :--- | :--- |
| [`rv32/`](rv32/README.md) | **RV32IM Rust guest.** Runs the unmodified pinned `stateless-validator-reth` with Keccak-f, secp256k1 recovery and SHA-256 compression as custom-0 instructions. Profile `rv32im-zkvm-ethereum-v1`. |
| [`rv64/`](rv64/README.md) | **RV64IM Rust guest.** The same validator and input contract on RV64IM/LP64. Its software profile uses no accelerator. Its service profiles reach the admitted Keccak-f and secp256k1 services through `ECALL`, and its v3 features add SHA-256, 256-bit modular arithmetic and bulk-memory services. |
| [`client_evmone/`](client_evmone/README.md) | **evmone Ethereum client guest.** A C++ client on RV64IM built from ZisK's ziskethone block pipeline and evmone's interpreter. It reads the same input and writes the identical output. |
| [`abi/`](abi/CONTEXT.md) | The service ABI, the prover's cost per instruction and per service call, and the execution-only candidate services. |
| [`runtime/`](runtime/README.md) | Shared `no_std` modules that the Rust guests include by `#[path]`: allocator, word-wise memory copy and Keccak sponge, SHA-256 framing, ELF capability note. |
| `tools/projection/` | Host tool `stwo-ethereum-input-projection`. It converts a ZisK `zisk-eth-client` block fixture into the canonical SSZ input and the runner input. |
| `tools/host_validation/` | Host tool `stwo-ethereum-host-validation`. It executes the canonical input natively and produces the expected 43-byte output independently of any guest. By default it admits only the pinned block 24,628,607; `--general` admits any canonical input up to 16 MiB. |
| `tests/sha256_precompile/` | Host and RV32 tests for `runtime/sha256_precompile.rs`, differential against RustCrypto `sha2`. |

## How the pieces fit

1. `tools/projection` turns a pinned ZisK fixture into canonical SSZ.
   [`rv64/build.py --prepare-fixture`](rv64/build.py) authenticates the fixture
   first.
2. `tools/host_validation` computes the expected output on the host.
3. A guest ELF is built from `rv32/`, `rv64/` or `client_evmone/` and executed
   by the RISC-V frontend. Its output must equal the host's byte for byte.
4. The regression basket of 15 mainnet blocks is
   [`tests/fixtures/ethereum/basket.json`](../../tests/fixtures/ethereum/basket.json).

All three guests are independent artifacts. A change to one does not change
another guest's protocol identity or ELF.

Upstream projects used here are credited in
[ACKNOWLEDGEMENTS.md](../../ACKNOWLEDGEMENTS.md).
