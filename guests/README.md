# Guest programs

A **guest** is a bare-metal RISC-V program whose execution this repository
proves. Guests are ordinary Rust or C++ programs compiled for a pinned custom
target. They run single-threaded with no operating system, read one input
window and write one output region, then halt. The RISC-V frontends under
[`src/frontends/riscv/`](../src/frontends/riscv/) execute the resulting ELF and
prove its retirement.

Products consume guests as **hashed artifacts, not source imports**: nothing
under `src/` compiles code from this directory. A build script produces an ELF
and a report that binds the ELF's SHA-256 to every source, linker script,
target specification and lockfile that produced it.

This directory holds the Ethereum block guests. The small conformance and
benchmark guests (ECDSA, Poseidon2, SHA-256, Keccak) still live under
[`vectors/riscv_guests/`](../vectors/riscv_guests/). The
[restructure plan](../design/repository/restructure-plan.md) records their move
to `guests/testing/`.

## Directory map

```text
guests/
└── ethereum/                  Ethereum stateless block validation
    ├── abi/                   service ABI contracts and the guest cost model
    ├── runtime/               shared no_std runtime modules for the Rust guests
    ├── rv32/                  RV32IM Rust guest (custom-instruction profile)
    ├── rv64/                  RV64IM Rust guest (software and ECALL-service profiles)
    ├── client_evmone/         RV64IM C++ guest: ZisK's ziskethone with evmone
    ├── tools/                 host tools: input projection and independent validation
    └── tests/                 host tests for the shared runtime
```

| Guest | ISA | Language and engine | Build entry |
| :--- | :--- | :--- | :--- |
| [RV32IM Ethereum guest](ethereum/rv32/README.md) | RV32IM, ILP32 | Rust, [`stateless-validator-reth`](https://github.com/paradigmxyz/stateless) | `cargo build` in `ethereum/rv32` |
| [RV64IM Ethereum guest](ethereum/rv64/README.md) | RV64IM, LP64 | Rust, `stateless-validator-reth` | [`ethereum/rv64/build.py`](ethereum/rv64/build.py) |
| [evmone Ethereum client guest](ethereum/client_evmone/README.md) | RV64IM, LP64 | C++, [ziskethone](https://github.com/0xPolygonHermez/ziskethone) and [evmone](https://github.com/ethereum/evmone) | [`ethereum/client_evmone/build.py`](ethereum/client_evmone/build.py) |

See the [Ethereum guest overview](ethereum/README.md) for how the three relate.

## The guest ABI

The Ethereum guests share one contract with the executor. The linker scripts
(`ethereum/rv32/linker.ld`, `ethereum/rv64/linker.ld` and
`ethereum/rv64/linker-wide.ld`) are its source of truth.

- **Machine.** RV32IM or RV64IM only, with no A, C, F or D extension. The
  Rust guests' custom targets enable LLVM's forced-atomic libcalls, and each
  Rust guest supplies single-thread implementations. These are not
  synchronization primitives.
- **Entry.** `_start` sets `gp` and `sp = __stack_top`, then calls the guest
  entry point. There are no interrupts and no host threads.
- **Input.** The input window starts at `__input_start` and holds a
  little-endian `u32` payload length followed by the canonical SSZ
  `StatelessInput` (schema-prefixed). The RV64 window is 4 MiB (`linker.ld`)
  or 16 MiB (`linker-wide.ld`).
- **Output.** A successful run writes exactly 43 bytes at `__output_data`:
  the 32-byte request root, a success byte, the chain ID (8 bytes, little
  endian) and the schema ID (2 bytes, little endian). It then sets
  `__output_len` and `__halt_flag`.
- **Failure.** Any rejection executes an illegal instruction and publishes no
  output. A failed guest can never look like a successful halt.
- **Accelerators.** The RV64 guests reach admitted services through `ECALL`
  (`a7` = service tag, `a0` = packet pointer, all registers preserved). The
  RV32 guest uses custom-0 instruction words and declares them in an ELF
  `.note.stwo.zkvm` capability note. The service contracts and their prover
  costs are in [`ethereum/abi/`](ethereum/abi/CONTEXT.md).

## Building and pinning

Each guest pins its whole build:

- **Toolchain.** Rust guests use `nightly-2026-08-08` with `build-std` for
  `core` and `alloc`. The C++ client uses `zig c++` 0.15.2 only.
- **Dependencies.** Cargo builds run `--locked` against committed lockfiles.
  Git dependencies carry exact revisions. The C++ client fetches its upstream
  sources at pinned commits and applies the patches in
  `ethereum/client_evmone/patches/`.
- **Identity.** `ethereum/rv64/build.py` writes a report with the byte count
  and SHA-256 of the ELF and of every source, linker script, target and
  lockfile used. `ethereum/client_evmone/build.py` writes
  `build-manifest-*.json` with commits, applied patches, defines and the ELF
  SHA-256.
- **Inputs.** Block fixtures come from ZisK's published
  [zisk-eth-client](https://github.com/0xPolygonHermez/zisk-eth-client)
  fixtures. They are authenticated by byte count, SHA-256 and Git blob
  against [`tests/fixtures/ethereum/`](../tests/fixtures/ethereum/), and the
  15-block regression basket is [`basket.json`](../tests/fixtures/ethereum/basket.json).

A guest build is preparation evidence only. Building, host validation and
emulated execution do not establish a STARK proof.

## Reproducing

From the repository root:

```sh
# RV64IM Rust guest, software profile:
python3 guests/ethereum/rv64/build.py --artifacts OUT

# RV64IM evmone client, admitted profile:
python3 -I guests/ethereum/client_evmone/build.py --out OUT

# Host tests for the shared SHA-256 framing:
cargo test --locked --manifest-path guests/ethereum/tests/sha256_precompile/Cargo.toml
```

Each guest README documents its profiles, flags and remaining validation steps.

`rv64/build.py --prepare-fixture` additionally downloads, authenticates,
projects and host-validates the pinned block fixture. Its final comparison step
still imports `autoresearch.benchmarks.ethereum_block_comparison`, which was
retired from `main`, so that step currently fails; the build itself does not
depend on it.

## Licences and credit

The repository is licensed under [Apache 2.0](../LICENSE). Third-party code is
kept apart and keeps its upstream licence:

- `ethereum/rv64/vendor/` holds patched copies of upstream crates, each with
  its upstream licence files. The [vendor index](ethereum/rv64/vendor/README.md)
  lists their origin, licence and local changes.
- `ethereum/client_evmone/` commits **no** third-party source. Its build fetches
  ziskethone, evmone, intx and blst at pinned commits. The patches in
  `patches/` modify those upstream files and should be read under the
  upstream licences, which the [client README](ethereum/client_evmone/README.md#licences-and-third-party-sources)
  lists.

These guests stand on the work of ZisK, evmone, revm, Reth, Alloy, RustCrypto,
RISC Zero and many others. [ACKNOWLEDGEMENTS.md](../ACKNOWLEDGEMENTS.md)
credits each project and says where this repository uses it.
