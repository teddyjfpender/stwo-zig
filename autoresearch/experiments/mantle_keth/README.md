# Keth → Stwo Zig: experimental Mantle integration

This development bridge pins Kakarot Labs' **Keth** and routes Cairo PIEs to
`stwo-cairo-cpu` or `stwo-cairo-metal`, with independent official Rust proof
verification. It does not implement or claim Mantle validity proving.
This route uses a Cairo execution implementation that must be made equivalent
to Mantle; it does not execute Kona's Rust program inside Cairo. Direct Kona
proving is a separate RISC-V integration option discussed below.

The starting Stwo Zig main is `6692d40639c88becff2a203c45727f31cbe23ad3`.
Upstream source identities are in [pins.json](pins.json). The bridge lives
outside released package closures and leaves all AIR/protocol pins unchanged.

## What can be reused

| Repository | Relevant capability | Decision |
| --- | --- | --- |
| [kkrt-labs/keth](https://github.com/kkrt-labs/keth/tree/e90c0a51699182f140e51c94d09ff9045c194769) | Ethereum Prague STF in Cairo; custom execution hints; MPT checking; PIE export; Stwo proving | Use as the execution-program starting point |
| [kkrt-labs/kakarot](https://github.com/kkrt-labs/kakarot) | Earlier Cairo EVM, archived at inspection | Historical reference; not the integration entry point |
| [kkrt-labs/kakarot-ssj](https://github.com/kkrt-labs/kakarot-ssj) | Cairo 1 EVM rewrite, archived at inspection | Not the integration entry point |
| [kkrt-labs/cairo-m](https://github.com/kkrt-labs/cairo-m) | A different M31-native CPU/compiler/AIR | Would require a new frontend; not needed for Keth |
| [kkrt-labs/zk-pig](https://github.com/kkrt-labs/zk-pig) | Ethereum execution witness generation | Potential starting point for witnesses; Mantle support must be established separately |

Keth itself describes its block flow as work in progress and targets Prague.
Its generic `--chain-id` option does not establish Mantle support. This bridge
admits **Ethereum chain ID 1 only** for upstream block tracing.

## Integration boundary

1. The pinned Keth runner executes its Cairo program with Keth-specific hints
   and exports a Cairo PIE. This retains Keth's execution dependencies outside
   the Zig prover.
2. Stwo Zig's existing official VM adapter replays the PIE through its pinned
   simple bootloader under `all_cairo_stwo`, hashing tasks with Blake.
3. The existing Zig Cairo frontend constructs witnesses and proves on the
   explicitly selected CPU or Metal product.
4. The canonical benchmark validates execution/proof receipts, canonical PCS
   settings, Zig self-verification, and official Rust acceptance of the exact
   published proof bytes. It records process/prove time and peak RSS.

Keth pins Stwo-Cairo `92232543…`; this checkout pins Stwo-Cairo `82f21252…`
(1.2.2). We do **not** treat Keth's serialized internal `ProverInput` as a
compatible transport, or migrate the Zig proof protocol to Keth's version.
PIE is the intended version boundary; full Keth builtin/hint compatibility
still needs a block-level run. A small sample only qualifies the sampled path.

## Reproduce

Python 3.10+ runs `bridge.py` and its standard-library tests. The optional smoke
exporter needs Python 3.10 and `cairo-lang==0.13.5`; this Python Cairo VM has
mutable dataclass defaults that fail under Python 3.11/3.12.

Clone and detach the upstream sources at the exact revisions in `pins.json`.
The checkouts must be clean, including untracked source files.

```sh
python3 autoresearch/experiments/mantle_keth/bridge.py audit \
  --keth-checkout /path/to/keth \
  --op-succinct-checkout /path/to/mantle-op-succinct \
  --out /tmp/keth-source-audit.json

python3 -m unittest autoresearch.tests.test_keth_stwo_bridge -v
```

To create a real PIE from Keth's own small sample, without building Keth's Rust
extension or obtaining RPC credentials:

```sh
uv venv --python 3.10 /tmp/keth-smoke-venv
uv pip install --python /tmp/keth-smoke-venv/bin/python cairo-lang==0.13.5
/tmp/keth-smoke-venv/bin/python autoresearch/experiments/mantle_keth/export_smoke_pie.py \
  --keth-checkout /path/to/keth --out /tmp/keth-smoke
```

This compiles the pinned `cairo/tests/programs/fibonacci.cairo`, executes its
actual input hint with `[1, 1, 10]`, checks output `144`, and records source and
PIE hashes. It is a **transport smoke test**, not EVM execution evidence.

Build the existing products and verifier following their owner guides. The
VM adapter product build is offline: populate its locked Cargo dependencies
first. The official verifier has its own isolated manifest and lockfile.
The older documented `nightly-2025-07-14` cannot build the currently locked
Cairo 2.20 adapter (MSRV 1.94), and its verifier build hits `ruint` const-slice
APIs unavailable on that nightly. Use the newer execution-only build toolchain
below without changing any source/proof pins; record both binary identities.

```sh
cargo +nightly-2026-05-15 fetch --locked \
  --manifest-path tools/stwo-cairo-vm-adapter-rs/Cargo.toml
RUSTUP_TOOLCHAIN=nightly-2026-05-15 zig build stwo-cairo-cpu -Doptimize=ReleaseFast -j1
cargo +nightly-2026-05-15 build --release --locked \
  --manifest-path tools/stwo-cairo-official-verifier-rs/Cargo.toml

python3 autoresearch/experiments/mantle_keth/bridge.py prove \
  --pie /tmp/keth-smoke/keth_fibonacci.pie.zip \
  --product zig-out/bin/stwo-cairo-cpu \
  --oracle tools/stwo-cairo-official-verifier-rs/target/release/stwo-cairo-official-verifier \
  --out /tmp/keth-smoke-proof
```

Select `stwo-cairo-metal` explicitly on an admitted macOS host to exercise the
GPU path. The existing benchmark enforces its authenticated-AOT receipt gates.
A successful receipt records `cairo_proof_verified: true` while keeping every
Ethereum-block/Mantle/derivation/settlement claim false. This `prove` command
accepts arbitrary PIEs: it does not establish a Keth application identity.
Source provenance from `trace`/`export_smoke_pie` is separate evidence.

For a real upstream **Ethereum** block, set up Keth's dependencies and compile
its programs in the clean pinned checkout (`uv run --frozen compile_keth`).
Generate a ZK-PIG witness and place it at
`/path/to/data/1/BLOCK/zkpi.json`, then:

```sh
python3 autoresearch/experiments/mantle_keth/bridge.py trace \
  --keth-checkout /path/to/keth --data-dir /path/to/data \
  --block 22615247 --out /tmp/keth-block-trace
```

This selects the monolithic `main` program, emits
`trace/cairo_pie_22615247.zip` and a provenance receipt. Feed that PIE to `prove`.
A receipt alone is not a verifier-side binding to a block or program. No
Mantle block execution or complete Keth block proof is claimed by this branch.
All evidence output paths must be fresh; failed verification never emits a
successful bridge receipt.

## What Mantle still needs

The current source of Mantle's Kona crates is **`mantle-v2/rust`**, not the
standalone `mantle-xyz/kona` repository. The inspected OP Succinct lockfile
pins it at `05e2f58d…` and Mantle's revm at `835cb4eb…`. See
[MANTLE_CHANGES.md](https://github.com/mantle-xyz/op-succinct/blob/6b1cb5742b6e26fa9ff7f6f82be498549ad7e057/MANTLE_CHANGES.md).
These are inspected source pins, not a claim about deployed contract keys.

| Layer | Available | Required before a Mantle validity claim |
| --- | --- | --- |
| Cairo execution/proving | Existing Stwo Zig frontend and PIE replay | Full Keth block/builtin compatibility and negative controls |
| EVM/STF | Keth's Ethereum Prague implementation | Mantle fork schedule, OP/deposit transaction types and receipts, BVM_ETH fields, mint/value and native-token handling, system transactions, L1/operator fees, precompile differences, and differential agreement with pinned Mantle execution |
| State witness | Keth/ZK-PIG Ethereum inputs | Authenticate account/storage/code proofs to the correct pre-state; bind post-state, headers and receipts to the selected block; reject missing/inconsistent witnesses |
| Rollup derivation | Kona implements it in Rust | Prove L1 headers, blob/KZG/DA checks, deposits, frame/channel/batch derivation and fork-dependent fallback behavior; an unproved host Kona run is only a differential oracle |
| Public statement | Keth commitments and Cairo program output | A constrained Mantle journal, domain/config identity, and accepted program/bootloader commitments |
| Chunk composition | Keth init/body/teardown/MPT-diff consistency checker | Authenticate every child program/output via applicative bootloader/recursion or verified children; proving the consistency checker alone is insufficient |
| Settlement | Mantle currently verifies SP1 proofs | A Stwo-capable Ethereum verifier or a proven wrapper plus contract/protocol changes |

Start the first differential fixture at mainnet block **94355445** or a later
small steady-state Arsia block. Mantle's inspected source sets the first
supported Arsia block to 94355444 and recommends avoiding the activation
bundle for the first test. Do not silently apply present-day rules to an old
block; use that block's exact configuration and fork schedule.

### The statement gap

At the Keth pin, `cairo/ethereum/prague/keth/main.cairo` publishes six felts:

| Offset | Value |
| --- | --- |
| 0–1 | Pre-state root, low/high 128-bit limbs |
| 2 | State account-diff commitment |
| 3 | State storage-diff commitment |
| 4 | Trie account-diff commitment |
| 5 | Trie storage-diff commitment |

That is not Mantle's range journal. The upstream range program commits the
ABI encoding of `BootInfoStruct` from `utils/client/src/boot.rs`:

| ABI word | Field |
| --- | --- |
| 0 | `bytes32 l1Head` |
| 1 | `bytes32 l2PreRoot` |
| 2 | `bytes32 l2PostRoot` |
| 3 | `uint64 l2BlockNumber` (left zero-padded to 32 bytes) |
| 4 | `bytes32 rollupConfigHash` |

`mantle_journal.py` pins this **host codec only** and rejects noncanonical
uint64 padding. These roots are **OP output roots**, not raw EVM state roots.
The output-root preimage includes version, state root, message-passer storage
root and latest block hash. The Cairo program must constrain that entire
relationship. Mantle hashes the pretty-serialized Rust `RollupConfig` with
SHA-256; a generic Python JSON dump is not automatically byte-compatible.
The aggregation journal is a separate six-word statement.

Also, Keth's `compile_cairo.py` computes Poseidon segment program hashes, while
Stwo Zig's admitted simple-bootloader path hashes tasks with Blake. Do not feed
those hash registries into a Blake applicative composition unchanged.

### Work sequence and acceptance gates

1. **Transport:** export the real Keth sample, replay it, generate a Zig proof,
   and independently verify the exact bytes. Then prove a minimal real Keth
   Ethereum block; record input/trace sizes, all stages, peak memory and proof
   bytes. Treat unsupported builtins or proof-version differences as blockers.
2. **Execution fork:** add a Mantle Cairo STF in a separate Keth fork. Begin
   with one user transaction plus L1/system deposits. Differentially compare
   state root, transaction root, receipts, gas, fee vault balances and output
   root against the exact pinned Mantle native client. Cover revert/deposit
   failures and each relevant fork boundary.
3. **Statement:** constrain and expose the journal above. The verifier must
   enforce the accepted program/bootloader identity and expected L1/config/
   pre-root/claim values. Independently mutate each field and require rejection.
4. **Derivation:** prove the corresponding L1→L2 derivation, either in a Cairo
   implementation or by porting Kona to the existing Stwo Zig RISC-V frontend.
   The RISC-V option needs ABI/syscall/precompile and ISA/toolchain admission;
   SP1's Rust guest and its accelerated dependencies are not drop-in binaries.
   Any split proof must cryptographically bind the exact derived payloads to
   the execution proof.
5. **Composition and settlement:** bind child proofs and block continuity,
   qualify CPU/Metal parity and official acceptance, then add the Ethereum
   verifier/wrapper. Measure cost and latency for the whole transaction before
   comparing with OP Succinct/SP1.

The first meaningful commercial milestone is **an independently verified
Mantle execution proof with exactly matching block outputs**, clearly marked
execution-only until derivation is proved. Claiming an SP1 replacement requires
all five gates. This branch introduces the transport tooling and source
assessment; it does not estimate performance before that workload exists.
