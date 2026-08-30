# Ethereum block equivalence benchmark

The primary cross-zkVM target is Ethereum mainnet block **24,628,607**.  It is
large enough to exercise a real stateless validator rather than a synthetic EVM
loop:

| field | pinned value |
| --- | ---: |
| block hash | `0xd6edeb114882eb19af618789a4ebd5f84984e7d340d54459d1b2d9d7c1ed99a9` |
| transactions | 66 |
| gas used | 7,372,614 |
| ZisK guest input | 2,718,960 bytes |
| ZisK RV64 steps | 60,465,946 |
| ZisK active AIR types / instances | 18 / 38 |
| ZisK padded rows | 131,596,288 |
| ZisK committed stage cells | 8,556,380,160 |

The canonical contract is
[`ethereum_block_mainnet_24628607.json`](ethereum_block_mainnet_24628607.json).
It binds the block roots, ZisK and ZisK Ethereum client revisions, guest ELF,
witness, tool binaries, emulator result, AIR plan, proving-key geometry, and
the current Stwo assurance boundary.

## What may be claimed today

The pinned ZisK guest executes the full stateless block validator and commits
the canonical block hash.  Its execution and AIR plan have been reproduced.
No ZisK proof for this block has been retained by this contract.

The input is not an opaque blob. It is exactly two `ZiskStdin` records, each
encoded as an eight-byte little-endian length followed by payload and zero
padding to an eight-byte boundary:

| record | payload bytes | SHA-256 |
| --- | ---: | --- |
| `guest_reth::RethInputPublic` | 37,233 | `89845d9725f5d169691bcf5032ad77d6a13dbd33d211333ba3948f168b50a9fa` |
| `guest_reth::RethInputWitness` | 2,681,704 | `9c93f7b11fac67fbc97b9a4b924bfd7e799e4ad13d314c350da2b665b6a54473` |

The two payloads use bincode while Stwo's ported eth-act guest accepts a
schema-prefixed canonical SSZ `StatelessInput`. Passing the ZisK file directly
to that guest therefore exercises only its malformed-input return path. Such a
run is explicitly not execution evidence and must never enter a performance
comparison.

The lossless semantic projection is now retained and host-validated:

| projection field | pinned value |
| --- | --- |
| canonical fork / schema | BPO2 / `0x1401` |
| canonical SSZ input | 2,700,688 bytes / `845b7c924728c1fcd3c7dbcd38b71e2744a1a36f2205d6e05ceb32db4278065c` |
| Stwo runner transport | 2,700,692 bytes / `faaf02583929396faed177914da27b4a493766993001357bd1720340ca1ddabb` |
| recovered transaction keys | 66 |
| witness state / code / legacy-key / header entries | 3,854 / 120 / 835 / 1 |
| successful host output | 43 bytes / `730396807814bc71f14405b3ecf27237778a5359732001b32c93692c3275a8c5` |
| new-payload-request root | `e63d2797ca5c6f826a32d20c41ba552d25777533ab295f9d232560b014d09030` |

The older ZisK fixture names timestamp `1,767,747,671` as `bpo1_time`; the
current canonical mainnet schedule names that same transition BPO2. Selecting
BPO1 caused the current validator to reject the exact excess-blob-gas
transition, while BPO2 reproduces it and validates the block. This fork join is
explicit in the manifest rather than inferred from the legacy field name.

Stwo's runner writes input bytes verbatim. The RV32 guest ABI therefore uses a
four-byte little-endian payload length followed by the canonical SSZ bytes; the
length prefix is transport only and is bound separately from the semantic
payload. The next promotion step is complete RV32 execution of that exact
transport, followed by proof of every adjacent segment and one recursively
verified root.

This promotes `matched_semantic_input_projected`, but not yet
`matched_guest_statement_reproduced`: ZisK publishes the block hash while the
eth-act guest publishes the SSZ new-payload-request root plus its success bit,
chain id, and schema id. The final comparison must bind those two output
formats to one reviewed block-statement projection rather than equating their
bytes.

Stwo's existing Revm accumulator benchmark executes a real EVM transition, but
it is **not** this block statement: it does not authenticate the block header,
stateless trie witness, receipts root, withdrawals, fork rules, or final block
hash.  Its CPU/Metal numbers remain useful optimization diagnostics and are not
an Ethereum-block comparison.

The repository's normative soundness ledger currently says:

```text
whole_frontend_verified = false
proof_system_soundness = false
```

The manifest and replay gate intentionally bind those false values.  They may
change only with new evidence.  Existing evidence is substantial—46/46 pinned
Sail retirement normalizers, 46/46 row-local AIR implications, full-step
framing, differential execution, proof mutation tests, and fresh-process
verification—but it does not yet establish arbitrary-trace refinement or an
independent proof-system theorem.

## Why segmentation and Ethereum precompiles are on the critical path

Stwo's current one-shot RISC-V statement admits at most 16,777,216 retirement
cycles.  The ZisK execution alone is 60,465,946 RV64 steps, before accounting
for ISA and guest-library differences.  A matched Stwo run must therefore use
the existing resumable execution and SegmentV2 proof substrate, aggregate all
adjacent leaves, and independently verify one recursive root.

The frontend now has a bounded-memory execution inventory for this work. The
trace tool's `--segment-steps` mode transfers each completed trace range out of
the live session, emits a content-addressed NDJSON record, and retains only the
state needed to execute the next range. The durable controller replays an
interrupted execution, byte-compares its fsynced prefix, and appends only new
records:

```sh
python3 scripts/riscv_segmented_execution.py capture \
  --repository . \
  --bundle /external/create-only/bundle \
  --tool zig-out/bin/riscv-trace-dump \
  --elf /path/to/guest.elf \
  --input /path/to/input.bin \
  --segment-steps 65536

python3 scripts/riscv_segmented_execution.py validate \
  /external/create-only/bundle
```

Replay the retained semantic projection independently with:

```sh
python3 autoresearch/benchmarks/ethereum_block_comparison.py validate-projection \
  --canonical-input /external/mainnet_24628607.canonical-ssz.bin \
  --stwo-runner-input /external/mainnet_24628607.stwo-input.bin \
  --host-output /external/mainnet_24628607.stwo-host-output.bin
```

This inventory is explicitly `execution-only-not-a-proof`. Segment Statement
V2 also caps *global* cycles at 2^24, and its access-clock predecessor is
range-checked below 2^26 (`low20 + high6 * 2^20`). Since access clocks use a
four-wide bucket, merely splitting a 60M+ execution into small traces does not
make those leaves V2-admissible. Large-block proving therefore needs a new,
versioned global-clock/range authority while retaining the 2^24 per-leaf row
ceiling. The existing V2 checks must not be widened in place.

The ZisK guest also uses native Keccak, SHA-256, secp256k1, big-integer, pairing,
and KZG operations.  Stwo currently exposes only its Poseidon2 guest extension.
A fair comparison must either:

1. execute portable software implementations on both VMs; or
2. provide semantically identical, constrained native operations on both VMs
   and disclose their AIR geometry.

Mixing ZisK-native Ethereum operations with a Stwo software-only guest is useful
engineering telemetry, but it is not an implementation-normalized performance
claim.

## Reproduction

After cloning the exact repositories and generating the two short execution
logs, replay all local identities and geometry with:

```sh
python3 autoresearch/benchmarks/ethereum_block_comparison.py validate-local \
  --client-root /path/to/zisk-eth-client \
  --zisk-root /path/to/zisk \
  --ziskemu /path/to/ziskemu \
  --cargo-zisk-dev /path/to/cargo-zisk-dev \
  --proving-key /path/to/provingKey \
  --execution-stdout /path/to/ziskemu.stdout.log \
  --execution-stats /path/to/ziskemu.stats.csv \
  --execution-output /path/to/ziskemu.output.bin \
  --plan-stdout /path/to/cargo-zisk-dev-execute.stdout.log
```

The two source commands are deliberately proof-free and quick:

```sh
ziskemu -e zec-reth.elf -i mainnet_24628607_66_7_zec_reth.bin \
  -o output.bin -m -X --sdk --opcodes --coverage --save-stats stats.csv

RUST_LOG=info cargo-zisk-dev execute --standalone \
  --elf zec-reth.elf \
  --inputs file:///absolute/path/mainnet_24628607_66_7_zec_reth.bin -v
```

An optional live mainnet cross-check is:

```sh
python3 autoresearch/benchmarks/ethereum_block_comparison.py validate-rpc \
  --endpoint https://your.ethereum.rpc
```

## Promotion gate

A headline Stwo-vs-ZisK Ethereum result requires all of the following:

- byte-identical semantic input or a reviewed lossless input projection;
- identical block number, block hash, pre/post-state commitment, transaction
  and receipts roots, fork rules, and public-output meaning;
- complete execution with exact segment adjacency and no omitted cycles;
- a fresh verification receipt for every SegmentV2 leaf;
- a recursive root binding every leaf exactly once and fresh verification of
  that root;
- mutation tests for witness, header/root, segment order, continuation state,
  leaf omission/duplication, parent topology, and final publication;
- disclosed ISA steps, AIR instances, padded rows, committed cells, security
  parameters, proof bytes, peak memory, and full request wall time; and
- an explicit assurance label until FV-3/FV-4/FV-5 and independent
  proof-system validation are complete.
