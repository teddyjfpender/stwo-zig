# Ethereum block equivalence benchmark

The primary cross-zkVM target is Ethereum mainnet block **24,628,607**.  It is
large enough to exercise a real stateless validator rather than a synthetic EVM
loop:

| field | pinned value |
| --- | ---: |
| block hash | `0xd6edeb114882eb19af618789a4ebd5f84984e7d340d54459d1b2d9d7c1ed99a9` |
| transactions | 66 |
| gas used | 7,372,614 |
| stateless witness | 2,718,960 bytes |
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
