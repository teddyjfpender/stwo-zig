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

The two payloads use bincode while Stwo's stateless-validator port accepts a
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

The full stateless-validator source is now ported and a pinned RV32 ELF has
been built under the combined `rv32im-zkvm-ethereum-v1` profile. This promotes
`full_block_guest_ported`, but it does not promote execution or proof claims:

| Stwo product | Bytes | SHA-256 | Retained execution |
| --- | ---: | --- | --- |
| full validator ELF | 3,352,364 | `b751305c0e350918a4a1e692fcfd620a54f5bce6c50322230e156faca95328fa` | no |
| recovery ABI smoke ELF | 7,076 | `4b119f7ebaa1d24ead9b46a67b980d26f4b0c8ec6dc2f9eddad07ec23f5a66fc` | yes, execution only |

The profile admits native Keccak-f (`CUSTOM-0`, funct7 2) and successful-only
transaction signer recovery (`CUSTOM-0`, funct7 3). The recovery operation
uses one aligned 168-byte record containing big-endian digest, `r`, `s`, and
recovered affine public-key bytes, plus little-endian `recovery_id` and
success status fields. Native rejection is fatal; a rejected retirement is
never retried in software. The deterministic smoke uses `d = z = k = 1` and
expects address `7e5f4552091a69125d5dfcb7b8c2659029395bdf`.

The deterministic smoke has now run through the combined production runner in
1,256 cycles: 1,254 ordinary core rows plus exactly two external-operation
rows. Its one-segment V3 journal is independently replayable, stderr is empty,
and its 20-byte output has SHA-256
`d6f781065c489e6513f45bc3dab82156055056d393c42f49a4defec22b5ee73f`,
which is the pinned address above. The exact runner and controller binaries are
retained with that bundle. This is execution evidence only; neither an
isolated arithmetic check nor this trace receipt is a proof of the joined
base-CPU, memory, caller, recovery, and Keccak transaction.

A separate, earlier Keccak-only guest has also completed the real block and
published the expected 43-byte output. Its replayed V3 journal contains 389
leaf-local execution segments, 1,630,632,307 total cycles, 1,630,599,472 core
rows, and 32,835 external Keccak rows. That guest consumes host-supplied
transaction public keys, recovers each key in software, and matches the two;
it is not the combined
Ethereum profile above. Its source was an exactly identified dirty variant of
`434cce33` carrying a byte-equivalent host memory-snapshot optimization. The
operator-observed 251.39-second wall time is not part of the V3 receipt and is
therefore explicitly nonnormative. The journal is execution-only and reports
`segment_statement_v2_admissible = false`, so it establishes neither segment
proofs nor recursion. For those reasons it remains a diagnostic and does not
promote `full_block_execution_reproduced` for the current combined product.

This acceleration boundary is intentionally narrow. It installs only Alloy's
transaction-recovery provider. Alloy verification against an already supplied
public key and Revm's EVM `ECRECOVER` precompile remain software, because the
successful-only AIR cannot authenticate the invalid-result semantics that
those interfaces require. The complete source overlay, ABI field offsets,
execution-profile descriptor, ELF identities, executable instruction-site
inventory, inputs, and expected host output are bound by manifest schema v5.

The segmented execution diagnostic now has a versioned typed inventory seam.
New V3 journal segments and summaries publish, in canonical family order, both
call counts and execution-row counts for Keccak and signer recovery; the V4
capture receipt reduces those per-segment values exactly. Aggregate V2
journals and V3 receipts remain replayable, but they cannot be relabeled as
typed evidence. The first complete combined execution predates this seam, so
its 32,901 aggregate external rows are not split or inferred here. One final
same-input rerun after source freeze is required before the manifest can bind
the dynamic Keccak/recovery totals.

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

### Execution and trace-generation checkpoint

The first complete Stwo execution of the projected block used the Keccak-only
profile, so transaction signer recovery still ran as RV32 software. It retired
1,630,632,307 cycles in 389 leaf-local segments, including 1,630,599,472 core
rows and 32,835 native Keccak rows. The final 43-byte output SHA-256 was the
pinned `73039680...8c5` value above. This is an execution baseline, not a fair
cycle comparison with ZisK's broader native Ethereum operation set and not a
proof receipt.

Two source-equivalent boundary changes were measured on the exact same ELF and
input. Replacing per-address boundary hash insertion with a compact sorted
union made a representative first leaf 12.85 s -> 1.32 s (9.73x). Retaining a
canonical initialized-word inventory, merging only new/touched addresses, and
using the already-recorded leaf-local first-access values instead of copying a
second entry snapshot reduced the complete run from 251.39 s to 133.08 s
(1.889x). The two complete journals are byte-identical (795,194 bytes, SHA-256
`7b071f128e05bb0cb650e9b083005ba9d79a95fb4bcdf0d432f7aad3b63e8024`),
including final CPU and RW-memory identities. These changes improve exact
streaming execution generally; they do not special-case Ethereum.

This still generates the full typed opcode/access/memory witness serially and
therefore is not the final trace architecture. ZisK's primary source describes
a two-phase pipeline: an AOT-translated executor emits ordered memory-read
values and register/PC checkpoints, then independent workers consume those
minimal traces to fill full witness chunks without owning the original memory.
The matching Stwo research direction is:

1. translate admitted RV32 basic blocks to a bounded native executor;
2. emit a versioned minimal trace containing read values, CPU checkpoints, and
   authenticated Keccak/recovery events;
3. memorylessly re-execute leaf-local chunks in parallel through the existing
   typed retirement/AIR witness authorities; and
4. require exact agreement between the fast execution result, minimal-trace
   custody, full-witness replay, and current interpreter on a mutation fleet.

The architectural references are the ZisK `rom-setup`, `emulator-asm`, and
`emulator/src/emu.rs` sources, plus the explanatory analyses
[`Deconstructing the 1.5 GHz zkVM`](https://hackmd.io/@0xdeveloperuche/rkd1vBsElx)
and
[`Beyond ZisK`](https://hackmd.io/@0xdeveloperuche/S1sZEi7Lxl).

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

Replay the experimental provider source overlay and built products separately:

```sh
python3 autoresearch/benchmarks/ethereum_block_comparison.py \
  validate-stwo-products \
  --source-root /external/stateless-reth-source-and-products
```

Replay the retained combined-profile execution smoke with:

```sh
python3 autoresearch/benchmarks/ethereum_block_comparison.py \
  validate-stwo-smoke \
  --bundle /external/stwo-ethereum-smoke/bundle \
  --controller /external/stwo-ethereum-smoke/riscv_segmented_execution.py \
  --runner /external/stwo-ethereum-smoke/riscv-trace-dump
```

Replay the older Keccak-only full-block diagnostic with:

```sh
python3 autoresearch/benchmarks/ethereum_block_comparison.py \
  validate-stwo-keccak-diagnostic \
  --bundle /external/keccak-only-block-bundle \
  --controller /external/riscv_segmented_execution-7267e158.py \
  --runner /external/keccak-only-riscv-trace-dump \
  --elf /external/keccak-only-stateless-validator.elf
```

This inventory is explicitly `execution-only-not-a-proof`. Segment Statement
V2 also caps *global* cycles at 2^24, and its access-clock predecessor is
range-checked below 2^26 (`low20 + high6 * 2^20`). Since access clocks use a
four-wide bucket, merely splitting a 60M+ execution into small traces does not
make those leaves V2-admissible. Large-block proving therefore needs a new,
versioned global-clock/range authority while retaining the 2^24 per-leaf row
ceiling. The existing V2 checks must not be widened in place.

The ZisK guest also uses native Keccak, SHA-256, secp256k1, big-integer, pairing,
and KZG operations. The pinned Stwo guest now accelerates Keccak and the
successful transaction-recovery subset of secp256k1; the other operations and
invalid-result paths are not implementation-normalized. A fair comparison
must either:

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

Manifest v5 freezes the result shape for the eventual apples-to-apples run. It
binds the same block while retaining the codec-specific ZisK and Stwo input
identities and their different public-output framings. Those identities do not
by themselves establish an identical guest statement, so
`matched_guest_statement_reproduced` remains false.

Every system result must report four mutually exclusive timing buckets:
execution, witness generation, proving, and fresh verification. Each bucket
uses integer nanoseconds for wall, user, and system time; when all four are
present, `total_wall_ns` must equal the exact sum of their wall times. Geometry
must disclose ISA steps, core and typed external rows, AIR types/component
instances, padded rows, and committed/constant/total cells. Proof results must
also disclose field and hash choices, query/blowup parameters, conjectured
security, proof bytes, and verifier independence. The hardware envelope binds
machine/CPU/GPU/memory/OS, power and thermal state, process/thread/worker
counts, plus execution multiplicity and strategy. In particular, the observed
ZisK minimal-trace path appears to validate the block repeatedly under its
parallel run strategy; its 679 ms wall observation is not admissible until
that multiplicity and CPU work are measured and bound rather than inferred
from log repetition.

Trace generation is reported as a second, explicit decomposition: one
sequential authoritative capture followed by parallel memoryless replay. Each
stage binds cycles, wall nanoseconds, an exact cycles-over-nanoseconds rate,
worker count, strategy, and whether the value was measured or modeled. Replay
efficiency is the exact rational replay rate divided by capture rate times
workers, and total trace-generation wall must equal capture plus replay wall.
The current 163.8 million cycles/s capture milestone remains a development
observation until its exact cycles, nanoseconds, hardware envelope, and
measured/modelled authority are retained in that result shape.

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
