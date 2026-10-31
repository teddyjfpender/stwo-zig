# RV64 private RAM roots and terminal certificates

Version 2 has concrete private caller AIR, a same-PCS CPU/service integration,
and serialized 70-query/26-bit-PoW graph and terminal receipts. These components
do not by themselves qualify a retained Ethereum execution. Full execution
requires every CPU/service/RAM batch, boundary adjacency, independently expected
initialization, and the final output certificate. Current whole-job status is
tracked in `rv64-delivery.md`. Legacy dense-v2/sparse-v3 fixtures are unchanged.

## Value and permission authority

`rv64_air.memory.values` commits either 512-byte chunks in a depth-55 sparse tree
or 4KiB pages in a depth-52 tree over the full 64-bit byte-address space. Each
8-byte value has four injective `u16` limbs; no integer is reduced modulo M31.
The rate-7/capacity-9 sponge uses RAM version 2, domain `RAMV`, geometry in
capacity lane 14, domain in lane 15, and an explicit delimiter/zero padding.
A chunk needs 38 permutations; a page needs 294. Both return nine M31 words.

Internal nodes reuse the qualified `ethereum_node_v1` framing/arithmetic and
full-I/O Poseidon relation. The old kind bit encodes child-height bit 5 and the
five height bits encode its lower bits. Its `ETN0`/`ETN1` preimages are disjoint
from the `RAMV` leaf domain, including zero leaves and heights above 31. Every
node needs four permutations. Geometry/version/root coordinates are bound in
the protocol; these roots are distinct from the retained version-1 `RAMP`
permission-limb control and the old RV32 word tree.

Permissions are immutable and separately authenticated. `Policy.fromMemory`
binds the complete sorted R/W/X mappings; its receiver-derived grant ROM has
maximal READ, WRITE and READ|WRITE intervals. Certificates prove full-width
containment/alignment through byte ranges and carry chains. Common chunks need
one certificate; boundary chunks use separately sized word certificates.
Touched partial-word mappings are explicitly outside this whole-word CPU
profile. `validateImmutableExecution` rejects writable executable mappings at
the immutable-ROM authority boundary; generic native memory still supports RWX.

The receiver loads its known ELF/input/ABI independently using
`ethereum_contract.load`, including the four-byte little-endian input length,
ELF/BSS data and zero remainder/output/stack/heap. `Cache.fromMemory` hashes only
nonzero backed chunks. Mapped and unmapped zero values share canonical defaults;
policy authenticates access rights. A zero-filled 224MiB heap therefore needs
neither materialization nor hashing every mapped chunk. Producer omission is
not an initialization authority. Fixture SHA pins provenance; this known-input
mode does not advertise a separately proved SHA input relation.

## Private transition and state closure

`CellTable` range-checks canonical before/after values and local 24-bit terminal
clocks. Untouched cells keep their value and clock zero. Chunk headers connect
those words to the sponge payload/digest relation; the node bus connects their
leaves to the two public roots. Clocks reset at each batch while the value root
preserves memory. PC/registers/context remain outer execution boundaries.

Every BEFORE node/leaf/side supplies exactly once unconditionally. Its optional
Boolean reuse supplies the same digest to AFTER. Computed nodes query two
canonical children at height minus one. Root-height sides are forbidden, all
weights are Boolean/unit, and characteristic bounds keep total mass below M31.
Height descent and root demand force all before records into the before graph;
an unused before side cannot manufacture an after value. A fresh-transcript
attack seals genuine changed after-tree hashes plus an orphan before side,
while keeping the cell witness read-only: only the orphan graph debt remains,
and the real protocol rejects it.

CPU and service bridges use the same full-width Tuple20 state challenge.
CellTable contributes `-initial(clock0)+terminal(local_clock)`. With public RAM
cells absent, CPU + service + CellTable state closes against independently
expected register delta only. `closeWithoutByte` checks graph/hash/policy and
returns typed state/BYTE debts for the containing proof's one global byte
provider. No host-computed RAM rational target is accepted. Omitted provider
claims and unused claim tails must be zero. Padded query-mass guards apply
before characteristic reduction.

Standalone `rv64_ram_private` graph receipts deliberately expose an OPEN state
debt and do not claim CPU execution. Independent rational claims must never be
added across unrelated transcripts. The joined coordinator draws challenges
only after all main/count commitments, binds every physical claim, and checks
the global register-only target in the same PCS proof.

## Construction and ownership

Native boundary capture observes true before/after events once and sorts cells
once. `openings.Owned` reads each distinct current-final chunk once and reverses
only first-before touched words. Its bounded owner lets native execution advance
without an all-RAM snapshot or replay. Prepare it before advancing the image
past that batch: block-final memory cannot reconstruct earlier untouched words.

`Trace.initOwned` consumes that owner. The qualified Poseidon fill writes each
S-box witness directly into one final ragged main arena and retains compact
full-I/O records; there is no second permutation pass or duplicate Call/output
array. `Source.takeMainForCommit` transfers the original allocation through the
existing PCS API. Post-challenge interactions restore canonical packets from
owned words/clocks/rights, frontier metadata and retained IO, with cached clock
inverses and bounded batch inversion. They never gather the wide source after
adoption. Exact physical interaction fields and final proof bytes match the
borrowed-source reference. Metadata retires after typed closure; sparse patches
publish after proof success. Allocation failures preserve the old cache and the
original opening owner. Stateless allocator identity never reads its undefined
context pointer.

`Preparation` computes frontier counts and permission classifications before
wide allocation. `Trace.initPreparedBorrowedOwned` fills concrete `MainBuffers`
provided by an outer arena, using the same row constructors as the owned path.
It consumes the preparation and native openings only on success. The policy
and global-byte tails remain untouched for the outer coordinator to seal.
`Source.releaseBorrowedMain` clears views without freeing the outer allocation;
retained narrow metadata produces identical interactions after that arena is
freed. Borrowed sources cannot use the owned detach API. Exact column parity,
tail preservation, alias rejection, and allocation-failure cleanup are tested.
Borrowed CPU and RAM admission also excludes their explicit native read inputs
before allocation or writes, including unused compact-tape capacity. A consumed
RAM preparation rejects phase before touching historical opening descriptors.

Immutable preprocessing depends on geometry, independent domain logs, policy,
and ABI selectors, not request counts. Every request refreshes active-prefix
bounds and provider row counts. Multiple independent source arenas require a
containing PCS ownership plan; do not describe a generic detaching fallback as
zero-copy adoption.

`rv64_authenticated_main_arena` supplies that concrete containing plan. It
derives canonical CPU/service/RAM roles from admitted `Layout` and prepared
materials, verifies every column height against `Prepared.logsForLayout`, and
allocates once before wide witness construction. RAM endpoint roots remain
request data, so planning needs no placeholder root or duplicate hash pass.
Sealing copies only ROM, BYTE, AND, SHIFT and RAM-policy multiplicities; every
wide column must already have the exact arena pointer, height and length.
Borrowed aliases clear before the consuming PCS handoff, including its error
paths. All native heights contain at least 16 M31 cells, so the raw allocation
adds only 15 cells (60 bytes) for alignment beyond the exact sum of role sizes.

## Final output observation

`rv64_ram_terminal` proves one unchanged final root with no timestamped RAM
events. A replacement CellTable component adds 17 constraints and seven ABI
position selectors, with no extra main/interaction columns. Public constants
bind flag 1 and length 43 in the first aligned word, followed by exactly 43
output bytes. The final word's upper five bytes remain private, while its entire
value remains root-authenticated. Expected output is evaluator data rather than
immutable key material. The receiver equates this root to the last authenticated
execution after-root and independently checks the expected absorbing final PC
against immutable ROM (`jal x0,0`). Net RAM roots alone do not prove general
first-write-of-halt semantics; this admission uses the absorbing-PC contract.

A 512-byte observation needs 258 permutations and 512 provider rows, with
752,000 bytes of main/interaction fields in the fixture. The 4KiB control needs
502 permutations at the same provider height. The final certificate composes
through public collision-resistant root equality, not independent LogUp debts.

## Receipts, costs and gates

Strong receipts and exact archived receivers are in:

- `vectors/reports/interop_artifacts/rv64-ram-20261030/public-receipt/`:
  retained version-1 public-ledger control.
- `vectors/reports/interop_artifacts/rv64-ram-20261030/private-receipt/`:
  version-2 private graph, open CPU debt, 512B/4KiB controls.
- `vectors/reports/interop_artifacts/rv64-ram-20261030/terminal-receipt/`:
  final-root observation, zero state debt, expected bytes and fresh negative
  receiver contexts, including a substituted ninth root word.

These use 70 FRI queries and 26-bit PoW. Explicit diagnostic APIs use 10 queries
and zero PoW; their proofs cannot enter strong receivers. Receipts contain no
public cell/permutation ledger, but no zero-knowledge masking claim is made.
Functional timings are not whole-execution benchmarks.

`private-layout-model.json` in `vectors/reports/rv64-ram-prototype-20261030/`
pins the actual 317,796,238-step Keccak-service guest census. Its independently
padded main/interaction source-cell model includes private callers and shared
internal nodes: 512B uses about 28% fewer aggregate fields than 4KiB, with a
slightly higher peak source bound. Rare boundary terms are conservative bounds,
not fabricated measured counts. Fixed keys, PCS/FFT buffers and native metadata
are separate; this is not an RSS or proof-seconds prediction. Changed guests or
service profiles require a new census.

ReleaseSafe AIR/RAM gates cover full-extension arithmetic/degrees, canonical
bytes, full `u64` addresses, local clock resets, immutable policy admission,
private graph attacks, root/output/header substitutions, private high-byte
masking, allocation cleanup, source adoption, phase guards, strong receipts and
fresh verification. The same-PCS execution integration has its separate
`test-riscv64-authenticated-execution` gate. Whole retained-block qualification
requires the real serialized batch chain and terminal receiver.
