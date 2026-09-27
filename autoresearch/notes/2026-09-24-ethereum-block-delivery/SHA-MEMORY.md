# General SHA compression: CPU and memory integration checkpoint

**Latest status:** canonical combined SHA leaf proofs, source artifacts, recursive parents and adjacent-segment full-custody roots are qualified. The default EVM SHA provider builds and the mainnet guest executes correctly; this fixture has zero EVM SHA calls. A full mainnet block proof is running and remains unqualified. Historical checkpoints follow.

The SHA arithmetic/DAG already passed a canonical q70/26 standalone STARK. The
provider now owns four final batched row arrays and emits arithmetic directly
into them. There is no per-round heap allocation. Fixed topology is reconstructed
from call count alone. `test-sha-provider-1.log`: canonical proof and provider
ownership/allocation-failure tests passed; measured proof gate 4.691747833s.

New general compression contract (`isa/sha256_compression_v1.zig`) uses two
register pointers, arbitrary eight-word chaining state, and a 64-byte message.
The state is overwritten, the message is preserved. Both spans are aligned and
disjoint. State words are little-endian in guest memory; message schedule words
interpret the same raw bytes big-endian. The prospective encoding uses funct7=6
and proof operation50, after the existing memcpy48/stack-swap49 contracts.
**Existing execution profiles still reject it. Production activation is pending.**

The native transaction has one owned call/instruction tape and performs all
fallible reservation before committing memory, tracker state, PC or external
retirement. Its tests exhaust allocation failures and verify exact state/message
bytes and clocks. The typed caller has 238 main columns, 63 direct constraints,
189 relation events; its semantic identity is
`e6a6504bd77f318065725524cd55e3378c71bced21c6bf1fc3c4260d8a067ed9`.
One caller row binds program/state retirement, both pointer registers, 24 memory
word transitions, 24 SHA input wires and 8 output wires. The complete graph closes
against exact memory tuples, and a forged output fails even when the external
output claim is changed to match it.

Typed aligned addresses now accept checked 28-bit word indices as well as the
existing 20-bit load/store indices. Twenty-bit nodes retain the original fixed
load/store-plan validator. A 28-bit component projection can only enter a matched
consume/emit/range triple; the pinned caller proves bounds and clock equations.
The caller uses the reviewed sequential-retirement constructor. The common scalar
test interpreter handles the closed machine-derived expressions.

`test-sha-memory-12.log`: all 17 tests passed, covering caller equations, full
compression graph/memory closure, upper address boundary, malformed closed
access groups, encoding, transaction rollback (including external retirement and mismatched aggregate counts), and existing typed load/store and
retirement compatibility. These are semantic/transaction tests; **they are not a
production VM proof of the new instruction**.

## Shared compiler and canonical memory-call proof

The shared direct/lookup compiler now admits validated closed machine expressions
and explicitly declared program-bound PC inputs. Native evaluation and polynomial
export lower those expressions through existing field arithmetic. Unqualified PC
inputs remain rejected. The caller needs 536 arena nodes; cold plan capacity is
now 640 nodes. This change postdates the saved memory-scaling binary.

`test-sha-compiler-4.log`: all 18 focused tests passed, including base/extension
field and polynomial-export agreement. `test-sha-memory-stark-2.log`: the canonical
q70/26 SHA memory-call STARK freshly verified in 30.576 seconds. It combines the
four SHA compression cohorts, typed caller, independently specified public
CPU/memory boundary and shared bitwise/range tables. A changed output boundary is
rejected. This is one qualification run, not a performance median.

The public boundary fixture has semantic identity
`c08a15c38e4b85cd4ea29faff61b849c8e5c2375482a6b73a968588ba57511a0`.
It supplies the opposite CPU/memory claims without recomputing the SHA output.
It is a standalone proof fixture, not the production VM memory-root provider.

## Next required integration

Add the combined execution profile and declared-program admission, thread the SHA
tape through sessions/segments, register the provider/caller in the leaf roster,
wire the guest SHA provider, and fresh-verify a guest proof through recursion.
Production SHA dispatch remains inactive. Full Ethereum block and GPU
qualification remain outstanding. The older source checkpoint predates the
shared compiler and canonical memory-call proof changes.

Peer basis: pinned ZisK 5c5f81c96929abed88894473ec6060b1b545b5c5,
`precompiles/sha256f/src/sha256f.rs`: separate state/input pointers, compression
operation, per-operation call records, and trace capacity independent of operation
semantics. Its 64-bit-field equations are not copied into M31.

## Qualified SHA integration foundation (2026-09-25)

The current focused gates pass: 11 memory-call/provider tests, 19 shared compiler
and typed-effect tests, six compression/provider tests, and three Rust guest
framing tests. The memory-call STARK freshly verifies at canonical q70/26 in
25.513 seconds; the compression STARK verifies in 4.856 seconds. These are single
qualification observations, not comparable end-to-end guest benchmarks.
Evidence: `test-sha-memory-stark-3.log`, `test-sha-compiler-5.log`,
`test-sha-provider-2.log`, and `test-sha-guest-2.log`.

The provider borrows native execution tape and owns only five final row arrays.
Independent preprocessing emits final fixed columns directly, removing full
placeholder witness arrays: at 64 calls, 4,993,024 placeholder bytes disappear
and 632,832 fixed-value bytes remain. This is an 8.89x reduction in those value
buffers, not in whole-prover memory. Allocation-failure and zero-call padding
checks pass. Lookup registration validates before mutation; verifier-derived
multiplicity bounds count 26 memory accesses per polarity per SHA call, with
23 extra accesses beyond the native retirement allowance. SHA internal wires
use independent transcript challenges while retaining shared VM memory and
lookup buses. A canonical component profile binds geometry and semantic digests;
a shared component owner keeps relation challenges alive after AST teardown.

The Rust SDK implements complete SHA-256 framing with aligned direct block reads
and bounded scratch. Host checks cover padding/alignment boundaries, standard
vectors and a million-byte input against the independent sha2 implementation.
The RV32 build emits the exact instruction 0x0c62800b; see
`sha-guest-qualification.json`. This qualifies framing and ABI compilation,
not a production guest execution or proof.

Production SHA dispatch remains inactive. Combined profile/program admission,
session tape plumbing, production leaf roster/admission and guest-provider
activation still require integration and a fresh recursive guest proof. The
memory-scaling measurements use the separately archived earlier binary; they do
not measure the current SHA/compiler source snapshot.

## Combined SHA execution session (2026-09-25)

`runner/guest_precompile/ethereum_sha.zig` now owns Keccak, recovery and SHA tapes
with checked aggregate counts and one external-retirement origin. The existing
Ethereum dispatcher delegates through an aggregate-count entry point; its old
profile behavior is preserved. The combined session enforces one total call
budget before mutation. It remains outside ELF admission pending the matching
production proof roster.

The native-call input to the canonical standalone SHA STARK now executes through
this combined session. It freshly verified at q70/26 in 24.772 seconds (single
observation, `test-sha-memory-stark-4.log`, all 11 selected tests passed).
`test-sha-combined-session-3.log` passes the SHA → Keccak → SHA sequence,
including shared memory-clock transitions, rejecting stale per-tape retirement
counts without mutation, rejecting total-budget overflow and releasing every
injected allocation failure. The first stricter test expected the wrong error
name; the trace correctly returns ProfileClockCountMismatch. No runtime change
was needed for that expectation correction.

This is execution-session integration and a standalone proof, not yet an
admitted SHA guest or a combined SHA/Keccak production leaf proof. Next: connect
combined session ownership to segmented results, declared-program admission and
the production leaf witness/statement, then qualify recursive guest proving.

## Combined ownership, admission and transcript integration

The SHA tape now freezes without allocation or copying. The combined session
validates cumulative trace counts minus the segment origin before moving any
of its five tape buffers; an invalid count leaves all ownership unchanged.
`EthereumShaSegmentResult` supplies the owned segment wrapper for subsequent
session plumbing. The canonical standalone SHA proof now consumes frozen tape
records. `test-sha-memory-stark-5.log` passes all 14 selected tests, including
mixed SHA/Keccak execution, allocation failures, frozen-pointer identity and
combined challenge replay. The q70/26 memory-call proof verifies in 24.896s
(single observation).

Combined verifier admission adds SHA's exact public fixed-table bounds and
23 additional memory terms per call, and validates the aggregate native external
retirement count. Zero-call SHA cohorts still contribute fixed padding demand.
The existing Ethereum admission path retains its previous bounds and identity.
The new `blake3_ethereum_sha_statement.zig` binds the Ethereum manifest, canonical
SHA component profile and combined certificate under the distinct B3ES/version-1
transcript frame. Altered SHA semantics and memory bounds are rejected.
`test-sha-combined-admission-2.log` passes all nine selected tests through the
existing Ethereum witness census, including zero/nonzero SHA admission deltas,
wrong aggregate counts and transcript separation. This is statement/admission
qualification, not a combined production proof.

`ethereum_sha_relations.zig` draws the existing 26 Ethereum challenges followed
by SHA's framed independent wire pair, retaining exactly the shared native VM
buses. Capture/replay and prover/verifier transcript agreement pass. The focused
admission script now delegates to the common SHA Zig harness rather than copying
its build command.

Remaining production work: connect the new owned result to segmented execution,
add the declared SHA-capable executable identity and program fetch authority,
join the SHA witness/interactions/components with the Ethereum leaf pipeline,
encode/decode the combined proof artifact, activate the guest SHA provider,
and freshly verify the resulting guest through recursion. Full Ethereum-block
root and GPU qualification also remain outstanding.

## SHA-capable ELF and segmented execution qualification

The explicit `rv32im-zkvm-ethereum-sha-v1` profile now uses ELF profile ID 4,
capability bits 14 and ABI version 1. Its execution semantic identity is the
SHA-256 of `riscv.ethereum.keccakf_1600.secp256k1_recover.sha256_compress.v1`.
Prior profile IDs, metadata and decoding remain unchanged. The shared CUSTOM-0
decoder admits both SHA pointer registers; declared and fetched program words
project to `{50, 0, rs1, rs2}`, matching the typed SHA caller. Old Ethereum
execution still rejects SHA. Wrong capabilities, ABI and digest are rejected
before loading. The old unknown-profile test now uses 0xffff because ID 4 has
an assigned identity.

The canonical ExecutionSession now selects the combined SHA state and returns
owned SHA-capable segment/run results. A seven-instruction ELF executes
SHA → Keccak → SHA through both global and leaf-local segmented clocks and the
same one-shot loop. The first segment is freed before resuming. Segment freezing
uses the extracted trace's local count; cumulative freezing remains a separate
entry point. This fixes the observed double-subtraction of the prior external
origin. Leaf-local tests explicitly select segment-owned trace retention, as
required by the existing bounded-memory session contract. Diagnostics has a
third external family for SHA; the old Ethereum minimal replay path explicitly
rejects the new opcode.

`test-sha-profile-5.log`: all 20 focused tests pass, covering the new admission,
all 1024 SHA operand pairs, both segmented clock modes, one-shot execution,
legacy rejection, mixed-session ownership/allocation failures, existing ELF
malformation/truncation tests and old CUSTOM-0/profile identities.
`test-sha-profile-regression-1.log` also passes the existing nine-test Ethereum
witness/admission census after introducing the profile.

Execution admission is now enabled for this explicit profile. End-to-end proof
activation remains incomplete: wire frozen SHA records into the combined native
leaf witness/program fetch census, register shared lookup demand before table
commitment, append SHA interactions/components and proof artifact encoding, and
qualify the admitted guest through recursion. The full Rust SHA SDK framing is
qualified separately; its Ethereum guest provider selection remains pending.
The earlier standalone SHA memory-call proof is not evidence of this combined
production guest proof. Full Ethereum-block root and GPU qualification remain
outstanding.


## Combined SHA production assembly qualification

The Ethereum prefix and five SHA components now have one combined component
owner for both proving and verification. It owns its relation copy and stable
component owners, validates the combined admission certificate, and derives SHA
column/constraint offsets from the actual preceding components. The original
Ethereum assembly shares the same checked compact-provider offset calculation.
It retains its original two-family admission path and transcript.

Combined Tree-0 generation uses verifier-derived SHA topology. Main columns reuse
the existing Ethereum views and project SHA rows directly to final columns.
Interaction output concatenates column descriptors without cloning their field
storage; each producer retains responsibility for its own backing allocations.
Cleanup releases these owners in reverse order.

The combined claim type binds all fourteen existing Ethereum claims and five SHA
claims with explicit framing and order. Zero SHA calls do not force its padded
lookup claims to zero. The strict claim codec retains the existing detailed
Ethereum claims, uses a distinct combined magic/component count, and rejects
noncanonical field limbs and truncation.

`test-sha-combined-assembly-2.log`: all 12 focused tests passed. The actual
SHA → Keccak → SHA witness closes every shared relation. Both prover and verifier
assemblies agree on placement; all three generated column trees end at the
expected offsets. Claims round-trip and reproduce the transcript. Leaf-local
splits before the first SHA instruction and before Keccak both pass after freeing
the preceding segment, including zero-SHA/zero-Ethereum padding. Existing Ethereum
witness census and SHA interaction allocation-failure cleanup also pass.

This is assembly/claims/witness qualification, **not yet a combined SHA leaf
STARK or recursive root**. Next integration batch: expose the combined profile
through the shared extension proof/prepared/manifest API; pass the existing
allocator into SHA coefficient admission instead of introducing an untracked
allocator; route full VM relations to SHA while preserving Ethereum's draw order;
add combined statement metadata encoding; prove, serialize and freshly verify the
combined leaf. Then wire its recursive capture and activate the guest SDK. Full
mainnet-block root remains pending.


## Canonical combined SHA leaf and source artifact qualified

`test-sha-combined-leaf-5.log`: all nine focused tests pass. Both full-table and
compact-provider versions of the admitted SHA → Keccak → SHA guest produce a
canonical **70-query / 26-PoW** STARK through the shared extension pipeline.
The original witness and prepared key are released before verification. The
strict combined proof codec round-trips; a modified SHA claim is rejected.
A separate key is derived from decoded metadata. The full source-bound artifact
then independently authenticates the supplied ELF/input, decodes its manifest,
derives another key and freshly verifies the proof.

| Provider mode | Inner proof bytes | Qualification elapsed |
| --- | ---: | ---: |
| Full tables | 4,108,400 | 4.647371334 s |
| Compact | 4,031,494 | 2.980226500 s |

These timings include witness/key preparation, artifact serialization, negative
claim verification and repeated positive verification. They are correctness-gate
timings, not an isolated prover benchmark or a full Ethereum block measurement.

The new B3ES profile uses allocator-aware admission and prepared-key identity,
832-byte extension metadata that binds all five SHA semantic/geometry descriptors,
and a disjoint B3SVART1 source envelope. SHA coefficient derivation is charged to
the caller's allocator. Compact transcript mixing now completes allocating
admission once before changing the channel; a capped allocator test verifies that
mixing does not allocate a second admission pass after channel mutation.

Existing Ethereum and guest-Poseidon full proofs, outer artifacts and recursive
replay checks passed in `test-sha-combined-leaf-4.log`. That entire invocation
failed because its SHA fixture lacked release ABI symbols. The production source
validator correctly rejected it; the fixture now uses the complete release ABI.
`-5.log` qualifies the corrected SHA fixtures. The earlier challenge-adapter type
mismatch was fixed by retaining each profile's fixed draw count at replay.

Source archive and exact hashes: `sha-combined-leaf-qualification.json` and
`sha-combined-leaf-source.tar.gz`. Combined SHA recursion remains unqualified;
the Ethereum guest SHA SDK provider, full mainnet block root, and GPU qualification
remain pending. The recursion handoff above lists the required symbolic challenge,
claim routing and geometry changes.


## SHA recursion, custody and default EVM provider qualification

Canonical combined SHA recursion is now qualified. The closed capture mapping,
profile-aware transcript replay, native public compensation and DEEP geometry
support the explicit SHA profile. Challenge replay retains the SHAW domain frame;
only SHA's internal wire relation is replaced with its separate symbolic pair.
The recursive composition recorder replays the fourteen Ethereum components and
all five SHA typed AIRs using the native verifier's authenticated programs. Its
constraint census covers all nineteen components. SHA claims remain circuit
inputs bound to the transcript, and changed claims are rejected.

`test-sha-recursive-parent-1.log`: all eight tests pass. A canonical SHA/Keccak
leaf produced a canonical recursive parent, serialized it, released the worker
and rows, and freshly verified the parent. Parent path: 48.822127125 seconds,
including 8.880612500 seconds preparation and 33.239605583 seconds proving;
979,542-byte parent artifact; tracked worker peak 9,818,400,272 bytes.
This worker peak excludes separately retained preparation allocations.

`test-sha-recursive-segments-1.log`: all eleven tests pass. Two adjacent SHA-profile
segments (SHA, then Keccak/SHA) prove full memory custody, aggregate, serialize,
and freshly verify a complete root at **70 queries / 26 PoW bits**. Elapsed:
121.026120416 seconds; parent artifact: 1,015,674 bytes; tracked worker peak:
19,183,383,520 bytes, excluding 9,104,411,864 retained preparation bytes. This is
a paired two-leaf qualification fixture, not a mainnet block timing or a claim
that the earlier unpaired streaming footprint increased. Existing Ethereum
boundary aggregation and guest-Poseidon proof/replay regressions also pass.

The shared segment-pair API now selects base, Ethereum or Ethereum/SHA by explicit
execution profile. The block stream and bounded preflight use that same profile
selection. There is no alternate SHA proof engine. The ISA activation marker is
true for this explicit capability; runner markers reference that single constant.
Older executable profiles continue to reject the SHA instruction.

The Rust Ethereum guest now defaults to a `sha256-precompile` feature and overrides
revm's `Crypto::sha256` through the shared allocation-free SDK. Its ELF note selects
profile 4 / capabilities 14 / ABI 1 at the same time. `--no-default-features` retains
the prior explicit profile for comparisons. Other SHA2 uses outside that EVM
provider are not automatically redirected. All three independent host framing
and alignment tests pass, and the default RV32 guest builds. A build-time check
now compares the emitted capability note with the canonical semantic digest.
The initial guest artifact was correctly rejected for a mis-transcribed digest;
`ethereum-block-sha-default-v2.elf` contains the corrected, checked note. Earlier
failed build/execution logs are retained as failed attempts.

The corrected guest executes mainnet block 24,628,607 (66 transactions) and matches
the existing expected output: 139,214,856 cycles, 32,835 Keccak calls, 78 recoveries,
**zero EVM SHA compression calls**, 40.089439375 seconds runner elapsed,
40.156780125 seconds process wall, and 256,713,536 bytes peak physical footprint.
This establishes guest integration compatibility, not a SHA speedup or native SDK
runtime-vector coverage. The previous guest executed 139,213,662 cycles in
39.916791458 seconds; these single runs are not a controlled performance comparison.

A full canonical block proof has started in
`measurements-mainnet-24628607-sha-canonical-4194304`, using the new profile-aware
stream binary and a 4,194,304-cycle upper bound. Its successful root has **not**
yet been observed. Power status is recorded by the measurement harness; this run
started on battery at 100%. Full block proof and GPU qualification remain pending.
The next SDK gate should execute native Rust SHA framing against known vectors;
the chosen mainnet fixture does not exercise that callback.

Exact sources and hashes: `sha-recursive-delivery-qualification.json` and
`sha-recursive-delivery-source.tar.gz`.


### SHA preflight profile correction

The initial full block proof attempt above **failed** after 1.23 seconds with
`InvalidPrecompileEncoding`; no proof was produced. Preflight execution selected
the SHA profile correctly, but its program commitment still used the old Ethereum
decode authority. That authority is now passed through both endpoint commitments.
The strict replay check supports the same two explicitly admitted profiles.
The terminal-publication regression now runs for both profiles, including an
unexecuted SHA instruction in the declared program, and all 15 focused checks pass.
Source archive and hashes: `sha-preflight-profile-fix-qualification.json`.
The failed run and its measurement are retained. Full block proof timing and memory
remain unqualified until a successful independently verified root is produced.


### Native Rust SHA SDK execution qualified

`sha-native-vectors-v1/qualification.json` records 44 native RV32 digest vectors:
offsets 0–3 and lengths 0, 1, 55, 56, 63, 64, 65, 127, 128, 129 and 1024 bytes.
All outputs match independent Python hashlib SHA-256, with exactly 148 admitted
compression instructions, 38,367 guest cycles, and no Keccak or recovery calls.
This covers padding boundaries and the direct aligned / copied unaligned block
paths using the actual SDK assembly instruction. It is an execution qualification,
not a proof timing. The test executable and Ethereum guest share the capability
note in `ethereum_admission_v1.rs`; the duplicate note was removed from main.rs.
`sha-native-sdk-vectors-source.tar.gz` preserves the sources. This closes the native
SDK vector gap above; the pinned mainnet fixture itself still has zero SHA calls.


### Full block proof partition qualification remains pending

The corrected preflight completes all 139,214,856 cycles in 10.049406584 seconds
with the 4,194,304-cycle counting limit, checks the expected output, and plans 64
leaves. The first witness then fails `CommitmentTraceTooLarge`: the supported
commitment AIR log-size cap is 24. This cap was retained. Failed invocation:
`measurements-mainnet-24628607-sha-canonical-4194304-v2/measurement.json`.
A smaller 262,144-cycle partition is now under measurement with witness-stage
profiling enabled. There is still no successful full-block root or block proof
throughput claim. The repeated SHA guest build after extracting the shared ELF
note passes (`build-sha-ethereum-guest-v3.log`, ELF/build manifest v3).
