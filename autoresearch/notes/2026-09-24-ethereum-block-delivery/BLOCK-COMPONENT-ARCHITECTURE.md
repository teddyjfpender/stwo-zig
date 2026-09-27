# Active implementation direction: separate block components

User steering on 2026-09-25 explicitly prioritizes this architecture over further
optimization of per-segment memory commitments. Full Ethereum block proving,
canonical security, independent verification and bounded memory remain required.
The old path remains a regression reference until the replacement is qualified;
its small fixtures are not completion evidence for this architecture.

## Target dataflow

```
ELF + input + expected output + independently admitted component definitions
                         |
              bounded execution / event spool
                         |
         +---------------+-------------------+
         |               |                   |
 execution instances  sorted memory     precompile instances
         |             instances       (Keccak / SHA / EC)
         +---------------+-------------------+
                         |
       commit every fixed/main trace; freeze ordered PCS-root manifest
                         |
      derive shared relation challenges from the complete commitment set
                         |
       independently prove instances under the same manifest authority
                         |
        aggregate actual instance count + close all global relations
                         |
          one independently verified complete-block root
```

Instance capacities depend on actual component work and columns, not a common
instruction quota. Instance count is not rounded to a power of two. Active
families must cover their entire assigned work; inactive families have no
instances. BLAKE3 remains the PCS/transcript hash. Removing repeated memory-tree
proofs does not mean removing commitment authentication or trusting host memory.

## Required contracts

1. **Real commitment barrier.** Every participating main trace must be committed
   before shared lookup randomness is derived. The manifest binds the complete
   instance census, role/index, admitted AIR/key identity, geometry, public
   statement, fixed root, main root, program/input/output identity and security
   configuration. Native and recursive verifiers must rederive the challenge and
   prove each leaf's commitment belongs to that same manifest. A hash of host
   columns or a caller-provided challenge is insufficient.

2. **Memory permutation and ordering.** Execution and precompile AIRs publish
   exactly their actual memory transitions. Separately sized memory AIRs prove
   address/time ordering, before/after value continuity and initialization.
   Bind ELF data, input, default-zero memory, register/PC boundaries and final
   output. Explicit initialization events are a possible way to avoid a giant
   default-zero lookup table; choose and prove one initialization contract.
   Use a timestamp representation that cannot wrap M31 on larger blocks. Current
   local access clocks use stride four, and segment-local predecessor clocks
   cannot simply be summed across instances.

3. **Typed relation versioning.** The current universal relation registry has 47
   pinned domains and its digest enters existing transcripts. Add the new block
   relation ABI through a versioned profile; do not silently change old challenge
   draws or reinterpret a recursion wire as a memory transition. Reuse the typed
   AIR compiler, witness generation and independent verifier path.

4. **Global closure.** The root must authenticate the actual instance count,
   unique role/index assignment and complete work coverage, then close every
   shared relation claim. Missing, duplicated, reordered or foreign-manifest
   instances must fail. Existing independent per-leaf LogUp sums use different
   challenges and cannot just be added together.

5. **Bounded host/GPU ownership.** Never retain all first-round traces or PCS
   schemes in RAM to cross the global barrier. Retain/spool authenticated roots
   and replay or reload bounded instance data, asserting commitment equality on
   the second pass. Schedule by memory reservations and component/key affinity.
   Actual allocation budgets remain mandatory; source-column area is only one
   part of a proving-memory estimate.

6. **Arbitrary instance aggregation.** Implement authenticated coverage for the
   actual manifest count. The current `JobContext` accepts non-power-of-two
   segment counts, but `Frontier.takeRoot` still requires authenticated padding
   nodes. Merely changing the scheduler's rounding does not solve this. New
   aggregation must constrain count/ranges and relation closure, with O(log N)
   retained nodes and no dummy execution proofs.

## Existing code that can be reused, and traps

- `air/memory_logup.zig`: typed intra-execution before/after tuple accounting;
  its own contract says ordinary boundaries still need authenticated custody.
- `air/opcode_memory.zig`: committed access layouts, including compact reads.
- `recursion/air/blake3_memory_boundary.zig`: current bridge from memory tuples
  to hash wires. This is a replacement point, not a reason to drop constraints.
- `prover/blake3_extension_proof.zig`: real fixed/main PCS commits happen before
  interaction generation. Extract a reusable owned first-round API here or at
  the PCS layer, then connect it to the new manifest and verification path.
- `prover/guest_precompile/split_leaf_prepare.zig` and `split_joint_pow.zig` are
  explicitly research-only. The former uses Blake2s seals, not PCS roots, and
  excludes base execution columns. Do not activate their flags as a shortcut.
- `recursion/blake3_stream_frontier.zig`: bounded ownership and failure-atomic
  folding are useful; its existing slot-shape restriction needs real proof work.
- Pinned ZisK sources and the exact comparison are in `ZISK-SEGMENT-SIZING.md`.

## Implementation state

- Added `prover/block_component_plan.zig`: independent family sizing, minimum
  instance count followed by minimum allocated rows for a supported height
  ladder, explicit source-column budget and bounded total instance count.
  Three tests pass, including three memory instances (no rounding to four),
  independent execution/memory geometry, empty SHA work and rejection cases.
  This planner is not yet connected to block proving and is not a proof gate.
- Existing-path work scheduling is now regression-qualified on a complete
  two-leaf q70/PoW26 authentication fixture, with a fresh-process receiver.
- All 256 work-balanced mainnet leaves passed commitment geometry screening;
  large representative proof experiments were cancelled after the user's
  architectural steering. This is not a mainnet root qualification.
- Next: real first-round PCS ownership and manifest binding, typed memory
  provider and execution/precompile bridges, arbitrary-count recursive closure,
  then full CPU block qualification and measured time/physical/tracked memory.

Completion must include end-to-end proofs, adversarial omission/duplication/
initialization/ordering/manifest tests and existing CSP regressions. Neither
planner tests, a host-only memory checker nor small standalone AIR fixtures
establish completion.

### First-round commitment implementation (2026-09-25)

The shared extension prover now exposes `commitFirstRound`: independently
admitted fixed and main PCS commitments, their owned scheme/transcript, and the
remaining coefficient budget. It draws no lookup randomness. Production `prove`
uses this extracted stage, preserving the existing verifier transcript. Temporary
extension columns are released at the boundary; PCS streaming has already copied
and owned each input batch. `proveReplaying` additionally rejects either root
changing from the census before generating interactions. A census caller can
copy two roots, destroy the entire first-round PCS, and rebuild one instance at
a time instead of retaining every scheme in memory.

Canonical ordinary and compact SHA/Keccak production-leaf regression tests pass
(`test-first-round-pcs-v2.log`, nine tests including imported declaration tests).
They discard first-round PCS state, replay, compare the eventual proof roots,
reject a changed replay root before interactions, serialize the proof, verify
with a fresh prepared key and independently replay the captured verifier. These
are small fixtures; their elapsed times include duplicated commitment work and
are not block-performance measurements.

`block_commitment_manifest.zig` adds an ordered BLAKE3 census transcript binding
canonical security, the admitted job and versioned relation ABI, exact per-family
work coverage, stable role/index, geometry, AIR/key/statement identities, and real
fixed/main root receipts. It refuses omitted or duplicate receipts, reordering,
foreign fixed roots, incomplete coverage and noncanonical security. Five focused
ReleaseSafe tests pass including the three planner tests (`test-block-manifest-v1.log`).
The manifest accepts descriptors from independently admitted code; it cannot
establish proof validity merely by hashing host-supplied roots.

The production SHA/Keccak extension prover now has an opt-in joint-manifest
transcript. Two adjacent, real compact SHA segments commit their fixed/main PCS
trees, seal a single ordered roster, prove at q70/PoW26 using identical shared
relations, serialize, and freshly verify through a bounded two-pass file receiver
(`test-sha-joint-segments-v3.log`). The receiver rejects missing, reordered and
duplicated proofs. Existing local proof artifacts keep their original transcript.
This is a verified execution-leaf census, not a block proof: the fixture supplies
only execution instances, and independent component identities/row geometry,
memory relations and state continuity still require block-level admission.

The recursive transcript recorder also has a manifest-specific path. It pins the
roster digest and main PCS root in fixed parent rows while routing both first-round
roots to Merkle path checks without absorbing them into shared challenge draws.
A canonical q70/PoW26 recursive parent for one genuine joint-manifest SHA leaf
freshly verifies (`test-sha-joint-parent-v3.log`, eight tests). Parent preparation
retained 4.60 GB, the worker peaked at 9.94 GB tracked, and preparation through
fresh verification took 50.84 seconds on this host. The admitted adjacent
two-child joint aggregate also freshly verifies with its complete existing
memory custody (`test-sha-joint-pair-v2.log`, seven tests): 120.01 s end to end,
9.10 GB retained rows and 19.18 GB tracked worker peak for six fixture cycles.
The first pair test used placeholder component identities. The current
`block_execution_admission.zig` derives AIR/profile identity, full span identity,
three-tree log geometry, fixed root and exact execution-cycle coverage separately.
The pair aggregator recomputes every descriptor and the job context before
proving. Its canonical fresh-root requalification passes
(`test-sha-joint-pair-admission-v3.log`, seven tests): 120.97 s total,
19.18 GB tracked worker peak, 1,019,289-byte artifact. The block-stream CLI
now exposes this route for an exactly two-segment canonical job with `paired joint`.
The installed `stwo-ethereum-block-stream` and standalone receiver now build
(`build-block-stream-joint-v1.log`, `build-block-verify-joint-v1.log`). Their
`paired joint` path proved a complete 21,635-cycle authentication fixture in
two unequal segments and freshly verified the persisted root in a separate
process (`joint-two-segment-root-v1/qualification.json`). Producer time was
76.87 s, tracked peak 18.76 GB, 70 queries and 26 PoW bits. This is not the
139-million-cycle mainnet block and still uses the existing memory custody.
The aggregate now transfers the committed PCS state into proving instead of
rebuilding both fixed/main trees after the census. Its canonical requalification
(`test-sha-joint-pair-reuse-v1.log`) verifies the same artifact size and parent
peak, with 119.68 s total; this fixture does not establish a material speedup.
These small recursive proofs establish neither block continuity nor global memory
closure. Next work remains the separate
typed sorted-memory AIR and initialization/clock bridges, actual-count recursive
coverage/global closure, and complete-block qualification. No new block proof,
end-to-end speedup, or reduced mainnet hash-row count is claimed by these tests.

### Sorted memory contract foundation (2026-09-25)

`air/block/memory_event.zig` projects the runner's **real** register and aligned
memory access log into a common `u64` timeline. It uses the segment's explicit
clock frame and one-based `global_first_cycle`; leaf-local subclocks gain
`4 * (global_first_cycle - 1)`. Already-global clocks are admitted only within
the declared segment interval. Canonical 17-byte event records contain address
space, full 32-bit address, global 64-bit clock and post-access value. Synthetic
old M31 clock-gap records are excluded. Invalid ordinals, range, alignment and
integer overflow fail admission; source events still require a proof-enforced
permutation against the execution/precompile AIRs.

`air/block/memory_order.zig` is a typed AIR **adjacency gadget** for the sorted
table. Its 41 polynomial constraints and 24 byte-range events enforce strict
five-byte `(space,address)` order when the key changes, strict eight-byte
64-bit clock order plus value continuity when the key is unchanged. It pins its
semantic digest (`a1de6d7d...85df4c28`). The limb equations reject M31 and
64-bit wrap. Five focused tests pass in `test-block-memory-components-v1.log`,
including cross-segment clock rebasing, real tracker projection, address-space
switch, timestamp extremes, illegal continuity, forged carries and non-byte
limbs. This is a component primitive, **not** a block-memory proof.

The runner currently retains post-access values, while execution/precompile AIR
witnesses own the actual before values. The new memory relation must publish the
execution side's constrained before/after transition, link it by a joint
permutation to sorted memory rows, and authenticate first values from the ELF,
input, registers or default zero. Adjacency row masks and cross-instance
continuations must be constrained before this gadget can enter production.

`air/block/memory_spool.zig` now has a bounded disk-backed external sorter for
these 17-byte events. It consumes the actual tracker access slice under an
explicit segment clock frame, flushes sorted chunks of at most the configured
row budget, bounds run metadata to 16,384 chunks, and merges at most eight runs at a time. It detects truncated,
malformed, duplicate or nonmonotone events; a failed append poisons the spool.
Each run is admitted only when its file length exactly matches its declared
census. Run readers use 1,024-record buffers rather than one positional read
per 17-byte event. The reader and run files have explicit lifetimes. Its chunk memory is
`chunk_events * sizeof(Event)` plus fixed write/head buffers; run metadata grows
with the number of chunks, not the number of accesses. Tests cover 2,113 events
across two runs and buffer boundaries, duplicate rejection, and two leaf-local
segments with a single global timeline (`test-block-memory-spool-v2.log`,
`test-block-memory-spool-v3.log`, `test-block-memory-spool-v4.log`,
`test-block-memory-spool-v5.log`). This is a
witness transport primitive; the proof still needs an authenticated permutation
and initialization/continuation AIR before sorted rows can replace hash custody.

`air/block/memory_transition.zig` reads the sorted stream into explicit
before/after transitions. For a repeated address, the preceding post-value is
the next pre-value; for a new address, an independently supplied initial-value
provider is mandatory. It emits inputs for the adjacency gadget, rejects
nonmonotone events and poisons the reader after a failed initialization. Three
focused tests pass (`test-block-memory-transition-v3.log`). This remains
witness transport until execution/precompile tuples, initialization and sorted
adjacency are committed and proved under a shared relation.

`air/block/memory_instance.zig` partitions this stream into independently sized
power-of-two AIR capacities while emitting the exact admitted count of real
rows. A predecessor adjacency witness accompanies the first row of each later
instance, so instance boundaries cannot silently drop continuity in the
witness. The final instance is published only after checking for surplus events;
truncation and sink failures poison the partitioner. The complete focused
memory root now passes 33 tests. This is also witness transport, not a PCS
proof or execution-to-memory permutation.

### Work-balanced 256-leaf proof gates

The complete mainnet geometry census proposed 256 explicit unequal execution
segments with no commitment component above log 24. Four distinct actual
canonical full-custody leaf-plus-recursive-wrapper proofs now pass under the
48 GiB process budget: terminal segment 255 (94,180 cycles, 163.56 s,
37.37 GB tracked peak), highest BLAKE3 G rows segment 53 (233,639 cycles,
195.98 s, 38.60 GB), peak other precompile-shaped rows segment 244
(159,229 cycles, 160.88 s, 37.32 GB), and longest segment 50 (4,194,304
cycles, 87.53 s, 17.42 GB). Evidence is the corresponding
`terminal-256-proof-v1/qualification.json` and
`segment-{53,244,50}-256-proof-v1/qualification.json`. These selected proofs
do not qualify the other 252 leaves or the complete block root. More
importantly, the old per-leaf memory custody and power-of-two recursion remain;
the schedule is a feasibility probe, not the intended optimized architecture.
