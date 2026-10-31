# Global memory argument

Status: proposed protocol `ram_global_v1`; physical AIR, aggregate receiver,
resource admission and adversarial qualification remain required. Builds on the
inactive model, collector and relation prototypes in
`src/frontends/riscv/rv64/air/memory/global_ram_v1/` and the choreography in
`rv64-global-ram-v1.md`; this document fixes the remaining choices (LogUp over
the multiplicative variant, tuple schema, epoch ordering, sparse boundaries,
manifest protocol, receiver algorithm) with the implementation obligations and corrections below remaining explicit.

## 1. What it replaces

Today every batch proves a private RAM transition: a Poseidon2 sparse Merkle
tree over 512-byte chunks (38 permutations per touched chunk, 4 per node),
cell/chunk/node/side/policy/terminal components, and a native RAM root chain.
Detached physical proof workers already support out-of-order proving once their
root-linked work packets exist; the native capture/root computation remains
sequential. Costs in the 36-batch round-one run: RAM witness 30.41 s,
worst batch 45 s with 2.1M padded Poseidon rows. The existing serial driver
is a scheduling choice, not a cryptographic
requirement that physical proofs finish in order.

After this version: RAM events are LogUp tuples in a relation shared across
all batches and services of one execution; initialization and teardown are
two sparse sorted tables; the challenge is drawn once from a sealed manifest
of every participant's stage-one root; batches prove in any order and in
parallel; the aggregate receiver closes the relation. No sparse-Merkle RAM update circuit remains; PCS commitments still hash the
committed memory columns.

## 2. Relation and tuple

LogUp (sum of inverses) over QM31 with the existing prefix/cyclic machinery.
The multiplicative variant in `rv64-global-ram-v1.md` is not selected: it
saves no CPU width, needs new degree analysis for masked AFTER tuples, and its
security budget must be re-derived. LogUp keeps the proven infrastructure; its
only extra obligation is the M31 mass bound, discharged at admission.

Tuple, 14 coordinates (`global_ram_v1/manifest.zig` ARITY):

    (space, addr[4], epoch, tick_lo, tick_hi, value[4], readable, writable)

- `space` = 1 for RAM (registers stay local, space 0 is never global).
- `addr` is the aligned 8-byte word address as four u16 limbs.
- `epoch` is the batch ordinal (u16); `tick_lo`/`tick_hi` the 24-bit local
  slot clock as u16 + u8, exactly the CPU clock limbs.
- `value` four u16 limbs; `readable`/`writable` Booleans from the immutable
  policy.

This is a bounded 40-bit logical timestamp, not a full-u64 clock. Epochs must
be range checked and bound to expected manifest ordinals (at most 65,535).
Local register clocks retain their own 24-bit cap. Expanding either contract
requires new integer-order equations and qualification.
Different arity-14 schemas (for example full-u64 time plus packed rights) must
have distinct tuple-schema identities. Matching arity does not imply matching
coordinate meaning. Read-only accesses still advance authenticated time.

Unit-flow equation per execution:

    sum BEFORE + sum TERMINAL = sum AFTER + sum INITIAL

Producers: the LOAD/STORE chip (one BEFORE and one AFTER per access), the
Keccak bridge (25 lanes per call, BEFORE and AFTER), the secp bridges (12 or
24 words per call), the initialization table (one AFTER per touched address
at epoch 0, tick 0, taken from the expected image) and the teardown table
(one BEFORE per touched address at its final time).

## 3. Order

Time is `(epoch, tick)` lexicographic. For an event with BEFORE time
`(e_p, t_p)` and AFTER time `(e, t)` the producer commits a Boolean `same_epoch`
and advice limbs and proves:

- `same_epoch = 1`: `e_p = e` and the two-limb strict order with carry of
  section 2.3 of `rv64-word16-cpu-2n.md` on `t_p < t`.
- `same_epoch = 0`: `e_p + epoch_gap + 1 = e` with `epoch_gap` a u16 range
  lookup; `t_p` is any canonical time (its limbs range checked).

AFTER times of CPU-owned events are fixed geometry (row, slot); service lanes
bind their tick to the CPU service row as today. Uniqueness is for **(address, epoch, tick)**, not time alone: Keccak's 25
distinct words share one service tick. Overlapping service pointers must be
coalesced to one net transition per word or use separately authenticated strict
subclocks. A lane number absent from the tuple cannot supply uniqueness. The
receiver checks event coverage and the AIR establishes origin and strict order;
a native count alone establishes neither.

Strict descent reaches the unique initialization source for every address, so
reads are canonical by induction from the expected image, provided every write
authority (LOAD/STORE merge, Keccak, secp) proves canonical limbs, which they
do through their own range lookups. The two counterexamples that make each
obligation necessary (disjoint future/past cycle; double initialization) are
retained as regression tests from `global_ram_v1/model_test.zig`.

## 4. Sparse boundaries

Two components per execution, each a sorted table over touched addresses
(U <= 3.4M for this block, bounded by the collector):

- **INIT**: rows `(addr, value, rights)` with time `(0, 0)`, emitted as AFTER.
  `value` is looked up in the receiver-derived nonzero image table (ELF data,
  BSS zeros, input), or through a disjoint zero-default proof. Permission-region
  membership alone does not prove a zero value: the zero route must prove
  absence from all expected nonzero ELF/input exceptions. The two routes must
  not authorize different initial values for the same address. The prover
  never chooses an initial value. Rows are strictly increasing in
  `addr` (four-limb comparison with borrow advice), so each address appears
  once.
- **TEARDOWN**: rows `(addr, value, rights, epoch, tick)` emitted as BEFORE
  with the final time; same strict address order; the final values are what
  the terminal certificate reads (the 43-byte output and halt flag are proven
  by binding their addresses' teardown rows to the public output).

Both tables have fixed log sizes per protocol version (2^22 covers U with
margin for this guest class) and sit in one component with two roles.

The native side is the existing `global_ram_v1/collector.zig`: one first/last
record per touched word, exact predecessor epoch/time for the tape, sorted
boundary records at `finish`. It is wired into capture in step 2 below.

## 5. Two-phase commitment protocol

Participants: `S` batch shards (CPU + chips + service providers), INIT,
TEARDOWN. A coordinator holds the manifest; workers hold proofs.

Phase one, per participant, independently and in parallel:

1. Start the local transcript with protocol id, execution identity (ELF,
   input, policy, terminal contract digests), shard ordinal, role, geometry.
2. Build the memory advice columns only: the RAM tuples' committed parts
   (addresses, values, rights, BEFORE times, same_epoch, gaps) for every
   RAM-producing component in the shard, in a dedicated **memory subtree**
   (its own PCS tree, committed before the main tree).
3. Return `Receipt = (identity, ordinal, role, geometry, memory_root,
   active_event_count)` to the coordinator.

Manifest seal, coordinator:

4. Validate the receipts against the independently expected inventory: all
   ordinals present once, roles complete, geometries equal the protocol's
   fixed shapes, PC/register endpoints of adjacent shards match, total event
   mass below M31. Serialize the ordered manifest; its digest `m` is the only
   message back to workers.

Phase two, per participant, in parallel:

5. Rederive `alpha_ram = H(m)` (QM31 challenges: offset and 14 coefficients).
   Check the local memory root is the one in the manifest at this ordinal.
   Build the remaining main columns, commit, draw all *other* challenges
   locally as today, generate interactions (RAM interactions use `alpha_ram`),
   compose, FRI, decommit. The proof carries its memory root, `m`, and its
   RAM claim (a QM31 sum).

The memory barrier does not seal unrelated global relations. If FUNCTION
claims are also shared across workers, their query tuples and multiplicities
must likewise be committed before their global challenge, with independently
expected roots and a physical join to CPU execution. Keeping FUNCTION local
is an alternative. A memory-only receipt does not bind later FUNCTION advice.

Workers must also admit the complete retained stage-one footprint. Holding all
wide PCS owners until the barrier is not a bounded-memory schedule. Projection
columns physically reused in the execution proof, or qualified durable spill /
root-checked reconstruction, need explicit ownership and transfer budgets.

The required local soundness argument is: the memory advice
is committed before `alpha_ram` exists, all other witness columns are committed
before their own challenges, and `m` is mixed into the local transcript before
any challenge is drawn.

## 6. Aggregate receiver algorithm

Given the manifest `M`, the expected inventory and all proofs:

1. Recompute `m = digest(M)` and `alpha_ram`. Reject if any proof carries a
   different `m`.
2. For each proof: verify it fully (its local verifier), then check that its
   first tree root equals the manifest's memory root for its ordinal and that
   its RAM claim is the one bound in its transcript.
3. Check the inventory: one proof per ordinal, roles complete, adjacency of
   `(pc, registers, epoch)` between consecutive batches, service call ranges
   contiguous, first batch at the expected initial PC and registers, last
   batch at the terminal PC.
4. Sum all RAM claims: `sum_batches + claim_INIT + claim_TEARDOWN = 0`.
5. Check the terminal output through the TEARDOWN rows bound to the output
   addresses.

Steps 1 to 5 are exactly what the leaf and parent circuits of
`rv64-aggregation.md` compute; the native receiver is the reference.

## 7. Security budget

- LogUp soundness as today, with total RAM mass (all producers plus both
  boundary tables, counted conservatively from fixed geometry) below
  the M31 characteristic: for this block about 2 * 67.3M events plus 2U rows,
  well below 2^31. Admission computes it from the manifest with checked
  integer arithmetic. Using smaller active counts instead requires those counts
  to be physically proved and pinned before the shared challenge; native
  `ram_events` metadata cannot replace that authority.
- Challenges are QM31 (about 124 bits), drawn from a Blake2s channel seeded by
  `m`; the manifest commits to every memory root so a root replacement after
  the draw is detected in step 2.
- Local BYTE, range16, ROM and family relations remain local and unchanged.

## 8. Attack tests required before promotion

Shared range providers need a separate mass admission calculation from RAM.
Using the round-5 opcode census, globally packed fixed instances for the current
conservative CPU, ALU (including branch predicates), LOAD/STORE and SHIFT
contracts, without weighted pure-function deduplication, would emit **2,408,579,072 U16 queries including padding**. This already
exceeds M31's characteristic by 261,095,425, before any additional chips. A
single global U16 ledger must therefore reject that proposed geometry. Current
local proof closures remain independent and do not activate this global plan.

One candidate partition assigns CPU/ALU to a 1,111,490,560-query ledger and
LOAD/STORE/SHIFT to a 1,297,088,512-query ledger, each with a distinct scoped
challenge and complete provider closure. Admission must include every later
chip too. Immutable table setup can still be shared; multiplicities, challenge
scope and physical claims cannot be reused across these ledgers. The
[reproducible mass model](../../vectors/reports/rv64-guest-lean-20261031/round5/global-u16-mass-review-v1.json)
records the experimental contracts and assumptions. This is a design requirement,
not a qualified global range protocol. Weighted fact reuse can lower the selected
roster; admission must use its actual padded physical rows and cannot assume
this conservative geometry or its partition is mandatory for every design.

Omitted shard, duplicated shard, reordered shards, memory root replaced after
the challenge, RAM claim replaced in the wire proof, init omitted or duplicated
for an address, wrong initial image or zero region, boundary fork (two
teardown rows for one address), future clock (BEFORE after AFTER), inactive
source (padding row emitting a tuple), service double event (CPU and service
both emitting the same word), cross-execution claim cancellation (two
executions sharing `alpha_ram`), characteristic overflow (mass admission),
terminal substitution. Each is a fresh-receiver test, not a model test.

## 9. Cost

Removed per batch: Poseidon2 chunk/node/side components, the RAM witness
(28.8 s over the run), the serial root chain. Added per batch: the memory
subtree commit (the LOAD/STORE and service RAM tuple columns were already
committed; they move trees, no new columns), two u16 epoch-order advice columns plus a Boolean same-epoch flag
per RAM producer row. Added per execution: INIT and TEARDOWN at 2^22 rows
each (14 and 16 main columns, 3 Q interaction) and the collector's sorted
boundary pass. Net per the cumulative source model in
`rv64-global-ram-model.json`: fewer bytes than the current RAM provider set,
provided the memory columns are the chips' own columns and not duplicates at
every CPU row (which the model shows would cost 1.3 GB more).

## 10. Implementation plan

| Step | Files | Gate |
| --- | --- | --- |
| 1. Memory subtree in the PCS | `prover/pcs/scheme.zig` (commit order, root export) | root export and inclusion tests |
| 2. Collector in capture; epoch/predecessor advice on the tape | `rv64/boundary_capture.zig`, `compact_tape.zig`, `global_ram_v1/collector.zig` | native parity with the current chunk openings on the full block |
| 3. RAM relation in LOAD/STORE and service bridges | `air/word16_v1/loadstore.zig`, `crypto/*/bridge/` | degree tests, order attack tests |
| 4. INIT/TEARDOWN component | `air/memory/global_ram_v1/boundary.zig` | sorted-unique attacks, image lookup attacks |
| 5. Manifest, receipts, coordinator | `integrations/riscv_cpu/rv64_ethereum_manifest.zig`, extend `rv64_work_packet_*` | manifest codec attacks (already covered for the functional prototype) |
| 6. Native aggregate receiver | `rv64_ethereum_verify_chain.zig` successor | full block, all attacks of section 8, fresh process |
| 7. Delete the Poseidon RAM route | `air/memory/{chunk,node,side,leaf,cell,...}` | fixtures re-pinned, CI target |
