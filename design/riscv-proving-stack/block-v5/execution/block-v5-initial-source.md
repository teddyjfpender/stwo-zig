# Block-v5 initial memory sources

The scoped v5 batch receiver in `block_v5_memory_batch_receiver_v1.zig`
freshly verifies every independently sized sorted-memory AIR proof and each
exact shared 8×8 range-table shard under the common v5 SourceSeal. It closes
cross-instance predecessor links, range requests, and initial values against
the independently pinned register, public-input, and RW image. A loader can
decode one proof at a time. The receiver does not verify execution, ROM
fetches, or a complete block. Program first touches are rejected until a
freshly verified ROM-table receipt joins the common source relation.

The trusted initial-source plan pins the memory layout, initial register words,
public-input hash and length, initial sparse RW root, and SHA-256 hash plus
exact record count for each of `input.bin`, `rw.bin`, and `first-touch.bin`.
Input and RW files use sorted `(byte address, nonzero word)` records. The
first-touch file uses strictly ordered `(space, byte address, initial word)`
records. The verifier reconstructs every nonzero public-input word from the
independently pinned input bytes, validates RW classification and ordering,
rehashes the combined sparse initial image, and checks each touch against that
image or the pinned register array. Public input is allowed inside one RW
address interval; the validator rejects ambiguous program/RW or RW/RW layout
overlaps. Missing or extra first touches cannot close the freshly proved
sorted-memory initial relation except through the field challenge soundness
error. The plan digest is mixed into SourceSeal before relation challenges.
The memory plan separately hashes the total event count, every ordered claim
(including AIR log size, row span, first/last transition, and predecessor),
the exact range-shard plan, and all first-round roots. The receiver recomputes
that digest from caller-pinned metadata before challenge draw.

The diagnostic q8 fixtures prove and freshly verify a four-event one-instance
case and a two-instance case with AIR log sizes 8 and 9 sharing one range
shard. Mutations cover file bytes, public input, plan digest, image root,
malformed layout, reordered and duplicate touches, a program touch, changed
memory log size, predecessor, first-round root, and seal digest. The old v2
q70/PoW26 memory/table proof test passes after the shared proof APIs became
generic over the seal interface. This is a proof-producing architecture slice;
the complete v5 block receiver and ROM linkage remain separate admission work.

The independently pinned mainnet exact-schedule first-touch file from the
earlier public-roster audit has 3,142,932 records: 31 register, 675,177 public
input, 2,467,724 RW, and **zero program first touches**. Its SHA-256 digest is
`576ac9b5fa22dc9b3c202657b447ebbd3c67f6de9b5f274973dea8df9711fa68`.
This is specific to that ELF/input roster, not a universal property. A future
program-touch bridge must derive raw byte-addressed u32 words from the
independently pinned ELF, separately verify its decoded M31 ROM root, and
require a fresh ROM receipt before emitting those memory initial tuples.

`block_v5_memory_batch_artifact_v1.zig` supplies the matching two-pass scoped
producer. Its first pass loads and releases each trace while retaining only
roots, exact range counters, and the canonical memory plan. Its second pass
reloads one trace, checks its first-round root against the sealed roster,
proves, and transfers one proof at a time to a caller-owned sink. The batch
receiver takes an on-demand proof loader and independently replays the plan,
root identities, and all fresh proofs. The artifact does not create trusted
pins; those must come from the public job/source admission boundary.

`block_v5_memory_replay_adapter_v1.zig` is the opt-in production seam. It
accepts the block Replay sorted spool, derives independently sized exact claims
with the existing count-first planner, transfers its roots and counters into
the v5 artifact, and reopens the immutable spool for the v5 second pass. The
existing v4 producer remains unchanged. This adapter is scoped to memory
proofs and requires the caller to supply the independently pinned v5 job,
source files, and complete first-round family roster.

The real Replay adapter passed a focused ReleaseFast fixture that wrote a
sorted spool, committed first-round roots, replayed it for proof production,
and freshly verified the v5 memory/table/source receipts (4/4 tests). This
does not admit native execution or a complete block.

Native v5 opens its universal seven-field `memory_access` sum. The ordinary
opcode sidecar must prove the opposite native consume/emit tuples from the
same PCS-opened typed opcode columns that it uses for the block transition
bridge. The consumed tuple uses the native previous-access clock; the emitted
tuple uses the native new-access clock. The block transition bridge separately
maps that new local clock and source address to the block-global sorted bus.
Precompile caller accesses are outside the ordinary native opcode claim and
need their own same-root, B5SS-bound branch. The native public compensation
still includes register and public I/O boundaries; canceling interior opcode
tuples alone does not close the native universal relation.

Replacing the old BLAKE3 memory custody also requires a final RW boundary.
The sorted AIR already proves address ordering and per-address value
continuity, so a first/last endpoint extension can select the first and last
row for each RW word. Its first values must match the independently pinned
initial RW image. Its last values must match a canonical final sparse RW
image whose root is bound as a block output; a hash-pinned full final image is
a valid scoped public-source implementation, while a succinct implementation
needs an AIR-authenticated root computation. Cross-segment register endpoints
and public I/O must be closed by exact global rules under the same B5SS
challenges. Until these checks exist, the complete v5 receiver must fail
closed rather than remove per-leaf memory custody.

The separately scoped final-memory endpoint receiver is now described in [block-v5-rw-endpoints.md](../memory/block-v5-rw-endpoints.md). Its fresh q8 gate binds last values and global clocks to the same sorted-memory roots, closes an exact precommitted endpoint roster, and checks the independently expected sparse full-image final root. This adds final memory custody to the scoped sorted/range/initial receiver; execution, ROM, precompile, and recursive block closure still belong to the complete v5 integration.
