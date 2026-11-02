# Result advice tape proposal

This is an inactive capture/projection design. The qualified 48-byte Tape,
portable packet format and worker acceptance protocol remain unchanged.

## Small concrete first version

Store one u64 logical result per retired instruction, one branch-taken bit per
instruction, the existing sparse u64 memory-before stream and existing typed
Keccak/secp call sidecars. Retain the immutable expected program, initial PC,
initial 32-register values and batch/global clock metadata. A result means the
computed destination value even when rd=x0; architectural x0 alone would lose
FUNCTION advice. The first version may retain unused zero results for stores,
branches, FENCE and service instructions rather than introduce another sparse
index format.

A forward projector keeps 32 register values and 32 local predecessor clocks.
At each PC it reads the independently cached immutable decode, obtains A, B and
previous-RD from this register state, reads the recorded logical result, derives
next PC from static control or the captured branch bit/JALR source register,
then advances registers and clocks using the existing opcode effects. It does
not calculate arithmetic, comparison, bitwise, load or crypto results. Those
remain advice checked by the same physical CPU/provider equations. The
projector must use existing source-slot and x0 conventions, not invent a second
clock policy. For stores, existing masked-store helpers derive memory-after
from the sparse before word and reconstructed source register. Ordinary loads,
including rd=x0, each consume their RAM-before word. Service words stay in their
typed sidecars and do not consume ordinary LS entries.

No current/next raw PC, A, B, previous-RD or per-step memory index is stored.
Ordinary RAM and service sidecars advance sequentially under immutable opcode
classification. Branch advice must be zero on nonbranches and agree with the
selected immutable edge. JALR computes wrapped address and clears bit zero;
misalignment and unknown target admission retain the current explicit policy.
The result tape stores full u64 values without field truncation.

## Chunk checkpoints and parallel projection

For parallel source filling, use fixed 4096-step checkpoints containing raw PC,
all 32 register values, all 32 local clocks and cumulative ordinary-RAM/K/ADD/
DOUBLE sidecar cursors. These are narrow native metadata, never proof authority.
Roughly 424 bytes per checkpoint adds about 0.104 bytes per instruction. The
collector can maintain these snapshots while observing its one execution; a
serial forward projection can also derive them once before disjoint chunks,
but it must not rerun the VM or repeat that pass for each provider/test. Each
chunk checks its derived final snapshot against the following checkpoint. The
last snapshot must equal the captured public boundary. Parallel workers own
separate register/clock scratch and disjoint wide output rows.

The new source API should project directly to the selected physical layout and
retain only metadata needed after main commitment. Re-expanding all advice to
48-byte Retirement or CPU metadata arrays would erase much of this saving.
Provider fact extraction, predecessor-clock calculation, range histograms and
ROM row counts should share this projection rather than each rescan execution.
Interaction generation may consume a sealed narrow event stream; it must not
require the original wide matrix or execute the VM again.

## Size model and limits

On the pinned round5 census (104,253,913 instructions and 33,457,230 ordinary
RAM events), current 48-byte records plus sparse memory-before words account
for 5,271,845,664 bytes, excluding capacity slack and service sidecars. Result8,
a bit per instruction and the same RAM-before words account for 1,114,720,884
bytes before checkpoints. A branch-only bitstream would be 1,102,842,895 bytes
using the actual 9,230,005 conditional branches, but the extra framing is not
needed for the first prototype. Service sidecar sizes are unchanged. At a
4,194,303-instruction batch, record storage alone changes from 201,326,544 to
34,078,712 bytes, excluding ordinary RAM words and checkpoints.

These are serialized/native-advice size models, not proof memory or runtime
measurements. Current workers have much larger wide polynomial/FFT storage;
reducing tape bytes alone does not meet a 16GB prover goal. CPU source metadata
and duplicated provider facts must be accounted for separately.

## Qualification before a new wire version

First qualify an in-memory adapter against the current Tape restoration on all
RV64IM opcodes and supported service profiles, including discarded rd=x0
results, signed/W/zero corners, aliases, branch directions, full64 PC wrapping,
JALR bit clearing, loads to x0, partial stores and service clock rebasing.
Compare every reconstructed retirement field, all source main/interactions,
claims and encoded proofs. Test checkpoint corruption, sidecar under/overflow,
nonbranch bits, invalid ROM PCs and all allocation/ownership failures. Result
and checkpoint corruption must never become trusted output or acceptance
status. A new explicit wire version needs bounded exact-EOF parsing, canonical
counts and independent request/program/profile binding before wide allocation;
no silent reinterpretation of the existing packet format is permitted.
