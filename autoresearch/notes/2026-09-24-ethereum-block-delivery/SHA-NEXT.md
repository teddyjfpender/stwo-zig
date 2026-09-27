# Latest checkpoint

See [SHA-MEMORY.md](SHA-MEMORY.md) for the verified provider, native transaction,
typed caller and remaining production integration. The older design notes below
are retained as history; the DAG and standalone compression STARK are complete.

# Current implementation checkpoint

Packed arithmetic is implemented in sha256_packed_arithmetic.zig and its shared
word-operation author. Round/expansion/feed-forward use 164/88/16 arithmetic
columns; semantic digests and geometry are pinned. Both substantive tests pass
(test-sha-packed-tables.log), including actual lookup-table membership, complete
compression traces, and scratch/range mutation rejection. Initial mutation tests
wrongly assumed every input-bit change must be rejected: masked Maj inputs can
legitimately preserve the output. The corrected test compares any accepted input
change against the scalar function, while rejecting all changed scratch values.

Production remains inactive. Next implement the fixed SHA word dependency graph,
round K-constant sources, wire/caller closure, CPU dispatch and memory binding.
The round author emits only next a/e: six state words must be carried through
aliases in the admitted graph, not forgotten. Expansion inputs must be bound to
W[t-2], W[t-7], W[t-15], W[t-16]; first16words to the actual block bytes.
The general interface uses eight u32 chaining-state words and one64byte block.
RISC-V memory words are little-endian; SHA's first16schedule words interpret
message bytes big-endian. State/output serialization must make this explicit.
Do not replace the existing host semantic oracle or activate the old wide fixed
pair candidate. Follow the pinned ZisK compression contract's generality.

## Earlier design notes

# General SHA-256 compression integration

Full goal requires a production precompile, not merely this semantic module.
Current production Ethereum profile still has only Keccak and successful signer
recovery. SHA CPU dispatch, efficient typed AIR and memory/caller linkage are NOT
implemented. Do not activate the wide fixed-pair candidate as the final solution.

## Implemented foundation

`air/guest_precompile/sha256_compression.zig` owns SHA constants, schedule, round
semantics, feed-forward, host output and optional round trace. It accepts arbitrary
8-word state and one64-byte block. Host output mode does not retain65round states.
The fixed-pair candidate imports this module; duplicate computation was removed.
No guest profile, opcode or proof identity changed. Tests compare arbitrary
chaining states directly against standard-library SHA state after one full block,
and chain/pad messages at boundary lengths against standard-library full digests.
Test results pending in test-sha-compression.log and test-sha-shared-regression.log.

## Pinned peer contract

ZisK5c5f81c96929abed88894473ec6060b1b545b5c5:
`precompiles/sha256f/src/sha256f.rs` uses step/caller address, state pointer,
input pointer,4u64 state words and8u64 block words. Operation is compression,
not fixed-length hashing. Copy this contract's generality, not its64-bit-field
constraints into M31 blindly. Our interface needs8u32 state words,16u32 input
words and8u32 output words, bound to guest CPU retirement and memory clocks.

## Efficient AIR direction (not implemented; estimates, not benchmarks)

Existing fixed-pair direct AIR has2162main columns per round. Most bits repeat
state/ring/base/digest data. Avoid making this the production geometry.

- Typed byte limbs and existing byte bitwise/range lookup tables can constrain
  32-bit additions as two16-bit equations with bounded carry. Every integer
  equation must stay below M31; no unchecked field-to-u32 interpretation.
- General rotate uses byte permutation plus two bounded cyclic limb carries;
  bit remainder<=7 keeps equations below2^23. Explicit bounded output bytes.
- Use Ch=g XOR(e AND(f XOR g)); Maj=(a AND b) XOR(c AND(a XOR b)).
- One round consumes8state words,W,K and produces only newA/newE; remaining six
  words are aliases in the next round's authenticated wire schedule.
- Separate schedule expansion rows enforce W[t] from W[t-2,-7,-15,-16].
  First16words bind to memory input. No freely supplied message schedule.
- Separate final feed-forward additions bind output state to initial state.
- K constants and row/wire topology must be independently admitted fixed data.
- Reuse semantic round author between typed equations and witness operations,
  following the current packed BLAKE3 implementation's structure. Preserve its
  existing semantic digests; avoid casually refactoring its proven author.
- Production integration must version the capability/profile, wire guest SHA
  provider, retirement/memory transaction, AIR/provider registration, transcript
  admission, direct proof and recursive capture. Preserve old artifacts explicitly.

Read actual execution-function-profile.json after profiler finishes before ranking
SHA against copying/other crypto. Counts are containing-symbol guest instructions,
not host precompile time or a direct estimate of STARK proving cost.
