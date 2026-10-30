# Ethereum execution without a final machine-memory commitment

Status: architectural investigation, not an implemented or qualified protocol.
The current v5/v6 checks remain mandatory. This proposal requires a new statement,
source policy, transcript version, AIR identities, key factory and receiver.

## Finding

The complete-block route proves a stronger claim than a fresh whole-program
Ethereum execution necessarily needs: it authenticates the entire initial and
final **RISC-V RAM image**. Those BLAKE3 roots are not Ethereum trie/state roots.
They commit the guest's allocator, stack, input buffer, scratch space and output.

This is already separable from segment linkage. The header and `merge` in
`src/frontends/riscv/recursion/block_v5_pc_clock_span_v1.zig` explicitly carry
PC/clock continuity only; register and RAM consistency close globally.
`block_v6_global_public_closure_v1.zig` closes execution transitions against the
sorted RAM lanes, then obtains machine-memory roots from
`block_v6_source_public_closure_v1.zig`. Thus this architecture does not need a
Merkle proof at each segment boundary to establish cross-segment RAM continuity.

The source proof still has a real job. `block_v5_initial_sources_v1.zig` binds
layout, initial registers, input bytes, RW words and first touches.
`block_v5_rw_endpoint_sources_v1.zig` constructs the final image by replacing
address endpoints and retaining untouched initial words. The current PAGE
algebra (`block_v5_memory_source_page_join_algebra_v1.zig`) authenticates those
records and their initial/final trees. Removing PAGE proofs from the current
statement would leave initialization and endpoint obligations open.

## Proposed statement

For a separately selected fresh-execution policy, prove:

1. The independently pinned executable/profile starts at its admitted entry PC,
   initial registers and loader-defined memory image.
2. Every ordinary and precompile memory operation belongs to one complete
   globally ordered execution and obeys the same memory history.
3. The guest terminates successfully and produces the exact public result at
   the admitted output ABI.

Do not claim a final root for unrelated scratch RAM. Do not permit arbitrary
resumption from an incoming machine-state root under this policy. Preserve the
existing state-transition protocol for applications that require those claims.

The Ethereum result must still identify the intended block and validated state
transition. The current guest calls pinned `run_stateless_guest` and asserts a
43-byte successful result (`autoresearch/benchmarks/guest_runtime/ethereum/src/main.rs`).
That call is not sufficient evidence for a redesigned public ABI: audit the
pinned validator's exact output fields and their input/header/state binding
before choosing the new public result. No Ethereum trie verification is removed;
it remains part of the guest execution/precompile constraints.

## Replacement obligations

| Obligation | Required mechanism |
|---|---|
| One complete memory history | Retain the execution-to-RAM permutation/LogUp relation, exact event counts, independently bounded sorted partitions and cross-partition links. |
| Last write wins | Retain strict address/clock ordering, canonical integer ranges and `next.before = previous.after` for the same address. No clock wrap or duplicate timestamp. |
| Correct first read | At each first touch, prove the initial value comes from the admitted ELF/input/default-zero policy; a first-touch spool or host assertion is insufficient. |
| Correct final output | Add an authenticated terminal read source, or a proved endpoint selection, for halt status, output length and every public output word. Match the final value, not any earlier write. |
| Nothing bypasses memory | Include ordinary loads/stores, all precompile accesses, partial-word operations and terminal reads in the exact source roster and demand counts. |
| Complete execution | Retain contiguous indices/clocks, PC/state/register relations, exact ROM fetch closure, final completion and independently selected program/profile. |
| Fiat–Shamir ordering | Commit all physical source/table witnesses and inventories before shared challenges; absorb every physical interaction claim. |

A useful terminal-read construction appends a separately typed, independently
specified read stream after the final guest clock. It reads output length and
words through the same memory relation, with `before = after`. Its count,
addresses, byte padding, value encoding and timestamps must be constrained and
bounded. An output word never accessed by the guest then resolves to its genuine
initial value through the same first-touch rule. This avoids a special loophole
for untouched output cells. It also avoids authenticating every other final RAM
word merely to expose a short result.

## Initialization without a RAM Merkle tree

Reuse the loader and source classification semantics, not their host-success
receipts. `runner/elf_loader.zig` defines ordered PT_LOAD bytes, BSS zeroing,
entry point and ABI addresses. `block_v5_initial_sources_v1.zig` provides exact
layout checks and little-endian partial input-word construction.

An independently derived initialization table can combine:

- Fixed ELF data and static runtime words, committed once per admitted program.
- Input words committed once per job before challenges.
- A proved interval/complement policy requiring zero at every other permitted
  first-touch address, including unwritten BSS/stack/heap positions.

The zero rule needs complete interval coverage or an equivalent constrained
non-membership check. A sparse list of nonzero words plus a prover-selected
"missing" bit is unsound. ELF segment overlaps, byte writes, input overlay
precedence, alignment, invalid addresses and all-zero words must preserve exact
loader behavior.

Input authentication has two distinct policies. To preserve the current public
input digest, prove that the input table is the canonical decoding of those
committed bytes, or independently derive its expected commitment from the actual
public bytes. A host hash embedded as a claimed value does not establish this.
A future Ethereum-only policy might instead make the validator witness private
and bind only the canonical block/result, provided the pinned guest checks every
relevant witness against that statement. That is a separate semantic change,
not a free optimization of the existing input-digest claim.

## Reuse and rollout

The packed two-event RAM AIR (`air/block/word_memory_lanes_v1.zig`,
`word_memory_v5.zig`) already provides ordering and value propagation. Keep its
transition/link/range parts; replace its first-touch provider and define the
terminal-output supplier. Existing initial-source and readonly-input interval
logic is useful specification material. The readonly classifier/global roster
modules already distinguish mutable accesses and require exact per-source
classification. However, input is mutable by default, and the current v6 public
closure explicitly rejects readonly mode. Do not silently mark input immutable
or plug an unqualified alternate receiver into the current root.

Implement one end-to-end new-policy fixture first: multiple segments, nonzero
ELF data, zero/BSS first touches, mutable input, ordinary and precompile writes,
and a short output. Require fresh detached verification with no source files.
Negative tests must cover hidden initialized words, false zero classification,
omitted/repeated first touches, missing events, broken shard links, earlier
output versions, omitted output words, wrong program/block and reordered claims.
Only then compare identical guest/input/result and security settings against
current v6. Record source preparation, original proofs, recursive preparation,
root proving, verification and peak memory separately.

This removes an entire machine-image proof obligation and its recursive
verifiers rather than accelerating its hashes. It is a credible architectural
candidate for a large improvement. There is no demonstrated end-to-end speedup
or projected multiplier here: the observed source work and retained proof count
must be remeasured under the new, explicitly narrower statement.
