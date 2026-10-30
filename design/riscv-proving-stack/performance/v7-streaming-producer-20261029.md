# Variable-size v7 execution producer

## Problem match and implementation boundary

The old two-segment fixture kept every wide native and caller first round alive
until the global challenge was known. That cannot model production memory or
larger executions. The appropriate pattern is **commit, persist, release, then
restore one source at a time**. A cache receipt is never proof authority.

`prover/block_v7_streaming_execution_v1.zig` accepts a pinned release ELF, private
input, independently selected 43-byte output and retired-cycle count, security
configuration, and variable segment size. It executes once using segment-owned
runner traces. Each segment creates its native/access witness once, exports its
RAM events once, collects exact program-fetch multiplicities and lookup counts,
and persists the original raw columns and PCS trees. Precompile-bearing segments
use `block_v7_caller_checkpoint_v1.zig` to persist the original arithmetic and
external-access trees too. No old v5 seal or memory-root receipt is fabricated.

The ordered roster then contains all native/caller first roots, the complete ROM,
compact lookup provider and joint memory provider. Only after that roster is
sealed are shared interaction challenges drawn. Proving restores one native or
caller source at a time, without reconstructing its wide commitment, and releases
it before loading the next. Every original proof passes the fresh v7 execution
receiver after all checkpoint files have been deleted.

The consumer callback sees this verified original bundle while its owners remain
alive. `recursion/block_v7_mixed_metadata_v1.zig` can retain independently owned,
variable-length proposal metadata for mixed-key construction and the detached
root receiver. It is not itself a recursive proof or a success receipt.

## Bounds and measurements

The caller supplies a shared host budget and an empty, dedicated checkpoint
directory. Limits independently bound segments, caller count, total events,
checkpoint bytes, column geometry, reconstructed storage and memory AIR shards.
All four caller checkpoint files count against the same checked byte budget.
The directory must be opened with iteration permission. Cleanup does not touch
unrelated directories or overwrite a populated checkpoint directory.

Statistics separate setup, execution, collection/checkpoint writing, global
first-round construction, native proofs, caller proofs, joint memory proof, ROM
proof, compact lookup proof, fresh verification, consumer work and total time.
They include event storage, per-family checkpoint bytes, maximum native codec
restore allocation, exact event/fetch/proof counts and charged host peak. The
codec allocation is not a whole-process or proving-scratch peak.

Global memory construction still collects and sorts all events in bounded host
memory. Original proof objects and O(roster) metadata also survive until consumer
completion. This is not yet an external-sort memory prover or arbitrary-size
recursive reducer. The mixed root still accepts at most 64 total children;
native segments, callers and three global providers all consume that limit.

## Reproducible larger workload

`prover/tests/block_v7_scaling_guest_test_support.zig` preserves the old mixed
fixture's repeated load/store loop, two SHA calls and one Keccak call. It changes
the terminal suffix to publish 43 bytes and adds one instruction. Thus 4,096
iterations retire **20,495** instructions, versus the old fixture's 20,494.
The output includes the final loop value. Any v6/v7 timing ratio must run both
protocols on this exact new ELF; previously recorded old-ELF timings are context,
not a matched comparison.

The test root is `src/frontends/riscv/block_v7_streaming_execution_test_root.zig`.
Its default workload retires 20 instructions over three segments. The same binary
accepts `STWO_V7_SCALE_ITERATIONS=4096` and
`STWO_V7_SCALE_SEGMENT_CYCLES=10248` for the larger two-segment workload.
`STWO_V7_SCALE_CANONICAL` selects q70/PoW26 when present; the default is explicitly
diagnostic q8/PoW0. No runtime or canonical qualification is inferred from source
compilation.

The caller census records all 19 arithmetic components' declared logical rows,
domain rows, columns, raw/LDE cells and constraint counts. A zero-signer-call
group is marked, but fixed-table providers within it are not presumed removable:
any specialization must preserve their original relation obligations and receive
a new independently derived profile.

## Qualified original-source cases

The original CPU source gate passed all 11 tests in each retained run. These are
q8/PoW0 **shared-host diagnostics**, including independent verification; no
recursive root or canonical-security qualification is claimed by these runs.
Receipts, full phase data and caller geometry are under
`vectors/reports/block-v7-streaming-20261029/`.

| Cycles | Native segments | Caller proofs | All original proofs | RAM events | Total s | Charged peak MB |
|---:|---:|---:|---:|---:|---:|---:|
| 20 | 3 | 1 | 7 | 103 | 10.443 | 125.06 |
| 20 | 5 | 2 | 10 | 103 | 16.282 | 126.33 |
| 20,495 | 2 | 1 | 6 | 8,293 | 10.670 | 166.15 |

The larger case spends 1.095 s proving native sources, 5.047 s proving its caller,
0.222 s proving joint memory, 0.0075 s on ROM and 0.102 s on compact lookup.
Fresh independent verification takes 3.198 s. The retained checkpoint files total
42.48 MB. These numbers must not be compared directly to the old v6 ELF.

**Unsupported boundary:** three-cycle cuts put the three consecutive precompile
instructions into a segment with no core instruction components.
`block_v7_native_source_v1.Pin.validate` rejects `shape.n_components == 0` as
`UnqualifiedV7NativeGeometry`. Supporting that valid execution requires an
explicit boundary-only native envelope, including initial/final PC, cycle,
register-state custody and program-fetch closure with the caller. Removing the
guard or treating a host boundary as a proof is not a valid fix. Consequently
the producer does not yet qualify arbitrary segmentation.

**Recursive specialization target:** in the larger fixture, the 19 caller
arithmetic AIRs contain 6,732 main columns, 7,508 interaction columns and 11,181
constraints. Ten zero-active signer AIRs alone contribute 4,001 main columns,
2,512 interaction columns and 3,609 constraints, but only 13,086 of 436,622 raw
committed cells. The additional signer byte provider contributes 11 main columns,
4 interaction columns, 11 constraints and 256 live table rows. It must be tracked
separately. Small padded base area therefore conceals substantial recursive
opening width and verifier arithmetic; the safe next change is a versioned
active-family roster derived from independently bound counts and relation demands.
