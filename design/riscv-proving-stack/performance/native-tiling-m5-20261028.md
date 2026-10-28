# Form larger native proofs before recursion

This experiment holds a guest execution fixed and changes the number of native
STARKs produced before recursive reduction. At 212,992 cycles, one native proof
and its recursive proof take **10.917 s**, versus **153.962 s** for nine native
proofs reduced through 8+1 batches and an upper proof: **14.10x** in this measured
phase sum. Charged allocator peak falls **19.511 to 3.528 GB**.

At the largest measured size, **851,968 cycles**, the reduction remains
**12.33x: 196.377 to 15.927 s**, with peak **22.915 to 4.308 GB**.
All three partitions commit exactly the same 45,580,288 native cells at that
size, while the one-proof route needs **11.05x fewer recursive AIR cells**.
This isolates proof partitioning as a large cost beyond native witness area.

Implementation: [`b13f67ec9`](https://github.com/teddyjfpender/stwo-zig/commit/b13f67ec9).
[JSON receipts](block-v6-native-tiling-m5-20261028.json) retain every source,
batch and upper-stage record, log hash and execution digest. The
[CSV](block-v6-native-tiling-m5-20261028.csv) contains all nine canonical
measurements and their stage breakdowns.

These are real proofs at the unchanged canonical q70/PoW26 profile. They prove
native execution constraints with **open global obligations**. The fixture has
no loads, stores or precompile calls, and uses synthetic global-provider pins.
It is not an Ethereum block, a closed execution proof, or a full-block speedup.

## Matched computation, different proof layout

The guest repeatedly executes `ADDI x1,x1,1; JAL x0,-4`. For a base size B,
every arm executes exactly 13B cycles. The partitions are:

```text
one:    [13B]                       -> one native proof -> one recursive proof
three:  [4B, 4B, 5B]                -> three native proofs -> one batch proof
nine:   [B,2B,B,2B,B,2B,B,2B,B]    -> nine native proofs
                                     -> batch of eight + tail of one
                                     -> one upper recursive proof
```

Every arm checks all 32 initial/final register values and both PCs through an
execution digest, together with exact cycle count and initial/final RW word
values. Leaf-local predecessor clocks and transcript identities deliberately
differ with segmentation and are not compared. The digest is a test comparison,
not proof authority. Actual proof authority comes from fresh native and
recursive verification, preserving each arm's explicit open obligations.

This experiment uses larger **execution segments**. It has not implemented a
joint PCS across independently sized execution, memory and caller AIRs. Those
are the proposed production mechanism for obtaining similar amortization
without making every component share the execution segment's memory limit.

## Results

Eight CPU workers, Apple M5 Max 64 GiB, Zig 0.15.2 ReleaseFast. Each row is one
sample, not a median. The unchanged canonical FRI fold step is one.

| Cycles | Native proofs | Native phase | Recursive phase | Phase sum | Charged peak | Recursive AIR cells |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 832 | 1 | 0.085 s | 5.806 s | 5.890 s | 2.644 GB | 226,129,836 |
| 832 | 3 | 0.724 s | 10.549 s | 11.273 s | 3.879 GB | 362,956,800 |
| 832 | 9 | 2.311 s | 58.705 s | 61.017 s | 10.984 GB | 2,092,388,780 |
| 212,992 | 1 | 0.535 s | 10.382 s | 10.917 s | 3.528 GB | 382,261,248 |
| 212,992 | 3 | 2.075 s | 31.028 s | 33.102 s | 9.287 GB | 1,036,865,536 |
| 212,992 | 9 | 2.806 s | 151.156 s | 153.962 s | 19.511 GB | 4,032,456,192 |
| 851,968 | 1 | 0.857 s | 15.070 s | 15.927 s | 4.308 GB | 413,530,112 |
| 851,968 | 3 | 3.620 s | 45.031 s | 48.652 s | 10.596 GB | 1,193,422,848 |
| 851,968 | 9 | 9.230 s | 187.147 s | 196.377 s | 22.915 GB | 4,569,327,616 |

The native phase includes guest execution, witness/commitment construction,
native proving and fresh verification/admission. Recursive phases include
preparation, key/setup, proving, encoding and fresh verification. Their sum
excludes compilation, pool initialization, teardown and extra negative probes;
it is not complete command latency. Peak is charged allocator memory across
the job, including retained inputs and probes, not process RSS. The job is
capped at 40 GiB with a nested 32 GiB upper-proof cap. Thread stacks and other
untracked allocations are outside those caps. Earlier upper-only memory
numbers measure a different scope and must not be compared as whole-job peaks.

At 212,992 cycles, the nine-proof route spends 97.605 s in its first batch layer
and 53.551 s in the upper proof. The single-proof route removes both repeated
native-verifier work and an entire recursive tier. Thus the observed 14.10x
is not a per-kernel gain, nor an asymptotic ratio for arbitrarily large jobs.

The one- and three-proof arms actually commit **more native cells** than the
nine-proof arm at this size: 14,024,704 versus 11,395,072, from padding. They
still reduce total work because recursive proof geometry dominates. Minimizing
native padded cells in isolation would select the wrong layout here.

## A concrete constraint on larger tiles

The current native implementation caps each opcode shard at 65,536 rows:

* `prover/opcode_trace.zig:MAX_OPCODE_SHARD_ROWS` controls witness sharding and
  row placement.
* `prover/blake3_execution_trace.zig:Owner.initWithExternalRecipe` creates
  additional components when a family exceeds that cap.
* `air/statement.zig:validateBlake3ExecutionWithExternal` admits that same shape,
  requires full nonfinal shards, and independently bounds access clocks.

At 212,992 cycles, the single execution segment crosses that boundary; its
native maximum domain log remains 16. More execution therefore becomes more
committed columns and verifier components. Changing only the constructor's cap
would break witness routing and receiver admission. A larger-domain experiment
must coordinate all three, retain strict count/order/clock checks, and bind
the new geometry into template and independent receiver identities.

The measurements do not establish that raising the opcode cap improves time:
it can enlarge composition domains and peak memory. The observed gain comes
from fewer native proofs and recursive tiers with the existing cap unchanged.

The retained Ethereum sizing study already selected roughly 2M-cycle segments
because of ordinary-access witness residency and recursive budgets. These
ALU-only results do **not** show that enlarging those segments is safe. They
show the cost of allowing the most memory-intensive component to dictate how
many expensive native proofs the whole pipeline creates.

## Design consequence

The block planner should minimize base proving **plus the recursive cost of
its output proofs**, under independent per-component memory bounds. A cycle
limit or native-cell minimum alone is insufficient. Three changes belong
together:

1. Use local register consistency and packed mutable-RAM proofs to remove
   unnecessary global events and release the present sidecar memory constraint.
2. Give native execution, memory, ROM and precompiles independently sized
   domains; vertically combine compatible work before issuing STARKs, and
   jointly prove compatible same-root projections instead of recursively
   wrapping each projection separately.
3. Aggregate the resulting base proofs directly, retaining the new native
   batching path. Include all global-family proofs and final typed relation
   closure before calling its output a standalone block root.

The existing capacity-fused companion proves projections plus ordinary access;
its source explicitly retains an independently verified capacity-native base
proof. It must not be counted as an already implemented native-plus-companion
joint proof. A proposed fusion must remove an actual transcript/FRI/proof and
retain all original constraints, rather than merely rename that companion.

The separate event-root bridge remains a versioned protocol project. A local
proof finished before the block seal cannot use the later global challenges.
Its local challenge must bind emitted event columns to execution; a later
relation proof must open those same committed columns after all roots are
sealed. This must cover every unresolved bus, including lookup requests and
caller events, not just RAM. Counting only RAM could hide a larger event plane
or leave another dependency on the old global challenge. Reject the redesign
if the added event commitment and late relation work exceed the wide witness
work removed. No saving is assumed merely from changing the timer boundary.

The 14.10x observation, earlier 17x wrapper-removal result and 10.14x modeled
memory-area reduction overlap or measure different work. They must not be
multiplied into a block forecast.

## Reproduction and negative controls

On `codex/ethereum-block-fast-lab`:

```sh
STWO_NATIVE_TILE_STEPS=2 python3 scripts/zig_protocol_test.py \
  src/frontends/riscv/block_v6_native_tiling_test_root.zig \
  -OReleaseSafe --test-filter 'tiling same execution diagnostic'

STWO_NATIVE_TILE_STEPS=64 python3 scripts/zig_protocol_test.py \
  src/frontends/riscv/block_v6_native_tiling_test_root.zig \
  -OReleaseFast --test-filter 'tiling same execution canonical' > tile-832.log 2>&1
STWO_NATIVE_TILE_STEPS=16384 python3 scripts/zig_protocol_test.py \
  src/frontends/riscv/block_v6_native_tiling_test_root.zig \
  -OReleaseFast --test-filter 'tiling same execution canonical' > tile-212992.log 2>&1
STWO_NATIVE_TILE_STEPS=65536 python3 scripts/zig_protocol_test.py \
  src/frontends/riscv/block_v6_native_tiling_test_root.zig \
  -OReleaseFast --test-filter 'tiling same execution canonical' > tile-851968.log 2>&1

python3 design/riscv-proving-stack/performance/native-tiling-results.py \
  tile-832.log tile-212992.log tile-851968.log
```

Each run passed eight selected tests. It reuses batch and upper-receiver
negative probes, including cancelling claim changes, omitted children and
wrong key/endpoint/domain rejection. The parser also rejects missing test
completion, false verification, changed execution digest, omitted arms and
inconsistent timing totals. This is focused evidence, not a whole-block
soundness qualification.
