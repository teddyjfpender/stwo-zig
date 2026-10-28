# Native batching: a real second recursive level and its remaining cost

The direct-native path now proves nine heterogeneous native segments, forms
an eight-child batch and a one-child tail, and proves a freshly verified upper
root over both batches. **Global memory, ROM and sidecar obligations remain
open. This is not a complete block proof.**

Implementation: [`68b6a1c167fc68415c255ede53aa52549743a477`](https://github.com/teddyjfpender/stwo-zig/commit/68b6a1c167fc68415c255ede53aa52549743a477),
on `codex/ethereum-block-fast-lab`. [JSON receipts](block-v6-native-batch-scaling-m5-20261028.json)
and [CSV](block-v6-native-batch-scaling-m5-20261028.csv) retain stage counters,
proof sizes, work counts, source-log hashes and final negative-test provenance.
This extends the earlier [two-segment experiment](direct-native-batch-m5-20261028.md);
its 17x recursion result must not be extrapolated to this workload.

## Workload and measurement boundary

The real guest alternates `ADDI x1,x1,1` and `JAL x0,-4`. Nine adjacent segments
alternate 64 and 128 steps, totaling 832 guest cycles. Their native template
identities differ and their register state changes. All native proofs, batch
proofs and the upper proof are generated and freshly verified. The global
provider pins are synthetic; the root explicitly retains open obligations.

Measurements use an Apple M5 Max with 64 GiB, eight prover workers, and Zig
0.15.2 ReleaseFast. The table is one matched run of each schedule, not medians.
A preceding canonical run measured a similar 58.833 s phase sum. These are
sums of measured native and recursive phases, **not complete command latency**:
compilation, extra negative probes and fixture bookkeeping are outside them.

| Profile | Native proofs | Batch proofs, 8+1 | Upper preparation | Upper key/setup | Upper proving | Upper encode/verify | Phase sum | Upper charged peak |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Canonical q70/PoW26, fold1 | 2.259 s | 22.565 s | 13.799 s | 4.049 s | 15.342 s | 0.206 s | **58.219 s** | 10.705 GB |
| Experimental q70/PoW26, fold2 | 3.164 s | 17.135 s | 8.700 s | 2.233 s | 8.834 s | 0.190 s | **40.256 s** | 7.049 GB |
| Experimental q70/PoW26, fold4 | 2.380 s | 18.352 s | 7.781 s | 2.196 s | 8.596 s | 0.187 s | **39.493 s** | 6.372 GB |

Charged peak is the upper proof's bounded allocator accounting, in decimal GB.
It is neither process RSS nor whole-job peak; retained child inputs and stacks
are outside that allocator. The upper allocator has a 32 GiB cap.

| Profile | Recursive AIR cells, both levels | BLAKE3 G rows, both levels | Root bytes |
| --- | ---: | ---: | ---: |
| Canonical fold1 | 2,092,388,780 | 8,428,056 | 982,775 |
| Experimental fold2 | 1,368,388,268 | 5,640,152 | 837,310 |
| Experimental fold4 | 1,370,732,204 | 5,526,136 | 816,906 |

The experimental profiles have distinct IDs bound into policy and key identity.
Existing canonical and diagnostic profiles are unchanged. Keeping q70/PoW26
does **not** establish an unchanged security bound for a different FRI schedule;
neither experimental profile is production-security qualified. All levels use
the same profile here. Mixed schedules at different tree levels were not tested.

## What the experiment establishes

* A batch can be consumed by another real recursive proof. The upper receiver
  independently reconstructs expected batch statements from the original
  native admissions and receipts. It does not trust producer-normalized frames.
* Transcript normalization preserves the original batch claim domain, digest
  and draw count, including the individual physical claims.
* Batch widths 1, 3, 4 and 8 pass fresh proof verification. Both 4+4+1 and 8+1
  cover the same nine-segment span. Only **8+1** was proved through the upper
  level; the existing exact-outer policy requires a dyadic decomposition.
  This is not arbitrary-partition root support.
* Changing native residual claims by +1 and -1 preserves their aggregate but
  fails fresh upper verification. Wrong final PC, omitted tail, changed batch
  key and changed normalized claim domain also fail. The final ReleaseSafe
  q8 gate passed all eight selected tests with this cancellation probe.

The canonical first-level 4+4+1 and 8+1 experiments took approximately 22 s
each and committed the same 799,134,124 AIR cells. Increasing batch fan-in
does not remove the verifier equations of the native proofs. It chiefly
changes how many proofs the next level must consume.

The wider FRI schedules improve the measured total by 1.45–1.47x and the upper
phase by 1.67–1.78x. They are useful, but **not a second tenfold improvement**.
Fold4 helps the upper level more than fold2, while fold2 has the cheaper first
batch level. The recursive tree must be optimized as a whole.

## Architectural decision

The nine native proofs take only 2.259 s in the canonical run; recursion takes
55.959 s. Even zero-cost native proving would barely change this fixture.
The next large recursion improvement must remove proofs or reduce what each
verification proves, rather than merely accelerate native execution.

There are two distinct work-removal targets:

1. **Joint native proof tiles.** Combine compatible execution and event AIRs
   under shared commitments, challenges and openings before recursion, so the
   first recursive stage verifies fewer STARKs. Vertical concatenation must
   constrain active lengths, resets, segment identity, continuity, event
   multiplicity and every physical LogUp claim. Merely joining already-created
   verifier traces retains the cost observed above. Select tile sizes using
   both base memory bounds and next-level verifier geometry.
2. **Local registers and one authenticated event stream.** Remove register
   events from global RAM; bind remaining event columns once to execution and
   a narrow late global relation. This attacks the separate modeled 10.14x
   memory-area opportunity and the repeated wide-trace construction in the
   retained Ethereum workload. Registers must remain constrained across
   instructions, calls and segment boundaries; event commitments must precede
   global challenges, and global proofs must be included in final recursion.

Further batch-preparation copy reduction is justified: the canonical eight-child
batch spends 10.086 s preparing rows versus 7.250 s proving them. However,
eliminating that entire preparation stage would still not deliver 10x here.
Keep it subordinate to proof-count and proof-geometry changes. None of these
ratios may be multiplied into a claimed block speedup without a complete,
matched, freshly verified block run.

## Reproduce on the lab branch

```sh
# Positive batch sizes and a real upper proof, canonical and diagnostic.
STWO_NATIVE_BATCH_UPPER=1 python3 scripts/zig_protocol_test.py \
  src/frontends/riscv/block_v6_native_batch_scaling_test_root.zig \
  -OReleaseFast --test-filter 'block-v6 scaling' > scaling.log 2>&1

# Matched 8+1 -> upper experiment, canonical and experimental FRI profiles.
STWO_NATIVE_BATCH_ROOT_ONLY=1 python3 scripts/zig_protocol_test.py \
  src/frontends/riscv/block_v6_native_batch_scaling_test_root.zig \
  -OReleaseFast --test-filter 'block-v6 schedule' \
  --test-filter 'job canonical' > schedules.log 2>&1

python3 design/riscv-proving-stack/performance/native-batch-results.py \
  --scaling scaling.log schedules.log

# Final cancellation and hostile receiver checks, with safety checks enabled.
STWO_NATIVE_BATCH_UPPER=1 python3 scripts/zig_protocol_test.py \
  src/frontends/riscv/block_v6_native_batch_scaling_test_root.zig \
  -OReleaseSafe --test-filter 'job q8'
```

The parser requires completed tests, consistent phase sums and counts, and
freshly verified batch/upper records. Missing completion, altered cycle counts
and altered partition cell totals were rejected in parser controls.
