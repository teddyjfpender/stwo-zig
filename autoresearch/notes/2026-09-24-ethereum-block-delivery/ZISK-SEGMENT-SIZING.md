# ZisK ideas for the segment-size bottleneck

Source audit, 2026-09-25. This compares implementations, not benchmark results.
ZisK checkout: `5c5f81c96929abed88894473ec6060b1b545b5c5`.
Proofman checkout: `d485fac207679076958b502554fb595568c2f954`.

## Measured problem in our mainnet fixture

The q70/PoW26 job executes 139,214,856 guest cycles. Uniform balanced schedules
produced these admission-only G row counts (these are not proof timings):

| Execution leaves | Region | G rows | Fits log 24 | Fits log 25 |
|---:|---|---:|---|---|
| 128 | entry | 35,327,040 | no | no |
| 256 | entry | 17,784,816 | no | yes |
| 512 | entry | 10,003,392 | yes | yes |
| 512 | recovery, 32 Keccak + 1 recovery | 2,325,344 | yes | yes |
| 512 | terminal | 28,093,016 | no | yes |

Evidence: `segment-geometry-v1/results.json` and individual stdout records.
The 1024-leaf baseline was deliberately stopped after 20 verified leaves. It has
no complete root and did not establish that all later leaves fit. In particular,
the terminal measurement invalidates choosing a size from the first leaf alone.
Log 25 was added consistently to native commitment admission, key geometry,
column geometry and coefficient-bound validation. Existing coefficient bounds
and the 48 GiB shared runtime budget remain enforced. A boundary test passes;
the measured 512-terminal log-25 attempt failed with `OutOfMemory` after 167.892 seconds under the unchanged 48 GiB total budget (`segment-proof-sizing-log25-v1/results.json`). Raising the cap alone did not qualify this configuration.

## What ZisK does differently

1. **Separate sorted memory proofs.**
   `state-machines/mem/pil/mem.pil` constrains address/time order, read/write
   values, first/last segment continuity and permutation matches with memory
   operations from execution and precompiles. It supports multiple lanes and
   paired compatible operations per lane. `mem_module_planner.rs` fills bounded
   memory instances from counters across emulator chunks. This is structurally
   different from our ordinary BLAKE3 memory boundary commitments and recursive
   full-memory custody conversion. It suggests removing much of that hash work
   through a different memory argument, not merely making the hashes faster.

2. **Choose capacity by component, with an explicit cost model.**
   `common/src/component/air_selection.rs` ranks assignments by proof-instance
   count, then memory. `select_sizes` covers the work with the minimum number of
   large instances, then demotes residual instances to smaller AIRs where possible.
   `state-machines/binary/src/binary_planner.rs` additionally compares packed-add
   and ordinary layouts, including use of already-paid spare capacity.
   An instruction count alone is not their universal capacity estimate.

3. **Execution instance counts need not be a power of two.**
   `state-machines/main/src/main_planner.rs::plan_count` uses ceiling division.
   Its emulator chunk size has a power-of-two requirement, but the number of
   proof instances does not. Our scheduler currently rounds the leaf count up
   because the existing span/frontier protocol expects that shape. Supporting
   arbitrary counts must preserve authenticated coverage and completion; simply
   skipping padded slots would not be a sound change.

4. **Schedule proof families to reuse keys and bound buffers.**
   Proofman's `proofman/src/scheduler.rs` prioritizes recursive stages and orders
   ready families by backlog, with explicit stream reservation ownership.
   The previously audited `stream_commit.cu` pipeline uses bounded slots and
   column streaming. This supports separate component jobs without requiring all
   traces and proving buffers to be resident together. It is not evidence of an
   available GPU path in our current CPU-only benchmark.

## Implementation direction

- Immediate qualification: prove the largest measured 512-leaf segment at log 25
  with canonical security and full custody under the existing memory budget,
  then entry and recovery regions. Do not claim the full block fits from these
  samples; add all-segment capacity screening before restarting a long job.
- Extend native hash-table partitioning using the existing recursive G-partition
  design. Preserve every row, authenticated wire multiplicity and lookup claim;
  measure total padding as well as largest-domain scratch. Independent proof
  instances need authenticated cross-instance relations, not just local checks.
- Replace the uniform instruction-only selection with measured component work
  and memory estimates, and remove unnecessary power-of-two *instance-count*
  rounding through an explicitly verified aggregation shape.
- The larger architectural opportunity is a versioned, globally closed memory
  permutation argument with separately scheduled memory instances. Bind program,
  initial input, output, execution completion, every access and every continuation
  in the final proof. Reject missing/duplicated accesses and reordered/omitted
  instances. Keep current custody until that replacement is cryptographically
  qualified. ZisK's Goldilocks relations cannot be copied as M31 relations without
  auditing field bounds and challenge/transcript binding.

No ZisK code was copied and no speedup is claimed by this source audit.
