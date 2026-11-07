# M9 prep: recursion witness without the task DAG (`STWO_RV64_M9_WITNESS_ROWPAR`)

Branch `codex/rv64-m9-witness-rowpar`, cut from `origin/codex/rv64-m7-integrate` @ 786429aca.
Plan row: `rv64-m9-plan.md` rev 3, section 4.1, lever #4. The plan's basis was "`chain_run` 19% of recursion [D]; ×0.2 residual [E]".
Labels: [M] measured, [D] derived from measurements, [E] estimate.

## Verdict

- **The ×0.2 factor holds for the Blake family only, not for the whole assignment.**
  - The fused Blake2s generator turns one compression step into one level: 21 DAG levels at about 1 µs become one level of about 4.4 µs. That is ×0.21 on the Blake chains [D, step logs].
  - Whole node, on recorded real nodes, byte-identical [M]:
    - leaf: **×0.513** (41.13 → 21.08 ms);
    - fold: **×0.740** (11.32 → 8.38 ms).
  - What remains is serial QM31 mul/add chains (Horner-style accumulations). After fusion they are 54% of the leaf's rowpar time and 62% of the fold's [M, steps-*.tsv]. They are as deep as before: the DAG had hidden them inside the Blake G levels.
- **Corrected lever row [E]:**
  - central whole-assignment residual ×0.50 (range ×0.45…×0.75);
  - p50 ΔGPU-s alone **−1.3** (−1.4…−0.7) instead of −2.2;
  - p95 **−2.2** (−2.4…−1.2) instead of −3.6.
  - Arithmetic: rec GPU-s × 0.19 × (1 − residual), with 14.0 / 23.3 rec GPU-s from plan section 2.
- **How to get back to ×0.2 [E, not prototyped]:** an affine-scan generator for the accumulation chains.
  - Each chain is a linear recurrence acc_k = acc_{k−1}·α + c_k.
  - Every acc_k is a MAIN variable, but field arithmetic is exact. A parallel prefix over composed affine maps therefore reproduces the same canonical values in O(log n) levels.
  - That is the "per-row closed form" item of delta section 4 item 6. It is the next prototype for this stream.
- **Path contraction of plain chains (strands) does not pay on this executor.**
  - A serial in-thread plain record costs about 0.65 µs, against about 1.5 µs for a whole level [D]. So merging records into strands only breaks even.
  - The best measured plans [M]: leaf with Blake fusion and no strands (×0.513); fold with strands on (×0.740 vs ×0.760).
  - The default recommendation is Blake fusion with strands off.

## What was built (all new files; nothing in the prover reads them)

| file | role |
|---|---|
| `src/integrations/riscv_cpu/rv64_m9_witness_rowpar_dump_test_root.zig` | CPU-only recorder of **real** node plans: production D2 leaf verifier graph (`leaf_graph.cpuTraceOnly` over the D2 native CPU fixture, both proofs freshly accepted) and production fold builder (`om31_outer.buildFoldTraceOnly`, m3_b4_q51_p26_fold4, 4 children). Both are padded with `outer_wrap.paddingTargets`, packed exactly like `outer_assignment.initFull`, and stored with the `witness_plan.evaluate` reference values. Step `zig build test-riscv64-m9-witness-rowpar-dump -Doptimize=ReleaseFast`, env `STWO_M9_ROWPAR_DUMP_DIR`. |
| `src/integrations/riscv_cuda/rv64/m9_witness_rowpar/plan.zig` (+ `plan_test.zig`, 6 tests) | Planner over the same 32-byte device records. It recognises Blake2s compressions structurally (80 G at `out = base + 4k`, g_state/sigma wiring, 8 finalisation triple-xors), optionally contracts strands, and layers by longest path. It refuses (error, so the DAG is kept) on duplicate producers, static `at` failures and cycles. A CPU two-pass reference executor is included. |
| `src/integrations/riscv_cuda/rv64/m9_witness_rowpar/plan_main.zig` | Standalone planner tool (`zig build-exe`). It proves on the CPU that the DAG order and the rowpar order both equal the recorded reference, then writes the GPU plan. |
| `src/backends/cuda/native/rv64/m9_witness_rowpar.cuh` | GPU executor, included after `circuit_fill_chain.cu` and reusing its exact `eval`/`at`. Contents: `rowpar_run_t<256>` (one CTA, one barrier per strand level, level ends in shared memory, next-level heads prefetched); `rowpar_wide`; `rowpar_blake_fill`. |
| `tools/rv64-m9-witness-rowpar/{bench.cu,blake_micro.cu,level_census.py,critical_units.py}` | Parity and CUDA-event bench against the production `chain_run` plan (`assignment_runs.initChain`, width 2048), a compression-latency microbenchmark, and analysis helpers. |

Key design point: deferred G outputs.
- On both real nodes, every G output of every fused compression is read only inside its own compression (`blake_inline = 0` [M]).
- So the critical pass computes each compression in registers and stores only h, its 8 finalisation words.
- One wide `rowpar_blake_fill` launch then recomputes and stores all 320 G outputs, in parallel: 0.07 ms on the leaf, 0.33 ms on the fold [M].
- This deferral is where the win comes from. A single thread spends 2.31 µs of its 2.92 µs compression issuing the 328 stores; the arithmetic alone takes 0.61 µs [M, `blake-micro.jsonl`]. Quad and lane-split store layouts were slower.

## Measurements (RTX 5090, dev 1, `flock` GPU lock, holds < 5 min, CUDA events)

Recorded nodes [M] (`dump-lines.txt`, `dump-sha256.txt`; the raw dumps, 0.34 GB and 0.67 GB, are kept out of git):

| node | vars | tasks | DAG levels | fused compressions | G tasks |
|---|---:|---:|---:|---:|---:|
| `leaf-d2` (actual D2 CPU leaf, mini fixture) | 11.27 M | 4.80 M | 41,664 | 16,747 (1.47 M tasks) | 2,097,152 incl. padding |
| `fold-m3-a4-b64` (production fold builder, 4 children) | 22.54 M | 9.37 M | 9,026 | 47,025 (4.14 M tasks) | 4,194,304 incl. padding |

GPU, best plan per node, all arms **exact**: 0 mismatched variables against the CPU reference, status 0 [M]. Times are the median of 7 runs (leaf) and 5 runs (fold):

| node | DAG `chain_run` | rowpar Blake only | strands cap 64 | strands cap 256 | strands uncapped |
|---|---:|---:|---:|---:|---:|
| leaf | 41.13 ms (328 launches) | **21.08 ms (×0.513)**, 9,379 levels | 26.55 | 25.01 | 29.08 |
| fold | 11.32 ms (649 launches) | 8.61 (×0.760) | 8.57 | 8.40 | **8.38 (×0.740)**, 1,320 levels |

Where rowpar time goes [M, `steps-*.tsv`]:
- Leaf, Blake-only plan:
  - plain arithmetic tail: 7,398 levels, 11.4 ms (54%), about 1.55 µs per level;
  - compression levels: about 4.4 µs each, against 21 DAG levels per compression step;
  - wide levels: 1.7 ms;
  - G fill: 0.07 ms.
- Fold, uncapped strands:
  - one tail step: 1,173 levels, 5.16 ms (62%);
  - wide levels: 1.81 ms;
  - fill: 0.33 ms.

The census of the recorded nodes (`level-census.jsonl`) and the CPU-checked planner stats for every option (`plans-*.jsonl`) are receipts in this directory.

Planner CPU time is 0.30–0.65 s per node [M, local M-series laptop]. The topology is class-stable, so in production it belongs with the class template, not the request.

## Production extrapolation [E]

- Production leaf census (M6, `level-census.json`): 101 k Blake levels (69%), 44 k mul/other levels, 146 k levels in all.
- The mini leaf has a smaller arithmetic share (14% of levels by census), but its tail is the same family.
- Residual = 0.69 × 0.21 (Blake) + 0.31 × 1.0 (tail unchanged) ≈ ×0.46. The fold measurement (×0.74) bounds the pessimistic side. **Central ×0.50.**

## Integration steps (after GPU-native is the default and the post-M8 cleanup lands)

1. **Plan at class build.** In `outer_assignment.initFull` (jobs-owned), behind `STWO_RV64_M9_WITNESS_ROWPAR=1`, call `m9_witness_rowpar/plan.zig` `build(tasks, indices, n_vars, level_ends, .{ .strands = false })` after `Pack.fill`.
   - Store the plan in `ClassCache.Template`, and persist it with the store, so a class hit never re-plans.
   - Emit the strand-ordered record stream (`srec`; the bench builds it on the host) directly from the planner.
   - Any planner error keeps today's chain plan. This is fail-closed and proof-neutral.
2. **Native library.** Include `m9_witness_rowpar.cuh` at the end of `circuit_fill_chain.cu`, or move `eval`/`at`/`fetch` to a shared `.cuh`.
   - Export `stwo_m9_rowpar_run_on`, `stwo_m9_rowpar_wide_on` and `stwo_m9_rowpar_fill_on`, with the same custody range checks as `stwo_circuit_assignment_chain_run_on`.
   - Add a capability bit. The step list is the bench's (`--threads 256 --wide 512`): runs of levels ≤ 512 strands go to `rowpar_run_t<256>`, wider levels to the grid kernel, then one fill launch.
3. **Graph path.** `assignment_graph` steps get a kind 2 (rowpar run) and a kind 3 (fill), so whole-node CUDA graphs (GPU-native) replay the rowpar schedule with no host round trips.
4. **Gates.**
   - Node dump parity: `STWO_RV64_M8_ASSIGNMENT_DUMP` plus this bench, on a real 24628607 leaf and fold. 0 mismatches is required.
   - MAIN byte identity is enough for proof identity, because the records and seeds are unchanged.
   - Then rv64_gate and 3+3 with the flag on and off. Accept only if `chain_run` GPU-s on 24628607 is ≤ 0.6× the flag-off value (the M8 ab8 kernel profile).
5. **Next prototype (to reach the plan's ×0.2).**
   - Planner: detect affine accumulation chains (mul by one fixed variable, then add) and emit a scan unit.
   - Kernel: parallel prefix over composed affine maps, with exact field values, storing every acc_k. Expected to remove most of the 54–62% tail [E].
6. Re-check the T2 lesson: never default on synthetic numbers. This stream's numbers are already real-node numbers, but the production leaf (146 k levels) must be re-measured from a dump before the plan row moves to [M].

## Reproduce

```
# CPU (local, memguard): record nodes
STWO_M9_ROWPAR_DUMP_DIR=<dir> STWO_M9_ROWPAR_NODES=leaf,fold4 zig build test-riscv64-m9-witness-rowpar-dump -Doptimize=ReleaseFast
# planner + CPU exactness check
cd src/integrations/riscv_cuda/rv64/m9_witness_rowpar && zig test plan.zig && zig build-exe plan_main.zig -O ReleaseFast
./plan_main <dir>/leaf-d2.m9rp leaf.blake.m9rw strands=0
# GPU (standalone, under the pod GPU lock)
nvcc -O3 -std=c++17 -arch=sm_120 -Isrc/backends/cuda/native/rv64 tools/rv64-m9-witness-rowpar/bench.cu -o rowpar_bench
./rowpar_bench leaf-d2.m9rp leaf.blake.m9rw --reps 7 --threads 256 --wide 512 [--step-log out]
```

Guardrails kept:
- no request-level GPU run;
- standalone kernels only, under `/workspace/m3/locks/gpu.lock` (holds < 5 min) and `build.3.lock`;
- pod directory `/workspace/m3/src/m9-witness-rowpar`, at most about 1 GB, deleted afterwards;
- no files under `jobs/` touched.

Local disk was down to 0.2–4 GB free during this work, which is why the worktree is a sparse checkout (it leaves out `vectors/` except the report directories, and `autoresearch/`).
