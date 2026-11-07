# T2: recursion MAIN-assignment chain executor (round 1)

Branch `codex/rv64-m8-opt-T2-assignment-chain`. Owned files: `src/backends/cuda/native/rv64/circuit_fill_chain.cu`
(the only product file changed; `circuit_assignment.{cu,h}` and `assignment_runs.zig` were claimed but not needed).

## What changed
- `chain_flow<WideWidth>` (new kernel, same ABI as `chain_run`: job, device level ends, first level, level count; one 512-thread CTA).
  Each window of levels is split into runs by width class.
  - Levels `>= kFlowWideWidth` run exactly as `chain_run` does (`run_levels`, same record pipeline and barriers).
  - Runs of narrower levels are cut into chunks of <= 512 tasks. Per chunk, a shared-memory map goes from each output variable to its producing task.
    Each task waits only on its own in-chunk producers (shared-memory ready flags) and takes their values from shared memory.
    That is 4 barriers per chunk instead of one barrier plus a dependent global round trip per level.
  - A chunk with a permutation task, a duplicate producer, or a producer not in a strictly earlier level (which also covers WAR)
    falls back to `chain_run` level semantics.
- Selection: `STWO_RV64_M8_ASSIGNMENT_FLOW=1` (default off; read once per process). It covers `stwo_circuit_assignment_chain_run_on` and the
  assignment graph (`stwo_assignment_graph_*_v1`, kernel fixed at graph create). No ABI or caller change, so the default path and the GPU-native
  whole-node graphs pick it up by env alone. With the flag off, `chain_run` is compiled from its original text.
- Diagnostic: `STWO_RV64_M8_ASSIGNMENT_DUMP=<dir>` (default unset) writes one real node (seeded values, records, ends, steps) for the bench.
- Plan item (2), pack-time Blake G macro tasks, was not done. It needs a new record kind written by `outer_assignment.zig` / jobs code (not owned).
  The dataflow executor removes the same per-level barrier the macro task would remove, with no record change.

## Frontier
- pil2-proofman (`starkpil/witness_hints_slot.cu`) and ZisK (`*_witness.cu`) generate witnesses row-parallel: one thread per trace row.
- Their recursion witnesses come from CPU or RISC-V execution.
- None of them has a GPU general-DAG assignment executor to compare against.
- The structural lesson is that DAG depth (120k levels per node) is the cost. Dataflow attacks the per-level constant; a row-parallel layout of the recursion verifier would remove the depth itself.

## Parity (chain_flow_bench.cu selftest) [M]
Bit-exact against `chain_run` (values and status) on:
- 6 random mixed DAGs;
- a 5,000-level width-1 chain and a mid-width Blake shape;
- edge cases: duplicate producer, write-after-read, permutation in a chunk, bad kind, out-of-range arg, Blake out+4 overflow;
- the graph API path (create + launch + relaunch) with the flag unset and with the flag set to 1.

## Microbenchmark (CUDA events, 7 reps; spread <= 0.2 %) [M]
| shape | chain_run (pre-T2 source) | chain_flow<32> |
|---|---|---|
| synthetic width-1 chain, 20k levels | 15.30 ms | 2.78 ms |
| synthetic 64-128-wide Blake, 2k levels | 2.66 ms | 2.58-2.60 ms |
| synthetic i.i.d. mixed widths, 20k levels | 39.56 ms | 34.3 ms (wide=never 29.9 ms) |

Ablation [M, synthetic width-1]: with the producer map disabled (no dependency waits; values not exact) the run takes 0.93 ms against 2.81 ms.
So about 94 ns per level is the dependency hop itself (poll, fence, task arithmetic, store), and the per-chunk build is the smaller share.

## Not yet measured (GPU blocked)
Orphan pid 3302210 (m8-native-hybrid combined-serve) has held 30.1 GB on each GPU since 19:27Z; at 01:41Z it was still there. Not measured yet:
- a real-node dump and replay (the WideWidth threshold of 32 is an [E] until then);
- rv64_gate default and FLOW=1;
- the canonical 3+3.

Pod tmux `t2-pipe2` (`runs/m8-opt-T2-assignment-chain/pipe2.sh`, status in `pipe2.status`) starts by itself once both GPUs are below 2 GB. Its steps:
1. Gate on 24628607, default path, with the dump env (`gate-1`).
2. Replay the real node: chain_run vs chain_flow<never,16,32,64,128> (`bench2/dump-bench.log`), then delete the dump.
3. Gate with STWO_RV64_M8_ASSIGNMENT_FLOW=1 (`gate-2`).

Image: `build/m8-opt-T2-assignment-chain/img2`, lib sha256 9e56412b..., from source ff821a8c7.
It is composed by `compose_image.py`: the m7-combined-residency recipe with 4 objects recompiled from the tree, because the frozen replacement objects are gone.
Not landed: landing requires a gate PASS and a 3+3 that is not slower.
