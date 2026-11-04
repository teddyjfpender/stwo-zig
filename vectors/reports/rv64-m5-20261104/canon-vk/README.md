# canon-vk receipts (M5, 2026-11-04)

Stream `canon-vk`, branch `codex/rv64-m5-canon-vk`, 2x RTX 5090 pod. Every run is a one-shot `rv64_m3_pod.py` run with no
ArtifactStore, so setup is cold. The M4 env was set (`NARROW_RUNS`, `GPU_CPU_REPLAY`, `CORE_SINGLE_STREAM`,
`DEVICE_ARENA`).

The pod was never quiet: the 1-minute load was 24–45 against a bar of 8. **Absolute timings are not quotable.** A/B comparisons
below use interleaved runs of one binary. Every number is a single observation **[M]** unless labelled otherwise.

| id | option | 26235156 | 24628607 | verdict |
|---|---|---|---|---|
| E1 | recsize port merged, r1 binary, exact shape (default) | 37/37 proofs byte-identical to M3/M4 | 55/55 identical | receivers accepted 2/2 |
| E2 | r1, `STWO_RV64_FOLD_ARITY=4` | producer OOM: the 4-ary r1 fold composition needs 18.4 GB (arena overrun) | not run | **infeasible on 32 GB with today's composition memory** |
| E3 | `m3_b4_q51_p26` on GPU | `InvalidTraceInputRetirementScope`: the N2B input retirement is blowup-1 only | not run | hook in `outer_source.zig` (retire only at blowup 1) |
| E4 | `STWO_RV64_OUTER_SHAPE=uniform-v1`, r1 binary | 1 fold VK, root 741,208 B | 1 fold VK (the **same** one), root 745,624 B | receivers accepted 2/2; exact receiver rejects (fail closed) |

## E4: one fold VK, shared across blocks

Distinct outer authorities (circuit VKs) per node kind, from `tree.json`:

| | 26235156 leaves / folds | 24628607 leaves / folds | distinct fold VKs over both blocks |
|---|---|---|---|
| exact (E1) | 11 / **8** of 10 | 17 / **8** of 16 | **11** |
| uniform-v1 (E4) | 11 / **1** of 10 | 17 / **1** of 16 | **1** (`bf610ea9ab704f91…`) |

- Every node pads to one shape: `RECURSION_NODE_SHAPE padded=[262144,8388608,1048576,2097152,8388608]`.
- The fold VK no longer depends on the block. It can therefore sit in `T_rec` as a constant per arity (binding note §1 `S_out`).
- Leaf VKs stay per-segment until canonical leaves `R_leaf[f, r]` land: they embed native key constants.

**Fail-closed check:** a receiver run without `uniform-v1` on the E4 26235156 proofs rejected it at the first fold with
`Om31CircuitWireAuthority`. The two leaves before that fold were accepted, because their exact shape already equals `S_OUT_V1`.

**Cost:**
- Cells: +19.5% recursion cells on 24628607 [D] (diet census row logs × fitted component widths: 32.4 → 38.8 G).
- Root proof: +5.5% (706,424 → 745,624 B).
- Wall time: see the A/B below.

Negative corpus on the E4 26235156 proofs: `26235156-e4-negative-corpus.json`.

## Per-node host preparation (gate: ≤ 0.1 s per node)

The values are medians of the pipeline prep stage, which covers graph + padding + PP columns + assignment plan
(`pipeline.json`):

| run | leaf prep | leaf graph | fold prep | fold graph |
|---|---:|---:|---:|---:|
| E1 26235156 | 1.63 s | 0.51 s | 1.53 s | 0.36 s |
| E1 24628607 | 2.07 s | 0.70 s | 1.48 s | 0.30 s |
| E4 26235156 | 2.14 s | 0.53 s | 1.16 s | 0.43 s |
| E4 24628607 | 2.44 s | 0.76 s | 1.19 s | 0.35 s |

**The 0.1 s gate is not met.** Making it a store hit needs three things:
- the per-class PP/plan to be reused in the pipelined prep stage (today it is rebuilt per node; only the device plan cache is
  class-keyed);
- canonical leaves;
- the hint tape (M6).
