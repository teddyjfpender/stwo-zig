# Stream integrate — RV64 M3 (2026-11-04)

Branch `codex/rv64-m3-integrate`, built from `fbb6c6c76` plus the stream merges below. All timings are
**measured**, single observations, 2x RTX 5090, on a pod shared with other work. Nothing here is a median.

## What was merged

| Stream | Head merged | Taken | Notes |
|---|---|---|---|
| infra | c81a8bd1f | all | harness, object store, catalogues-v2, timeline line |
| host | b009891ec | all | lock-free budget + smp child, side-thread native verify, single capturing verify, warm SetupCache |
| pipe | 8c93f1402 | all | three-stage nodes and pipelined executor. Conflict in `resident_batch.zig`: kept host's smp child, which is thread-safe and the same allocator, and dropped pipe's page-child env toggle |
| mem | 6d1191553 | all | LDE→Merkle streaming, direct composition, PCS streaming, two pools, plus the checker's trim fix 810b1f466. Script conflict: kept infra's harness |
| topo | fe0fc87d3 | all | fold message v2 (**proof-changing**: folds/root only) and the producer/receiver class caches. The checker's high-severity double free is fixed in 7afb20e2b. Conflict in `device_prove.zig`: kept pipe's host hooks and topo's `class_hint` |
| recsize | 5d68d0f01 | **not merged** | see below |

Integration change (`423b53a87`): topo's plan-class cache keys on a threadlocal `class_hint`, which only
the lane path set. Pipe's pipelined prep builds the assignment plan on a host prep thread. The hint is now
set there too for folds, so plan-class hits work on the default (pipelined) path. The cache is host-only
and was check-mode qualified by topo.

**recsize was not merged.** Its proof-changing m3 outer profile and k-ary folds are off by default and
were never run on a GPU or on a real block. Its merge conflicts in `om31_outer.zig`, `prove.zig`,
`execution_wrap.zig` and `ready_dag.zig` are semantic:
- k-ary `[]Child` against topo's v2 message and `classKey([2]Child)`;
- `Node.left/right` removed, while pipe's executor uses them.

Resolving them correctly needs `classKey` and the v2 message generalised to N children. Every
pipelined-path call site must then move to `kids()`, followed by a GPU qualification. That did not fit
this window next to the scale-up. The branch is intact for a follow-up.

## Host tests (pod)

These are in `tests.log` and `test-outer.log`:
- `host_budget_allocator` 8/8;
- `shared_external_memory_test_root` 19/19;
- `test-rv64-recursion-ready`, `test-rv64-gkr-plan` and `test-trace-stream-plan` pass;
- `test-riscv64-om31-outer` (ReleaseFast) passes, including topo's v2 binding test (`OM31_FOLD_ROOT fresh_accepted=true`).

## Dev blocks (receipts in `dev/`, combined in `24628607.json`)

| run | request | capture | setup | native prove | recursion | receiver |
|---|---:|---:|---:|---:|---:|---|
| 24628607 cold | 52.44 | 3.25 | 12.68 | 6.33 | 29.97 | accepted |
| 24628607 warm (disk-seeded SetupCache) | 41.11 | 3.39 | 0.77 | 6.51 | 30.21 | accepted |
| 24628607 warm + narrow runs | **37.44** | 3.24 | 0.72 | 6.25 | 27.04 | accepted |
| 26235156 cold | 35.82 | 2.46 | 8.82 | 4.35 | 20.00 | accepted |

- **Native verify:** it runs on a side thread, which takes about 1.9 s. The join wait is about 16 µs, so it
  is 0 s on the critical path.
- **Parity:** native bins, bundle and all leaf proofs are byte-identical to accepted v7. The 16 folds, the
  root and the tree differ by design, because of fold v2.
- **Narrow runs:** the warm and narrow-run recursive proofs are byte-identical to the cold run. That
  qualifies narrow runs on 24628607; topo's checker had qualified them on 26235156.
- **Acceptance:** a fresh, separate, CPU-only receiver built from this tree, with
  `STWO_RV64_FOLD_CLASS_CACHE=0` forced by the harness.

## Scale-up failure and fix (24628590)

The first ordered scale-up stopped at 24628590 (38 CPU segments). Stage two of native proving failed with
`CudaGlobalWitnessFailed`.
- **Where it failed:** a failure-only diagnostic (`global_stage.zig`) showed the core initial/terminal
  public-boundary global projection at **log 23**. The AOT kernel wrapper rejected it with
  `cudaErrorInvalidValue` (`if(log<5||log>22)`).
- **Why the accepted driver works:** the Zig side admits public-boundary logs up to
  `MAX_PUBLIC_BOUNDARY_LOG`, and the generator (`global_aot.zig`, commit bb61cca24) emits `log>23` for
  those two kernels. The frozen rebuild-package global catalogue that every stream built from predates
  that commit. The accepted d5766d83 driver with the accepted library proved this block on 2 GPUs
  (`diag/24628590-accepted-assets-2gpu.json`, byte-identical to v7). Infra's pre-mem library failed
  identically, so neither the mem stream nor any other stream caused it.
- **Fix:** I regenerated the global catalogue with `rv64-global-fixtures --catalog` at the integrate head.
  27 of 29 files are byte-equal. The two boundary kernels differ only in that guard line. The result is
  `/workspace/m3/catalogues-v3` (v2 with that change), now the harness default.
- **Proof bytes:** unchanged. Only an admission bound moved, to the value the generator and the Zig policy
  already use.
