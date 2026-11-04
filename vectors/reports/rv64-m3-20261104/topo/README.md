# Stream topo — proof-independent fold topology (RV64 M3)

Branch `codex/rv64-m3-topo`, built on the pod from this tree (zig only; binaries `build-v2{a,b,c}.json`). The CUDA runtime is the accepted
`library.so` (sha 25295868…). Infra showed that this pairing gives byte-identical output for
26235156 (`/workspace/m3/runs/infra/26235156-2gpu-srcdriver-acceptedlib`). Hardware: 2× RTX 5090.
Every timing below is a **single measured observation**, not a median. Binding argument:
`design/riscv-proving-stack/rv64-m3-topo-binding.md`.

## What changed

1. **Fold message v2** (`om31_outer.zig`). The child authority identity and the child FIXED root are now
   *guessed, range-checked words* instead of circuit constants. The child's in-circuit transcript absorbs the
   same wires, and they are hashed into the fold's public digest. The receiver recomputes that digest from
   authorities it built itself, so a different child key changes the digest and the fold is rejected.
   With this change a fold's circuit depends only on the child **geometry class** (`classKey`).
   This changes the proofs: fold message version word 1 → 2.
2. **Receiver fold-class cache** (`execution_wrap.zig` `FoldClasses`). This cache is in-process, built by the receiver
   itself from honest graphs, and never persisted. A later fold of the same class skips the graph, PP and CPU FIXED work
   and is restored and freshly verified under the class authority. Modes: `STWO_RV64_FOLD_CLASS_CACHE=0|check`.
3. **Producer fold-class assignment-plan cache** (`riscv_cuda/rv64/outer_assignment.zig` `ClassCache`). It reuses the
   tasks, permutation indices, level ends and seed layout of a class, and re-reads only the seed values.
   This does not change proofs. Modes: `STWO_RV64_OUTER_PLAN_CLASS_CACHE=0|check`; the default is on. The class hint
   is passed through `device_prove.class_hint` (threadlocal, host-only).
4. **Producer fold-class PP cache** (`om31_native/outer_wrap.zig` `PPCache`). Later folds of a class reuse the
   immutable preprocessed circuit, so the columns are not rebuilt. The authority and the device FIXED precommit are
   still built per proof. This does not change proofs. Modes: `STWO_RV64_OUTER_PP_CLASS_CACHE=0|check`; the default
   is on.
5. **Topology census** (`om31_native/topology_fingerprint.zig`). `STWO_RV64_TOPOLOGY_CENSUS=1` logs per-node digests
   of the gate graph, the constant table and the witness origins.

## Measured

### Distinct topologies on 24628607 (`census-v1.json`, `census-v2.json`)

| | v1 accepted control | v2 |
|---|---:|---:|
| authority identities (33 nodes) | 33 | **25** |
| row-geometry classes | 8 | 8 |
| fold gate graphs / fold topologies (16 folds) | 8 / 16 | 8 / **8** |
| leaf gate graphs (17 leaves) | 17 | 17 (leaf proofs byte-identical) |

In v1, folds of the same shape already had identical gate graphs and differed only in their constants (the child keys).
In v2 the number of fold topologies equals the number of fold geometry classes.

### Correctness

- v2 on GPU with 2× 5090 (`24628607-2gpu-v2a.json`): native bins, bundle and all 17 leaf proofs are byte-identical
  to accepted v7. The 16 folds and the root differ, as intended. The independent receiver (separate process,
  CPU-only, built from this tree) **accepted**.
- The GPU-produced v2 proofs and the CPU-produced v2 proofs (CPU outer prover, from the accepted leaves) are
  **byte-identical** across all 35 files.
- Fresh receivers on the CPU-produced v2 proofs (`recv-v2.jsonl`): accepted with the class cache on, off and in
  check mode. Check mode: all 8 cached authorities are equal to authorities rebuilt from scratch.
- Adversarial test (`adversarial-fold-swap.json`): two fold proofs of the same class, sharing one authority but with
  different children, were swapped. The receiver rejects them with `CurrentOm31OutputDigest`, with the cache both on
  and off.
- Plan cache in check mode on GPU (`24628607-2gpu-v2b-check.json`): all 8 template reuses are equal to a full rebuild
  (tasks, indices, levels, seeds, identity). The receiver accepted.
- With the plan cache on (`v2b`) and off (`v2a`), the recursive proofs are byte-identical. In the warm two-block run
  they are byte-identical with the cache on and off, and the warm root equals the cold root.
- Unit test `rv64_om31_outer_test_root.zig` "fold v2 topology is proof-independent and digest binds child keys":
  two children with different FIXED roots and identities produce equal circuits and equal constant tables, while
  their digests differ. A key-swapped child is rejected in-circuit. The existing fold-root test still passes.

### Timings (seconds)

| Run | request | recursion | fold plan hits |
|---|---:|---:|---:|
| accepted v7 control (handoff) | 98.92 | 63.62 | n/a |
| v2a: v2, no plan cache, cold | 98.66 | 63.86 | 0 |
| v2b: v2 + plan cache, cold | 97.12 | 63.40 | 8/16 |
| warm two-block, plan cache **off**, 24628607 second | 96.36 | 63.62 | 0 |
| warm two-block, plan cache **on**, 24628607 second | 91.63 | 58.50 | 13/16 |
| warm two-block, plan + PP cache **check**, 24628607 second | 96.60 | 64.62 | 0 hits (15 checks ok) |
| warm two-block, plan + PP cache **on**, 24628607 second | **87.46** | **54.93** | **13/16 plan, 13/16 PP** |
| warm two-block, plan + PP cache on, 26235156 first (cold) | 64.76 | 41.83 | 2/10 |

- **Measured, attributable** (single observations, same warm two-block layout; only the caches are toggled):
  - The plan cache alone cuts 24628607 recursion by 5.1 s (63.62 → 58.50).
  - The plan + PP caches cut it by 8.7 s (63.62 → **54.93**). The request goes 96.36 → **87.46** s.
  - Cross-block reuse raises the fold hits from 8 (cold) to 13 of 16.
  - The recursive proofs are byte-identical across all four warm runs. Both blocks are accepted by fresh receivers
    (`warm-two-block.json`).
- Cold, the effect is within run-to-run noise: fold node mean 2.67 → 2.48 s, and the fold tail after the last leaf
  11.96 → 10.43 s (`rv64_m3_timeline.py`).
- CPU receiver, fold verification time (`recv-v2.jsonl`): 21.8 s with the class cache off, 10.5 s with it on.
  Receiver recursion: 51.3 s → 38.8 s.
- Host preparation per fold in v2a (summed over 16 folds): finalize 1.39 s, PP columns 4.65 s, authority 0.97 s,
  graph 0.22 s mean. Plan + pack + hash over all 33 nodes is 24.7 s; folds are now mostly cache hits.

## Not done / open

- **Leaves still depend on the proof.** Each CPU segment declares its own native geometry: tail components and
  bridges are present or absent per segment, and keccak, bulk, sponge and division logs vary per segment. The leaf
  verifier mirrors that geometry (pre-finalize vars range from 19.3M to 33.3M). Leaf class reuse needs canonical
  native segment geometry: never omit tails or bridges, and bucket the logs. That is a native-proof change with a
  proving-cost trade-off and was not attempted. Once geometry is canonical, the leaf-side constants also become
  removable. The native FIXED root is already exposed in the frame words, so `requireDigest` at `cpu_leaf.zig:71` and
  `keccak_leaf.zig:97` / `truth_leaf.zig:97` can go. `emitBindingBegin` constants would become guessed frame words
  (leaf v2).
- **Narrow-run assignment kernel: not qualified.** The accepted `library.so` does not export
  `stwo_circuit_assignment_narrow_run_on`, and infra's from-source CUDA image was still compiling during this stream.
  It stays default-off.
- The device FIXED precommit and the authority (AIR parse/bind) still run for every fold. They could become
  class-cached too, if the immutable device FIXED forest can be shared across proofs.
- The plan templates and the PP cache are allocated from `smp_allocator`, outside `SharedHostBudget` accounting.
  Each has a default cap of 6 GiB (`*_CLASS_CACHE_BYTES`); the PP cache holds about 0.36–0.54 GB per fold class.
- No persisted (on-disk) cross-process cache. Reuse across blocks is in-process (resident service) only.
