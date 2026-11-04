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
| E5 | interleaved A/B on 24628607, one binary: exact (A) vs uniform-v1 (U), class-PP reuse on | — | recursion A 21.91 / 23.25 s, U 23.61 / 25.94 s | A 55/55 byte-identical (both runs); the U1 receiver accepted |
| E6 | **NAMED** `m5_outer_canonical_r1_b2_q108_p20_fold4_v1` (uniform-v1 implied) | 1 fold VK `20ff5bd6…`, recursion 14.03 s (load 25.5), root 748 KB | the **same** fold VK, recursion 20.71 s (load 16.6), root 745,752 B | receivers accepted 2/2 |
| E7 | `m3_b4_q51_p26` 4-ary on GPU, after the retire hook | leaf interaction LDE at blowup 4 requests 5.93 G words (23.7 GB): `CudaAllocationFailed` | not run | **blocked on device memory**: needs a chunked/streaming LDE commit (kernels/M6) |
| P02 | the receiver selects m3 for r1 proofs | arity 4: `MissingRecursiveNodeProof`; arity 2: `Om31CircuitWireProfile` | — | rejected |
| P03 | unknown outer profile name on the receiver | `error: UnknownOm31OuterProfile`, exit 1, no panic | — | clean rejection (was a panic, exit −6) |

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

Negative corpus [M]. Both runs used donor 24628607, 0 unexpected accepts and 0 crashes:
- E4 uniform-v1 proofs: `26235156-e4-negative-corpus.json`, **36/36**;
- E6 named canonical profile proofs: `26235156-e6-negative-corpus.json`, **36/36**.

## Per-node host preparation (gate: ≤ 0.1 s per node)

The values are medians of the pipeline prep stage, which covers graph + padding + PP columns + assignment plan
(`pipeline.json`):

| run | leaf prep | leaf graph | fold prep | fold graph |
|---|---:|---:|---:|---:|
| E1 26235156 | 1.63 s | 0.51 s | 1.53 s | 0.36 s |
| E1 24628607 | 2.07 s | 0.70 s | 1.48 s | 0.30 s |
| E4 26235156 | 2.14 s | 0.53 s | 1.16 s | 0.43 s |
| E4 24628607 | 2.44 s | 0.76 s | 1.19 s | 0.35 s |

Under uniform-v1 with class-PP reuse (E5 U1, U2; E6), the fold prep median is 0.47 / 0.66 / 0.51 / 0.57 s. The class
plan cache hits: fold `host_plan` falls 0.756 → 0.012 s.

**The 0.1 s gate is not met.** Making it a store hit needs three things:
- per-class PP/plan reuse for **leaves** (done for folds in `b833f4e3e`; every leaf is still its own circuit);
- canonical leaves;
- the hint tape (M6).

## Receiver: in-process fold-class reuse under the canonical profile (E6 24628607) [M]

The strict receiver argv of the E6 24628607 run, re-run with `STWO_RV64_FOLD_CLASS_CACHE` in {0, 1}, interleaved
(`24628607-e6-receiver-class-reuse-ab.jsonl`):

| mode | wall | accepted | class hits |
|---|---:|---|---:|
| 0 (the acceptance harness setting) | 67.62 / 67.74 s | yes / yes | 0 |
| 1 (receiver-built class authority, never persisted, never producer-fed) | **45.49 / 44.66 s** | yes / yes | 15 / 15 |

Under the canonical profile all 16 folds share one class. The receiver therefore derives one fold authority from its own
trace-only graph and reuses it, which cuts **−33% verifier wall [M]**.

Under exact, fold classes vary per block, so the same switch buys less. On the E1 24628607 proofs it gives 53.41 s
(8 hits) against 63.81 s off (`24628607-receiver-class-reuse-check-and-exact.jsonl`).

`check` mode on the canonical proofs: **15/15** cached fold authorities equal the freshly rebuilt ones. The run was accepted in
69.03 s.

The acceptance harness forces mode 0 ("cache-disabled"). The cache is in-process and receiver-derived, so admitting it for
acceptance is a policy decision for rootverify/integrate. The `check` mode rebuilds every fold and compares.

## Leaf and fold topology census (E8, lane path, `STWO_RV64_TOPOLOGY_CENSUS=1`) [M]

`{26235156,24628607}-e8-topology-census.txt` has one line per node, after padding (exact shape). The leaf/fold split below is a
heuristic: it classifies by interned-constant count (> 1000 = leaf).

| block | leaves: distinct gate graphs | folds: distinct gate graphs |
|---|---:|---:|
| 26235156 | 10 of 10 | 9 of 11 |
| 24628607 | 16 of 16 | 9 of 17 |

Every leaf circuit has its own gate graph. The fingerprint hashes constant var ids, so constant-count differences alone already
separate graphs. Canonical leaves `R_leaf[f, r]` therefore need two things:
- constant-independent topology: native VK words guessed and table-checked, not interned;
- canon-native's rung padding.

Only then can a leaf VK be shared.
