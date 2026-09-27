# Reuse canonical transcript hash graphs — 2026-09-24

**Rejected as a performance change. Candidate archived; qualified control restored.**

The previous turn made progress: exclusive persistent-worker ownership was fixed,
all three pipeline adapters were qualified, and current-kernel matched scheduling
measurements supported explicit overlap for same-key jobs. This checkpoint removes
repeated immutable graph construction in shared hash-witness preparation.

Query and retry batches already construct one canonical draw graph for their sizes
and output endpoints. Their frame emitters previously rebuilt that same graph for
every attempt/block. Transcript absorption/PoW likewise built a sizing graph and
then rebuilt it inside the emitter. All now pass the existing graph through
`destinationWithPlan`, using the same live, trusted and direct-column emission.
Public-input secure draws use the existing planned live APIs plus a planned trusted
API that still binds actual public input bytes. The latter checks input length before
writes; it does not substitute the length-only private-message projection.

No new hash algorithm, AIR, key identity, precompile or dispatch mode is introduced.
Graph ownership stays with the caller and remains valid until each synchronous
emitter returns. Per-frame routing is still independently derived for its bindings.
This avoids one topology build per frame in these paths. A 70-query batch with nine
draw frames builds one graph instead of ten inside the batch; outer count-planning
still builds its own graph. It does not remove trusted transcript full-row storage.

## Qualification

The frame/transcript/draw/retry/query ReleaseSafe gates passed 7/7. After extending
the public-input path, hash/draw gates passed 7/7, including full fixed-row parity
across empty, block, chunk and unbalanced-tree boundaries, malformed destination and
mismatched input-length rejection before writes, mutation and allocation cleanup.
The draw gate is repeated across these two sets; this is **12 distinct focused
checks**, not fourteen. Canonical Metal qualification passed **7/7** at q70/PoW26. Both artifacts
remain exactly 839,853 bytes with SHA256
`33b85e0a6519962ca53511b4dc06cecc0f2f5d0e06f299f95a8868efd10744dd`.
The candidate is **not retained in live code**: matched timing did not establish an
end-to-end benefit. All six modified files were restored byte-for-byte to `control/`;
`candidate-source/` and `changes.patch` preserve the complete experiment.

## Reproduce

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-frame-witness test-blake3-transcript-plan test-blake3-draw test-blake3-bounded-draw test-blake3-query-batch -Doptimize=ReleaseSafe --summary all
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-hash test-blake3-draw -Doptimize=ReleaseSafe --summary all
STWO_RISCV_PARENT_BENCH_ALLOCATOR=smp STWO_RISCV_PARENT_BENCH_WORKERS=8 python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_metal test-blake3-native-parent-pipeline-aot -Dmetal-core-aot-bundle="$PWD/autoresearch/notes/2026-09-24-blake3-rotate7-limbs/core" -Doptimize=ReleaseFast --summary all
```

The worktree is dirty; source snapshots and the relative patch isolate this change.
Broader goal items remain open, including trusted transcript materialization,
effective PCS/DEEP fusion, canonical multi-job tree scheduling, and the separately
reviewed parameter experiment. No 10×, subsecond recursion or superiority claim.

## Matched result — rejected as a performance change

Control/candidate/candidate/control, both arms using explicit overlap, one frozen
binary per arm and the same accepted ABI24 bundle. Eight workers prove two identical
jobs while one worker prepares. The driver checks exact artifact identity, canonical
parameters, independent verification, plan reuse and worker budget on each run.
All **eight timed artifacts** independently verify.

| Arm | Complete fixture (s) | Two-job window (s) |
| --- | ---: | ---: |
| control | 20.904 | 9.640 |
| candidate | 21.716 | 9.727 |
| candidate | 21.281 | 9.732 |
| control | 21.238 | 9.702 |

Median preparation sum: **3.51811 → 3.50982 s (0.24% lower)**. Median complete
fixture: **21.07072 → 21.49864 s (2.03% higher)**. Two-job window:
**9.67099 → 9.72974 s (0.61% higher)**. Peak physical footprint:
**28,178,414,304 → 28,173,334,976 bytes**, effectively unchanged. Two samples per arm
cannot identify the cause of the small differences, but do not support promotion.
The control is the immediately preceding pipeline-lease checkpoint, not Poseidon.
No timing improvement or memory reduction is claimed.

The measured preparation stage includes all witness work; removing these graph
builds did not materially reduce it. Next work should address materialized full-row
trusted transcript buffers and final-column staging, or reduce verifier rows through
PCS/DEEP fusion. The compact trusted transcript path still needs metadata destination
propagation through bounded draws/queries, compact-aware plan counts, and independent
fixed-tail admission for both row-oracle and direct-column consumers. It must retain
public-byte, transcript-role, retry-capacity and consumer binding checks.

The source commands above describe the archived candidate. To repeat timings without
altering live source:

```sh
python3 autoresearch/notes/2026-09-24-transcript-graph-reuse/measure.py
```

`binaries.json`, raw logs, `results.json`, `summary.json` and checksums retain both
observations and executable identities. This is evidence-driven rejection, not a
completed broader performance goal.
