# H100 Cairo memory pipeline follow-up

Canonical inputs were `15590913_15590913` (dense) and
`15582797_15582797`; both used the managed-capacity policy, pinned canonical
preprocessing, an H100 SXM, 70 queries, and 26 query PoW bits. Every completed
trial produced the same proof SHA-256 as the saved reference and passed the
pinned independent Rust verifier. Whole-device memory was sampled about every
250 ms, so these peaks are lower bounds, not strict maxima.

| Experiment | PIE | Publication (s) | GPU peak (GiB) | Exact proof and Rust verifier |
| --- | --- | ---: | ---: | --- |
| Capacity reference | dense | 34.310 | 56.487 | yes |
| Capacity reference | second | 29.651 | 48.362 | yes |
| Per-instance relation migration | dense | 29.135 | 56.487 | yes |
| Per-instance relation migration | second | 26.371 | 48.362 | yes |
| Completed-tree host placement | dense | 33.241 | 56.487 | yes |
| Completed-tree host placement | second | 26.386 | 48.362 | yes |

The reference values come from `host-placement/early-evaluations*` in this
directory; the other rows have raw `summary.json`, `memory.csv`, `report.json`,
`process.log`, and `official-verdict.json` under `relation-streaming/` and
`tree-host-placement/`. Runtime and pod warmup affect the publication times;
the decisive result is the unchanged peak on both inputs. The two policy
experiments were removed from production after this falsification.

The dense phase diagnostic in `phase-diagnostic-dense/` uses the same proof
hash and records opt-in proof-session markers. Approximating command-relative
time by adding the measured 5.344 s ingress to each proof-session marker:

| Boundary | Approximate command time (s) | Nearby sampled GPU usage (GiB) |
| --- | ---: | ---: |
| Relation complete | 20.75 | 42.84 |
| Interaction commitment complete | 22.43 | 54.47 |
| Trace commitment complete | 26.02 | 55.47 |
| FRI commitment complete | 29.32 | 56.49 |

This identifies interaction commitment as the large new residency event.
The current trace commitment extends LDE cohorts in order, then submits a
fused mixed-leaf kernel that reads the retained interaction LDE cohorts.
Whole-array host preference does not bound pages touched by that fused launch.
The next meaningful implementation is row-tiled mixed-leaf commitment with
cohort-range residency, followed by bounded AIR/quotient reads and sparse
opening replay. The candidate must retain exact Merkle roots and full proof
bytes; a host-placement hint alone is not a 48 GB admission guarantee.

The GPU pod was stopped after receipts were copied. The phase-marker code is
off by default and enabled only with `STWO_CUDA_MEMORY_PHASES=1`.
