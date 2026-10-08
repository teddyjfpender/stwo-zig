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

## Tiled mixed-leaf falsifier

The capacity-only row-tiled leaf kernel preserved both exact proof hashes
and passed the independent Rust verifier. Explicit device/host prefetch around
each tile made whole-device usage worse: 79.069 GiB for the dense PIE and
67.896 GiB for the second PIE. Dense publication took 79.113 s, including a
cold trace-generation interval. Removing the tile prefetch restored the exact
baseline peaks of 56.487 and 48.362 GiB, with publication 31.750 and
37.899 s respectively. The host RSS observation of 72.597 GiB in the second
no-prefetch run shows that managed pages may be retained in host memory while
the GPU peak stays unchanged. The tiling code was removed from production.
Raw summaries, 250 ms samples, stage logs, reports, and verifier verdicts are
in `tiled-prefetch-falsifier/` and `tiled-no-prefetch-falsifier/`.

The next experiment moves the 11.71 GiB interaction-coefficient slot's
host preference and prefetch ahead of interaction LDE generation. This may
allow coefficients to be consumed from host while evaluations are produced.
Its proof bytes, whole-device peak, and time must be qualified before the
capacity policy is retained.

The early coefficient-host experiment was also falsified: both exact proofs
and Rust checks passed, but whole-device peaks remained 56.487 and 48.362
GiB. Publication times were 38.761 and 38.573 s; the second process RSS
reached 72.602 GiB. Its raw receipts are in `early-coeff-host-falsifier/`.
Changing managed-memory hints and their timing is not a reliable way to
establish a lower physical HBM bound on this workload. The next test uses
an explicit host-backed allocation, with its bandwidth cost measured.

## First-write host placement: qualified capacity result

The distinction is **when the placement is set**. Host-preferring a managed
buffer after the GPU has filled it does not release its HBM residency on this
H100. Applying the capacity policy before the GPU first writes the main and
interaction coefficient slots kept those large buffers host resident through
their production and later reads. The ordinary and throughput policies retain
their previous placement order.

| Policy | PIE | Publication (s) | Sampled GPU peak (GiB) | Saved proof SHA-256 and Rust verifier |
| --- | --- | ---: | ---: | --- |
| Earlier capacity reference | `15590913_15590913` | 34.310 | 56.487 | match / pass |
| Interaction coefficients before first write | `15590913_15590913` | 39.901 | 44.862 | match / pass |
| Both coefficient slots before first write | `15590913_15590913` | 51.273 | **30.860** | match / pass |
| Earlier capacity reference | `15582797_15582797` | 29.651 | 48.362 | match / pass |
| Interaction coefficients before first write | `15582797_15582797` | 34.255 | 38.610 | match / pass |
| Both coefficient slots before first write | `15582797_15582797` | 36.097 | **26.983** | match / pass |

The final policy cuts sampled whole-device peak by 25.627 GiB (45.4%) and
21.379 GiB (44.2%) respectively. The dense publication time rose by 49.4%
against the saved baseline; the second rose by 21.7%. These are single-run
timings on the same H100 class, so they describe the cost of this capacity
mode rather than a ranked throughput claim. Raw summaries, 250 ms device
samples, stage logs, reports, and independent verdicts are in
`coeff-before-write-positive/` and `both-coeff-before-write-positive/`.

To test reduced free capacity, a separate process reserved 34 GiB of HBM,
leaving 47,957,868,544 bytes (44.66 GiB) free before the dense proof. The
proof completed with the same saved SHA-256 and passed the Rust verifier.
Whole-device peak was 65.372 GiB **including** that reservation, or about
31.372 GiB above it; publication was 52.717 s. The reservation and proof
receipts are under `pressure-48gb-dense/`. This is not a substitute for an
actual 48 GB GPU qualification: architecture, bandwidth, and physical-card
memory accounting can differ. The measured peak is also a 250 ms sampled
lower bound rather than a strict instantaneous maximum.

An opt-in whole-arena mapped-host experiment reached only 1.24 GiB sampled
HBM before a trace-writer illegal address and did **not** produce a proof.
That implementation was removed. Managed-memory prefetch to CPU was also
checked in a standalone 2 GiB CUDA experiment; after synchronization,
`cudaMemGetInfo` still reported the same HBM free bytes. The usable win here
comes from choosing host placement before first write, not from evicting
already-resident pages.

Aligning the proof-session phase markers with the report's ingress duration
places the new highest sampled peaks **inside constraint evaluation**, at
46.48 s command time for the dense PIE and 33.11 s for the second. The dense
peak is 30.860 GiB and remains at that level into FRI; it was not first
created by decommitment. The geometry report shows a 12.40 GiB writer-scratch
slot live during trace generation and a 3.56 GiB evaluation tile live during
constraint evaluation. Further capacity work should measure the physical
contribution and access pattern of these buffers before changing their
placement or geometry. Sparse opening replay remains a separate longer-term
opportunity, not an explanation for this measured peak.
