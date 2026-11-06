# P1 checkpoint: memory work remains incomplete

Raw evidence links below now resolve through `../raw-artifacts-summary.json`; verified raw copies are retained outside Git under the receipt policy.

**Negative request-time result; no P1 exit.** The default remains D2 + truth
coalescing, automatic arena and one lane. `STWO_RV64_RC_COMPOSITION_COLUMNS`
and `STWO_RV64_RC_INTER_REUSE` remain off. Conjectured-128 proof/security
parameters are unchanged.

| Headline 24628607, two RTX 5090s | Default | Composed candidate |
|---|---:|---:|
| Warm request median, interleaved 3+3 [M] | 12.332337 s | 12.401008 s |
| Capture median [M] | 2.106 s | 2.148 s |
| Native prove median [M] | 4.434 s | 5.116 s |
| Native verify median [M] | 1.589 s | 1.576 s |
| Recursion median [M] | 5.538 s | 4.652 s |
| Warm whole-request kernel GPU-seconds, separate profile [M] | 10.583957 | unavailable: incomplete capture |
| After-native kernel busy, separate profile [D] | 52.36% | unavailable |
| Exact per-node peak | unmeasured | unmeasured; 11 GB target open |
| Root proof bytes [M] | 749,688 | 749,688; byte-identical |

The primary six services completed, all twelve proof payload sets matched,
and all twelve fresh CPU receivers accepted. Candidate request median is
0.56% slower [D]; stage medians are independently computed and must not be
summed as the latency of a single request. The quiet gate explicitly permits
up to 0.5% idle cgroup PSI, requires zero throttling and five stable idle
intervals, and excludes foreign GPU/compiler/receiver activity. This is not
a zero-PSI comparison or a matched comparison with the historical 12.9 s.

The implementation packs only composition columns referenced by the
unchanged authenticated role and reuses one sorted contiguous INTER slab
for coefficient custody. The largest observed selected role arena is
7,818,182,656 bytes [M], and node-4 INTER retains 4,981,268,480 input bytes
including a 268,435,456-byte scratch tail [M]. Its coefficient ingress copy
and additional coefficient allocation are zero [M]. These are allocation
sizes, not whole-node peaks.

The separate profile exposed another warm capacity stall: required
23,152,558,080 bytes versus 23,085,449,216 capacity [D, admission model]. The
owner stopped the stuck producer after 161.253 s [M]. All three completed
profiled proofs were byte-identical and freshly CPU-accepted, but the warm
candidate produced no root and zero payload files. Its CUPTI kernel/runtime
records stop 12.856 s before even the completed cold request ends [M]. The
retained `metrics-audit.json` invalidates its helper GPU-seconds/completeness
flags. Raw Nsight reports/SQLite files are preserved losslessly as gzip files.
The baseline busy fraction uses exclusive-native end plus a 5 ms uncertainty
band through request end, summed over two GPUs; it does not establish an
exact historical 54% comparison.

Prior failures are preserved: geometry-inapplicable coset prototype,
column-packing warm timeout, multi-lease INTER rejection, and profiler
startup/child-process ownership failures. The current sorted slab preserves
PCS's contiguous borrow checks. No candidate profiling retry is justified
without a new memory reduction.

Commit gate: **PASS**, `p1-gate-evidence-20261106-01/p1-gate-20261106-01/gate.json`.
Production build, all five Zig targets, Python tests, both small-block
proofs matching all 32 frozen artifacts [M], both fresh CPU accepts [M], and
all 19 required corpus cases [M] pass. V04 cross-block-root rejection is a
resource-size rejection, not semantic rejection. Gate cold/warm request walls
25.403 / 11.599 s [M] are correctness observations, not matched timings.
The tested source hash map matches the local source exactly. The M8 ledger
validates; the global checker still encounters the pre-existing missing
commit in `device-fs.jsonl:1`. No global ledger PASS is claimed.

Next: reduce actual composition and interaction workspaces, starting with a
static column-use census for bounded groups of existing constraint roots.
Keep full global mask geometry and original reverse RLC powers; do not grow
admission scheduling to accommodate the failed footprint. The static census finds at most 31 masks per root [D]; a 32-column cache
models a 2.181 GB role arena [D], with 126 versus 116 role-4 mask-column
loads and 87 versus 87 role-5 loads [D]. This is the next candidate, not
a GPU result; see `outer-chunks-hypothesis.json`.

Evidence: `inter-reuse-v2-result.json`, `inter-reuse-hypothesis.json`,
`p1-inter-reuse-v2-source-20261106-02/`,
`p1-inter-reuse-v2-headline-evidence-20261106-02/`, and
`p1-profile-retry2-evidence-20261106-02/` (including `metrics-audit.json`).
