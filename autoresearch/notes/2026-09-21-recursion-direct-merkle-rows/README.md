# Direct selected Merkle witness rows

Trace Merkle and FRI leaf, node and anchor generation now emit selected logical
rows without first allocating padded main columns and then extracting/transposing
them. The column path and dense-row path share the existing stateful hash emitter;
there is no second hash implementation. A common output sink assembles main values,
authenticated preprocessing metadata and parameters in their canonical order.

All four generators validate the complete reference, preprocessing and witness
before emission. Outputs are fresh allocations, and the packed-node path frees its
output on failure. Full-column generation remains available to existing callers
and the differential test oracle. The detached production path uses dense output.
This changes neither the AIR nor its keys, identities, transcript or proof parameters.

## Validation and measurement

The guarded real-parent capture test passed, comparing both selected lanes against
full-column extraction, including every logical row and provider input/output. Each
lane includes 47,478 trace rows, 11,580 FRI leaf rows and 86,850 provider calls. It
also evaluates the typed row constraints and checks provider permutations. Both
CPU and Metal producers built in ReleaseSafe. A fresh CPU root proof independently
verified after producer exit and matched the qualified key, claims and proof bytes.

Apple M5 Max, 64 GiB; unchanged developmental `recursive_q193_v1` with 193 queries,
16 PCS PoW bits, 10 interaction PoW bits, log blowup 1 and fold step 4. This is not
the CSP 70-query profile or a production-security qualification.

Complete Metal parent processes were compared against the preceding persistent-worker
checkpoint binary, using one excluded warmup per arm and three ABBA rounds. Each arm
has six measured samples. All **14 comparison proofs** independently verified after
producer exit and matched the qualified artifacts. No build or other proof benchmark
overlapped these timed runs.

| Metric | Baseline | Direct rows |
| --- | ---: | ---: |
| Complete-parent median seconds | 5.676281083 | 5.535802854 |
| Summed child row-generation median seconds | 0.652836792 | 0.532217229 |
| Median peak process RSS bytes | 4,392,353,792 | 4,392,206,336 |

The paired candidate/baseline ratio is 0.976160960, approximately **2.38% improvement**,
with the driver's bootstrap 95% interval [0.974888597, 0.978620012]. Row generation
falls about 18.5%; it is only one part of the complete process. Peak RSS is effectively
unchanged. This is local advisory evidence, not a judged board result.

A two-worker persistent replay additionally produced and independently verified
all seven parents, covering both segment-child and parent-child preparation and
matching every qualified artifact. Its single observation was 28.901 seconds,
with sampled aggregate process RSS 8,985,968,640 bytes. This is retained-leaf tree
qualification, not a controlled tree-speedup claim. Together with the comparison
and CPU check, the checkpoint has **22 fresh independently verified proofs**.

For the retained root geometry, the removed padded column buffers represent
57,704,448 bytes per child / 115,408,896 bytes across two children. This is a
source-derived allocation-volume estimate, not a measured peak-memory reduction.
`evidence/allocation-estimate.json` gives the component counts and padded heights.

Source conformance remains at the same 103 existing finding identities, with no
new findings. `git diff --check` passes. Evidence, command provenance, build/test
logs and fresh verifier receipts are retained below; full proof bundles remain
under `/tmp/stwo-recursion-direct-merkle-20260921`. Source snapshots and
`manifest.json` pin the checkpoint.

## Remaining full objective

The four-part goal remains active. Persistent plans and bounded concurrent workers
are integrated, but useful final-layout buffer reuse and explicit within-worker
preparation/proving pipelining remain. This change removes an intermediate witness
layout; the cohort still copies logical rows and later builds final columns.
Immutable authority construction and source tuple projection remain substantial.
Fused PCS/DEEP components and the separately reviewed parameter experiment are
still unimplemented. These small fixed-profile gains do not establish subsecond
recursion or the tenfold aspiration.
