---
title: Bend parallel CSP and compact FFT plans
author: Codex
created_utc: 2026-09-18T08:40:47Z
---

# Problem match: parallel Bend transforms for complete CSP proofs

Task/semantics: compute exact ordered Circle FFT/IFFT/LDE columns and FRI arrays;
retain canonical M31, protocol, transcript and byte-identical CPU-verified proofs.
Inputs: pass4 ECDSA has 5,425,005 cycles, 15,011 native requests, 12.335 GB
request traffic and 6.164 GB responses. This host has an eight-CPU cgroup quota.
Computational model: parallel work/span plus serialized I/O and runtime allocation.

| Candidate | Relationship | Guarantee / complexity | Fit and risk |
|---|---|---|---|
| Independent column map | Exact decomposition | Same O(c n log n) work; c independent outputs | Removes session lock from distinct columns; memory grows with workers |
| Recursive within-column FFT | Existing exact algorithm | O(n log n) work; span depends on serial leaf size | Bend parallel lets already present; native worker count was one |
| Flat staged FFT | Exact alternative with same Circle twiddles | O(n log n), O(n) storage | Avoids runtime Plan node traversal; new lowering/parity burden |
| GPU-resident batched FFT | Exact potential transfer | Hardware-dependent traffic/launch cost | No GPU available; no measured claim possible here |

Selected first transfer: bounded independent column execution plus explicit native
thread counts. Both CPU and Bend host paths use eight Zig workers. Compare one
Bend process with eight native threads and a four-process/two-thread configuration.
Total native compute workers are eight; host orchestration and parity consume
additional CPU and must be disclosed rather than hidden. Cache budget stays 64 MiB
across all sessions. Each worker owns its pipe, runtime heap and cache. Join all
jobs before return or error; no shared mutation of overlapping columns. Small or
aliased batches take the serial path. FRI remains within-column parallel Bend.

Mapping: each column is one independent exact transform instance. Solution
recovery writes the result to its original column index after exact Zig parity.
Derived: changing the schedule preserves arithmetic dependency order within each
column and preserves transcript order because the join precedes the prover step.
Hypothesis: removing the single session lock improves multi-column wall time;
falsifier is unchanged full-proof time or peak concurrent native requests <=1.
Do not infer 8x from eight threads: traffic, memory, leaf scheduling and host work
remain. Measure 1x8 versus 4x2 and baseline, then select by verified end-to-end data.

Sources: FFTW's official threading guidance says synchronization overhead and size
control the useful thread count, and its thread-safety guidance separates immutable
plans from mutable arrays. Transfer scheduling principles only, not FFTW arithmetic
or implementation code (Circle FFT differs from complex FFT).
https://www.fftw.org/fftw3_doc/How-Many-Threads-to-Use_003f.html
https://www.fftw.org/fftw3_doc/Thread-safety.html
Pinned Bend guide: ../bend-toolchain/guide/GUIDE.md, parallel lets and balanced calls.
Existing implementation: bend/stwo/circle_fft.bend, runtime.zig, pass4 receipts.

Validation: native multi-column parity, observed concurrent requests, failure joins,
existing FRI tests, then unchanged secure CSP corpus including ECDSA. Record worker
configuration and host pool actually resolved in every receipt. Keep rejected runs.
Open uncertainty: native parallel lets' scaling, pipe traffic and Plan allocation;
parallelism enables opportunity, not guaranteed superiority over SIMD Zig.

## Second transfer: compact leaf twiddle plans

Derived: the native adapter allocates one runtime Plan node per butterfly group,
and Bend recursively destructures it even inside a 256-element local leaf. Replace
only leaf plans with a flat binary-heap array of twiddles, retaining the outer
balanced parallel recursion. A depth-d leaf stores root at 1 and children 2i/2i+1.
Forward stages visit groups 1,2,4,...; inverse visits in reverse. Within each group,
the unchanged M31 butterfly uses the same twiddle and offset. This is an exact
representation/schedule transfer, not a replacement of Circle FFT by complex FFT.
The C adapter only rearranges input twiddle words; all arithmetic remains Bend.
Prediction: reduce per-transform Plan allocations from n-1 to O(n/256), reduce
Bend recursive dispatch in leaf transforms, preserve parallel calls above leaves.
Small cases and 2x extension must be parity checked because the special Circle
bottom twiddle signs and omitted zero-half layer are semantic constraints.


Follow-up experiments, final small-leaf LDE correction and measured outcomes are
recorded in `autoresearch/notes/2026-09-18-bend-parallel-csp/note.md` and
`vectors/reports/bend-pr198/pass5/README.md`.
