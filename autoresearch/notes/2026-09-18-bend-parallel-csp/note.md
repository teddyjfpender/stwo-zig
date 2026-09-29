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

## Third transfer: invariant plan reuse across independent queries

Exact preprocessing/query match: for a fixed Circle domain and direction, the
preorder twiddle bytes are identical across all columns. Retain the last complete
plan independently in each native session; omit it from the next frame only after
full byte equality in Zig. New BND3 framing fails closed against older binaries.
The native side retains canonical input twiddle words, not computed FFT outputs.
It still constructs the affine Bend plan for each invocation. Prediction: nearly
halve transform request wire bytes for long same-domain batches. Response traffic,
input values, field arithmetic and proof semantics are unchanged. Native result
parity and complete proof equality are the falsifiers. Template memory is separate
from the bounded result-cache budget and must be reported/documented.

## Fourth transfer: three-product split-limb multiplication

Exact Karatsuba identity with wrapping U32 products: a=a0+2^16 a1 and
b=b0+2^16 b1. p00=a0*b0 and p11=a1*b1 fit U32. The wrapped product
(a0+a1)*(b0+b1)-p00-p11 equals the cross term modulo 2^32. The true
cross term is at most 2*65535*32767=4294770690 <2^32, so its recovered
U32 value is exact despite overflow in the intermediate sum-product.
Use the same canonical reduction/rotation as before. Derived operation change:
four limb multiplications become three, with extra additions/subtractions.
Hypothesis only: CPU instruction scheduling may erase the saving. Keep only
with parity plus paired kernel improvement; no claim of universal proof from
concrete fixtures. This is the standard product-of-sums identity, rederived for
this bounded wrapping-word special case rather than copied implementation code.


Exploratory outcomes (shared host, some compilation/kernel trials overlapped):
- Pass4 native with new 4-process/2-thread bridge: SHA 11.127 s, peak native
  requests 4; host pool actually resolved 8 workers in both lanes.
- Compact leaf plans + buffered word fast path + 4x2: SHA 7.274 s and ECDSA
  67.590 s, complete verified byte-identical proofs with shadow checking enabled.
- Same compact kernel with 1x8: SHA 14.707 s; column parallelism is preferable.
- 4096-leaf flat candidate rejected after regressions. Exact candidate retained.
- Selected shared-plan kernel passed 4096 seeded FFT/IFFT fixtures plus log16–24
  at eight native threads. Parallel native tests observe >1 concurrent request
  and plan reuse. ReleaseSafe passes. More threads are not a substitute for
  reducing serial transport and heap traffic.

Final review: compact leaf LDE originally fell back to a full forward transform
while the profile receipt stated one skipped layer. Implemented a clone of the
lower half followed by flat stages starting at group 2. This aligns physical
work with the receipt and preserves the algebraic zero-tail specialization.
Retained the entire earlier 24-proof suite separately and requalified the final
binary. Expanded native LDE tests across leaf/coarse boundary logs 7 and 8.
The three-product M31 candidate was rejected; selected M31 source is unchanged.

## Final repeated full-proof results

All 24 proofs verified; all 12 CPU/Bend pairs had byte-identical proof bytes.
Three alternating pairs per workload, fresh processes and cold result caches.
Both host lanes use eight Zig workers; Bend uses four processes × two native
threads. Every Bend proof observed four concurrent native requests. This table
uses the explicitly qualified no-shadow mode. Time includes guest execution,
witness and proving; verification, serialization and complete process wall time
are retained separately in `csp-final.json`.

| Workload | CPU median s | Bend median s | Bend / CPU | Previous Bend / new Bend |
|---|---:|---:|---:|---:|
| sha256 | 2.198 | 6.669 | 3.03x | 2.43x |
| keccak | 1.643 | 6.097 | 3.71x | 2.58x |
| poseidon2_m31 | 1.685 | 6.408 | 3.80x | 2.38x |
| ecdsa_secp256k1 | 16.919 | 56.684 | 3.35x | 2.56x |

**Bend improved, but CPU superiority and the requested 20x goal are not achieved.**
The comparison with pass4 is an observed checkpoint change, not an isolated
attribution: it includes scheduling, representation, transport, explicit host
worker counts and removal of duplicate shadow computation after qualification.
The checked-mode exploratory ECDSA result (67.590 s) is retained separately.
All timings are CPU-only on a shared host; these do not measure Bend GPU potential.
The final suite had no concurrent builds or kernel performance trials.

ECDSA executed 5,425,005 VM cycles. Its first final sample sent 7.212 GB and received 6.468 GB, reused 14,613 plans and 1,109 exact Bend results. Peak process RSS was 9.279 GB (a per-process high-water mark, not aggregate concurrent memory). The bridge time is accumulated across workers and must not be added to wall time.

