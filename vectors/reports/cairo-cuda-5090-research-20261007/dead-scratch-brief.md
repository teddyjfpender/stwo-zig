# Problem match: reclaiming a dead writer slot before its arena address is reused

**Task and semantics.** Preserve exact Cairo proof bytes while allowing the
trace-writer scratch slot to be device-resident during trace generation, then
make its contents disposable before later arena occupants reuse its physical
address. No later kernel may read old scratch contents.

**Measured scale and model.** For `15582797_15582797`, writer scratch occupies
11,468,681,796 logical bytes and is live only in trace generation. Host
preference for that slot contributes to a 54.693 s trace-generation stage on
the 5090. Earlier L40S experiments showed 12.01 s without the host preference
versus 43.30 s with it on the dense case, but removing the preference raised
HBM residency. The 5090 has 31.84 GiB reported HBM; later phases need that
capacity for interaction coefficients and constraint sources.

**Canonical match.** This is lifetime-based storage reuse with an explicit
discard after last use. The existing arena plan already aliases writer
scratch with later `trace_evaluations` storage. The physical interval of
scratch has no overlap with another slot still live at the end of trace
generation for this geometry; the only large overlapping slot begins in trace
commit. CUDA 13's stream-ordered managed-memory discard marks contents
unneeded and lets the driver avoid moving them during eviction, but does not
promise immediate physical deallocation ([CUDA runtime memory API](https://docs.nvidia.com/cuda/cuda-runtime-api/cuda_runtime_api/group__CUDART__MEMORY.html),
[unified-memory guide](https://docs.nvidia.com/cuda/archive/13.2.0/cuda-programming-guide/04-special-topics/unified-memory.html)).

**Selected transfer.** Add an opt-in authenticated-slot discard after the
trace-writer kernels and before trace-commit kernels on the same CUDA stream.
The call validates managed-allocation containment and enforces that no
currently live arena placement physically overlaps the discarded range. CUDA
12 retains its previous behavior; the opt-in requires CUDA 13. Compare
scratch-device alone and scratch-device-plus-discard with the same exact PIE.

**Alternatives.** Prefetching the scratch slot back to host after its use did
not release HBM on an earlier H100 experiment. A separate allocation that is
freed at the stage boundary could guarantee reclamation but would alter arena
pointer binding and complicate aliasing. Virtual memory remapping offers
stronger physical control, with substantially larger soundness and build risk.

**Prediction/falsifier.** If discard lets the device use writer scratch during
trace generation without holding its old pages later, the first stage should
approach the previous L40S no-host-scratch time and whole-device peak should
remain below 32,607 MiB. If the pages remain resident, later kernels hit CUDA
OOM, or proof bytes change, reject the policy. Even success in this stage
would not solve the measured 136 s relation and 93 s constraint bottlenecks.

**Qualification.** Test CUDA 13 API behavior on a standalone 5090 allocation,
compile the product, then prove the small and dense canonical PIEs with exact
proof hashes and the pinned Rust verifier. Save phase timings, complete
command time, device peak, host RSS, proof hash, and failure logs. The discard
must stay opt-in until it passes dense validation and the arena-overlap check
is covered by a focused test.

**Open uncertainty.** A 35 GiB host-touched discard probe did not reduce cgroup
memory use and a subsequent 35 GiB touch was OOM-killed. That result does not
establish whether GPU-resident managed pages are reclaimed under pressure;
the standalone HBM probe is required before integrating this path.

**HBM discard falsifier.** A separate 5090 probe touched 12 GiB of managed
memory on the GPU, then optionally discarded it and touched another 20 GiB.
Reported free HBM stayed at 20,252,196,864 bytes immediately after discard;
the second touch took 3.61 s versus 3.66 s without discard. This API does not
reclaim HBM promptly on the present driver. Do not ship the proposed discard
path on that assumption.

**Revised exact variant.** Keep writer scratch on the GPU for trace generation,
then issue an explicit stream-ordered prefetch of that authenticated dead slot
to host before trace commitment. Leave interaction coefficients in GPU memory
for their later stage. The prefetched range may alias a later slot only after
its old scratch contents are dead; the next stage will overwrite those bytes.
This avoids any inference about discard semantics and preserves the proof
graph. First test that host prefetch actually increases free HBM in a
standalone probe, then run the full exact proof. If it does not reclaim HBM,
reject the combined policy.

**Qualification result.** Scratch-device alone produced the expected dense
proof and passed the independent Rust verifier. Trace generation fell from
54.693 to 16.468 s, but relation and constraint work remained slow: total
proof execution was 335.675 s, device peak 27.117 GiB, host RSS 72.620 GiB.
An attempted combined-policy trial failed with CUDA allocation status 2 after
41.825 s, but its build accidentally used an older proof-session source file
from a different checkout. That receipt is **invalid** as a test of the
combined policy and must not be compared with the qualified results. The
combined opt-in was removed from source pending a proper HBM-reclamation
design and source-matched dense qualification.
