# Circuit verifier witness replay: problem match (2026-10-01)

Task and required semantics: Produce the same leaf and fold STARK proof bytes
for each verified Cairo PIE, including the same variable values, numbering,
padding, transcript, and output digest. The source is an authenticated,
fixed circuit topology; per-PIE proof values change. A proof must still be
independently verified before publication.

Inputs, measured scale/provenance, encoding, and computational model: The
two-PIE H200 run in `vectors/reports/recursive-product-20260918/
cuda-resident-pipeline-h200-20261001` has 32.1 million raw and 44.5 million
padded leaf variables per PIE, and 12.2 million raw and 19.6 million padded
compact-root variables. The warmed process takes 13.363 s: Cairo 6.987 s,
wraps 4.074 s, fold 1.340 s, overhead 0.962 s. The second leaf uses a
topology-cache hit, but `leaf_wrap.zig` still builds and pads the full gate
arrays. Source-level cost is CPU allocation/field work plus H200 proving.

Constraints, promises, invariants, and exploitable structure: The registry
authenticates the leaf topology and root circuit; `topology_key.zig` binds
the leaf configuration. The resident prover independently verifies the GPU
proof against the expected preprocessed root. The builder computes values
online in the same order as the Rust circuit. Padding gates have constant
outputs and no dependency on proof data. A cache miss must still build full
gate arrays to create and authenticate the preprocessed circuit.

Candidate matches, relationship, and evidence status:

| Candidate | Relationship | Fit, guarantee, and risk |
| --- | --- | --- |
| Static dataflow-graph evaluation | Exact for cached topology if variable assignments and ordered operations are preserved | Selected first. Omit duplicate gate records, retain row counts, prove against authenticated cached columns. |
| Compiled instruction tape / GPU witness interpreter | Exact if it reproduces all builder operations and field semantics | Next architectural step if CPU arithmetic remains dominant; needs tape encoding, device execution, and full parity. |
| CUDA Graphs for circuit prover launches | Analogy to a separate host-submission bottleneck | Lower priority: it cannot remove CPU witness construction. NVIDIA documents setup/launch reuse, but the measured witness work is outside those launches ([CUDA Programming Guide](https://docs.nvidia.com/cuda/cuda-programming-guide/04-special-topics/cuda-graphs.html)). |
| Parallel independent leaf processes | Resource-constrained DAG scheduling | Rejected for single-H200 latency now: two memory-safe processes took 15.106 s for leaves versus about 11.4 s sequential in one shared runtime. |

Chosen canonical problem and exact variant: Evaluate the same fixed acyclic
arithmetic circuit repeatedly with different input assignments while an
authenticated immutable representation of its constraints is retained. This
is static computation-graph reuse, with a proof verifier as the final
correctness oracle, rather than construction of a new graph per request.

Project -> canonical mapping and solution recovery: The cached leaf or root
preprocessed columns are the graph topology; guessed Cairo/circuit proof
values are inputs; the ordered builder operations produce the witness vector.
The existing CUDA prover consumes that vector. On a cache hit, suppress gate
array writes while tracking exact logical row counts; bulk-fill independent
trivial padding values. Check final variable count against the authenticated
topology. The independent verifier checks that the GPU proof uses its expected
preprocessed commitment and satisfies the AIR.

Complexity/limits and selected transfer: Full construction is O(V + G) time
and O(V + G) host storage for values and gates. Witness-only replay remains
O(V) time but drops most O(G) host storage and gate-array writes. Bulk padding
changes the constant-value suffix from per-gate allocation to one resize and
fill. This alone cannot remove 6.987 s of Cairo work and therefore cannot
deliver the end-to-end 3.23 s target. The following experiment determines
whether an instruction tape and device-side witness evaluation are justified.

End-to-end prediction, crossover, and falsifier: Predict lower host RSS and
less wrap/fold build time with identical proof bytes on the second leaf and
root. A proof mismatch, variable-count mismatch, failed independent
verification, or slower warmed pipeline falsifies the transfer. Measure same
H200/source/input canonical before and after, including process time, per-
phase time, host RSS, whole-device peak, and leaf/root digests. Do not count
one-time graph construction as a warm speedup unless the service amortizes it.

Correctness and benchmark plan: Differential-test full and gate-free builders
on arithmetic, Blake, permutation, constant finalization, and padding cases.
Run the focused recursion product and local parity checks. On H200 run the
full two-PIE CUDA pipeline with exact leaf/root digests against the pinned
Rust-qualified receipt, then repeat enough warmed trials to see whether the
change is larger than run noise.

Open uncertainty: The remaining Cairo fixed-image ingress and genuine device
execution need a separate Nsight Systems timeline; the gate-free replay result
will not predict them. A GPU instruction tape is a larger implementation and
must be selected using the measured post-replay host/device split.

Measured transfer, same H200 and inputs: The canonical root and both leaves
matched the pinned qualified proof digests. The warmed canonical end-to-end
run was 15.372 s, versus 15.195–15.323 s before this change: no material
pipeline gain. The two leaf wraps fell to 3.339 s from 3.983–4.220 s, but
Cairo rose to 7.744 s from 7.321–7.349 s in that trial. The experimental
compact root completed in 13.203–13.548 s, compared with 13.363 s before;
the sampled trial used 51.11 GiB whole-device peak. The detailed receipt is
in `vectors/reports/recursive-product-20260918/cuda-witness-replay-h200-20261001`.
The evidence supports witness replay as a useful local simplification, but
falsifies it as the main route to the 3.231 s full-pipeline target.

Updated bottleneck: The sampled compact trial spent 6.978 s on Cairo, 3.079 s
on two wraps, 1.187 s on the root, and 1.052 s process overhead. The Cairo
proof-execute/decode calls were 0.439 and 0.336 s; the first fixed-image load
alone took 2.769 s. Source profiling found 0.907 and 0.481 s in adapted-input
read/parse and 0.222 and 0.189 s in request compilation. The second cached
leaf still materializes 44.5 million values on the CPU. Next problem match:
long-lived authenticated GPU image and request-plan reuse, then a compiled
verifier witness program or device-side interpreter; profile the host/device
critical path before choosing lane overlap. A two-process parallel attempt
was previously slower, so concurrent launch by itself is not the answer.
