# Circuit recursion CUDA: problem match before optimization

Task and required semantics: Produce the same circuit STARK proof and Fiat–Shamir transcript as the pinned Rust R7 flow, then aggregate PIE proofs through wrap, fold, and root. No proof-stage host reads or CPU fallback; the only download is the terminal proof envelope.

Inputs, scale, and model: The recorded circuit registry has 11 AIR components, four mixed-height trace trees, four-fold FRI, and 70 queries at the canonical configuration. The local `geometry.zig`, `resident_composition.zig`, and `resident_decommit.zig` derive exact tree, source, and opening counts. CUDA time includes launch and transfer costs; GPU memory is a hard feasibility constraint.

Constraints and structure: The transcript order, canonical sample order, plain Blake2s Merkle profile, two distinct PoW challenges, and all four committed trees are fixed. Fixed circuit topology and preprocessed columns can be prepared before proof execution. Witness values, interaction challenges, and openings are proof dependent.

Candidate matches and evidence status:

| Candidate | Relationship | Fit and risk |
| --- | --- | --- |
| Lifetime-aware offline arena packing | Exact allocation subproblem; implemented in `runtime/arena.zig` | Derived from stage lifetimes; aliases only nonoverlapping ranges. Check peak and retained proof bytes. |
| Streaming or recomputation of commitments | Time/space tradeoff, not equivalent without preserving coefficients and authentication paths | Hypothesis for later profiling; adds kernels and risks changing transcript material. |
| Host-assisted proof generation | Different computational model | Rejected: violates resident proof requirement and obscures GPU performance. |

Chosen canonical problem and mapping: Assign each resident buffer a size, alignment, and inclusive stage lifetime. Reuse offsets only for nonoverlapping lifetimes, while the terminal envelope remains live from ingress through publication. This is interval-constrained storage allocation; the existing deterministic arena planner is the implementation boundary. No new allocation algorithm is needed before measured size is known.

Complexity and limits: Planner cost is secondary to proof execution; GPU peak equals the maximum assigned arena extent, plus CUDA runtime reservations. The proof must fit H100/H200 capacity with a safety reserve. The exact crossover of recomputation versus retention is unknown until profiling.

Selected transfer and falsifier: Bind the circuit plans to one proof-owned arena, prime all immutable tables at ingress, execute the entire stage schedule, then decode and independently verify the one downloaded proof. The hypothesis is that this removes intermediate transfers and exposes the real CUDA bottlenecks. A nonzero mid-proof read, CPU fallback, invalid verifier result, or memory above the target GPU falsifies qualification.

Correctness and benchmark plan: Compare stage roots, sampled values, nonces, FRI coefficients, and decoded proof against CPU/Rust vectors; verify a genuine multi-PIE wrap→fold→root proof. Record ingress, each GPU stage, publication, total latency, peak device memory, and proof bytes for all representative PIEs before optimizing kernels. Only optimize measured dominant stages, and repeat byte/parity checks after each change.

Measured qualification (H100 SXM, `sm_90`, ReleaseFast, 1 October 2026 UTC): four R7 circuit proofs passed native verification and matched the pinned Rust `CircuitSerialize` digests. Fibonacci internal/root took 0.766/0.610 s; Blake G internal/root took 0.556/0.560 s. The resident arena was 1.465–1.466 GB. The fixed one-read terminal transport was 3.295 MB, and the device stage times summed to approximately 50–60 ms. These are single runs of standalone circuit proofs, not PIE-to-root pipeline measurements.

Updated problem match: a sub-60 ms device schedule inside a 0.59–0.74 s prove call is primarily a host orchestration and setup problem at this R7 scale. Candidate causes are repeated static preprocessed-tree commitment work, twiddle preparation, per-proof AOT module/context binding, buffer allocation, kernel launch submission, and zero-filling unused terminal capacity. The benchmark must separate these with host wall timers and repeated proofs in one process before ranking them. Cache only topology-static material; keep witness-dependent work and all proof stages resident. CUDA graphs may help the repeated launch sequence, but transcript-dependent kernel arguments and per-proof buffer addresses must remain correct. The packed four-row FRI leaf format was a correctness requirement learned from the CPU/Rust implementation and also cut FRI Merkle tree storage by four.

Next falsifiers: compare first and warmed proof latency in one process; profile host call stacks and CUDA API time, then test cached static commitments/twiddles and reusable device allocations. Run the same four R7 cases after every change. A speedup that changes any Rust digest, adds a proof-stage host read or CPU PCS call, or increases peak memory beyond the target GPU is rejected. The larger wrap/fold circuits and the complete PIE-to-root path remain unmeasured.
