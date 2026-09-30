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

Open uncertainty: Full arena demand and CUDA kernel timings for this new circuit path are unmeasured. Existing PIE CUDA timings do not establish recursion performance.
