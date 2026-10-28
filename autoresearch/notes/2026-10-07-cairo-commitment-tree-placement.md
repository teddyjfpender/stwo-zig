# Cairo commitment-tree residency: problem-match brief

Required semantics: Keep every Cairo trace and FRI Merkle root, opening path,
proof byte, and verifier result identical while reducing peak physical HBM.
The source input and transcript order are unchanged.

Measured scale: The dense PIE `15590913_15590913` peaks at 56.487 GiB under
the current managed-capacity policy, and `15582797_15582797` at 48.362 GiB.
Streaming relation instances produced exact verified proofs but exactly the
same peaks on both. The dense plan retains 4 GiB of preprocessed tree hashes,
1 GiB each of main, interaction, and composition hashes, and nearly 2 GiB of
FRI hashes until decommitment. The full tree storage lives through phases in
which only the roots are needed. The source inventory is
`vectors/reports/cairo-cuda-h100-managed-20261007/geometry-dense.txt`.

Canonical problem match: This is authenticated-tree path storage with a long
write-to-read gap. Construction writes all hashes and produces a root; later
decommitment reads only sampled paths. CUDA managed-memory preferred placement
and ordered prefetch can migrate finished tree pages to host immediately after
their root is committed. The ordered proof stream preserves the root-before-
challenge boundary. Before decommitment, the tree pages are read-only and the
driver may service sparse accesses remotely or migrate the touched pages.

Prediction: Removing 7 GiB of trace hashes and up to 2 GiB of FRI hashes from
the late-stage HBM resident set could bring the dense peak below about 49 GiB,
subject to page faults and other live allocations. This is a prediction, not a
48 GB guarantee. A 48 GB card provides about 44.7 GiB usable before runtime
reserve, so a further bounded evaluation/replay design may still be needed.

Implementation: In the opt-in managed-capacity path, host-place each tree's
hash slot after its commitment root is captured. Keep the original slot and
root identity, and do not host-read or rewrite any hash. Do not apply to the
default high-throughput path. Test both dense PIEs with exact proof SHA-256,
independent Rust verification, sampled whole-device peak, stage times, and
host RSS. If the peak does not fall materially or decommit time becomes
unreasonable, reject this placement policy and move to bounded evaluation
storage and sparse path recomputation.

References: Current Merkle slot lifetimes are in
`src/integrations/cairo_cuda/executor/resident_plan.zig`; phase ordering is in
`src/integrations/cairo_cuda/executor/proof_session.zig`. NVIDIA documents
managed-memory preferred placement as a policy hint, not a hard residency
bound: <https://docs.nvidia.com/cuda/cuda-programming-guide/04-special-topics/unified-memory.html>.

## Result

Rejected for peak-memory reduction. The opt-in post-root host placement
produced byte-identical, independently verified proofs on both dense PIEs.
Peaks stayed **56.487 GiB** and **48.362 GiB**, while dense publication time
rose from 29.135 to 33.241 seconds on this pod. Raw receipts are in
`vectors/reports/cairo-cuda-h100-managed-20261007/tree-host-placement/`.
The production calls were removed. The phase-aligned run shows the main rise
occurs within interaction commitment, before tree retirement can help.
