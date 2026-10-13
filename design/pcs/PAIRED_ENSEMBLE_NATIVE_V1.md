# Native paired FRI input: implementation boundary

The current native PCS prover computes one accumulated DEEP quotient word in `src/prover/pcs/scheme.zig`; its verifier reconstructs that one quotient with `friAnswers` and passes it to FRI. This is not the degree-corrected batch-opening protocol in the [S-two whitepaper, Protocols 3–4 and Theorem 5](https://www.researchgate.net/publication/407022099_S-two_Whitepaper). Protocol 4 extends **every** original word `f_(i,j)` with its own quotient `(f_(i,j)-v_(i,j))/v_Q`. Protocol 3 Eq. 66 batches all words at each height with powers of **one shared challenge** `lambda`, and Eq. 68 inserts each height's batch into its FRI fold. The authors state the two-point conjugate quotient used by the implementation should inherit the analysis, but omit its details. Their Section 4.5 also leaves the list-decoding proof for their actual circle-domain query schedule open.

## Executable slice

`src/core/pcs/paired_ensemble.zig` defines a separately tagged experimental transcript and a uniform-domain shape. Once source commitment roots and OOD claims are in the channel, it draws one batch challenge. Its first FRI word at row `P`, in explicit pair order, is

```text
B(P) = f_0(P) + lambda*q_0(P)
     + lambda²*f_1(P) + lambda³*q_1(P) + ... .
```

Every pair has its own source and quotient column. The module rejects missing or extra columns and wrong domain lengths, and precomputes challenge powers once for a complete first layer. `src/core/pcs/paired_authenticated.zig` provides a verifier-side bridge: it checks the existing compressed Merkle multiproof for **all** source query columns against the committed root, then computes each native two-point quotient from precisely those authenticated values and their claimed OOD values before folding the pairs. It refuses wrong height, wrong column count, or reordered source openings.

The native CPU tests use the actual quotient arithmetic for `f(P)=x(P)`, a nonzero quotient, the production `FriProver` and `FriVerifier`, and a source Merkle commitment/decommitment. The verifier reconstructs and authenticates the source queries, derives its own quotients, combines the pair, and accepts the FRI proof. Changed source values are rejected by Merkle verification before an answer is returned; changed paired answers are rejected by FRI. A separate two-column test confirms source order, pairing, and uniform-height refusal.

`src/core/fri/multidomain_insertion.zig` adds a separate scalar kernel for one Eq. 68 height transition. Given a previous line word on `S_(i-1)` and a new circle batch on `D_i`, it checks that the previous line domain doubles exactly to the new batch's half-coset. It returns the native folds in this order:

```text
G_i = FoldLine(G_(i-1), alpha_i)
    + alpha_i² * FoldCircle(H_i, alpha_i).
```

The existing native inverse butterflies omit the factors of `1/2` displayed in the paper's Eq. 70; theorem refinement must explicitly account for that normalization. The production `foldCircleIntoLine` helper uses the reverse weighting, `alpha² * previous + FoldCircle(inserted)`, so the experimental insertion kernel does not reuse its destination-combination behavior. A CPU test starts at a 16-row circle domain, inserts independent batches at 8 and 4 rows, checks each output row against the native scalar formula using its actual `x` and `y` coordinates, and rejects mismatched height and coset geometry. A second test supplies `x`, `x`, and a constant at those heights and checks that the last layer is the expected constant in the native normalization. This kernel is not yet connected to FRI commitments, openings, or a multi-domain verifier.

## Experimental multi-height source-opening envelope

`src/core/pcs/paired_envelope.zig` defines a separate binary source-opening envelope with the eight-byte magic `S31PMH01`, a little-endian version and total length, largest-domain size, query count, then one record per strictly descending adjacent height. Each height record includes its domain/degree/count shape, a Blake2s source root, each column's OOD point and claim, source values in projected largest-query order, and a compressed Merkle witness. The decoder checks the magic **before** reading any protocol values; it rejects legacy `STWOPRW1`, unknown versions, reserved flags, trailing/truncated bytes, noncanonical M31, invalid shapes, and bounded-size violations. The verifier's `decodeAndBind` entry point also requires a locally chosen exact geometry/query profile and leaves its channel unchanged on a decoding or profile failure. This is an experimental *source-opening fragment*, not a complete PCS proof wire format.

`src/core/pcs/paired_projection.zig` applies the existing bit-reversed circle projection to the largest-domain positions, preserving the conjugate-pair bit and duplicate positions. It verifies the matching source Merkle multiproof before returning each height's paired answers in largest-query order. A native fixture commits `f=x` at 16 and 8 rows, decommits at all largest-domain positions, serializes and decodes the envelope, replays a single domain-separated batch challenge from both roots and OOD claims, authenticates both heights, and inserts their batches into the line fold. It checks that geometric point doubling agrees with projected positions and that changing one duplicated source value is rejected before insertion.

The fixture deliberately opens its entire small domain and does not use a Fiat–Shamir sampled FRI query schedule. The envelope has no multi-height FRI layer commitments or decommitments, and the experimental transcript schedule only binds source roots, geometry, OOD points/claims, and query count before drawing the batch challenge. Neither the fixture nor its wire decoder admits a proof in the production PCS verifier. A production variant needs to derive OOD points and folding challenges in the specified schedule, commit each folded layer, draw queries only after all required commitments, authenticate the relevant FRI layer openings at each projected height, and check the last-layer degree.

This is **not** a production PCS opening. The source-opening envelope and test assembly lack a complete FRI proof and production prover path. Legacy PCS transcripts and proof acceptance are untouched. No native soundness bit claim follows from these tests.

## Required production work

1. Extend the experimental source-opening envelope into a complete separately tagged PCS/FRI proof with a canonical wire decoder. Keep variant selection before transcript replay. Legacy proofs must never opt into paired verification, and paired proofs must never parse as legacy.
2. Bind source commitments, sampled OOD points and claims, source/quotient pair order, all domain heights and degree bounds, and one shared batch challenge in the theorem-matched transcript schedule. Reject inconsistent or repeated source entries before FRI.
3. On the prover, produce **each** quotient word from the corresponding committed source polynomial and claimed OOD value. Stream the paired first layer into FRI without materializing an unbounded second column set. Verify prover outputs against the scalar reference and query reconstruction.
4. Authenticate all source columns at the exact FRI query positions before quotient arithmetic. The experimental bridge now handles per-height projected positions with duplicates; complete the matching source and FRI query schedule, lifted query maps, and borrowed-proof capture semantics.
5. Wire Protocol 3's per-height batches to the experimental Eq. 68 insertion kernel in both FRI commit and verifier decommit, with a complete versioned proof shape and authenticated FRI query projections across all heights. A repeated smaller-height source column on the largest domain is not a substitute for that reduction. Validate each per-height pair's target polynomial space and the small-table condition of Eq. 80; reject profiles outside the admitted theorem envelope.
6. Refine the published interactive theorem to the native two-point quotient, actual query sampler, Merkle layout, Fiat–Shamir channel, field, and proof decoder. Only then calculate conservative native security bits and change release admission.

Until these steps pass, native PCS/FRI proven security remains unknown and proved release admissibility must stay false.
