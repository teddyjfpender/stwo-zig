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

This is **not** a production PCS opening. The test assembles its transcript in code, and there is no versioned serialized PCS proof envelope or production prover path. Legacy PCS transcripts and proof acceptance are untouched. No native soundness bit claim follows from these tests.

## Required production work

1. Add a separately tagged PCS proof and canonical wire decoder. Select the variant before transcript replay. Legacy proofs must never opt into paired verification, and paired proofs must never parse as legacy.
2. Bind source commitments, exact OOD points and claims, source/quotient pair order, all domain heights and degree bounds, and one shared batch challenge in a single documented transcript schedule. Reject inconsistent or repeated source entries before FRI.
3. On the prover, produce **each** quotient word from the corresponding committed source polynomial and claimed OOD value. Stream the paired first layer into FRI without materializing an unbounded second column set. Verify prover outputs against the scalar reference and query reconstruction.
4. Authenticate all source columns at the exact FRI query positions before quotient arithmetic, as this experimental bridge does for one uniform domain. Preserve raw query multiplicities, lifted query maps, and borrowed-proof capture semantics.
5. Implement Protocol 3's cross-domain batches and Eq. 68 folding **with insertion**. A repeated smaller-height source column on the largest domain is not a substitute for that reduction. Validate each per-height pair's target polynomial space and the small-table condition of Eq. 80; reject profiles outside the admitted theorem envelope.
6. Refine the published interactive theorem to the native two-point quotient, actual query sampler, Merkle layout, Fiat–Shamir channel, field, and proof decoder. Only then calculate conservative native security bits and change release admission.

Until these steps pass, native PCS/FRI proven security remains unknown and proved release admissibility must stay false.
