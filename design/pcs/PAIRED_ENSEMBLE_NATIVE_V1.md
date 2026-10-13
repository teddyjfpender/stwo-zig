# Native paired FRI input: implementation boundary

The published S-two degree-corrected batch-opening reduction checks a paired ensemble of original polynomial words `f_i` and their claimed OOD quotients `(f_i-v_i)/v_Q`. Its source map explicitly says that leaving out the original words changes the relation. The current native PCS prover computes one accumulated quotient word in `src/prover/pcs/scheme.zig`; `src/core/pcs/verifier.zig` reconstructs only that quotient with `friAnswers` and passes it to one `FriVerifier`. That native proof is **not** a degree-corrected paired-ensemble proof. See the [S-two whitepaper source map](https://github.com/starkware-libs/stwo/blob/dev/.agents/papers/llm/Stwo_Whitepaper.llm.md), batch-evaluation construction and soundness result.

## Executable slice in this change

`src/core/pcs/paired_ensemble.zig` defines a version-1 transcript tag and a uniform-domain shape. Once source commitments and OOD claims are already in the channel, it draws independent original-batch and quotient-batch challenges. For one domain with a common degree bound, its first FRI word at a row `P` is

```text
B(P) = f_0(P) + gamma*f_1(P) + ... + gamma^(m-1)*f_(m-1)(P) + eta*q(P).
```

The module accepts exactly `m` source columns of exactly the selected domain length. It precomputes `gamma` powers once for the full first layer. The row function uses the same order for verifier queries. A changed version or geometry changes the challenge transcript. All existing PCS calls retain their old transcript and proof format because they do not call the new module.

The native CPU integration test computes a nonzero quotient for `f(P)=x(P)` with the actual `pcs.quotients.friAnswers` law, combines the source and quotient, commits and decommits the resulting first layer using the production `FriProver`, reconstructs query answers independently from queried source values and `friAnswers`, and accepts them with the production `FriVerifier`. A changed first-layer answer is rejected. Separate tests check source-column multiplicity, shape refusal, and transcript geometry binding.

This is an **experimental FRI input**, not a production PCS opening. The FRI test provides one source column and quotient arrays directly; it does not authenticate source columns through a PCS proof or bind a new serialized PCS envelope. No native soundness bit claim follows from this test.

## Required production steps

1. Add a separately tagged PCS proof variant and canonical wire decoder. The verifier must choose the variant before transcript replay. A legacy proof cannot opt into paired verification, and a paired proof cannot be interpreted as legacy.
2. After commitment roots and OOD claims are mixed, draw the versioned paired challenges. All verifier entry points, including borrowed proof capture and recursion capture, must replay the same schedule.
3. For each committed source column, derive its value from the authenticated opening at every FRI query. Construct the quotient from those *same* opened values and sampled OOD claims. Combine both with the paired challenges before the first-layer FRI check. Reject omitted, repeated, out-of-order, or wrong-height source columns.
4. On the prover, build the paired first-layer word from original committed columns and the quotient provider. Preserve bounded-memory streaming and backend residency; do not materialize a second full unbounded column set. The first-layer root must bind the paired word before queries are drawn.
5. Replace the uniform-domain restriction with explicit multi-height degree correction. For every source and quotient term, record the domain, lift, degree bound, and insertion level. Enforce the published small-table condition and verify each fold/batching equation on the actual native circle-domain and Merkle query layout.
6. Establish a theorem-to-code refinement for source authentication, quotient arithmetic, challenge order, lifting, sampling, FRI, hash binding, and query count. Only then attach conservative native security parameters to the paired proof variant.

Until those steps pass, the release gate must continue to report native PCS/FRI proven security as unknown and reject a claim of proved release admissibility.
