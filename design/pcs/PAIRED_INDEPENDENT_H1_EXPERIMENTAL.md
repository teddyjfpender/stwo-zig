# Independent original and own-quotient degree tracks at one height

**Status:** experimental one-height native prover/verifier slice. It has a
canonical `S31DIH08` outer wire and nested XDM05 source fragment, but no
production selector, release profile, or proven security bits. The accepted
Gate key has 17 source-height positions and seven present
heights, so this slice cannot prove that key. CAS07/XDM05 remains the
geometry-capable candidate, with its own unresolved security obligations.

For source columns `f_j` committed in one XDM05 root, the verifier derives the
OOD point `P`, binds claims `v_j`, then draws a shared batch challenge `lambda`
and first-fold challenge `alpha`. At each native circle row `r`, this slice
builds **two** words from the same authenticated source row:

```text
O(r) = sum_j lambda^j f_j(r)
Q(r) = sum_j lambda^j q_j(r)
q_j(r) = [c_j f_j(r) - a_j y(r) - b_j] / d(P,r)
```

`(a_j,b_j,c_j)` is the native conjugate-line interpolation of the claim
`v_j`; `d(P,r)` is the same native two-point divisor used by CAS07. The
prover materializes all rows of `O` and `Q` separately. With the *same*
`alpha`, it circle-folds each into a separate line vector. It interpolates
each line vector and refuses nonzero coefficients above the declared terminal
length. The transcript absorbs the two terminal coefficient vectors under
different role tags before drawing queries. The verifier authenticates the
source pair under the XDM05 root, recomputes both words from the same opened
row, and compares **both** first folds with their respective terminal
polynomials. The byte envelope fixes the profile, root, point, claims, nested
source wire, and both terminal vectors under version 8 and an exact length.
The original and quotient can therefore no longer cancel each other inside a
single FRI word.

The focused native test has `k=5`, blowup log `2`, two columns `x+7` and `11`,
and 16 sampled raw queries. It encodes one proof, checks both terminal tracks,
and matches the final prover/verifier transcript digests. A separate pure
full-domain test keeps the constant original `f=7` but changes its claimed OOD
value by one. The original's folded line remains within the four-coefficient
bound while the derived own quotient has a nonzero coefficient above that
bound. This is an arithmetic test, not a forged proof-acceptance fixture.

This experiment uses separate degree tracks for clarity. It does **not** yet
provide the paper's multi-domain insertion, source-height projection across
absent levels, intermediate Merkle line commitments, or an all-height
transcript/BCS analysis. It does not establish the
two-point circle-code quotient theorem, the required correlated agreement,
actual Gate AIR claim ownership, or any numerical soundness bound. A
production candidate must extend both tracks through every CAS07 height,
including empty heights, and then prove that its exact versioned wire and
query schedule meet the conservative paper work-factor target at `T=2^64`.

Focused check:

```sh
zig build --build-file src/prover/build.zig test-paired-independent-h1 -j4 -Doptimize=Debug
```
