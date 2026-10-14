# CAS11: H1 original and own-quotient checks from four Gate source roots

**Status:** experimental H1 integration, stacked on CAS10 source-custody PRs.
It has no production selector, native security bits, or accepted Gate AIR
proof. The full multi-height, multi-mask protocol remains open.

The typed version-11 verifier takes an external statement containing four
production-plain Merkle roots and FRI-extended column logs in fixed/main/
interaction/composition order; a verifier-owned OOD point and one OOD claim
per column; a post-OOD batch challenge; a first-fold challenge; and ordered
raw query positions. The source openings are in the versioned `S31G4P01`
subproof. CAS11 checks the external roots/logs against its bytes and verifies
both adjacent lifted rows under every root. It flattens source values in the
same four-tree order as the OOD claims.

For each opened circle row `r`, CAS11 builds two separate words:

```text
O(r) = sum_j lambda^j f_j(r)
Q(r) = sum_j lambda^j own_quotient(f_j(r), claim_j, OOD_point, r)
```

The quotient uses that column's own claim and the native conjugate two-point
line divisor. Each track is independently circle-to-line folded with the
same native twiddle and fold challenge, then compared with its own bounded
line terminal polynomial. No mixed `O + beta Q` value can satisfy one track
in place of the other. The verifier rejects columns at different heights in
this H1 slice. A later H17 protocol must insert batches at seven present
source heights, handle absent heights, and give every multi-mask claim its
own quotient track.

The focused honest proof has 11 columns: one fixed, one main, one interaction,
and all eight composition columns. Every column is `x + constant` or a
constant on a 32-row circle domain. The test evaluates its OOD claims,
constructs both native folds and bounded terminal polynomials, serializes
the four-root source subproof, and opens **all 16 adjacent pairs**. The
verifier authenticates every pair and checks both terminal tracks at every
line position. This demonstrates the implementation join for that concrete
small profile, not probabilistic soundness or the real Gate AIR.

The external statement/challenges/raw queries must eventually come from a
new role-framed, versioned Gate transcript that preserves fixed/main/
interaction/composition commitment epochs. This H1 module does not draw them,
and the version-11 typed proof has no complete outer byte codec. New FRI
line-tree hash framing, exact-uniform query sampling, PoW accounting, and the
paper's multi-domain correlated-agreement theorem join are separate work.
The 193-column source-log-4 bucket and the paper's common padded batch width
`M` remain a quantitative obstacle; no CAS11 result certifies the selected
`T=2^64`, `epsilon(T)/T <= 2^-96` target.

Focused check:

```sh
zig build --build-file src/prover/build.zig test-four-root-independent-h1 -j4 -Doptimize=Debug
zig build --build-file src/prover/build.zig test-four-root-independent-h1 -j4 -Doptimize=ReleaseSafe
```
