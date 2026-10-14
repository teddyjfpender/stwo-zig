# Native FRI query capture and the PCS soundness gap

The production PCS verifier authenticates trace openings and recomputes the
DEEP quotient answers at the sorted unique FRI queries. It then authenticates
FRI folding groups and checks the terminal polynomial. Recursive witness
capture additionally expands those openings into **raw transcript-query
order**, where duplicate draws remain separate slots.

## Bound position invariant

`FriVerifier.sampleQueryPositionsWithRaw` now owns the exact raw draw as well
as its normalized query set. `decommitWithQueryCapture` has no independent
position argument: it expands each authenticated folding group at the raw
position owned by that same verifier. Returned raw and unique slices are
copies. Changing a returned slice cannot relabel a later capture. Ordinary
PCS verification already passed the sampled positions to its own Merkle and
FRI checks; this change closes the separate recursive capture API boundary.

The focused regression draws 32 queries from a 16-position domain, so at
least one duplicate is certain. It changes one returned raw position to the
other position in the same two-point folding group and checks that the
verifier-owned position stays fixed. This is an implementation invariant,
not a proof of FRI or PCS soundness.

```sh
zig build --build-file src/core/build.zig test-fri -j2 -Doptimize=ReleaseSafe --summary all
```

## Published theorem versus native protocols

The [S-two whitepaper theorem map](https://github.com/starkware-libs/stwo/blob/dev/.agents/papers/llm/Stwo_Whitepaper.llm.md)
states a degree-corrected batch evaluation relation with **both** an original
word `f` and its single-point quotient `(f-v)/v_Q` in the FRI ensemble. Its
small-domain condition is `1-theta > (1-delta)*(1+2/N_t)`. The theorem's
correlated agreement is on the lifted, cross-domain ensemble; separate
per-domain low-degree claims do not supply it.

The production path in `src/core/pcs/verifier.zig` supplies only the
`quotients.friAnswers` vector to `FriVerifier.decommit`. It does not commit an
original-plus-own-quotient paired ensemble. Experimental CAS07/XDM05 in draft
PR #269 introduces a paired sparse-height representation, but production
format admission does not select it. The capture fix neither changes the
accepted proof format nor makes that candidate theorem-admissible.

The next admissible reduction needs all of the following evidence:

1. A production-selected, statement/key-bound paired source format; exact
   source row, absent-height, and line-root Merkle authentication.
2. A native-to-paper polynomial map for every admitted domain height,
   including `H=1`, zero batches, circle-to-line fold normalization, and the
   original/own-quotient degree bounds.
3. A correlated-agreement reduction for the **same** sampled, authenticated
   original and quotient words. Its agreement threshold must satisfy the
   paper's small-domain condition, including the minimum table height.
4. Fiat-Shamir/BCS and random-oracle accounting for the exact native
   transcript, query distribution, hash domains, grinding, and all round
   errors. A declared hash-query budget `T` must make the conservative
   work-factor target `epsilon(T)/T <= 2^-96` checkable.

Until those are discharged, native proven security bits remain unset. The
raw query count or `FriConfig.securityBits()` product is not a certificate
for the published theorem.
