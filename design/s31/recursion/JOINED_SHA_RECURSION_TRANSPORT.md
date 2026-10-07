# Joined SHA fold proof transport and the remaining verifier work

`S31FCF01` is a native-verified proof of one Bitcoin fold circuit joined to
the SHA256d AIR. It has 21 AIR components: 11 circuit components, then the
SHA caller, caller bus, fused round trace, fused word bus, and three pairs of
feed trace and feed word bus. Its 17 interaction claims include 11 circuit
claims, one Gate claim, and five SHA word-bus claims.

The native verifier authenticates this joined proof and its fixed root. The
wire shape records every SHA opening, all 17 claims across 21 components,
and both previous-row caller-bus sums. An accepted proof now converts to the
same wire bytes from either prover memory or a fresh proof file after native
verification. The current recursive circuit still does **not** verify an
`S31FCF01` child. A second block cannot currently use this proof as its
recursively verified predecessor.

## The format mismatch

The generic recursion wire format was built around circuit AIRs in which
every component has at least four interaction columns, every main trace
column is opened at one OODS point, and the composition tree has eight M31
columns (split depth one). The joined SHA proof differs in three ways:

| Property | Joined SHA proof | Original generic-circuit format |
| --- | ---: | ---: |
| AIR components | 21, including five trace-only components | All components assumed to have an interaction cumulative sum |
| Composition columns | 16, split depth two | 8, split depth one |
| Fused round state and schedule openings | Five shifted points per relevant column | One point per main trace column |

The shifted main-tree openings are represented by `core.circuit_proof_shape`,
`circuit_serialize`, `stark_verifier.proof`, and the proof conversion adapter.
The joined column inventory and the static ordered masks live in
`sha_fused_fold_shape.zig`; proof bytes do not choose them. In
`sha_fused_air.zig`, `state_offsets = [-3, -2, -1, 0, 1]` and
`word_offsets = [-16, -15, -7, -2, 0]`. Each of 64 state columns and 32
schedule columns supplies five OODS values. The wire stores them in column
order and mask order; `traceMaskRange(column)` locates each column's values.
Focused format tests check that the extra openings retain their mask order.
The joined proof test compares the full wire encoding made from prover
auxiliary data with the encoding made from a freshly decoded and natively
verified proof capture. A changed public output is rejected before the
transport is returned. The default outer test uses reduced FRI 0/12;
`S31_FUSED_FOLD_PRODUCTION=1` exercises the same path with FRI 26/70.

## Next implementation boundary

The next boundary is the in-circuit statement: it must connect the caller, fused round, feed, and bus
equations to the shifted OODS values and the two independent lookup challenge
pairs. It must then check Gate/word-bus closure, composition, Merkle openings,
quotient, FRI, and public outputs under the admitted key. The isolated
in-circuit transcript implementation already matches the native transcript
through the interaction root on an accepted production proof, including the
20-bit interaction nonce. That test checks transcript parity; it does not
establish recursive soundness. Full native-versus-circuit parity and negative
proof mutation tests are required before exposing a recursive `verify` entry
point for `S31FCF01`.
