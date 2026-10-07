# Joined SHA fold proof transport: what the current verifier can represent

`S31FCF01` is a native-verified proof of one Bitcoin fold circuit joined to
the SHA256d AIR. It has 21 AIR components: 11 circuit components, then the
SHA caller, caller bus, fused round trace, fused word bus, and three pairs of
feed trace and feed word bus. Its 17 interaction claims include 11 circuit
claims, one Gate claim, and five SHA word-bus claims.

The native verifier authenticates this joined proof and its fixed root. The
current recursive circuit does **not** verify an `S31FCF01` child. A second
block cannot currently use this proof as its recursively verified predecessor.

## The format mismatch

The generic recursion wire format was built around circuit AIRs in which
every component has at least four interaction columns, every main trace
column is opened at one OODS point, and the composition tree has eight M31
columns (split depth one). The joined SHA proof differs in three ways:

| Property | Joined SHA proof | Previous recursion format |
| --- | ---: | ---: |
| AIR components | 21, including five trace-only components | All components assumed to have an interaction cumulative sum |
| Composition columns | 16, split depth two | 8, split depth one |
| Fused round state and schedule openings | Five shifted points per relevant column | One point per main trace column |

The first two differences are now represented by `core.circuit_proof_shape`,
`circuit_serialize`, and `stark_verifier.proof`, with split depth one retained
as the default for existing proofs. The joined column inventory is recorded
in `sha_fused_fold_shape.zig` and tested against the actual prover output.

The third difference still prevents proof transport. In
`sha_fused_air.zig`, `state_offsets = [-3, -2, -1, 0, 1]` and
`word_offsets = [-16, -15, -7, -2, 0]`; 64 state columns and 32 schedule
columns are sampled at these five positions. The current
`verifier_proof.fromVerifiedCapture` uses `singleRow` for main trace samples,
which rejects a column with more than one OODS value. Its `wire.Proof` also
stores only one OODS value per main column. Treating the extra openings as
if they did not exist would omit SHA transition checks, so no conversion API
for this joined proof is exposed.

## Next implementation boundary

The wire proof needs a verifier-owned mask-point layout: for every committed
column, the ordered OODS offsets and the corresponding number of sampled
values. The capture adapter, serializer, in-circuit proof type, OODS response
collector, quotient replay, and joined component evaluators must all consume
that same layout. The in-circuit statement must then reproduce the native
profile transcript, both independent LogUp challenge pairs, Gate/word-bus
closure, every SHA equation, and the split-two composition reconstruction.
Only after full native-versus-circuit parity and mutation tests should a
recursive `verify` entry point for `S31FCF01` exist.
