# MAIN-only OM31 components for the local-GKR route

These additive components enforce the original direct arithmetic polynomials
without allocating or inventing legacy lookup inverse/prefix columns. They are
not independently sufficient execution proofs: authenticated local GKR lookup
bindings and global classic RAM/KIO/Wire closure remain mandatory.

| Role | Fixed | MAIN | Direct residuals | Maximum degree | Previous MAIN |
|---|---:|---:|---:|---:|---|
| CPU | 3 | 47 | 41 | 3 | active; next_pc[4] |
| ALU | 0 | 47 | 49 | 3 | none |
| BINARY | 0 | 29 | 30 | 2 | none |
| SHIFT | 0 | 52 | 27 | 3 | none |
| LS | 3 | 70 | 247 | 3 | active |
| JALR | 0 | 17 | 1 | 2 | none |
| MUL | 3 | 87 | 141 | 3 | count |
| DIV | 3 | 78 | 164 | 3 | count |

`main_only/authority.zig` selects existing arithmetic authorities and validates
physical slice widths. The CPU's original 52 residuals contain 41 direct
polynomials followed by 9 local inverse checks and 2 local prefix checks. A
new `emitMainFor` extracts precisely the direct prefix; the original emitter
calls it and then emits the same 11 lookup residuals in the original order.
JALR similarly exposes its single existing ACTIVE Boolean polynomial. Its ADD
and AND semantics are delegated obligations, not dropped equations.

ALU, BINARY and SHIFT reuse projected physical rows, including the existing
inactive-times-multiplicity residual. LS expands the same affine physical
projection, reuses every original local LS/RAM arithmetic residual, and retains
the final address-limb identity. Only the previous active coordinate is read
by this local authority. MUL calls the original `arithmeticFor`; DIV calls its
existing integer-normalization/output-policy emitter. No ISA semantics or
range soundness argument is independently reimplemented here.

`main_only/component.zig` provides concrete native OM31 verifier vtables,
precise current/previous masks, typed public geometry validation and scaled
core OM31 accumulation. The interaction width is zero because these components
own no lookup argument. This is zero physical columns, not a fabricated zero
interaction witness. The actual wide prover adapter is intentionally not
exposed until its real trace/domain interfaces are integrated.

Focused tests execute all eight role authorities on dense eight-coordinate
OM31 values. Counts match the table. Finite differences exercise a nonzero
coefficient at each stated maximum degree and a zero next difference. Actual
verifier vtables match independently scaled direct accumulation; tree2 is
empty, predecessor masks are exact, truncated predecessor samples are rejected,
and allocation failures in all metadata operations clean up atomically.
Existing actual GKR native/circuit controls run in the same gate.

The route assembler must compose these constraints with all local GKR and
global classic obligations before acceptance. Declaring a second independent
component over the same MAIN block can duplicate columns under the current
concatenated PCS geometry. Combining the MAIN authority and wide global
constraints inside one role component preserves a single MAIN commitment.
Service bridges/truths, boundary/ROM/range providers, authenticated GKR
terminal expressions, the complete wide proof driver and the whole-protocol
128-bit budget remain separate integration gates.

## Actual wide prover qualification

The follow-up `main_only/domain.zig` now supplies the real OM31 prover adapter.
It borrows the existing bounded2n column/coset evaluator and the exact predecessor
column declaration above. Direct equations run over the explicitly tagged
packed-M31 lane, and the existing native packed-OM31 kernels accumulate random
weights into exactly eight output columns. Domain and OODS paths call the same
MAIN authority. No scalar QM31 composition path or legacy interaction witness
is substituted.

A real 32-row ALU trace, with different operands, carries, signs and inverses
across rows, is committed and proved through the actual OM31 PCS and FRI engine.
A newly constructed core OM31 receiver accepts it. MAIN and composition samples
both have nonzero high extension halves, ruling out the constant-zero special
case. Mutating a high-half opening or an arithmetic result is rejected. This
qualifies actual arithmetic-fragment proving; local range/FUNCTION GKR closure
is still required before these facts can count toward an execution proof. Test
parameters are a small fixture configuration, not a 128-bit production profile.
