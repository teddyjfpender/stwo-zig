# Inactive MAC12 rows: bounded soundness audit

The1,105 `(1−active)*MAIN[c]` constraints are redundant for the complete pairing program's functional result under the obligations below. They are **not implied** by the remaining equations: removing them expands the allowed trace/commitment language. This must be a new explicit source/AIR authority, not a silent change to the qualified MAC12 profile. No current AIR, witness, protocol or admission file was changed for this audit.

The present row has1,203 constraints. `source.zig:76` fixes MAIN active to the independently source-derived FIX_ACTIVE. Lines77 then enforce zero padding. Retaining active equality, the sign equation,65 byte-carry equations and31 canonical equations gives98 constraints. Every removed equation is identically zero on active rows, so the active field-operation and canonical-output argument is unchanged.

A concrete separating trace has all FIXED zero, all MAIN zero except INPUT[0]=1. Every retained residual is zero. The old numeric `witness.valid` rejects it at `witness.zig:128–130`, and the original padding AIR rejects it. A second example sets accumulator-byte0=7, output-byte0=7 and distance-byte0=M31−7, with all other values zero. The retained canonical equations hold in M31, although the distance is not a BYTE and has no integer canonical interpretation. Both examples pass the isolated audit against the real unmodified emitter after selecting only the proposed98 residuals.

## Why no functional operation can escape

- The fixed mask is receiver/source authority. `bn254_pairing/fixture.zig:185–200` derives active status, all25 read IDs, writer ID and fanout from the immutable lowered plan. The kept active equality forbids a producer disabling an operation. Rebuilding FIXED from producer-selected masks would invalidate this argument and was never safe.
- In `fixture.zig:57–69`, every arithmetic read weight is `−active`; the writer weight is `active*fixedFanout`. On inactive rows they are exactly zero. No new writer, read, fanout or source assertion appears. The unique active-writer DAG and initial frontier still supply every active canonical operand.
- In `fixture.zig:76–78`, every arithmetic BYTE consumer numerator is active. Inactive output, quotient, carry and distance fields need no range authority because they are not inputs to an active operation. `recount` correctly visits active rows only (`fixture.zig:203–218`). Its unchanged histogram is not a missing provider obligation.
- MAC arithmetic and canonical equations read only the current MAIN row. `op_pairing_mac12/component.zig:80–82` gives MAIN/FIXED shift0 only; shifted INTER columns belong to the separately authenticated MLE/prefix binding. There is no MAC state-transition edge through a padding row.
- The active no-wrap theorem remains conditional on canonical BYTE/SSA writers. Inactive fields are no longer ranged, so an audit must explicitly stop claiming integer residual bounds there. Their remaining constraints are ordinary field equations with no functional interpretation. Removing the padding equations does not increase any polynomial degree; the active integer proof is unchanged.

## Denominators, poles and masking

Zero weights do not authorize skipping denominator binding. `fixture.ssaFraction` still constructs its tuple from the **actual** inactive MAIN bytes. The INPUT[0]=1 example changes the SSA denominator even though its numerator is zero. `native.Reader.read:143–176` reads actual committed columns for every physical row; it does not substitute `(0,1)` for padding rows. Synthetic lanes outside the declared fraction recipe are a separate fixed `(0,1)` case.

`op_pairing_mac12/projection.zig` must continue evaluating exactly that same expression, including all padding denominators, on the global-lifted-domain masks. Its equality/prefix columns authenticate the full N and D polynomials. Arbitrary inactive values can therefore change the terminal D and the honest prefix witness, but cannot change the active lookup sum. The current packed/scalar equality gate is relevant to this obligation.

Every individual LogUp output denominator is required nonzero in `gkr_local/closure.zig:18–24,38–43`. This explicitly rejects zero-weight0/0 poles. Omitting that check would be unsound: an inactive0/0 leaf could make an entire projective sum0/0 and hide active debt. For nonzero D, each inactive fraction is exactly0/D=0.

The pole and GKR soundness ledger must continue counting **all padded facts**, not only active weighted queries: the six-source model still has17,961,216 padded facts. Unrestricted padding can make their D values distinct. The source-owned active characteristic masses remain unchanged (11,576,181 BYTE queries and814,785 SSA units after literal folding); inactive numerators add zero mass. MAIN is committed before beta/SSA challenges, and the binding challenge follows the complete GKR transcript.

## Wrapper and protocol obligations

The old numeric `Mac12.witness.valid` explicitly requires an all-zero inactive row, and `Mac12.tests:105–130` pins that old contract. The current honest materializer emits zeros for padding. Those may remain an honest encoding policy, but a new validator or generic helper must not claim the stronger zero-row condition follows from its98-constraint AIR. No current whole-provider verifier calls the numeric validator on a decoded MAIN matrix; it authenticates FIXED and evaluates the generic component AIR.

A new profile must preserve the immutable active mask, all active constraints, exact actual N/D source expressions, six-source closure, unconditional pole checks and independent fresh FIXED authority. It must update constraint counts, composition/recursive keys and source identity explicitly. Columns, lookup facts and Merkle opening widths do not shrink, so the main expected gain is composition evaluation and recursive AIR work; no whole-proof multiplier is established here.

Suggested qualification is a new inactive-flexible helper/AIR with: active-vector parity; degree≤3; accepted nonzero inactive INPUT and unbounded inactive distance examples; actual-column GP closure and terminal binding; coherent wrong-active read, missing writer, inactive-mask substitution and pole negatives; new physical positive/negative proof; and a separately source-derived recursive statement. The old qualified profile should remain available unchanged.

## Reproducible isolated checks

```
zig test -O ReleaseSafe --dep stwo_core \
  -Mroot=src/frontends/riscv/rv64_bn254_mac12_padding_audit_test_root.zig \
  -O ReleaseSafe -Mstwo_core=src/core/mod.zig --test-filter research
```

Both checks pass. This is a research selector over the original emitter's residuals, not an accepting protocol or a changed AIR.
