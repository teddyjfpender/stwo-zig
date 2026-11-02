# Explicit OM31 RV64 evaluation plumbing

This additive helper layer permits degree-eight OODS and base-field SIMD
constraint evaluation through the original constraint authorities. It does not
select a production protocol or widen any existing four-coordinate component
layout. No whole-protocol 128-bit security claim follows from this plumbing.

## Typed APIs

- `evaluation.ConstFor(OM31)` is OM31; native publics/counts remain integer types.
  `ConstFor` of an external OM31 circuit lane remains that lane, so publics and
  challenges are wires. Legacy QM31 and packed-QM31 types are unchanged.
- `packed_fields.BaseForField(OM31)` is a distinct tagged packed-M31 type, not
  the legacy packed-M31 type whose constants imply QM31. Its operations forward
  to the original native M31 SIMD kernels.
- `packed_fields.SecureForField(OM31)` uses the existing packed-OM31 quadratic
  authority. Sixteen independent rows retain all eight coordinates.
- `SinkFor`, `WeightedAccumulatorFor`, `qFor`, `liftFor`, `splatFor`,
  `mulBaseFor` and `denominatorFor` recognize the explicit OM31 family. Packed
  base residuals accumulate by a packed-OM31 by packed-M31 multiply. They do not
  need an OM31 multiplication for each base-field local residual.
- `secureFromCoordinatesForField(C,F,[degree]F)` and
  `secureForField(C,F,coordinates,offset)` decode exactly the selected degree.
  Native/wire OODS coordinate values may themselves be extension-valued, so
  reconstruction is a sum of coordinates times the eight basis constants.
- `lane.NativeMasksForField(OM31)` owns no memory and borrows actual OM31 sampled
  values. `secureSampleForField` validates the sample count of every coordinate.
  Four-column legacy helpers deliberately reject degree-eight lanes at compile
  time; changing a challenge type cannot silently reuse old physical offsets.
- `geometry.localPointFor`, `previousPointFor` and `denominatorInverseFor`
  support explicit native OM31 and circuit OM31 points; native QM31 delegates
  to its previous implementation.

The concrete circuit OM31 lane declares its extension degree explicitly and
provides eight-coordinate `fromPartialEvals`, with the same native tower basis.
It still guesses two QM31 wires for each supplied OM31 witness value.

## Focused qualification

`test-riscv64-gkr-circuit` includes the new evaluation tests alongside the actual
GKR circuit fragment and legacy QM31 controls. The original thin CPU activity
and data equations, ALU local equations and LS local equations are evaluated on
dense, non-base-field native OM31 values and actual circuit wires, comparing all
eight coordinates. The production full CPU's REG, FUNCTION, ROM, OWNER and range
denominators and combined inverse-denominators reuse their original tuple and
challenge authorities and receive the same check.

Packed base-field residuals agree with native evaluation, distinct sixteen-row
packets agree with scalar OM31 multiplication and mixed base multiplication,
and coordinate roundtrips preserve the high half. Explicit eight-column mask
access tests reject truncated/misindexed storage. Weighted accumulation checks
scale and a skipped zero residual, including all high coordinates. Native count
types and wire count types are checked independently. Circle denominator
inverses agree between native OM31 and actual constrained norm inversion.
`test-riscv64-simd-fields` retains the original QM31 SIMD controls.

These tests qualify helper arithmetic and selected shared authorities, not a
complete wide frontend. Old component interaction layouts still use four
columns and must be adapted explicitly, with matching physical claims, metadata,
challenge profiles, receiver authority and recursive topology. No old proof is
reinterpreted as an eight-coordinate proof. Wide PCS/DEEP/FRI integration and the
whole-protocol security budget remain separate gates.
