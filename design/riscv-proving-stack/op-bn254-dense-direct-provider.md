# Direct dense BN254 polynomial provider (closed source prototype)

This module generates all twelve output-coordinate polynomials of an arbitrary,
noncyclotomic Fq12 square or multiply in i²=−1,v³=9+i,w²=v. Square combines
symmetric products, including ±18 coefficients. Multiplication reads24 Fq;
square reads12. No production operation, tag, ABI or whitelist is introduced.

`bn254_dense/spec.zig` owns the exact coefficients and derives one common
integer envelope through the existing `curves.spec.deriveRelation`. Positive and
negative product coefficient masses are independently bounded across all twelve
rows. The envelope applies to full raw u256 operands; field inputs need not be
assumed below p. It gives one source-owned K*p,34 quotient bytes,65 one-byte
carry groups and64 21-bit carries with offset883205. Strict integer residual
bounds are429,152,039 and429,141,826, both below M31. These bounds are not a
modular-wrap heuristic and cannot be producer-selected.

`row.zig` constructs quotients, byte-encoded carries, canonical results and
strict distance/borrow witnesses. Its exact residual validator rejects altered
output, quotient, carry, borrow and activity; zero padding has no effect. It
currently checks every input byte explicitly. Production input-range inheritance
is **pending** full authenticated frontier/local-SSA closure. The standalone test
compares against an independent nested Fp2/Fp6/Fp12 implementation, including all
144 basis pairs, zeros,p−1,raw u256 maximum and mixed values. No whole-block run
or physical STARK is part of this source slice.

## Proposed single ROM class, not twelve wrapped proofs

Use one periodic12-coordinate ROM, fixed by the expected key. The call ID,
coordinate ID and all input/output local-value IDs are source-derived. Every
arithmetic row consumes all12/24 inputs and writes one canonical result. The
frontier supplies those input values with exact fanout12 and consumes every
final output once; no free cycles or chosen multiplicities are permitted.
The existing Wire35 packet relation must bind every input/output coordinate.
A square needs12 frontier rows; multiply24 (with12 readonly tail coordinates).

The coefficient expression is ROM-selector times a quadratic input product;
this is degree3. Avoid another activity multiplier: homogeneous zero padding,
source-owned active-prefix/count constraints and K*p*active preserve degree3.
All carry/range parameters are uniform from the shared envelope. Byte queries
remain linear (including the top carry-byte shift times active). A BYTE provider
must have a physically committed multiplicity column, negative numerator and
source-owned0..255 table; no metadata-only multiplicities. Local SSA/GKR binding,
source masks, characteristic mass and fixed transcript/recursive framing still
need implementation and physical adversarial qualification.

## Cost before adoption

| Class | Main/row | Planned bindings/row | Arithmetic rows/call | Planned active cells incl frontier |
| --- | ---: | ---: | ---: | ---: |
| Square |691|32|12|9,360|
| Multiply |1075|32|12|14,652|

These are proposed local-GKR costs, not an implemented prover. They assume
frontier33 MAIN+24 INTER, and two arithmetic instances (BYTE512 padded lanes,
SSA16/32) adding32 binding columns. Each arithmetic row has354 byte queries;
input ranges are inherited only after qualification of the stated frontier.
Square+multiply would be24,012 cells, versus53,220 classic Fp2 cells or88,632
three-sparse reuse cells. Padded GKR facts are6,348/6,552 per call, versus16,188
for three sparse calls. Opening width rises:780/1164 total columns per new class
versus483 for the existing sparse class; fewer leaves must compensate for that.

A conditional1023-call shard model gives6 square leaves and2 multiply leaves,
with107,102,208 committed cells for5439squares+1764multiplies. This cap is a
comparison assumption, **not a qualified resource policy**; actual GKR buffers,
fixed trees, retention and recursion can change the preferred class. Both
families may share one composite PCS/leaf with independently sized components;
component count must not imply a proof per coordinate. Packet RAM events are48
for square/96 for multiply, versus240 per three-sparse product; Wire messages
are24/36 versus96. These packet identities require complete new joins before
any runtime admission.

Next gates: source-ROM degree testing; bounded BYTE/multiplicity and SSA physical
closure; complete public frontier and forged input/output/call/ROM controls;
fresh proof receiver and recursive source factory. No selected guest change is
justified until total native+recursive cost is measured.
