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

| Class | Main/row | Planned inter/row | Arithmetic rows/call | Planned active cells incl frontier |
| --- | ---: | ---: | ---: | ---: |
| Square |691|40|12|9,456|
| Multiply |1075|40|12|14,748|

These are proposed local-GKR costs, not an implemented prover. They assume
frontier33 MAIN+24 INTER, and two arithmetic instances (BYTE512 padded lanes,
SSA16/32) adding32 binding columns plus8 global Wire columns. Each arithmetic row has354 byte queries;
input ranges are inherited only after qualification of the stated frontier.
Square+multiply would be24,204 cells, versus53,220 classic Fp2 cells or88,632
three-sparse reuse cells. Padded GKR facts are6,348/6,552 per call, versus16,188
for three sparse calls. Opening width rises:788/1172 total columns per new class
versus483 for the existing sparse class; fewer leaves must compensate for that.

A conditional1023-call shard model gives6 square leaves and2 multiply leaves,
with108,052,480 committed cells for5439squares+1764multiplies. This cap is a
comparison assumption, **not a qualified resource policy**; actual GKR buffers,
fixed trees, retention and recursion can change the preferred class. Both
families may share one composite PCS/leaf with independently sized components;
component count must not imply a proof per coordinate. Packet RAM events are48
for square/96 for multiply, versus240 per three-sparse product; Wire messages
are24/36 versus96. These packet identities require complete new joins before
any runtime admission.

The planned cost ledger is corrected in `guest/dense-direct-source-v2.json`: the
initial v1 model omitted8 global Wire columns per arithmetic row.

Next gates: source-ROM degree testing; bounded BYTE/multiplicity and SSA physical
closure; complete public frontier and forged input/output/call/ROM controls;
fresh proof receiver and recursive source factory. No selected guest change is
justified until total native+recursive cost is measured.

## Closed physical arithmetic gate

`test-riscv64-op-dense-proof` now produces a real237,192-byte OM31 proof for one
multiply call/log8 and a fresh independently rebuilt FIXED key. The one-call
source ROM fixes the active prefix and all twelve output coordinates. Inputs are
receiver-pinned public parameters mixed into the transcript and constrained byte
by byte; expected outputs come from the independent nested-tower reference.
This deliberately avoids claiming the future SSA/global-memory frontier exists.

The complete classic BYTE argument uses committed MAIN multiplicities; all
inactive arithmetic private cells are zero, while provider multiplicities may
occupy inactive rows of the immutable256-byte table. MAIN1075/INTER1432 is a
correctness reference, not the planned32-column GKR projection. All constraints
have degree≤3, including ROM and interaction clearing; packed and scalar domain
emitters agree. Fresh reception rejects altered opened output/quotient/carry/
provider values and wrong public input/output. A coherent provider multiplicity
change also fails BYTE closure. The allocator has a2GiB hard cap.

This uses **q12/P0 correctness-only** settings. It establishes neither a128-bit
security profile nor an execution/RAM/service join. The square class, local GKR,
recursive source factory, mass/resource ledger and full production frontiers are
still pending. Exact source/proof hashes are in `guest/dense-direct-physical-v1.json`.

The follow-up physical gate covers **both** classes: multiply237,192B (exact
prior proof bytes) and noncyclotomic square203,304B. Both fresh receivers also
reject a mutated source-ROM FIXED root. A stronger canonicality control replaces
the result by result+p and coherently adjusts quotient/carries: all integer
carried identities and byte ranges still pass, but the strict canonical writer
rejects all24 cases. This rules out relying on algebraic congruence alone.
See `guest/dense-direct-physical-v2.json`. BYTE-local-GKR projection is next;
production SSA/frontier joins and recursive admission remain closed.

## BYTE-local GKR checkpoint (equal-log control)

The closed public-packet fixture now proves its355-term BYTE relation using the
existing checkpointed LogUp-GKR engine, without constructing a dense fact plane
or allocating the classic1432-column interaction witness. The source reader and
terminal projection invoke the **same** range-fraction emitter, including the
negative committed MAIN multiplicity and padded0/1 lanes. The original complete
arithmetic/canonicality emitter is unchanged. A verified child still needs the
physical16-column Eq/prefix binding; the public output debt keeps8 classic
columns. Fresh reception recomputes the GKR transcript and expected source key.

Actual equal-log8 proofs: multiply113,736B +20,284B GKR =134,020B (43.5% below
classic237,192B); square79,592B +20,284B =99,876B (50.9% below203,304B). Native
MAIN+INTER cells drop641,792→281,344 and543,488→183,040 respectively; GKR work
is additional and these are not wall-time claims. Changed Eq/prefix/output
openings, wrong input scope and corrupted child proofs reject. Receipt:
`guest/dense-byte-local-gkr-v1.json`.

Both components are currently log8. The required next gate separates the BYTE
provider at log8 from arithmetic at log9, with a shared local challenge and
cross-instance closure, so a lifted-domain mask error cannot hide behind equal
geometry. Production joins, recursive authority and security admission remain
closed throughout.

## Mixed-height BYTE binding gate

The BYTE provider is now an independent log8 component with1 MAIN multiplicity
column and16 Eq/prefix binding columns. Arithmetic keeps355→512 lanes; its old
embedded multiplicity is constrained zero. Both instances share one beta and
close **together**; each individual numerator is nonzero in the qualified cases.
Both source projections are physically authenticated, using the verifier-derived
local row point on the global lifted PCS domain. Two components remain one proof.
The experimental payload is explicitly DENSELG2; old equal-log artifacts retain
their qualified DENSELG1 commit and are not silently reinterpreted.

Actual complete native+GKR proof sizes are137,624B for multiply8/table8,
144,744B for multiply9/table8, and108,328B for square9/table8. The latter cases
exercise genuine mixed-height masks; they are not timing comparisons against a
different geometry. Fresh receivers reject arithmetic/table Eq and prefix
mutations, output mutation, a deliberately wrong row-MLE point, a different table
beta, wrong public input, corrupt child and producer geometry substitution.
Complete degree≤3 checks cover both roles/classes and public auxiliary
polynomials. Main/interaction cells and exact hashes are in
`guest/dense-byte-local-gkr-mixed-v1.json`.

Splitting adds17 log8 columns (4,352 cells per proof) to the prior planned ledger;
this amortized table cost must be counted. Production opening-width estimates
become805/1189 for square/multiply, with the input frontier included. Runtime
admission, typed SSA/global joins, recursion and wall-time claims remain closed.

### Two-operation local SSA authority (research, not admitted)

`bn254_dense/chain.zig` fixes square(A) → temporary followed by multiply(temporary, B) → public output. A separate log-5 producer pins 24 initial raw-u256 values in its immutable FIXED columns. Arithmetic rows call `air.emitInherited`; they contain no equality to a public input list. Local SSA carries all 32 bytes, using typed `(family, call_id, value_id, bytes32)` tuples. IDs 0–23 are initial values and 24–35 are the square outputs. Each source-owned writer has fanout 12; positive and negative SSA mass are exactly 432. The square's strict canonical write, rather than a constructor assertion, supplies the multiply's intermediate range authority.

The source-GKR fixture has six independently sized instances: BYTE square/multiply/table and SSA initial/square/multiply, with 413,984 padded facts. BYTE and SSA use independent challenges and close separately. A balanced transfer of debt between their groups is rejected. The coherent `temporary+p` test propagates the forged byte vector into every multiply row, recomputes BYTE multiplicities, and preserves the final modular output: BYTE and SSA still close, while the original square canonical-write equations reject it.

The actual binding width is 16 M31 columns per local instance. Consequently this chain uses initial 16 INTER, square 32, multiply 40 (including the final eight-column public output debt), and BYTE table 16. The earlier BYTE-only arithmetic fixture's 24 INTER was 16 binding plus eight output columns. Physical terminal binding of this two-operation chain is a separate pending gate; these source tests do not authorize a service or claim a proving speedup.
