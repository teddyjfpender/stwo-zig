# Full64 Word16 execution foundation

This namespace is a concrete Ethereum-services-v2 RV64IM bus-emitter AIR. It is
not a standalone accepting execution verifier: its physical merged claim must
close against the independently admitted ROM, local register boundary, range,
FUNCTION and OWNER providers. EBREAK does not retire. Ordinary trapping ECALL
has a different execution meaning and is not admitted by this authority.

The CPU has 3 fixed, 53 main and 40 interaction columns, with 55 residuals of
maximum degree 3. The ROM table has 32 fixed, 1 main and 8 interaction columns,
with 4 residuals of degree at most 2. The optional nonzero-immediate JALR
composite has 2 fixed, 18 main and 12 interaction columns and 6 degree-3
residuals. All use the existing 2n quotient geometry. `emitFor` is the single
polynomial authority shared by QM31 OODS, PackedM31 domain and external circuit
lanes; no circuit lane may capture a native challenge, physical claim or public
endpoint as an unconstrained host constant.

## Tuple and closure contract

FUNCTION13 is `(operation,A[4],B_effective[4],C_effective[4])`. The old pure
operation IDs stay unchanged; nonzero-immediate JALR uses 10 and MUL/DIV use
raw decoded opcode numbers 49 through 61. Dispatch must use the explicit opcode
set, not a contiguous family interval. Architectural B is retained separately
from IMM. PC, immediate and dynamic-next selection are quadratic projections;
therefore FUNCTION has a strict single inverse, not a product with another
quadratic denominator.

OWNER19 is `(raw_opcode,A[4],IMM[4],B_store[4],C_load[4],epoch16,tick24)`.
The epoch is independently expected and the tick is `4*row+4`. LS and ECALL
providers validate disjoint raw-opcode whitelists. Its weight is exactly
`active-function`, while FUNCTION weight is `function`; both are Boolean.
Stateful OWNER events cannot be deduplicated with arbitrary multiplicities.
ECALL reads a0/a7, carries zero IMM/C, and delegates service truth and RAM effects
to the service provider. OWNER truth alone does not establish service behavior.

ROM30 binds active valid membership, full PC and static next PC, architectural
register identities/zero flags, normalized IMM, all effect flags, dynamic JALR
link C and branch*C0. That last coordinate is necessary: without it a branch
could authenticate the wrong edge independently from the ALU predicate.
Padding has an unbroken PC chain to the independently expected final endpoint.
The expected program derives Entry metadata from immutable instruction decoding;
`fromInstruction` is an internal cache-reuse helper, not an admission API for
producer-chosen decoded records.

REG has three strict before/after inverse products and signed unit transition
contributions. Gap16/U8 lookups prove the 24-bit nonnegative gap. Together with
independently canonical register boundary tuples, unique fixed after-times,
unit positive mass below M31 and global local-REG closure, chronological
induction anchors predecessor clocks and values. These are joint proof
obligations; local CPU residuals alone are not an independent canonicality
proof. Register clocks reset per independently admitted batch, and PC/all
register values must be linked between batches by the receiving protocol.

## JALR composition and the signed-marginal attack

Nonzero-immediate JALR delegates a negative FN10(A,I,C) request and positive
ADD0(A,I,SUM) and AND16(SUM,~1,C) requests using the same FUNCTION challenges.
SUM is advice. Base ADD/AND components establish its meaning. Physical weight
is constrained to equal the Boolean active column, not merely to vanish on
inactive rows. The admitted positive FUNCTION mass must include both support
queries per JALR capacity in addition to other consumers.

Allowing signed field weights would be unsound even though the operation graph
10 -> {0,16} is acyclic. Four rows `(A,I,C,SUM,weight)`
`(0,0,2,0,+1)`, `(1,1,0,0,+1)`, `(1,1,2,0,-1)`, `(1,1,2,2,+1)`
have only true ADD/AND marginals but falsely join JALR(0,0)->2 and JALR(1,1)->0.
The regression constructs those exact global rational sums and shows that only
the mandatory unit-weight residual rejects them. Weighted composition is not
supported by this schema.

Immutable raw JALR immediate zero instead delegates directly to
AND16(A,~1,NEXT), with normalized IMM=~1; raw instruction immediate remains zero
for native-advice consistency checks. ROM still binds link C=PC+4. This avoids
composite/support rows without changing JALR semantics. `features.identity`
binds the normalization, tuple schema and opcode map.

## Qualification scope

Focused native tests exercise all 65 decoded opcode classes, raw/cached decode
parity, full64 wrapping, x0 and source aliasing, branch/link bindings, native
witness residuals, strict unused poles, all55 dense-Q degree checks and packed
per-residual parity. ROM and JALR tests check their own degree metadata, native
claims, source release/one-shot/OOM behavior and scalar/packed domain parity.
Actual external circuit point adapters for CPU, ROM and JALR compare against
QM31 with challenges, claims, public fields and masks supplied as circuit wires.

These focused gates do not replace a q70 whole-roster proof with independent
fresh verification. No full RV64/service/continuation qualification is claimed
until all delegated relations and expected public boundaries close physically.
Column reductions alone are not a whole-prover performance result.
