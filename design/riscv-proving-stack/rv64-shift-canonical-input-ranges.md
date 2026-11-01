# SHIFT canonical-input range reduction

The concrete Word16 SHIFT interaction encoding evolves from v2 to v3. MAIN53,
local arithmetic27, FUNCTION13 IDs32..37, table truth and metadata30B are unchanged.
Only the four direct B-limb U16 memberships are removed. No runtime profile enum
or accepting open verifier is added. Legacy BYTE SHIFT is unchanged.

## Exact query and degree ledger

The five SHIFT queries still authenticate four A limbs and the constant65535
fill row, all at the same microshift amount. Five U16 queries remain: quotient,
64*quotient, `2*A1-sign31*65536`, `2*A3-sign63*65536`, and
`2*C1-signC31*65536`. Ten unit fractions use five strict pair inverses (20 M31
columns); the strict FUNCTION inverse uses4 and the joint prefix uses4:28 INTER,
36 residuals, degree3/native2n/split1. Previously14 unit fractions needed36 INTER
and38 residuals. All table/range queries remain unit weight on every padded row;
only FUNCTION uses the existing multiplicity. Zero weights do not suppress poles.
Only the sum of SHIFT/range/FUNCTION ledger shares is physically authenticated.

## Canonical inputs, count and outputs

The immutable SHIFT table makes every queried A limb and microshift amount
canonical. Both quotient ranges remain essential: ranged q and ranged64*q give
q<=1023 without field wrap (64*65535<p). Boolean offset/ignored-W-bit constraints
then bound the reconstructed low B limb to65535. High B limbs do not participate
in local count or result arithmetic. Full FUNCTION13 equality nevertheless binds
all B coordinates to the closed CPU/ROM canonical operand. Independently expected
native u64 facts supply the same premise in standalone diagnostic fixtures.

Every table output is a bounded16-bit chunk. For each amount, the maximal left
low/carry masks are disjoint and union to65535; the maximal right low/carry masks
have the same property. Exhaustive tests cover all65536 inputs times16 amounts
against these bounds. Thus combining chunks from adjacent source limbs is always
canonical, even when those source limbs differ. `shift_chunk_arithmetic` chooses
either a real chunk or an outside fill for each part; the parts never overlap.
Boolean sign fills choose zero or the corresponding constant-row mask. Boolean
operation/offset selectors choose exactly one case on active rows. W upper limbs
are zero or65535, and the retained C31 sign query authenticates their sign.
Inactive selectors produce C=0. Therefore all contributing C outputs are canonical
independently of the removed B-high ranges, so register induction is noncircular.

The closed REG6 clock argument and known initial u64 values supply canonical
register reads; ROM supplies immediates. ALU, LS, BINARY, SHIFT, DIV/MUL and static
ROM writes retain their independent anchors. Stateful OWNER/RAM activity stays
Boolean/unit on both sides, separate from reusable pure-function multiplicities.
The new encoding identity is mixed by the full CPU protocol and standalone
Word16 SHIFT fixtures. Fixed table geometry and its semantic identity are unchanged.

## Qualification

Scalar Q finite differences and sixteen-lane packed-base/secure comparisons cover
all36 complete residuals, including previous-prefix masks. Actual Circuit wires
compare the same residual authority and challenge/claim/inverse mutations.
Native projection, serial/parallel generation and weighted tests compare all
columns and physical claims after MAIN/input retirement, with pole/retry/drain
and allocation-failure coverage. The native histogram oracle reads the actual
wide matrix independently of the narrow payload reconstruction.

Positive semantic tests cover all6 operations, all64 counts and full-word corner
values. They also replace unused B-high coordinates by noncanonical field values:
local equations, remaining ranges and canonical C stay valid, demonstrating the
precise external FUNCTION input premise rather than assuming it.

The full-Core test commits such a B-high replacement, constructs its actual
interactions, and obtains a real physical STARK accepted by a fresh polynomial
verifier. SHIFT and range debts are unchanged/closed; only FUNCTION changes. The
fresh closed CPU receiver must reject `UnclosedExecutionRelations`. Complete
standalone and mixed-service proofs, worker parity, and independent CSP/Sail
fresh receivers provide positive end-to-end qualification. The receipt records
final results/pins; this is a manual argument, not a machine-checked proof.

## Cost limits

The exact source reduction is8*N M31 INTER cells per physical SHIFT component,
with8 fewer Q opening samples and unchanged previous-prefix samples. MAIN and
metadata are unchanged, so this does not reduce retained Stage1 MAIN volume.
The mandatory table footprint is unchanged. Summed source cells are not peak RSS,
and component width reduction is not a whole-job speedup claim.

The retained full-S4 physical roster has40 SHIFT components and6,146,048 padded
SHIFT rows. At those unchanged geometries, SHIFT28 removes49,168,384 interaction
cells (196,673,536 bytes of summed source volume),24,584,192 U16 queries and320 Q
opening samples. These are counts from the retained roster, not a measured new
full-block run or peak-memory estimate.
