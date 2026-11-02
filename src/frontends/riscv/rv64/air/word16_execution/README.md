# Full64 Word16 execution foundation

This namespace is a concrete Ethereum-services-v2 RV64IM bus-emitter AIR. It is
not a standalone accepting execution verifier: its physical merged claim must
close against the independently admitted ROM, local register boundary, range,
FUNCTION and OWNER providers. EBREAK does not retire. Ordinary trapping ECALL
has a different execution meaning and is not admitted by this authority.

The CPU has 3 fixed, 47 main and 40 interaction columns, with 52 residuals of
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

## Opt-in fused-tail interaction (36 columns, 51 residuals)

`Geometry.cpu_fused_tail` (default false) selects `emitFusedFor` instead of
`emitFor`. False keeps the 40-column AIR, the transcript and bundle JSON
byte-identical; true additionally mixes `features.fusedTailIdentity()` and
the shape width 36. The LogUp statement and every honest per-row increment
are unchanged; only the witness form changes:

- REG slots 0..2 are FRACTION witnesses `R*before*after = enabled*(after-before)`
  (degree 3), contributing `R` (degree 1). This replaces the strict inverse
  product, so a REG pole is no longer rejected per row: if `before*after = 0`
  the row's `R` is free. A one-sided pole with nonzero numerator is
  unsatisfiable, and a disabled slot with no pole forces `R = 0`.
- OWNER+U16 (slot 5) is a fraction witness `F*d0*d1 = d0 + (active-function)*d1`.
  Its numerator is affine, so the inverse form would make the fused residual
  degree 4. If `d0 = 0` and `active-function = 0` the row's `F` is free; if
  `d1 = 0` the residual forces `d0 = 0`. So the slot adds two poles per row.
- Pole bound. Every denominator is `z - <alpha, tuple>` with the tuple
  committed before `(z, alpha)`, so each is zero with probability at most
  `1/|QM31|` per row (Schwartz-Zippel in `z`). A row has 8 non-strict poles
  (`before_s`, `after_s` for 3 slots, and `d0`, `d1`), so the encoding is
  non-strict on some row with probability at most `8*2^22/|QM31| = 2^-99`
  per proof (|QM31| ~ 2^124). This is the standard stwo `LogupAtRow`
  fraction argument.
- FUNCTION, ROM, U16+U16 and U8+U8 keep strict inverses `d*I = 1`.
- The U8 single has no column. It is enforced through the prefix:
  `(S - S_prev + claim*first - C8)*d6 - 1 = 0`, where every term of `C8` has
  degree at most 2. This is strict: `d6 = 0` makes the residual `-1`.
  Otherwise it forces `S - S_prev = C8 + 1/d6 - claim*first`, the same
  recurrence as the old (inverse, sum) pair. `last*S = 0` is unchanged.

Register closure and chronological induction rely only on the rational identity
`sum(+-1/(z-t)) = 0`, never on per-row strictness, so they are unaffected.
The main-only authority uses only `emitMainFor`, which both encodings share.

Routes. Every prover source takes `cpu.fused_tail` from `Geometry` in
`Source.fromPreparedInternal`, and every verifier component takes it from the
same geometry (`components.zig`), so the core, global, Keccak, secp and
services routes all follow the declared geometry. `ethereum/plan.zig` sets it,
together with `cpu_u8_pairs` (below), by default ONLY for the
`ethereum_services_v3` route (`CpuLayout.forProfile`); `ethereum/main.zig
admitProfile` refuses either flag on any other profile. The local GKR lane (`services/gkr_local/roster.zig`) has no
fused variant and fails closed with `UnsupportedFusedTailInLocalGkr`. No
recursion lane wraps a Word16 CPU proof yet; the shape diagnostic
(`word16_recursion/main.zig`) reads widths through `Components.init` and so
follows the geometry. Any future CPU recursion leaf must implement
`emitFusedFor` or refuse `cpu_fused_tail`.

## Opt-in byte-pair lookups (32 columns, 50 residuals)

`Geometry.cpu_u8_pairs` (requires `cpu_fused_tail`, default false) selects
`emitPairsFor`. The three gap8 U8 range queries become two byte-pair queries
`(gap8_0, gap8_1)` and `(gap8_2, 0)`. They use no new relation and no new
challenge: a pair is the tagged tuple `(x, y, 0, 1)` of the AND relation,
whose tuples are `(x, y, x&y, 0)`. The AND table (log 16, fixed `x = row>>8`,
`y = row&255`) gains one multiplicity column for the pair tuples
(`binary_component` kind `and_pair_table`), so the AND claim covers both
families. False keeps the fused or legacy AND table and CPU bytes; true also
mixes `features.pairIdentity()` and the shape widths (CPU 32, AND MAIN 2).

CPU witnesses (all degree one, so the fused residual stays degree 3):
- REG x3 and OWNER+U16: the fused fraction forms, unchanged.
- FUNCTION `G*d_fn = function` and ROM `H*d_rom = active` (d quadratic).
- U16+U16 `K*d2*d3 = d2 + d3`.
- Both byte pairs are fused: `(S - S_prev + claim*first - C7)*p0*p1 - (p0 + p1) = 0`,
  with `C7` the sum of the seven witnesses. If `p0*p1 != 0` this forces
  `S - S_prev = C7 + 1/p0 + 1/p1 - claim*first`. A one-sided pole is
  unsatisfiable (`-p1 = 0`); a double pole frees the step.

AND pair table: `I*d*p = 1` (strict) and the prefix
`S - S_prev*(1-first) + (m*p + m_pair*d)*I = 0`; `last*(S - claim) = 0`.
The legacy separate first-row residual `first*(S + term)` is omitted: at
`first = 1` the transition residual already reads `S + term = 0`, and keeping it
would be degree 4.

Soundness. Range: a pair query balances only against a table tuple, whose
coordinates are canonical bytes, so `gap8_k < 256` exactly as with three U8
queries; `(gap8_2, 0)` forces `gap8_2 < 256`. Tag separation: the fourth
coordinate makes pair and AND tuples distinct linear forms, so a BINARY AND
query cannot be served by a pair row or vice versa (Schwartz-Zippel over the
AND challenges, drawn after MAIN). Mass: AND plus pair multiplicities are
admitted together below M31 (`Geometry.validate`, `Request.initWithPairs`).
Poles: the non-strict slots add the FUNCTION, ROM, U16 pair and byte-pair
denominators to the fused set: 6 REG + 2 OWNER/U16 + 1 FUNCTION + 1 ROM +
2 U16 + 2 byte-pair = 14 per row, so at most `14*2^22/|QM31| < 2^-98` per
proof. Padding rows query `(0, 0)` twice, so their two pair denominators
coincide; that is still one pole event. The 24-bit gap identity
`gap = gap16 + 2^16*gap8` is unchanged, and range8 keeps serving MUL and LS.

## Fused-tail / byte-pair layouts of the other components

The same two constructions extend to the providers that kept the classic
"strict inverse per pair + separate prefix" interaction. Each is a separate
opt-in `Geometry` flag (omitted from JSON when false; when set, its layout
identity and widths are mixed into the transcript), v3-only on the Ethereum
route (`ethereum/main.zig admitProfile` refuses each flag elsewhere; the
local GKR lane refuses each one). Every byte pair is the tagged AND-relation
tuple `(x, y, 0, 1)` served by the pair column of the pair-capable AND table,
so every pair flag requires `cpu_u8_pairs`. Pair multiplicities are added to
that column (`sources.zig`, services `mergeAndPairTable`) and their mass is
admitted with the AND relation (`Geometry.andMass`, services `admitDword`).

| Flag | Component | Interaction | Residual form |
|---|---|---|---|
| `mul_u8_pairs` | MUL (`multiplication.pairs_layout`) | 200 -> 100 | 48 byte pairs, two per strict inverse; FUNCTION fused `(S-S'+claim*first-C)*d_fn+active` |
| `ls_fused_pairs` | LS32 / LS32 tail | 32 -> 20 | RAM fused `(S-S'+c*first)*b*a-active*(a-b)`; K0..K2 fractions; pairs `(b13,b26),(b73,b74)` fused |
| `ls_fused_pairs` | INIT / TEARDOWN | 8 -> 4 | fused single `(S-S'+c*first)*d-w` |
| `alu_fused_tail` | ALU / ALU tail | 32 -> 28 | five U16 pair fractions, FUNCTION fraction `G*d_fn=m`, last U16 pair fused |
| `ls_dword_fused_pairs` | LS-D64 (services) | 28 -> 16 | RAM fused; K0, K1 fractions; `(U16_3, (b13,b26))` fused |

Soundness is the argument of the two sections above, component by
component: every residual has degree <= 3 (checked by the cubic tests and by
the honest physical proofs); a fraction witness `K*a*b = n` or a fused tail
is exact whenever its poles are nonzero, a one-sided pole with nonzero
numerator is unsatisfiable, and every denominator is `z - <alpha, tuple>`
with the tuple committed before its challenges, so the non-strict poles
(MUL: none besides the inactive-row FUNCTION offset; LS32: 10 per row;
INIT/TEARDOWN: 1; ALU: 13; LS-D64: 8) are zero with probability at most
`(poles * 2^22 * deg_z)/|QM31| < 2^-95` per proof. Range: a byte pair balances
only against a canonical AND-table pair row, so both elements are `< 256`
exactly as two U8 queries; the tag coordinate separates pair from AND tuples.
LS32/LS-D64 claim shares: the `range8` share carries the AND-relation pair
share; only the total is authenticated (unchanged). The physical STARK tests
(`mul_u8_pairs_proof_test`, `ls_fused_pairs_proof_test`,
`alu_fused_tail_proof_test`, `load_store_dword/tests.zig`,
`services/ls_dword_test.zig`) forge every slot (active and padding rows) with
the prefix repaired, move fractions between rows with every claim unchanged,
perturb single prefixes, and cross-check receivers of the other layouts.

## Affine zero-register flags

The three zero-register flags are `1-enabled`, not independent committed
columns. An active row authenticates that complement against the immutable
ROM's Boolean zero flags and architectural register IDs. The local guard
`(1-active)*enabled=0` makes every disabled padding slot have `enabled=0`.
The unchanged zero-value constraints become `(1-enabled)*value=0` for A, B and
previous RD; predecessor-clock disabling remains explicit. Register bus weights
still equal enabled. ROM and REG debts must close together: a local proof with
an unauthenticated enable flag is insufficient.

The zero-flag substitution preserved the original55 residuals, full64 PCs and the
existing40 interaction columns. It changes the MAIN encoding and proof
transcript, so the feature-authority domain is explicitly full64.v2; old proof
bytes are not parity fixtures for this encoding. No independently supplied
Boolean hint, range lookup or new runtime profile is introduced.

## Derived predecessor clocks

A register predecessor time is `4*row+slot-gap16-65536*gap8`. It is the exact
substitution of the former committed-clock/gap equality, not a new clock-range
assumption. Three MAIN columns and three identity residuals disappear. ROM,
local REG, public boundaries, fixed after-times and gap range closure still
establish chronological consistency. A canonical gap can produce a negative
field predecessor locally; the complete REG relation must reject that orphan.
The disabled-register guard remains explicit and forces predecessor time zero.

All REG tuples, native clocks and range query values remain identical on honest
rows. Full64 PCs,40 interaction columns and the24-bit clock cap are unchanged.
The deliberate encoding domain is full64.v3; old proof bytes are not new-shape
fixtures. A retained false-witness test repairs all interactions and ranges,
verifies the actual physical STARK, and requires a pristine closed receiver to
reject precisely the remaining REG predecessor debt.

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
witness residuals, strict unused poles, all52 dense-Q degree checks and packed
per-residual parity. ROM and JALR tests check their own degree metadata, native
claims, source release/one-shot/OOM behavior and scalar/packed domain parity.
Actual external circuit point adapters for CPU, ROM and JALR compare against
QM31 with challenges, claims, public fields and masks supplied as circuit wires.

These focused gates do not replace a q70 whole-roster proof with independent
fresh verification. No full RV64/service/continuation qualification is claimed
until all delegated relations and expected public boundaries close physically.
Column reductions alone are not a whole-prover performance result.
