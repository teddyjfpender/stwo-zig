# Word16 DIV trims: constant MULHU result and canonical-input A/B ranges

This changes the narrow Word16 DIV row
(`src/frontends/riscv/rv64/air/delegations/division/word16_product/`) in two
ways. Integer semantics, opcode IDs, FUNCTION13 tuple shape, MUL/MULHU support
facts and every other chip are unchanged. Proof bytes change.

| DIV row (per padded row) | before | after |
| --- | --- | --- |
| MAIN columns | 82 | 78 |
| INTERACTION columns | 76 | 60 |
| U16 queries | 31 | 23 |
| strict linear pairs / quadratic singles | 16 / 2 | 12 / 2 |
| arithmetic residuals | 172 | 164 |
| total residuals (`layout.CONSTRAINTS`) | 192 | 180 |
| OODS samples per DIV component (fixed + main + COUNT prev + inter + prefix prev) | 166 | 146 |
| retained query metadata | 96 B | 88 B |

Arithmetic residuals fall by 8, not 4: the four `PRODUCT_HIGH[i] = 0`
residuals go, and so do the four `(1 - active) * PRODUCT_HIGH[i]` padding
residuals. The `(1 - active) * v` loop covers every column below `SELECTORS`.

The transcript already mixes `word16_product.layout.MAIN` and
`.INTERACTION` (`src/integrations/riscv_cpu/word16_execution/protocol.zig:116`).
So schema5 proofs made with the 82/76 DIV cannot verify under the 78/60 DIV.
The ALU v3->v4 range trim (commit 37ea5b553) did not bump
`protocol.SCHEMA` either. This change follows that precedent, and `SCHEMA`
stays 5. The list of mixed words keeps its length, so circuit transcript
replays keep their word count. Historical receipts are untouched.

## 1. PRODUCT_HIGH becomes a tuple constant

Removed: four MAIN columns `PRODUCT_HIGH[0..4]`, their residuals
`PRODUCT_HIGH[i] = 0`, and their padding-zero residuals.

What they did: they were the result coordinates 9..12 of the MULHU support
tuple. Those coordinates were forced to zero locally.

What replaces them: `equations.tupleFor`
(`word16_product/equations.zig:18-33`, line 26) now writes the field
constant 0 into those coordinates for the MULHU support. The DIV support
denominator is still affine in MAIN, so the strict pairing is unchanged.

The invariant this relies on: the positive MULHU fact (`lookup.zig:24`, weight `+active`)
must be cancelled by a MUL-provider row with tuple
`(MULHU, Q bytes, |B| bytes, RESULT bytes)`
(`multiplication/provider.zig:41-45`; production
`multiplication/degree3_provider.zig:21-22`). Here RESULT is byte-ranged
(`provider.zig:53-55`) and equals the 128-bit product's high word
(`provider.zig` `arithmeticFor`). So the constant zero gives exactly the old
statement: `floor(Q*|B| / 2^64) = 0`. This is the same equation as before,
minus four committed copies of zero. The native witness refuses a row
whose high product is nonzero (`witness.zig:62`). The existing high-product
attack (`division_product_integration_test.zig`, `falseFragment((1<<62)+3)`)
still needs the complete MUL closure to reject it.

## 2. A/B operand U16 memberships removed

Removed: the eight direct U16 queries on `A[0..4]` and `B[0..4]`. Previously
`rangeValuesFor` began with `m[A..A+12]`, which covered A, B and C.

Kept in `rangeValuesFor` (`equations.zig:43-54`): C(4), ABS_A(4),
REMAINDER(4), GAP(4) and OUT(4), plus the two selected-top sign queries
`2*top - 65536*sign` (`RANGE_QUADRATIC = {20, 21}`) and the OUT32 sign query.
No query is moved or merged. Each remaining query keeps unit weight, padding
included.

### Where the removed checks were used inside DIV

1. Signed normalization (`equations.zig:79-84`). The equation is
   `ABS[i] = (1-2*NEG)*eff[i] - prior + 65536*carry[i]`, with Boolean carries
   (`equations.zig:64`) and `carry = 0` when `NEG = 0` (line 83). It is an
   integer equation only when `eff[i]` is canonical.
2. Selected-top sign queries (`equations.zig:48-51`). `sign = top >> 15`
   holds only when `top` is canonical. A doubled query alone does not range
   `top`. For example, `top = (p+1)/2` passes with `sign = 0`, as in the ALU
   note.
3. The FUNCTION13 tuple (`equations.zig:27-30`, `lookup.zig:22-25`, weight
   `-active`). A/B appear here verbatim.

Locally, an unsigned non-W A is still pinned without the query:
`ABS_A[i] = A[i]` and ABS_A is ranged. Unsigned non-W B satisfies
`ABS_B = B`, and ABS_B is MUL-ranged. Signed rows with `NEG = 1`, and the upper
limbs of every W row, are not locally pinned. The tests construct all three
gaps (see 4).

### Which producer makes A/B canonical, and which invariant it relies on

Every active DIV row consumes its tuple with weight -1. Padding rows have
`active = 0`, and every column below `SELECTORS` is forced to zero there
(`equations.zig:68`). The only producer of DIV-opcode FUNCTION tuples is the
CPU.

* CPU FUNCTION tuple: `word16_execution/tuples.zig:14-26`.
  `out[1+i] = a + use_pc*(pc - a)` and `out[5+i] = b + use_immediate*(imm - b)`
  (lines 21-22). For DIV/REM opcodes, ROM authenticates
  `use_pc = use_immediate = 0` (defaults at `word16_execution/features.zig:17-19`).
  It also authenticates `operation = @intFromEnum(opcode)` (lines 89-97) and
  `function = 1` (line 21; ROM flags are bound in `tuples.zig` `rom`). The
  FUNCTION weight is Boolean (`word16_execution/equations.zig:84`). So the
  CPU tuple's A/B are exactly the register-read limbs `row[m.a]` and
  `row[m.b]`, the same columns as the REG `before` tuple (`tuples.zig:27-36`).
  Reads of x0 are zero (`equations.zig:80`).
* REG read canonicality, by induction (unchanged; see
  `rv64-alu-canonical-input-ranges.md`). The receiver admits initial
  registers as u64. Fixed after-clocks and the retained gap16/U8 queries
  order each read after its write. Every writer has its own anchor: ALU
  (retained sum/difference ranges), BINARY/SHIFT lookup truths, MUL RESULT
  bytes, LS C4, ROM link/constant, and DIV C. The **DIV C range is
  retained** (`equations.zig:45`) for exactly this reason. Removing it would
  make the induction circular. A/B canonicality is therefore not assumed
  anywhere in the chain.
* Separation of opcode IDs. DIV opcodes are 53..56 and 58..61
  (`decode.zig` enum order). Other IDs on the same bus: ALU 0..9, JALR 10,
  BINARY 16..18 and SHIFT 32..37 (`word16_v1/operations.zig:28-40`), and MUL
  49..52 and 57. Only the CPU adds FUNCTION mass at DIV IDs. DIV is the only
  consumer, and each of its rows has weight 0 or -1.
* Multiset closure. Positive FUNCTION mass is admitted below p
  (`word16_execution/geometry.zig:47`), so with high probability over the
  FUNCTION challenge each DIV-ID tuple has the same multiplicity on both
  sides. Every active DIV `(op, A, B, C)` therefore equals some CPU tuple
  coordinate by coordinate. That makes A/B canonical u16 limbs, and checks
  1-3 above become ordinary bounded-integer statements again.

The relation that closes this is the complete FUNCTION relation. Only the
closed Word16 receivers check it: `word16_execution.Execution.verify` and the
global, services and Ethereum receivers built on it. The narrow DIV appears
in no other receiver (`word16_product` is imported only by
`src/integrations/riscv_cpu/word16_execution/*`). A standalone DIV component
is not a truth verifier for arbitrary M31 input words.

## 3. Retained soundness dependency: MUL byte ranges (do not remove)

DIV has no range queries on QUOTIENT, ABS_B or PRODUCT_LOW, and it never
did. Their only authority is the MUL provider.

* DIV emits `+MUL(Q, |B|, PRODUCT_LOW)` and `+MULHU(Q, |B|, 0)`
  (`equations.zig:20-26`, `lookup.zig:22-25`).
* The MUL tuple is `main[0..24]`, which is A, B and RESULT bytes
  (`multiplication/provider.zig:41-45`). Every one of those bytes is a direct
  BYTE query (`provider.zig:53-55`, `values[0..40] = main[0..40]`). The
  production degree3 MUL uses both (`degree3_provider.zig:11,21`). Native
  admission rejects bytes of 256 or more (`multiplication/trace.zig:192-196`).
* The FUNCTION13 -> byte25 basis change
  (`word16_execution/arithmetic_bus.zig:10-19`) maps DIV limb coefficient
  `c` onto MUL `(lo, hi)` coefficients `(c, 256c)`. Tuple equality gives
  `limb = lo + 256*hi` with `lo, hi` in [0, 255], so each limb is in
  [0, 65535].

Consequences: ZERO detection (`sum ABS_B` < 2^18, `equations.zig:76-77`),
`PRODUCT_LOW + R = ABS_A` without a field carry alias, the strict gap
`R < |B|`, and the ABS_B negation chain all depend on these MUL byte
queries. Comments in `layout.zig` and `equations.zig` record this. The test
`"DIV support coordinates stay byte ranged by the MUL provider and
PRODUCT_HIGH is a constant zero tuple"` (`word16_product/test.zig`) fails
in three cases: if any MUL A/B/RESULT column stops being an identity BYTE
query, if the MUL tuple stops carrying those columns, or if native MUL
admission stops rejecting a 256 byte. It also checks that none of
QUOTIENT, ABS_B, PRODUCT_LOW, A or B is a retained DIV U16 membership.

### ABS_B carries when NEG_B = 1

The carries are Boolean and B is canonical (by authority). ABS_B is canonical
(through MUL). So
`ABS_B[i] + eff_B[i] + prior_i = 65536*carry_i` is an integer equation
(|terms| <= 2^17 + 1). It is the borrow chain of `0 - B` (mod 2^64 or 2^32),
and given canonical limbs the chain is unique. For W rows, `eff_B[2..4] = 0`
and `prior_2 = 0` force `ABS_B[2..4] = 0` and `carry = 0`. The test
`"DIV ABS_B negation carries are unique when NEG_B=1 ..."` enumerates all 16
Boolean carry vectors for signed 64-bit and W divisors. Only the honest
vector gives a canonical ABS_B. Flipping any carry against the honest ABS_B
leaves a nonzero residual. Without canonical B the chain is not unique:
`B = (p-1, 65536, ...)` with `carry0 = 0` gives the same ABS_B as the honest
`(0xffff, 0xffff, ...)` with `carry0 = 1`. That alias is the signed-B
adversarial case below.

## 4. Adversarial qualification

* `word16_product/test.zig`, test `"DIV operand A/B limbs have no local
  range ..."`: rows that satisfy all 164 local residuals and all 23 retained
  U16 queries but carry non-canonical tuple limbs.
  * Signed A alias: `-15` as `(p-15, 65536, 0xffff, 0xffff)` with `CARRY_A[0] = 0`.
  * Signed B alias: `-1` as `(p-1, 65536, 0xffff, 0xffff)` with `CARRY_B[0] = 0`.
  * W upper garbage: `A[3] = p-1` and `B[2] = 2^20`.

  The same test also checks that an unsigned non-W A with `A[0] = 65536` is
  still rejected locally.
* `word16_execution/division_product_integration_test.zig`, test
  `"real valid local DIV proofs with non-canonical A/B operand limbs fail only
  the closed CPU FUNCTION relation"`. Each of the three aliases is committed
  into an actual DIV MAIN. The DIV interaction is rebuilt from the committed
  MAIN values. A real full-PCS proof is produced, and
  `verifyPhysicalFragment` accepts it: every AIR constraint holds. Then:
  * `claims.validate()` reports `UnclosedExecutionRelations`, and so does
    the fresh `Execution.verify`.
  * After rebalancing the DIV claim so the aggregate sum is zero, the fresh
    receiver still rejects (OODS/prefix mismatch).

  This exercises the missing-read authority seam directly.
* Existing high-product and low-product attacks (`falseFragment`) still
  reject with the constant-zero MULHU tuple.

## 5. Shapes affected (recursion not updated)

* Every Word16 CPU proof with a non-omitted DIV component changes:
  * DIV MAIN, INTERACTION and constraint counts drop as tabled.
  * Each DIV component opens 20 fewer columns (166 -> 146 OODS samples).
  * Range16 multiplicity mass drops by 8 per padded DIV row
    (`geometry.zig:74` reads `layout.RANGE_QUERIES`).
* Circuit lane: `word16_product.component.ComponentFor(Lane)` is
  layout-generic, so the external-wire point evaluator follows automatically
  (`test-riscv64-division-product-circuit` passes). Any in-circuit
  verifier, recursion layout digest or verifier key pinned to schema5 Word16
  CPU proof shapes must be regenerated: DIV tree widths 3/82/76 -> 3/78/60,
  and 192 -> 180 constraint coefficients. This includes the native RV64
  recursion on other branches and the `rv64-word16-recursion-shape` report.
  This change does not touch recursion code.

This is a manual source argument, not a machine-checked proof.

## Recovery review gates

The focused DIV suite now includes a production-route regression, rather than
checking only the legacy helper accessors: each of the 24 MUL A/B/RESULT byte
coordinates is independently changed to 256, and the actual degree-three MUL
emitter must produce the expected nonzero BYTE-pair and FUNCTION residuals.
This guards the canonicality dependency against a future provider rewrite.
The suite floors are raised to 20 DIV tests and 36 coordinator tests so the
new soundness checks cannot silently disappear from their test roots.
