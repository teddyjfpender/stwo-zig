# Word16 small AIR trims v1: derived ALU/SHIFT payloads, JALR unit weight, LS affine b_low

Status: implemented on `codex/rv64-perf2-air-small-trims` (base `eac3b7c07`).
This is an AIR/protocol change. Proof bytes change; historical receipts and
old proof bytes are controls for the old layouts, not parity fixtures.

## Summary

| Chip (roles) | MAIN before | MAIN after | Physical residuals before -> after | Encoding identity |
|---|---|---|---|---|
| ALU (`alu`, `alu_tail`) | 52 | 47 | 63 -> 58 | `alu_encoding.VERSION` 4 -> 5 |
| SHIFT packed (`shift`, `shift_tail`) | 53 | 52 | 36 -> 35 | `shift_word_encoding.VERSION` 3 -> 4 |
| JALR (`jalr`) | 18 | 17 | 6 -> 5 | role shape mixed by `word16_execution/protocol.zig` |
| LS v2 (`ls`, `ls_tail`) | 71 | 70 | 261 -> 261 | `load_store_v2/encoding.zig` v4 -> v5 |

Every removed column was tied by an equality residual to a polynomial in the
remaining committed columns. Each trim is an exact substitution: the column is
replaced by that polynomial at every native, packed SIMD, OODS point and
external circuit-lane evaluation. For any assignment of the remaining columns
there was exactly one value of the removed column satisfying its old equality,
so the set of accepted remaining-column assignments, and every lookup tuple or
fraction they produce, is unchanged. No range, Boolean, lookup or closure
obligation was removed. The only change in polynomial shape is the ALU FUNCTION
denominator, which becomes quadratic; its strict single inverse keeps degree 3.

`core_schema` (`word16_execution/protocol.zig:14`) stays 5, following the
BINARY derived-payload precedent (29bae9f5d), which versioned only the chip
encoding. The transcript still changes: `mixMaterials` mixes every role's
`[fixed, main, interaction]` widths and the ALU, SHIFT and LS encoding mixes
(`src/integrations/riscv_cpu/word16_execution/protocol.zig:110-126`). The base
receiver rejects the new prefix4 bundle with `GlobalExecutionInventoryMismatch`.

## 1. ALU: derive op and C (payload[0], payload[9..13])

### Removed checks

Logical residuals that held at base (`word16_v1/alu.zig`, base lines 45 and 77):

* `payload[0] - sum_i i*S_i = 0` (affine)
* `payload[9+i] - output_i = 0` for i = 0..3, where `output_i` is
  `S_add*sum_i + S_sub*difference_i + S_addw*addw_i + S_subw*subw_i`,
  plus `sum_j S_(4+j)*predicate_j` for i = 0. `addw_i/subw_i` are `sum_i`, `difference_i`
  (i<2) or `65535*sign[2]`, `65535*sign[3]` (i>=2). The predicates are
  `signed_less, borrow[3], zero, 1-zero, 1-signed_less, 1-borrow[3]`. Every
  factor is a committed column, so `output_i` is quadratic.

### New authority

* `derivePayloadFor` (`src/frontends/riscv/rv64/air/word16_v1/alu.zig:58`) is
  the single expression authority for op and C.
* `rowFromColumnsFor` reads only A[4] and B[4] of the payload. It then calls
  `derivePayloadFor` (`alu_lookup.zig:27-46`). `rowToColumnsFor` writes only A/B
  (`alu_lookup.zig:48`). Committed column map: `alu.zig:20` (`columns`).
* The physical evaluator is `emitProjectedFor` (`alu.zig:91`, called at
  `alu_lookup.zig:70`). It omits the 5 substitution identities. The logical
  diagnostic `emitFor` (`alu.zig:86`) keeps them at `alu.zig:106` and `alu.zig:128`
  for tests that hand-build `RowFor` values.

### Producers and consumers of the removed coordinates

* Producer (native): `alu_source.zig:52-85` (`nativeRow`) computes op and C
  from the validated fact (`alu_source.zig:158` rejects any `c != nativeResult`).
  The derived auxiliaries feed `rowToColumnsFor` (`alu_source.zig:335`). The
  13-coordinate FUNCTION metadata (`alu_source.zig:340`) is native advice for
  interaction generation only (`alu_interaction.zig`). It is not a committed
  authority: the AIR evaluates the FUNCTION denominator on the derived payload.
* AIR consumer 1: the FUNCTION strict inverse
  `D(payload)*inverse - 1` and the prefix contribution `-inverse*multiplicity`
  (`alu_lookup.zig:82-83`).
* AIR consumer 2: the sign decompositions and limb equations read only
  `payload[1..9]` (A/B) (`alu.zig:109-118`). The inactive padding guard reads only
  `payload[1..9]` (`alu.zig:130`). None of them read op or C.
* Counterparties of the FUNCTION fact: the CPU FUNCTION request
  (`word16_execution/tuples.zig:14`, op and C from CPU REG/ROM state), the JALR
  composite ADD request (`word16_execution/jalr_equations.zig:25`), and the
  complete claim ledger (`src/integrations/riscv_cpu/word16_execution/protocol.zig:71-79`).

### Invariant relied on

op and C were never range-checked as committed columns. Their canonicity came
from the same sources before and after the change:

* U16 memberships of `sum[4]`, `difference[4]` and `2*low[4]` (`alu.zig:143`, `rangeValueFor`)
* Boolean selectors with `sum S = active`, Boolean carries and borrows, Boolean
  signs, Boolean `zero` and `signed_less`

With these, each `output_i` is an integer in [0, 65535]. On padding rows
(`active=0`), every selector is 0, so op = C = 0, as before. Substitution
therefore preserves the accepted FUNCTION tuple set exactly. A false C now
needs a false auxiliary, which the limb equations or the U16 memberships reject.

### Degree (native 2n domain, bound 3)

* FUNCTION inverse residual: `D` is quadratic and `inverse` is linear, so the
  residual has degree **3** (was 2).
* Prefix residual: degree 2 (unchanged).
* All other physical residuals are unchanged, with maximum degree 3
  (`signed_less`).
* Logical-only identities `payload - derived` have degree 2. They are not
  emitted physically.
* Checked by `alu_merged_prefix_test.zig`
  ("ALU32 joint polynomial is genuinely cubic ..."): it takes a 4th finite
  difference over all 58 residuals at arbitrary extension points, and requires a
  genuine cubic.

## 2. SHIFT (packed Word16): derive payload[0]

### Removed check

`payload[0] - sum_i S_i*(32+i) = 0`, an affine residual
(`shift_chunk_arithmetic.zig`, base line 43).

### New authority

* `busIdFor` (`src/frontends/riscv/rv64/air/word16_v1/shift_chunk_arithmetic.zig:31`).
* `rowFromColumnsFor` derives `payload[0]` (`shift_word.zig:30-54`, line 53).
  `rowToColumnsFor` skips it (`shift_word.zig:56`).
* The physical evaluator is `emitProjectedFor` (`shift_word.zig:103`, called at
  `shift_word_lookup.zig:36`). It uses `emitHeadProjectedFor`
  (`shift_chunk_arithmetic.zig:46`).
* The byte-interface prototype (`shift_byte.zig`) still commits `payload[0]`
  and still binds it through `emitHeadFor` (`shift_chunk_arithmetic.zig:41`, line 60).

C stays committed. Its residual `payload[9+i] - resultFor` is already degree 3
(offset times selector times table output), and C also feeds a U16 sign
query (`payload[10]`). Deriving C would raise the FUNCTION inverse to degree 4.

### Producers and consumers

* Native producer: `shift_word_source.zig:62` writes it into metadata only. The
  metadata sanity check is at `shift_word_source.zig:255`.
* AIR consumer: the FUNCTION denominator only (`shift_word_lookup.zig:48`).
  It stays affine, so the inverse residual stays degree 2.
* Counterparties: the CPU FUNCTION request (`word16_execution/tuples.zig:14`).
  Globally disjoint op IDs come from `operations.zig:busIdFor`.

### Invariant

Boolean selectors with `sum = active` (`shift_chunk_arithmetic.zig:52-59`) mean
the derived opcode is in {32..37} on active rows and 0 on padding. That is
exactly the set the old equality admitted.

## 3. JALR: WEIGHT == ACTIVE

### Removed check

`WEIGHT - ACTIVE = 0` (`word16_execution/jalr_equations.zig`, base line 43),
plus its column (base index 17).

### New authority

`ACTIVE` (index 16) is the multiplicity. It is Boolean
(`jalr_equations.zig:44`) and it weights the composite prefix contribution
(`jalr_equations.zig:51`, `contributionFor` at :39).

### Producers and consumers

* Producer: `src/integrations/riscv_cpu/word16_execution/jalr_source.zig:55-66`
  (`rowValues`, ACTIVE=1 for facts). Interaction generation uses a unit weight
  for facts (`jalr_source.zig:97`) and leaves padding rows out of the prefix.
* Consumers: the unit composite join request(10) -> ADD(0) and AND(16)
  (`jalr_equations.zig:22-36,49-51`). The external ADD/AND facts are
  `jalr_source.zig:67-75`. The component and packed rows are generic in `J.MAIN`
  (`jalr_component.zig:17,103`, `jalr_packed_rows.zig:17`). The role shape is
  `src/integrations/riscv_cpu/word16_execution/geometry.zig:118` (no longer
  hard-coded 18).

### Invariant

Signed or non-unit composite multiplicities are forbidden, because marginals
alone allow false joins (header comment, `jalr_equations.zig:1-3`). The old
`WEIGHT=ACTIVE` with Boolean ACTIVE gave weight in {0,1}. Boolean ACTIVE used
directly gives exactly the same set. The prefix degree is unchanged (3).

## 4. LS v2: b_low = B0 - 256*b_high

### Removed check

`B0 - b_low - 256*b_high = 0` (`memory/load_store_v1/equations.zig:78`). It
remains in the shared logical evaluator, but it is identically zero on expanded
LS v2 rows. The residual count stays 261, like the other retired LS columns
(1, 3, 4, 44..48).

### New authority

* Logical column 73 joins `REMOVED`
  (`memory/load_store_v2/projection.zig:8`).
* `expandFor` reconstructs it as `logical[36] - 256*logical[74]`
  (`projection.zig:61`).

### Producers and consumers

* Producer: `load_store_v2/native.zig:77-78` (`logicalRow`, from the validated
  event `native.zig:15`). The narrow U8 cache and histogram are built from the
  same logical row (`native_fill.zig:106-110`, `layout.zig:27-29`).
* AIR consumer 1: the U8 membership. `local_lookup.zig:17` iterates
  `LOGICAL_U8 = {13, 26, 73, 74}` on the expanded row (`layout.zig:17`), so the
  fraction denominator `range8(B0 - 256*b_high)` stays affine and keeps the
  strict pair inverse.
* AIR consumer 2: the SB store write
  `flag*offset*(b_low - selected_byte)*{1,256}` (`load_store_v1/equations.zig:116`).
  Its degree is still 3.
* AIR consumer 3: the inactive guard `(1-active)*b_low` (`equations.zig:47`).
  Its degree is 2, and it is implied by the B0 and b_high guards.
* `LS.U8` (a physical column map) no longer exists, because b_low has no MAIN
  column. Users switched to `U8_QUERIES` and logical expansion:
  `source.zig:85`, `native_fill.zig:91`, `geometry.zig:79`, and the test oracles
  `memory/native_test.zig` and `memory/range_induction_proof_test.zig`.

### Invariant

B0 is a U16 limb authenticated by the closed CPU REG/OWNER relation
(`layout.zig:12-15`, `equations.zig:11-17`). U8 membership of `b_high` and of
`B0 - 256*b_high` gives the unique canonical byte split, because p > 2^16
excludes wraparound. That is the same pair of memberships the committed b_low
had, now applied to the substituted expression. On loads, `load*B0 = 0`
(`equations.zig:108`) together with both memberships forces `b_high = b_low = 0`.

## Adversarial negative tests (removed-check exploits)

| Test | Exploit | Rejected by |
|---|---|---|
| `test-riscv64-word16-alu-proof`, attack `.result` (`alu_fixture_trace.zig`) | False C on ADD row: the only expressible way is forging the committed SUM; the roster carries the same false C so FUNCTION balances | ALU limb residual: `ConstraintsNotSatisfied` |
| same step, attack `.noncanonical_result` | Non-canonical C limb split `(65536,65535,65535,65535)=2^64` with all carries 0; every local ALU residual vanishes (checked in the fixture); every representable forged U16 query is counted | U16 LogUp imbalance on SUM[0]=65536: `ConstraintsNotSatisfied` |
| `alu_merged_prefix_test.zig` (`test-riscv64-word16-alu`) | Arbitrary extension rows: derived op/C substitution identities vanish; projected = logical minus 5 | equality of residual vectors |
| `test-riscv64-word16-shift-packed-proof`, attack `.opcode` | Relabel SLL as SRL(33): opcode is derived, so the committed selectors are flipped; roster carries 33 so FUNCTION balances | SHIFT committed-C residual: `ConstraintsNotSatisfied` |
| `test-riscv64-word16-execution`, "signed composite marginal forgery ..." | Signed JALR multiplicity −1 that closes all global ADD/AND/FN10 marginals | Boolean ACTIVE residual = 2 |
| `test-riscv64-word16-memory`, "noncanonical derived store byte split" | SH row: b_high 0→1 makes derived b_low = 17−256 mod p; all local LS/RAM residuals vanish (checked); U8 table rebalanced for every representable forged query | valid physical PCS proof, but complete receiver: `UnclosedExecutionRelations` (U8 debt cannot close) |

## Recursion / circuit-lane shapes changed (recursion code not updated)

* The leaf circuit instantiates the batch constraint code on circuit wires
  (`src/integrations/riscv_cpu/rv64_recursion/circuit_lane.zig`). The CPU proof's
  main-tree mask has 8 fewer columns per CPU proof that has all tails present
  (ALU −5, SHIFT −1, JALR −1, LS −1), plus −5, −1 and −1 for the ALU, SHIFT and
  LS tails. Constraint counts change: ALU 63→58, SHIFT 36→35, JALR 6→5; LS stays
  at 261. The ALU FUNCTION residual adds the quadratic C derivation in-circuit.
* The leaf circuit hash and the `rv64_recursion/layout_digest.zig` digest
  change, so trusted topologies (`root_admission.zig`) pinned to base must be
  regenerated.
* Direct external-lane qualifications still pass on the new shapes:
  `test-riscv64-alu-merged-circuit`, `test-riscv64-shift-merged-circuit`,
  `test-riscv64-ls-circuit-lanes`, `test-riscv64-word16-execution-circuit`.

## Measured (Apple M5 Max, shared machine)

The prefix4 run (4 CPU and 3 truth proofs) was checked against the `eac3b7c07`
baseline `perf2-baseline-prefix4`.

* Native cells: 3,057,402,784 -> 3,039,216,544, a change of -18,186,240
  (-0.59%). By CPU proof: -5.06M, -4.35M, -4.24M and -4.54M. Truth proofs are
  unchanged.
* Main columns per CPU proof: 630 -> 615, 577 -> 563, 525 -> 516 and
  1017 -> 1002. The tails present differ by proof.
* Wall 27.26 s vs 26.95 s; user 190.7 s vs 192 s; sys 11.3 s vs 11 s; peak
  footprint 16.30 GB vs 16.32 GB.
* Per-stage seconds summed over the 7 proofs show no change beyond the
  shared-machine noise. Examples: main_commit 5.695 -> 5.692 and
  composition_evaluation 10.311 -> 10.369. The cell saving is too small to
  measure in one run.
* A fresh `verify-prefix` accepted the new bundle. The base receiver rejects it
  with `GlobalExecutionInventoryMismatch`.
* Complete block (25 CPU and 5 truth proofs): produce took 232 s wall with a
  28.3 GB footprint. A fresh `verify` accepted it with
  `completed_ethereum_block: true`. Native cells: 21,013,550,400.
