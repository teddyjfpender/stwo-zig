-- Transcription of the production DIV/DIVU/REM/REMU symbolic AIR.
--
-- Authority: the exported symbolic IR at /tmp/tb-ir/div.json
--   family "div", modulus 2147483647, 73 columns, 434 nodes,
--   85 constraints, 25 lookups, 9 unmodelled bus requests,
--   sha256 430a06a8919e469251deab180b492e89a4a6452de0014b2b0c3ea6c350912e4d
-- and its Zig source src/frontends/riscv/air/semantics/div.zig plus
-- src/frontends/riscv/air/semantics/common.zig.
--
-- Transcription conventions, each recording an exact production fact:
--   * A column that carries a `range_check_8_8` / `range_check_8_11` byte
--     component is typed `BitVec 8`.
--   * A column pinned by a `value * (1 - value) = 0` residual is typed `Bool`.
--   * A field residual whose operands are all bounded well below the M31
--     modulus is transcribed as the corresponding `Nat` equation; every
--     product-chain limb here is below 2 ^ 20, so no wrap can occur.
--   * A prover-chosen inverse witness (`c_sum_inv`, `r_sum_inv`, `r_inv_*`,
--     `destination_inverse`) contributes exactly one fact -- that the value it
--     inverts is nonzero -- and is transcribed as that fact.
--   * `r_abs_*` carries no range lookup. Its byte range is a consequence of the
--     negation recurrence together with the `r_inv_*` witnesses, so it is typed
--     `BitVec 8` and the recurrence is recorded in `Nat`.

import RiscvRefinement.Arith.Division

namespace RiscvRefinement.Air.Family

open RiscvRefinement

/-- sha256 of the exported production symbolic AIR this file transcribes. -/
def divIrDigest : String :=
  "430a06a8919e469251deab180b492e89a4a6452de0014b2b0c3ea6c350912e4d"

/-- Column count of the exported production AIR. -/
def divIrColumns : Nat := 73

/-- Constraint count of the exported production AIR. -/
def divIrConstraints : Nat := 85

/-! ## The committed row -/

/-- One committed DIV-family trace row.

`rs1Next` is the dividend `b`, `rs2Next` is the divisor `c`, exactly as in
`div.zig`: the semantics compute on the emitted limbs, and the read-only
residuals force those to equal the consumed limbs. -/
structure DivRow where
  pc : Word
  clock : Nat
  rd : RegisterIndex
  rdPreviousClock : Nat
  rdPrevious : WordBytes
  rdNext : WordBytes
  rs1 : RegisterIndex
  rs1PreviousClock : Nat
  rs1Previous : WordBytes
  rs1Next : WordBytes
  rs2 : RegisterIndex
  rs2PreviousClock : Nat
  rs2Previous : WordBytes
  rs2Next : WordBytes
  zeroDivisor : Bool
  rZero : Bool
  quotient : WordBytes
  remainder : WordBytes
  bSign : Bool
  cSign : Bool
  qSign : Bool
  signXor : Bool
  remainderAbs : WordBytes
  ltMarker0 : Bool
  ltMarker1 : Bool
  ltMarker2 : Bool
  ltMarker3 : Bool
  ltDiff : Nat
  isDiv : Bool
  isDivu : Bool
  isRem : Bool
  isRemu : Bool
  destinationNonzero : Bool
  claimedNextPc : Word
deriving DecidableEq, Repr

namespace DivRow

/-- `is_div + is_rem`: the two signed selectors. -/
def isSigned (row : DivRow) : Bool := row.isDiv || row.isRem

/-- `is_div + is_divu`: the two quotient-producing selectors. -/
def isDivision (row : DivRow) : Bool := row.isDiv || row.isDivu

end DivRow

/-! ## Sign-extension bytes

Each operand is extended to eight limbs by repeating one extension byte. The
byte is `255` when the corresponding sign witness is set and `0` otherwise,
matching `c_hi`, `q_hi`, `b_hi` and `r_hi` in `div.zig`. -/

def divDividendHigh (row : DivRow) : Nat := 255 * row.bSign.toNat

def divDivisorHigh (row : DivRow) : Nat := 255 * row.cSign.toNat

def divQuotientHigh (row : DivRow) : Nat := 255 * row.qSign.toNat

/-- `r_hi = b_sign * (1 - r_zero) * 255`: the remainder is extended with the
dividend's sign, and not extended at all when it is zero. -/
def divRemainderHigh (row : DivRow) : Nat :=
  255 * (row.bSign && !row.rZero).toNat

/-- The eight-limb value of a committed 32-bit limb group under a repeated
extension byte: `value + high * (256 ^ 4 + 256 ^ 5 + 256 ^ 6 + 256 ^ 7)`. -/
def divExtendedValue (bytes : WordBytes) (high : Nat) : Nat :=
  bytes.value + 72340172821233664 * high

/-! ## The eight truncated convolution limbs

These are exactly the eight `product_carries` numerators of `div.zig`, before
division by the byte radix: limb `k` of `divisor * quotient + remainder` over
the sign-extended eight-limb operands. -/

def divConv0 (row : DivRow) : Nat :=
  row.rs2Next.limb0.toNat * row.quotient.limb0.toNat +
    row.remainder.limb0.toNat

def divConv1 (row : DivRow) : Nat :=
  row.rs2Next.limb0.toNat * row.quotient.limb1.toNat +
    row.rs2Next.limb1.toNat * row.quotient.limb0.toNat +
    row.remainder.limb1.toNat

def divConv2 (row : DivRow) : Nat :=
  row.rs2Next.limb0.toNat * row.quotient.limb2.toNat +
    row.rs2Next.limb1.toNat * row.quotient.limb1.toNat +
    row.rs2Next.limb2.toNat * row.quotient.limb0.toNat +
    row.remainder.limb2.toNat

def divConv3 (row : DivRow) : Nat :=
  row.rs2Next.limb0.toNat * row.quotient.limb3.toNat +
    row.rs2Next.limb1.toNat * row.quotient.limb2.toNat +
    row.rs2Next.limb2.toNat * row.quotient.limb1.toNat +
    row.rs2Next.limb3.toNat * row.quotient.limb0.toNat +
    row.remainder.limb3.toNat

def divConv4 (row : DivRow) : Nat :=
  row.rs2Next.limb0.toNat * divQuotientHigh row +
    row.rs2Next.limb1.toNat * row.quotient.limb3.toNat +
    row.rs2Next.limb2.toNat * row.quotient.limb2.toNat +
    row.rs2Next.limb3.toNat * row.quotient.limb1.toNat +
    divDivisorHigh row * row.quotient.limb0.toNat +
    divRemainderHigh row

def divConv5 (row : DivRow) : Nat :=
  row.rs2Next.limb0.toNat * divQuotientHigh row +
    row.rs2Next.limb1.toNat * divQuotientHigh row +
    row.rs2Next.limb2.toNat * row.quotient.limb3.toNat +
    row.rs2Next.limb3.toNat * row.quotient.limb2.toNat +
    divDivisorHigh row * row.quotient.limb0.toNat +
    divDivisorHigh row * row.quotient.limb1.toNat +
    divRemainderHigh row

def divConv6 (row : DivRow) : Nat :=
  row.rs2Next.limb0.toNat * divQuotientHigh row +
    row.rs2Next.limb1.toNat * divQuotientHigh row +
    row.rs2Next.limb2.toNat * divQuotientHigh row +
    row.rs2Next.limb3.toNat * row.quotient.limb3.toNat +
    divDivisorHigh row * row.quotient.limb0.toNat +
    divDivisorHigh row * row.quotient.limb1.toNat +
    divDivisorHigh row * row.quotient.limb2.toNat +
    divRemainderHigh row

def divConv7 (row : DivRow) : Nat :=
  row.rs2Next.limb0.toNat * divQuotientHigh row +
    row.rs2Next.limb1.toNat * divQuotientHigh row +
    row.rs2Next.limb2.toNat * divQuotientHigh row +
    row.rs2Next.limb3.toNat * divQuotientHigh row +
    divDivisorHigh row * row.quotient.limb0.toNat +
    divDivisorHigh row * row.quotient.limb1.toNat +
    divDivisorHigh row * row.quotient.limb2.toNat +
    divDivisorHigh row * row.quotient.limb3.toNat +
    divRemainderHigh row

def divConvSum (row : DivRow) : Nat :=
  divConv0 row +
    256 * divConv1 row +
    65536 * divConv2 row +
    16777216 * divConv3 row +
    4294967296 * divConv4 row +
    1099511627776 * divConv5 row +
    281474976710656 * divConv6 row +
    72057594037927936 * divConv7 row

/-! ## The high-to-low magnitude comparison

`diffs[limb] = (1 - 2 * c_sign) * (rs2_next[limb] - r_abs[limb])`. The scan
requires the highest differing limb to make this positive, which compares
`|remainder| < |divisor|` in both divisor-sign directions. -/

def divCompareDiff (row : DivRow) (divisorLimb absLimb : Byte) : Int :=
  if row.cSign then (absLimb.toNat : Int) - (divisorLimb.toNat : Int)
  else (divisorLimb.toNat : Int) - (absLimb.toNat : Int)

def divCompareDiff0 (row : DivRow) : Int :=
  divCompareDiff row row.rs2Next.limb0 row.remainderAbs.limb0

def divCompareDiff1 (row : DivRow) : Int :=
  divCompareDiff row row.rs2Next.limb1 row.remainderAbs.limb1

def divCompareDiff2 (row : DivRow) : Int :=
  divCompareDiff row row.rs2Next.limb2 row.remainderAbs.limb2

def divCompareDiff3 (row : DivRow) : Int :=
  divCompareDiff row row.rs2Next.limb3 row.remainderAbs.limb3

/-! ## The committed result -/

/-- `result[limb] = is_division * q[limb] + (1 - is_division) * r[limb]`. -/
def divResultBytes (row : DivRow) : WordBytes :=
  if row.isDivision then row.quotient else row.remainder

/-! ## The constraint system -/

/-- Every residual, lookup range and inverse witness of the production DIV
family, transcribed one field per production fact. Field-order groups follow
the emission order of `evaluate` and `lookups` in `div.zig`. -/
structure DivHolds (row : DivRow) : Prop where
  /-- The placement residual `active - is_active` together with the four
  selector booleanity residuals: exactly one selector is set. -/
  selectorUnique :
    row.isDiv.toNat + row.isDivu.toNat + row.isRem.toNat + row.isRemu.toNat = 1
  /-- Booleanity of `special_case = zero_divisor + r_zero`. -/
  specialExclusive : row.zeroDivisor = true → row.rZero = false
  /-- `zero_divisor * rs2_next[limb] = 0`. -/
  zeroDivisorLimb0 : row.zeroDivisor = true → row.rs2Next.limb0 = 0
  zeroDivisorLimb1 : row.zeroDivisor = true → row.rs2Next.limb1 = 0
  zeroDivisorLimb2 : row.zeroDivisor = true → row.rs2Next.limb2 = 0
  zeroDivisorLimb3 : row.zeroDivisor = true → row.rs2Next.limb3 = 0
  /-- `zero_divisor * (q[limb] - 255) = 0`: the all-ones quotient. -/
  zeroDivisorQuotient0 : row.zeroDivisor = true → row.quotient.limb0 = 255
  zeroDivisorQuotient1 : row.zeroDivisor = true → row.quotient.limb1 = 255
  zeroDivisorQuotient2 : row.zeroDivisor = true → row.quotient.limb2 = 255
  zeroDivisorQuotient3 : row.zeroDivisor = true → row.quotient.limb3 = 255
  /-- `c_sum_inv` witnesses a nonzero divisor limb sum off the zero-divisor
  branch. -/
  divisorNonzero : row.zeroDivisor = false → row.rs2Next.value ≠ 0
  /-- `r_zero * r[limb] = 0`. -/
  remainderZeroLimb0 : row.rZero = true → row.remainder.limb0 = 0
  remainderZeroLimb1 : row.rZero = true → row.remainder.limb1 = 0
  remainderZeroLimb2 : row.rZero = true → row.remainder.limb2 = 0
  remainderZeroLimb3 : row.rZero = true → row.remainder.limb3 = 0
  /-- `r_sum_inv` witnesses a nonzero remainder off both special branches. -/
  remainderNonzero :
    row.zeroDivisor = false → row.rZero = false → row.remainder.value ≠ 0
  /-- `(1 - is_signed) * b_sign = 0` and `(1 - is_signed) * c_sign = 0`. -/
  unsignedDividendSign : row.isSigned = false → row.bSign = false
  unsignedDivisorSign : row.isSigned = false → row.cSign = false
  /-- `sign_xor = b_sign + c_sign - 2 * b_sign * c_sign`. -/
  signXorDefinition : row.signXor = (row.bSign != row.cSign)
  /-- `(1 - zero_divisor) * q_sum * (q_sign - sign_xor) = 0`. -/
  quotientSignMatches :
    row.zeroDivisor = false → row.quotient.value ≠ 0 → row.qSign = row.signXor
  /-- `(1 - zero_divisor) * (q_sign - sign_xor) * q_sign = 0`. -/
  quotientSignImpliesXor :
    row.zeroDivisor = false → row.qSign = true → row.signXor = true
  /-- `zero_divisor * (q_sign - is_signed) = 0`. -/
  zeroDivisorQuotientSign :
    row.zeroDivisor = true → row.qSign = row.isSigned
  /-- `(1 - sign_xor) * (r_abs[limb] - r[limb]) = 0`. -/
  absSameLimb0 : row.signXor = false → row.remainderAbs.limb0 = row.remainder.limb0
  absSameLimb1 : row.signXor = false → row.remainderAbs.limb1 = row.remainder.limb1
  absSameLimb2 : row.signXor = false → row.remainderAbs.limb2 = row.remainder.limb2
  absSameLimb3 : row.signXor = false → row.remainderAbs.limb3 = row.remainder.limb3
  /-- The two's complement negation chain used when `sign_xor = 1`. The three
  residuals per limb pin each carry to a bit, force a zero carry to zero the
  absolute limb, and (through `r_inv`) exclude the value `256`. -/
  negationRecurrence :
    row.signXor = true →
      ∃ n0 n1 n2 n3 : Bool,
        row.remainder.limb0.toNat + row.remainderAbs.limb0.toNat =
            256 * n0.toNat ∧
        n0.toNat + row.remainder.limb1.toNat + row.remainderAbs.limb1.toNat =
            256 * n1.toNat ∧
        n1.toNat + row.remainder.limb2.toNat + row.remainderAbs.limb2.toNat =
            256 * n2.toNat ∧
        n2.toNat + row.remainder.limb3.toNat + row.remainderAbs.limb3.toNat =
            256 * n3.toNat ∧
        (n0 = false → row.remainderAbs.limb0 = 0) ∧
        (n1 = false → row.remainderAbs.limb1 = 0) ∧
        (n2 = false → row.remainderAbs.limb2 = 0) ∧
        (n3 = false → row.remainderAbs.limb3 = 0) ∧
        (n1 = n0 ∨ n1 = true) ∧
        (n2 = n1 ∨ n2 = true) ∧
        (n3 = n2 ∨ n3 = true)
  /-- The eight `product_carries` residuals with their `range_check_8_11`
  carry components. This is the AIR's proof that
  `divisor * quotient + remainder = dividend` over sign-extended limbs. -/
  productRecurrence :
    ∃ k0 k1 k2 k3 k4 k5 k6 k7 : Nat,
      k0 < 2048 ∧ k1 < 2048 ∧ k2 < 2048 ∧ k3 < 2048 ∧
      k4 < 2048 ∧ k5 < 2048 ∧ k6 < 2048 ∧ k7 < 2048 ∧
      divConv0 row = row.rs1Next.limb0.toNat + 256 * k0 ∧
      k0 + divConv1 row = row.rs1Next.limb1.toNat + 256 * k1 ∧
      k1 + divConv2 row = row.rs1Next.limb2.toNat + 256 * k2 ∧
      k2 + divConv3 row = row.rs1Next.limb3.toNat + 256 * k3 ∧
      k3 + divConv4 row = divDividendHigh row + 256 * k4 ∧
      k4 + divConv5 row = divDividendHigh row + 256 * k5 ∧
      k5 + divConv6 row = divDividendHigh row + 256 * k6 ∧
      k6 + divConv7 row = divDividendHigh row + 256 * k7
  /-- `sign_range`: `2 * is_signed * (rs1_next[3] - 128 * b_sign)` is a byte,
  which pins `b_sign` to the dividend's top bit on signed rows. -/
  dividendSignBit :
    row.isSigned = true →
      row.bSign = decide (128 ≤ row.rs1Next.limb3.toNat)
  /-- `sign_range`, second component: `c_sign` is the divisor's top bit. -/
  divisorSignBit :
    row.isSigned = true →
      row.cSign = decide (128 ≤ row.rs2Next.limb3.toNat)
  /-- `quotient_sign_range`: on a signed row with a nonzero divisor that is not
  the both-negative class, `q[3] - 128 * q_sign` fits in seven bits, pinning
  `q_sign` to the quotient's top bit. -/
  quotientSignBit :
    row.isSigned = true →
      row.zeroDivisor = false →
      ¬(row.bSign = true ∧ row.cSign = true) →
      row.qSign = decide (128 ≤ row.quotient.limb3.toNat)
  /-- `active * (1 - prefixes[0]) = 0` with all markers and `special_case`
  boolean: exactly one of the five scan participants is set. -/
  scanTotal :
    row.zeroDivisor.toNat + row.rZero.toNat +
        row.ltMarker3.toNat + row.ltMarker2.toNat +
        row.ltMarker1.toNat + row.ltMarker0.toNat = 1
  /-- `(1 - prefixes[limb]) * diffs[limb] = 0`, high limb first. -/
  scanEqual3 :
    row.zeroDivisor = false → row.rZero = false → row.ltMarker3 = false →
      divCompareDiff3 row = 0
  scanEqual2 :
    row.zeroDivisor = false → row.rZero = false → row.ltMarker3 = false →
      row.ltMarker2 = false → divCompareDiff2 row = 0
  scanEqual1 :
    row.zeroDivisor = false → row.rZero = false → row.ltMarker3 = false →
      row.ltMarker2 = false → row.ltMarker1 = false → divCompareDiff1 row = 0
  scanEqual0 :
    row.zeroDivisor = false → row.rZero = false → row.ltMarker3 = false →
      row.ltMarker2 = false → row.ltMarker1 = false → row.ltMarker0 = false →
      divCompareDiff0 row = 0
  /-- `lt_markers[limb] * (lt_diff - diffs[limb]) = 0`. -/
  scanMarker3 : row.ltMarker3 = true → (row.ltDiff : Int) = divCompareDiff3 row
  scanMarker2 : row.ltMarker2 = true → (row.ltDiff : Int) = divCompareDiff2 row
  scanMarker1 : row.ltMarker1 = true → (row.ltDiff : Int) = divCompareDiff1 row
  scanMarker0 : row.ltMarker0 = true → (row.ltDiff : Int) = divCompareDiff0 row
  /-- `positive_remainder_diff`: `lt_diff - 1` is a `range_check_20` value off
  the special branches. -/
  ltDiffLower : row.zeroDivisor = false → row.rZero = false → 1 ≤ row.ltDiff
  ltDiffUpper :
    row.zeroDivisor = false → row.rZero = false → row.ltDiff ≤ 1048576
  /-- `destinationConstraints`: the write-enable witness is exact. -/
  destinationFlag : row.destinationNonzero = decide (row.rd ≠ zeroRegister)
  /-- `destinationResultConstraints`. -/
  destinationLimb0 :
    row.rdNext.limb0 =
      if row.destinationNonzero then (divResultBytes row).limb0 else 0
  destinationLimb1 :
    row.rdNext.limb1 =
      if row.destinationNonzero then (divResultBytes row).limb1 else 0
  destinationLimb2 :
    row.rdNext.limb2 =
      if row.destinationNonzero then (divResultBytes row).limb2 else 0
  destinationLimb3 :
    row.rdNext.limb3 =
      if row.destinationNonzero then (divResultBytes row).limb3 else 0
  /-- `readOnlyAccessConstraints` for both source registers. -/
  sourceOneLimb0 : row.rs1Next.limb0 = row.rs1Previous.limb0
  sourceOneLimb1 : row.rs1Next.limb1 = row.rs1Previous.limb1
  sourceOneLimb2 : row.rs1Next.limb2 = row.rs1Previous.limb2
  sourceOneLimb3 : row.rs1Next.limb3 = row.rs1Previous.limb3
  sourceTwoLimb0 : row.rs2Next.limb0 = row.rs2Previous.limb0
  sourceTwoLimb1 : row.rs2Next.limb1 = row.rs2Previous.limb1
  sourceTwoLimb2 : row.rs2Next.limb2 = row.rs2Previous.limb2
  sourceTwoLimb3 : row.rs2Next.limb3 = row.rs2Previous.limb3
  /-- The access-chain clock gaps, `range_check_20` on `next - previous - 1`. -/
  clockPositive : 0 < row.clock
  sourceOneClock :
    validPreviousClock row.rs1PreviousClock (accessClock row.clock 1)
  sourceTwoClock :
    validPreviousClock row.rs2PreviousClock (accessClock row.clock 2)
  destinationClock :
    validPreviousClock row.rdPreviousClock (accessClock row.clock 3)
  /-- The emitted `registers_state` program counter. -/
  nextPcResult : row.claimedNextPc = nextPc row.pc

/-! ## Retirement, program tuple and relation tuples -/

/-- `programLookup`: the opcode identifier selected by the four flags. -/
def divOpcodeId (row : DivRow) : Nat :=
  if row.isDiv then 41
  else if row.isDivu then 42
  else if row.isRem then 43
  else 44

def divRetirement (row : DivRow) : Retirement where
  nextPc := row.claimedNextPc
  write := architecturalWrite row.rd row.rdNext.word
  read := none
  store := none

def divProgramTuple (row : DivRow) : ProgramTuple where
  pc := row.pc
  opcodeId := divOpcodeId row
  rd := row.rd.toNat
  rs1 := row.rs1.toNat
  operand := row.rs2.toNat

structure DivRelations where
  program : ProgramTuple
  stateConsume : StateTuple
  stateEmit : StateTuple
  sourceOneConsume : RegisterTuple
  sourceOneEmit : RegisterTuple
  sourceTwoConsume : RegisterTuple
  sourceTwoEmit : RegisterTuple
  destinationConsume : RegisterTuple
  destinationEmit : RegisterTuple
deriving DecidableEq, Repr

def divRelations (row : DivRow) : DivRelations where
  program := divProgramTuple row
  stateConsume := { pc := row.pc, clock := row.clock }
  stateEmit := { pc := nextPc row.pc, clock := row.clock + 1 }
  sourceOneConsume := {
    addr := row.rs1
    clock := row.rs1PreviousClock
    value := row.rs1Previous.word
  }
  sourceOneEmit := {
    addr := row.rs1
    clock := accessClock row.clock 1
    value := row.rs1Next.word
  }
  sourceTwoConsume := {
    addr := row.rs2
    clock := row.rs2PreviousClock
    value := row.rs2Previous.word
  }
  sourceTwoEmit := {
    addr := row.rs2
    clock := accessClock row.clock 2
    value := row.rs2Next.word
  }
  destinationConsume := {
    addr := row.rd
    clock := row.rdPreviousClock
    value := row.rdPrevious.word
  }
  destinationEmit := {
    addr := row.rd
    clock := accessClock row.clock 3
    value := row.rdNext.word
  }

/-! ## Derived facts

Everything below is *derived* from `DivHolds`. No fact in this section is a new
hypothesis, and in particular nothing here presumes that the committed quotient
or remainder is architecturally correct. -/

/-- Pure ring identity: the eight-limb product of the sign-extended operands
splits into the eight truncated convolution limbs plus a multiple of `2 ^ 64`. -/
theorem div_conv_expand (row : DivRow) :
    divExtendedValue row.rs2Next (divDivisorHigh row) *
          divExtendedValue row.quotient (divQuotientHigh row) +
        divExtendedValue row.remainder (divRemainderHigh row) =
      divConvSum row +
        18446744073709551616 *
          (divDivisorHigh row *
              (row.quotient.limb1.toNat + 257 * row.quotient.limb2.toNat +
                65793 * row.quotient.limb3.toNat) +
            divQuotientHigh row *
              (row.rs2Next.limb1.toNat + 257 * row.rs2Next.limb2.toNat +
                65793 * row.rs2Next.limb3.toNat) +
            283686952174081 * divDivisorHigh row * divQuotientHigh row) := by
  simp only [divExtendedValue, divConvSum, divConv0, divConv1, divConv2,
    divConv3, divConv4, divConv5, divConv6, divConv7, WordBytes.value]
  grind

/-- Telescoping the eight `product_carries` residuals. -/
theorem div_conv_sum_telescope (row : DivRow) (holds : DivHolds row) :
    ∃ overflow : Nat,
      divConvSum row =
        divExtendedValue row.rs1Next (divDividendHigh row) +
          18446744073709551616 * overflow := by
  obtain ⟨k0, k1, k2, k3, k4, k5, k6, k7,
    _, _, _, _, _, _, _, _, e0, e1, e2, e3, e4, e5, e6, e7⟩ :=
    holds.productRecurrence
  refine ⟨k7, ?_⟩
  simp only [divConvSum, divExtendedValue, WordBytes.value]
  omega

/-- The AIR's product chain, aggregated: over the sign-extended eight-limb
operands, `divisor * quotient + remainder` agrees with the dividend modulo
`2 ^ 64`. -/
theorem div_product_identity (row : DivRow) (holds : DivHolds row) :
    ∃ overflow : Nat,
      divExtendedValue row.rs2Next (divDivisorHigh row) *
            divExtendedValue row.quotient (divQuotientHigh row) +
          divExtendedValue row.remainder (divRemainderHigh row) =
        divExtendedValue row.rs1Next (divDividendHigh row) +
          18446744073709551616 * overflow := by
  obtain ⟨overflow, telescope⟩ := div_conv_sum_telescope row holds
  refine ⟨overflow +
    (divDivisorHigh row *
        (row.quotient.limb1.toNat + 257 * row.quotient.limb2.toNat +
          65793 * row.quotient.limb3.toNat) +
      divQuotientHigh row *
        (row.rs2Next.limb1.toNat + 257 * row.rs2Next.limb2.toNat +
          65793 * row.rs2Next.limb3.toNat) +
      283686952174081 * divDivisorHigh row * divQuotientHigh row), ?_⟩
  rw [div_conv_expand, telescope]
  grind

/-! ### Word-level bridges for the register bus -/

theorem div_source_one_word (row : DivRow) (holds : DivHolds row) :
    row.rs1Next.word = row.rs1Previous.word :=
  congrArg WordBytes.word <|
    WordBytes.eq_of_limbs row.rs1Next row.rs1Previous
      holds.sourceOneLimb0 holds.sourceOneLimb1
      holds.sourceOneLimb2 holds.sourceOneLimb3

theorem div_source_two_word (row : DivRow) (holds : DivHolds row) :
    row.rs2Next.word = row.rs2Previous.word :=
  congrArg WordBytes.word <|
    WordBytes.eq_of_limbs row.rs2Next row.rs2Previous
      holds.sourceTwoLimb0 holds.sourceTwoLimb1
      holds.sourceTwoLimb2 holds.sourceTwoLimb3

theorem div_destination_word (row : DivRow) (holds : DivHolds row) :
    row.rdNext.word = architecturalValue row.rd (divResultBytes row).word := by
  by_cases hzero : row.rd = zeroRegister
  · have hflag : row.destinationNonzero = false := by
      rw [holds.destinationFlag]; simp [hzero]
    rw [hzero, architecturalValue_zero]
    apply BitVec.eq_of_toNat_eq
    simp [WordBytes.word_toNat, WordBytes.value, holds.destinationLimb0,
      holds.destinationLimb1, holds.destinationLimb2, holds.destinationLimb3,
      hflag, zeroWord]
  · have hflag : row.destinationNonzero = true := by
      rw [holds.destinationFlag]; simp [hzero]
    rw [architecturalValue]
    simp only [hzero, ↓reduceIte]
    apply BitVec.eq_of_toNat_eq
    simp [WordBytes.word_toNat, WordBytes.value, holds.destinationLimb0,
      holds.destinationLimb1, holds.destinationLimb2, holds.destinationLimb3,
      hflag]

/-! ### Selector facts -/

/-- On an unsigned row every sign witness collapses. `b_sign` and `c_sign` are
forced by `(1 - is_signed) * sign = 0`; `sign_xor` follows from its definition;
`q_sign` follows from `(1 - zero_divisor) * (q_sign - sign_xor) * q_sign = 0`
off the zero-divisor branch and from `zero_divisor * (q_sign - is_signed) = 0`
on it. -/
theorem div_unsigned_signs (row : DivRow) (holds : DivHolds row)
    (unsigned : row.isSigned = false) :
    row.bSign = false ∧ row.cSign = false ∧
      row.signXor = false ∧ row.qSign = false := by
  have hb := holds.unsignedDividendSign unsigned
  have hc := holds.unsignedDivisorSign unsigned
  have hx : row.signXor = false := by
    rw [holds.signXorDefinition, hb, hc]; rfl
  refine ⟨hb, hc, hx, ?_⟩
  cases hzd : row.zeroDivisor with
  | true => rw [holds.zeroDivisorQuotientSign hzd, unsigned]
  | false =>
    cases hq : row.qSign with
    | false => rfl
    | true =>
      have := holds.quotientSignImpliesXor hzd hq
      rw [hx] at this
      exact absurd this (by simp)

theorem div_unsigned_extensions (row : DivRow) (holds : DivHolds row)
    (unsigned : row.isSigned = false) :
    divDividendHigh row = 0 ∧ divDivisorHigh row = 0 ∧
      divQuotientHigh row = 0 ∧ divRemainderHigh row = 0 := by
  obtain ⟨hb, hc, _, hq⟩ := div_unsigned_signs row holds unsigned
  refine ⟨?_, ?_, ?_, ?_⟩ <;>
    simp [divDividendHigh, divDivisorHigh, divQuotientHigh, divRemainderHigh,
      hb, hc, hq]

/-! ### The exact unsigned product identity

With every extension byte zero the eight-limb chain has no room for a
`2 ^ 64` overflow, so the aggregated identity holds over the integers. -/

theorem div_unsigned_exact (row : DivRow) (holds : DivHolds row)
    (unsigned : row.isSigned = false) :
    row.rs2Next.value * row.quotient.value + row.remainder.value =
      row.rs1Next.value := by
  obtain ⟨hbHigh, hcHigh, hqHigh, hrHigh⟩ :=
    div_unsigned_extensions row holds unsigned
  obtain ⟨overflow, identity⟩ := div_product_identity row holds
  rw [hbHigh, hcHigh, hqHigh, hrHigh] at identity
  simp only [divExtendedValue, Nat.mul_zero, Nat.add_zero] at identity
  have hc := row.rs2Next.value_lt
  have hq := row.quotient.value_lt
  have hr := row.remainder.value_lt
  have hb := row.rs1Next.value_lt
  simp only [Nat.reducePow] at hc hq hr hb
  have hprod :
      row.rs2Next.value * row.quotient.value ≤ 4294967295 * 4294967295 :=
    Nat.mul_le_mul (by omega) (by omega)
  generalize row.rs2Next.value * row.quotient.value = product at identity hprod
  omega

/-! ### The two's complement negation chain

When `sign_xor = 1` the row commits `r_abs` as the two's complement negation of
`r`. The three residuals per limb (carry bit, `(1 - carry) * r_abs = 0`, and the
`r_inv` witness excluding `256`) make the chain exact, and the carry
monotonicity residual makes the top carry the indicator of `r ≠ 0`. -/

theorem div_abs_negated (row : DivRow) (holds : DivHolds row)
    (negated : row.signXor = true) :
    ∃ top : Nat, top ≤ 1 ∧
      row.remainder.value + row.remainderAbs.value = 4294967296 * top ∧
      (top = 0 ↔ row.remainder.value = 0) := by
  obtain ⟨n0, n1, n2, n3, e0, e1, e2, e3, z0, z1, z2, z3, m1, m2, m3⟩ :=
    holds.negationRecurrence negated
  have zero0 : n0.toNat = 0 → row.remainderAbs.limb0.toNat = 0 := by
    intro h; cases n0 with
    | false => simp [z0 rfl]
    | true => simp at h
  have zero1 : n1.toNat = 0 → row.remainderAbs.limb1.toNat = 0 := by
    intro h; cases n1 with
    | false => simp [z1 rfl]
    | true => simp at h
  have zero2 : n2.toNat = 0 → row.remainderAbs.limb2.toNat = 0 := by
    intro h; cases n2 with
    | false => simp [z2 rfl]
    | true => simp at h
  have zero3 : n3.toNat = 0 → row.remainderAbs.limb3.toNat = 0 := by
    intro h; cases n3 with
    | false => simp [z3 rfl]
    | true => simp at h
  have mono1 : n1.toNat = n0.toNat ∨ n1.toNat = 1 := by
    rcases m1 with h | h <;> simp [h]
  have mono2 : n2.toNat = n1.toNat ∨ n2.toNat = 1 := by
    rcases m2 with h | h <;> simp [h]
  have mono3 : n3.toNat = n2.toNat ∨ n3.toNat = 1 := by
    rcases m3 with h | h <;> simp [h]
  have bit0 : n0.toNat ≤ 1 := by cases n0 <;> simp
  have bit1 : n1.toNat ≤ 1 := by cases n1 <;> simp
  have bit2 : n2.toNat ≤ 1 := by cases n2 <;> simp
  have bit3 : n3.toNat ≤ 1 := by cases n3 <;> simp
  have r0 := row.remainder.limb0.isLt
  have r1 := row.remainder.limb1.isLt
  have r2 := row.remainder.limb2.isLt
  have r3 := row.remainder.limb3.isLt
  have a0 := row.remainderAbs.limb0.isLt
  have a1 := row.remainderAbs.limb1.isLt
  have a2 := row.remainderAbs.limb2.isLt
  have a3 := row.remainderAbs.limb3.isLt
  simp only [Nat.reducePow] at r0 r1 r2 r3 a0 a1 a2 a3
  refine ⟨n3.toNat, bit3, ?_, ?_⟩ <;> simp only [WordBytes.value] <;> omega

/-! ### The high-to-low magnitude scan -/

/-- The five scan participants, orientation-free. Exactly one of them is set,
`lt_diff` records the difference at the set marker, and every limb above the
set marker has a zero difference. -/
theorem div_scan_facts (row : DivRow) (holds : DivHolds row)
    (hzd : row.zeroDivisor = false) (hrz : row.rZero = false) :
    (row.ltMarker3.toNat = 0 ∧ divCompareDiff3 row = 0 ∨
        row.ltMarker3.toNat = 1 ∧ (row.ltDiff : Int) = divCompareDiff3 row) ∧
      (row.ltMarker2.toNat = 1 ∧ (row.ltDiff : Int) = divCompareDiff2 row ∨
        row.ltMarker2.toNat = 0 ∧ row.ltMarker3.toNat = 1 ∨
        row.ltMarker2.toNat = 0 ∧ row.ltMarker3.toNat = 0 ∧
          divCompareDiff2 row = 0) ∧
      (row.ltMarker1.toNat = 1 ∧ (row.ltDiff : Int) = divCompareDiff1 row ∨
        row.ltMarker1.toNat = 0 ∧
          1 ≤ row.ltMarker3.toNat + row.ltMarker2.toNat ∨
        row.ltMarker1.toNat = 0 ∧ row.ltMarker3.toNat = 0 ∧
          row.ltMarker2.toNat = 0 ∧ divCompareDiff1 row = 0) ∧
      (row.ltMarker0.toNat = 1 ∧ (row.ltDiff : Int) = divCompareDiff0 row ∨
        row.ltMarker0.toNat = 0 ∧
          1 ≤ row.ltMarker3.toNat + row.ltMarker2.toNat +
            row.ltMarker1.toNat ∨
        row.ltMarker0.toNat = 0 ∧ row.ltMarker3.toNat = 0 ∧
          row.ltMarker2.toNat = 0 ∧ row.ltMarker1.toNat = 0 ∧
          divCompareDiff0 row = 0) := by
  refine ⟨?_, ?_, ?_, ?_⟩
  · cases h3 : row.ltMarker3 with
    | false => exact Or.inl ⟨by simp, holds.scanEqual3 hzd hrz h3⟩
    | true => exact Or.inr ⟨by simp, holds.scanMarker3 h3⟩
  · cases h2 : row.ltMarker2 with
    | true => exact Or.inl ⟨by simp, holds.scanMarker2 h2⟩
    | false =>
      cases h3 : row.ltMarker3 with
      | true => exact Or.inr (Or.inl ⟨by simp, by simp⟩)
      | false =>
        exact Or.inr (Or.inr
          ⟨by simp, by simp, holds.scanEqual2 hzd hrz h3 h2⟩)
  · cases h1 : row.ltMarker1 with
    | true => exact Or.inl ⟨by simp, holds.scanMarker1 h1⟩
    | false =>
      cases h3 : row.ltMarker3 with
      | true =>
        exact Or.inr (Or.inl
          ⟨by simp, by simp only [Bool.toNat_true]; omega⟩)
      | false =>
        cases h2 : row.ltMarker2 with
        | true =>
          exact Or.inr (Or.inl
            ⟨by simp, by simp only [Bool.toNat_true]; omega⟩)
        | false =>
          exact Or.inr (Or.inr ⟨by simp, by simp, by simp,
            holds.scanEqual1 hzd hrz h3 h2 h1⟩)
  · cases h0 : row.ltMarker0 with
    | true => exact Or.inl ⟨by simp, holds.scanMarker0 h0⟩
    | false =>
      cases h3 : row.ltMarker3 with
      | true =>
        exact Or.inr (Or.inl
          ⟨by simp, by simp only [Bool.toNat_true]; omega⟩)
      | false =>
        cases h2 : row.ltMarker2 with
        | true =>
          exact Or.inr (Or.inl
            ⟨by simp, by simp only [Bool.toNat_true]; omega⟩)
        | false =>
          cases h1 : row.ltMarker1 with
          | true =>
            exact Or.inr (Or.inl
              ⟨by simp, by simp only [Bool.toNat_true]; omega⟩)
          | false =>
            exact Or.inr (Or.inr ⟨by simp, by simp, by simp,
              by simp, holds.scanEqual0 hzd hrz h3 h2 h1 h0⟩)

/-- Off both special branches the scan proves a strict unsigned comparison in
the direction selected by the divisor sign. -/
theorem div_compare_positive (row : DivRow) (holds : DivHolds row)
    (hzd : row.zeroDivisor = false) (hrz : row.rZero = false)
    (hc : row.cSign = false) :
    row.remainderAbs.value < row.rs2Next.value := by
  obtain ⟨f3, f2, f1, f0⟩ := div_scan_facts row holds hzd hrz
  have total := holds.scanTotal
  rw [hzd, hrz] at total
  have lower := holds.ltDiffLower hzd hrz
  have c0 := row.rs2Next.limb0.isLt
  have c1 := row.rs2Next.limb1.isLt
  have c2 := row.rs2Next.limb2.isLt
  have c3 := row.rs2Next.limb3.isLt
  have a0 := row.remainderAbs.limb0.isLt
  have a1 := row.remainderAbs.limb1.isLt
  have a2 := row.remainderAbs.limb2.isLt
  have a3 := row.remainderAbs.limb3.isLt
  simp only [Nat.reducePow] at c0 c1 c2 c3 a0 a1 a2 a3
  simp only [divCompareDiff0, divCompareDiff1, divCompareDiff2,
    divCompareDiff3, divCompareDiff, hc, Bool.false_eq_true,
    ↓reduceIte] at f0 f1 f2 f3
  simp only [Bool.toNat_false, Nat.zero_add] at total
  simp only [WordBytes.value]
  omega

theorem div_compare_negative (row : DivRow) (holds : DivHolds row)
    (hzd : row.zeroDivisor = false) (hrz : row.rZero = false)
    (hc : row.cSign = true) :
    row.rs2Next.value < row.remainderAbs.value := by
  obtain ⟨f3, f2, f1, f0⟩ := div_scan_facts row holds hzd hrz
  have total := holds.scanTotal
  rw [hzd, hrz] at total
  have lower := holds.ltDiffLower hzd hrz
  have c0 := row.rs2Next.limb0.isLt
  have c1 := row.rs2Next.limb1.isLt
  have c2 := row.rs2Next.limb2.isLt
  have c3 := row.rs2Next.limb3.isLt
  have a0 := row.remainderAbs.limb0.isLt
  have a1 := row.remainderAbs.limb1.isLt
  have a2 := row.remainderAbs.limb2.isLt
  have a3 := row.remainderAbs.limb3.isLt
  simp only [Nat.reducePow] at c0 c1 c2 c3 a0 a1 a2 a3
  simp only [divCompareDiff0, divCompareDiff1, divCompareDiff2,
    divCompareDiff3, divCompareDiff, hc, ↓reduceIte] at f0 f1 f2 f3
  simp only [Bool.toNat_false, Nat.zero_add] at total
  simp only [WordBytes.value]
  omega

/-! ### The zero-divisor branch -/

theorem div_zero_divisor_facts (row : DivRow) (holds : DivHolds row)
    (hzd : row.zeroDivisor = true) :
    row.rs2Next.value = 0 ∧ row.quotient.value = 4294967295 ∧
      row.remainder.value = row.rs1Next.value := by
  have l0 := holds.zeroDivisorLimb0 hzd
  have l1 := holds.zeroDivisorLimb1 hzd
  have l2 := holds.zeroDivisorLimb2 hzd
  have l3 := holds.zeroDivisorLimb3 hzd
  have hval : row.rs2Next.value = 0 := by
    simp [WordBytes.value, l0, l1, l2, l3]
  refine ⟨hval, by
    simp [WordBytes.value, holds.zeroDivisorQuotient0 hzd,
      holds.zeroDivisorQuotient1 hzd, holds.zeroDivisorQuotient2 hzd,
      holds.zeroDivisorQuotient3 hzd], ?_⟩
  have hrz : row.rZero = false := holds.specialExclusive hzd
  have hcs : row.cSign = false := by
    cases hs : row.isSigned with
    | false => exact holds.unsignedDivisorSign hs
    | true => rw [holds.divisorSignBit hs, l3]; simp
  have hcHigh : divDivisorHigh row = 0 := by simp [divDivisorHigh, hcs]
  have hrHigh : divRemainderHigh row = divDividendHigh row := by
    simp [divRemainderHigh, divDividendHigh, hrz]
  obtain ⟨overflow, identity⟩ := div_product_identity row holds
  rw [hcHigh, hrHigh] at identity
  simp only [divExtendedValue, hval, Nat.mul_zero, Nat.add_zero,
    Nat.zero_add, Nat.zero_mul] at identity
  have hr := row.remainder.value_lt
  have hb := row.rs1Next.value_lt
  simp only [Nat.reducePow] at hr hb
  omega

/-! ### The signed reading of the committed limb groups -/

/-- A committed limb group read as a signed integer under an imposed sign
witness: `value - 2 ^ 32 * flag`. -/
def divSignedInt (bytes : WordBytes) (flag : Bool) : Int :=
  (bytes.value : Int) - 4294967296 * (flag.toNat : Int)

theorem div_extended_cast (bytes : WordBytes) (flag : Bool) :
    ((divExtendedValue bytes (255 * flag.toNat) : Nat) : Int) =
      divSignedInt bytes flag +
        18446744073709551616 * (flag.toNat : Int) := by
  cases flag <;> simp [divExtendedValue, divSignedInt] <;> omega

set_option maxRecDepth 8000 in
/-- The aggregated product chain, read over the integers: the signed readings
satisfy the division identity modulo `2 ^ 64`. -/
theorem div_signed_congruence (row : DivRow) (holds : DivHolds row) :
    ∃ n : Int,
      divSignedInt row.rs2Next row.cSign *
            divSignedInt row.quotient row.qSign +
          divSignedInt row.remainder (row.bSign && !row.rZero) =
        divSignedInt row.rs1Next row.bSign + 18446744073709551616 * n := by
  obtain ⟨overflow, identity⟩ := div_product_identity row holds
  have castIdentity :
      ((divExtendedValue row.rs2Next (divDivisorHigh row) *
            divExtendedValue row.quotient (divQuotientHigh row) +
          divExtendedValue row.remainder (divRemainderHigh row) : Nat) : Int) =
        ((divExtendedValue row.rs1Next (divDividendHigh row) +
          18446744073709551616 * overflow : Nat) : Int) :=
    congrArg (fun n : Nat => (n : Int)) identity
  simp only [Int.natCast_add, Int.natCast_mul] at castIdentity
  simp only [show ((18446744073709551616 : Nat) : Int) = 18446744073709551616
    from by simp] at castIdentity
  have hDivisor :
      ((divExtendedValue row.rs2Next (divDivisorHigh row) : Nat) : Int) =
        divSignedInt row.rs2Next row.cSign +
          18446744073709551616 * (row.cSign.toNat : Int) :=
    div_extended_cast row.rs2Next row.cSign
  have hQuotient :
      ((divExtendedValue row.quotient (divQuotientHigh row) : Nat) : Int) =
        divSignedInt row.quotient row.qSign +
          18446744073709551616 * (row.qSign.toNat : Int) :=
    div_extended_cast row.quotient row.qSign
  have hRemainder :
      ((divExtendedValue row.remainder (divRemainderHigh row) : Nat) : Int) =
        divSignedInt row.remainder (row.bSign && !row.rZero) +
          18446744073709551616 * ((row.bSign && !row.rZero).toNat : Int) :=
    div_extended_cast row.remainder (row.bSign && !row.rZero)
  have hDividend :
      ((divExtendedValue row.rs1Next (divDividendHigh row) : Nat) : Int) =
        divSignedInt row.rs1Next row.bSign +
          18446744073709551616 * (row.bSign.toNat : Int) :=
    div_extended_cast row.rs1Next row.bSign
  rw [hDivisor, hQuotient, hRemainder, hDividend] at castIdentity
  refine ⟨(row.bSign.toNat : Int) + (overflow : Int) -
    ((row.bSign && !row.rZero).toNat : Int) -
    (row.cSign.toNat : Int) * divSignedInt row.quotient row.qSign -
    (row.qSign.toNat : Int) * divSignedInt row.rs2Next row.cSign -
    18446744073709551616 * (row.cSign.toNat : Int) * (row.qSign.toNat : Int),
    ?_⟩
  grind

/-! ### The exact signed division identity

The congruence above is lifted to an exact integer identity by the sign
lookups, which bound the divisor magnitude by `2 ^ 31`, and by the byte ranges,
which bound the quotient magnitude by `2 ^ 32`. Their product cannot reach
`2 ^ 64`, so the `2 ^ 64` multiple must vanish. -/

theorem div_signed_bound (bytes : WordBytes) (flag : Bool) :
    (divSignedInt bytes flag).natAbs ≤ 4294967296 := by
  have h := bytes.value_lt
  simp only [Nat.reducePow] at h
  cases flag <;> simp [divSignedInt] <;> omega

theorem div_signed_bound_of_msb (bytes : WordBytes) (flag : Bool)
    (msb : flag = decide (128 ≤ bytes.limb3.toNat)) :
    (divSignedInt bytes flag).natAbs ≤ 2147483648 := by
  have b0 := bytes.limb0.isLt
  have b1 := bytes.limb1.isLt
  have b2 := bytes.limb2.isLt
  have b3 := bytes.limb3.isLt
  simp only [Nat.reducePow] at b0 b1 b2 b3
  by_cases h : 128 ≤ bytes.limb3.toNat
  · have : flag = true := by rw [msb]; simp [h]
    simp only [this, divSignedInt, WordBytes.value, Bool.toNat_true]
    omega
  · have : flag = false := by rw [msb]; simp [h]
    simp only [this, divSignedInt, WordBytes.value, Bool.toNat_false]
    omega

theorem div_signed_identity (row : DivRow) (holds : DivHolds row)
    (signed : row.isSigned = true) :
    divSignedInt row.rs2Next row.cSign *
          divSignedInt row.quotient row.qSign +
        divSignedInt row.remainder (row.bSign && !row.rZero) =
      divSignedInt row.rs1Next row.bSign := by
  obtain ⟨n, congruence⟩ := div_signed_congruence row holds
  have hDivisor :=
    div_signed_bound_of_msb row.rs2Next row.cSign (holds.divisorSignBit signed)
  have hDividend :=
    div_signed_bound_of_msb row.rs1Next row.bSign (holds.dividendSignBit signed)
  have hQuotient := div_signed_bound row.quotient row.qSign
  have hRemainder :=
    div_signed_bound row.remainder (row.bSign && !row.rZero)
  have hProduct :
      (divSignedInt row.rs2Next row.cSign *
          divSignedInt row.quotient row.qSign).natAbs ≤
        9223372036854775808 := by
    rw [Int.natAbs_mul]
    exact Nat.mul_le_mul hDivisor hQuotient
  generalize hp : divSignedInt row.rs2Next row.cSign *
    divSignedInt row.quotient row.qSign = product at congruence hProduct
  omega

/-! ### Selector case analysis -/

theorem div_selector_cases (row : DivRow) (holds : DivHolds row) :
    (row.isDiv = true ∧ row.isDivu = false ∧ row.isRem = false ∧
        row.isRemu = false) ∨
      (row.isDiv = false ∧ row.isDivu = true ∧ row.isRem = false ∧
        row.isRemu = false) ∨
      (row.isDiv = false ∧ row.isDivu = false ∧ row.isRem = true ∧
        row.isRemu = false) ∨
      (row.isDiv = false ∧ row.isDivu = false ∧ row.isRem = false ∧
        row.isRemu = true) := by
  have unique := holds.selectorUnique
  cases hd : row.isDiv <;> cases hdu : row.isDivu <;> cases hr : row.isRem <;>
    cases hru : row.isRemu <;> rw [hd, hdu, hr, hru] at unique <;> simp_all

theorem div_opcode_id_div (row : DivRow) (holds : DivHolds row)
    (selector : row.isDiv = true) : divOpcodeId row = 41 := by
  rcases div_selector_cases row holds with
    ⟨a, b, c, d⟩ | ⟨a, b, c, d⟩ | ⟨a, b, c, d⟩ | ⟨a, b, c, d⟩ <;>
    simp_all [divOpcodeId]

theorem div_opcode_id_divu (row : DivRow) (holds : DivHolds row)
    (selector : row.isDivu = true) : divOpcodeId row = 42 := by
  rcases div_selector_cases row holds with
    ⟨a, b, c, d⟩ | ⟨a, b, c, d⟩ | ⟨a, b, c, d⟩ | ⟨a, b, c, d⟩ <;>
    simp_all [divOpcodeId]

theorem div_opcode_id_rem (row : DivRow) (holds : DivHolds row)
    (selector : row.isRem = true) : divOpcodeId row = 43 := by
  rcases div_selector_cases row holds with
    ⟨a, b, c, d⟩ | ⟨a, b, c, d⟩ | ⟨a, b, c, d⟩ | ⟨a, b, c, d⟩ <;>
    simp_all [divOpcodeId]

theorem div_opcode_id_remu (row : DivRow) (holds : DivHolds row)
    (selector : row.isRemu = true) : divOpcodeId row = 44 := by
  rcases div_selector_cases row holds with
    ⟨a, b, c, d⟩ | ⟨a, b, c, d⟩ | ⟨a, b, c, d⟩ | ⟨a, b, c, d⟩ <;>
    simp_all [divOpcodeId]

theorem div_flags_div (row : DivRow) (_holds : DivHolds row)
    (selector : row.isDiv = true) :
    row.isSigned = true ∧ row.isDivision = true := by
  constructor <;> simp [DivRow.isSigned, DivRow.isDivision, selector]

theorem div_flags_divu (row : DivRow) (holds : DivHolds row)
    (selector : row.isDivu = true) :
    row.isSigned = false ∧ row.isDivision = true := by
  rcases div_selector_cases row holds with
    ⟨h, _, _, _⟩ | ⟨h1, _, h3, _⟩ | ⟨_, h, _, _⟩ | ⟨_, h, _, _⟩ <;>
    simp_all [DivRow.isSigned, DivRow.isDivision]

theorem div_flags_rem (row : DivRow) (holds : DivHolds row)
    (selector : row.isRem = true) :
    row.isSigned = true ∧ row.isDivision = false := by
  rcases div_selector_cases row holds with
    ⟨_, _, h, _⟩ | ⟨_, _, h, _⟩ | ⟨h1, h2, _, _⟩ | ⟨_, _, h, _⟩ <;>
    simp_all [DivRow.isSigned, DivRow.isDivision]

theorem div_flags_remu (row : DivRow) (holds : DivHolds row)
    (selector : row.isRemu = true) :
    row.isSigned = false ∧ row.isDivision = false := by
  rcases div_selector_cases row holds with
    ⟨_, _, _, h⟩ | ⟨_, _, _, h⟩ | ⟨_, _, _, h⟩ | ⟨h1, h2, h3, _⟩ <;>
    simp_all [DivRow.isSigned, DivRow.isDivision]

/-! ### Word-level readings of the committed limb groups -/

theorem div_word_eq_zero_iff (bytes : WordBytes) :
    bytes.word = zeroWord ↔ bytes.value = 0 := by
  constructor
  · intro h
    have := congrArg BitVec.toNat h
    simpa [WordBytes.word_toNat, zeroWord] using this
  · intro h
    apply BitVec.eq_of_toNat_eq
    simp [WordBytes.word_toNat, h, zeroWord]

theorem div_unsigned_value_word (bytes : WordBytes) :
    Arith.unsignedValue bytes.word = bytes.value :=
  WordBytes.word_toNat bytes

/-- A limb group whose sign witness is its own top bit reads, under
`divSignedInt`, exactly as the architectural signed value of its word. -/
theorem div_signed_int_eq (bytes : WordBytes) (flag : Bool)
    (msb : flag = decide (128 ≤ bytes.limb3.toNat)) :
    divSignedInt bytes flag = Arith.signedValue bytes.word := by
  have b0 := bytes.limb0.isLt
  have b1 := bytes.limb1.isLt
  have b2 := bytes.limb2.isLt
  have b3 := bytes.limb3.isLt
  simp only [Nat.reducePow] at b0 b1 b2 b3
  rw [Arith.signedValue_eq_sub, WordBytes.word_toNat]
  by_cases h : 128 ≤ bytes.limb3.toNat
  · have hf : flag = true := by rw [msb]; simp [h]
    have hv : 2147483648 ≤ bytes.value := by
      simp only [WordBytes.value]; omega
    simp only [hf, divSignedInt, Bool.toNat_true, hv, ↓reduceIte]
    omega
  · have hf : flag = false := by rw [msb]; simp [h]
    have hv : ¬ (2147483648 ≤ bytes.value) := by
      simp only [WordBytes.value]; omega
    simp only [hf, divSignedInt, Bool.toNat_false, hv, ↓reduceIte]
    omega

/-! ### The unsigned architectural result -/

theorem div_unsigned_remainder_lt (row : DivRow) (holds : DivHolds row)
    (unsigned : row.isSigned = false) (hzd : row.zeroDivisor = false) :
    row.remainder.value < row.rs2Next.value := by
  obtain ⟨_, hc, hx, _⟩ := div_unsigned_signs row holds unsigned
  cases hrz : row.rZero with
  | true =>
    have : row.remainder.value = 0 := by
      simp [WordBytes.value, holds.remainderZeroLimb0 hrz,
        holds.remainderZeroLimb1 hrz, holds.remainderZeroLimb2 hrz,
        holds.remainderZeroLimb3 hrz]
    have := holds.divisorNonzero hzd
    omega
  | false =>
    have compare := div_compare_positive row holds hzd hrz hc
    have a0 := holds.absSameLimb0 hx
    have a1 := holds.absSameLimb1 hx
    have a2 := holds.absSameLimb2 hx
    have a3 := holds.absSameLimb3 hx
    have : row.remainderAbs.value = row.remainder.value := by
      simp [WordBytes.value, a0, a1, a2, a3]
    omega

theorem div_unsigned_result (row : DivRow) (holds : DivHolds row)
    (unsigned : row.isSigned = false) (hzd : row.zeroDivisor = false) :
    row.quotient.value = row.rs1Next.value / row.rs2Next.value ∧
      row.remainder.value = row.rs1Next.value % row.rs2Next.value :=
  Arith.div_mod_unique (div_unsigned_exact row holds unsigned)
    (div_unsigned_remainder_lt row holds unsigned hzd)

/-! ### The signed architectural result -/

theorem div_msb_value (bytes : WordBytes) (flag : Bool)
    (msb : flag = decide (128 ≤ bytes.limb3.toNat)) :
    (flag = true → 2147483648 ≤ bytes.value) ∧
      (flag = false → bytes.value < 2147483648) := by
  have b0 := bytes.limb0.isLt
  have b1 := bytes.limb1.isLt
  have b2 := bytes.limb2.isLt
  have b3 := bytes.limb3.isLt
  simp only [Nat.reducePow] at b0 b1 b2 b3
  by_cases h : 128 ≤ bytes.limb3.toNat
  · have hf : flag = true := by rw [msb]; simp [h]
    refine ⟨fun _ => ?_, fun hcontra => absurd (hf.symm.trans hcontra) (by simp)⟩
    simp only [WordBytes.value]; omega
  · have hf : flag = false := by rw [msb]; simp [h]
    refine ⟨fun hcontra => absurd (hf.symm.trans hcontra) (by simp), fun _ => ?_⟩
    simp only [WordBytes.value]; omega

/-- The AIR's comparison scan, read as the architectural remainder bound. -/
theorem div_signed_remainder_bound (row : DivRow) (holds : DivHolds row)
    (signed : row.isSigned = true) (hzd : row.zeroDivisor = false) :
    (divSignedInt row.remainder (row.bSign && !row.rZero)).natAbs <
      (divSignedInt row.rs2Next row.cSign).natAbs := by
  have divisorNonzero := holds.divisorNonzero hzd
  obtain ⟨cHigh, cLow⟩ :=
    div_msb_value row.rs2Next row.cSign (holds.divisorSignBit signed)
  have hC := row.rs2Next.value_lt
  have hR := row.remainder.value_lt
  have hA := row.remainderAbs.value_lt
  simp only [Nat.reducePow] at hC hR hA
  cases hrz : row.rZero with
  | true =>
    have hRzero : row.remainder.value = 0 := by
      simp [WordBytes.value, holds.remainderZeroLimb0 hrz,
        holds.remainderZeroLimb1 hrz, holds.remainderZeroLimb2 hrz,
        holds.remainderZeroLimb3 hrz]
    cases hc : row.cSign with
    | false =>
      have := cLow hc
      simp only [divSignedInt, Bool.not_true, Bool.and_false,
        Bool.toNat_false, hRzero]
      omega
    | true =>
      have := cHigh hc
      simp only [divSignedInt, Bool.not_true, Bool.and_false,
        Bool.toNat_false, Bool.toNat_true, hRzero]
      omega
  | false =>
    have hRnonzero := holds.remainderNonzero hzd hrz
    cases hb : row.bSign with
    | false =>
      cases hc : row.cSign with
      | false =>
        have hx : row.signXor = false := by
          rw [holds.signXorDefinition, hb, hc]; rfl
        have habs : row.remainderAbs.value = row.remainder.value := by
          simp [WordBytes.value, holds.absSameLimb0 hx, holds.absSameLimb1 hx,
            holds.absSameLimb2 hx, holds.absSameLimb3 hx]
        have compare := div_compare_positive row holds hzd hrz hc
        simp only [divSignedInt, Bool.false_and, Bool.toNat_false]
        omega
      | true =>
        have hx : row.signXor = true := by
          rw [holds.signXorDefinition, hb, hc]; rfl
        obtain ⟨top, htop, hsum, hiff⟩ := div_abs_negated row holds hx
        have compare := div_compare_negative row holds hzd hrz hc
        have := cHigh hc
        simp only [divSignedInt, Bool.false_and, Bool.toNat_false,
          Bool.toNat_true]
        omega
    | true =>
      cases hc : row.cSign with
      | false =>
        have hx : row.signXor = true := by
          rw [holds.signXorDefinition, hb, hc]; rfl
        obtain ⟨top, htop, hsum, hiff⟩ := div_abs_negated row holds hx
        have compare := div_compare_positive row holds hzd hrz hc
        have := cLow hc
        simp only [divSignedInt, Bool.not_false, Bool.and_true,
          Bool.toNat_true, Bool.toNat_false]
        omega
      | true =>
        have hx : row.signXor = false := by
          rw [holds.signXorDefinition, hb, hc]; rfl
        have habs : row.remainderAbs.value = row.remainder.value := by
          simp [WordBytes.value, holds.absSameLimb0 hx, holds.absSameLimb1 hx,
            holds.absSameLimb2 hx, holds.absSameLimb3 hx]
        have compare := div_compare_negative row holds hzd hrz hc
        have := cHigh hc
        simp only [divSignedInt, Bool.not_false, Bool.and_true,
          Bool.toNat_true]
        omega

/-- The committed quotient and remainder of a signed row with a nonzero divisor
are the truncating quotient and remainder of the architectural operands. The
derivation runs entirely through the row's own product recurrence, sign
lookups and comparison witnesses. -/
theorem div_signed_result (row : DivRow) (holds : DivHolds row)
    (signed : row.isSigned = true) (hzd : row.zeroDivisor = false) :
    divSignedInt row.quotient row.qSign =
        (Arith.signedValue row.rs1Next.word).tdiv
          (Arith.signedValue row.rs2Next.word) ∧
      divSignedInt row.remainder (row.bSign && !row.rZero) =
        (Arith.signedValue row.rs1Next.word).tmod
          (Arith.signedValue row.rs2Next.word) := by
  have hbeta :=
    div_signed_int_eq row.rs1Next row.bSign (holds.dividendSignBit signed)
  have hgamma :=
    div_signed_int_eq row.rs2Next row.cSign (holds.divisorSignBit signed)
  rw [← hbeta, ← hgamma]
  have identity := div_signed_identity row holds signed
  have bound := div_signed_remainder_bound row holds signed hzd
  have nonzero : divSignedInt row.rs2Next row.cSign ≠ 0 := by omega
  refine Arith.tdiv_tmod_unique nonzero identity (by omega) (by omega) ?_ ?_
  · intro hpos
    cases hb : row.bSign with
    | false =>
      have hR := row.remainder.value_lt
      simp only [Nat.reducePow] at hR
      simp only [divSignedInt, Bool.false_and, Bool.toNat_false]
      omega
    | true =>
      exfalso
      have hB := row.rs1Next.value_lt
      simp only [Nat.reducePow] at hB
      rw [divSignedInt, hb] at hpos
      simp only [Bool.toNat_true] at hpos
      omega
  · intro hneg
    cases hb : row.bSign with
    | true =>
      have hR := row.remainder.value_lt
      simp only [Nat.reducePow] at hR
      cases hrz : row.rZero with
      | true =>
        have hRzero : row.remainder.value = 0 := by
          simp [WordBytes.value, holds.remainderZeroLimb0 hrz,
            holds.remainderZeroLimb1 hrz, holds.remainderZeroLimb2 hrz,
            holds.remainderZeroLimb3 hrz]
        simp only [divSignedInt, Bool.not_true, Bool.and_false,
          Bool.toNat_false, hRzero]
        omega
      | false =>
        simp only [divSignedInt, Bool.not_false, Bool.and_true,
          Bool.toNat_true]
        omega
    | false =>
      rw [hb] at identity bound hneg
      have hzero : divSignedInt row.rs1Next false = 0 := by
        rw [divSignedInt] at hneg ⊢
        simp only [Bool.toNat_false] at hneg ⊢
        omega
      rw [hzero] at identity
      have hprod :
          (divSignedInt row.rs2Next row.cSign *
              divSignedInt row.quotient row.qSign).natAbs =
            (divSignedInt row.remainder (false && !row.rZero)).natAbs := by
        omega
      rw [Int.natAbs_mul] at hprod
      have hquot : divSignedInt row.quotient row.qSign = 0 := by
        rw [← Int.natAbs_eq_zero]
        rcases Nat.eq_zero_or_pos
            (divSignedInt row.quotient row.qSign).natAbs with h | h
        · exact h
        · exfalso
          have h2 :
              (divSignedInt row.rs2Next row.cSign).natAbs * 1 ≤
                (divSignedInt row.rs2Next row.cSign).natAbs *
                  (divSignedInt row.quotient row.qSign).natAbs :=
            Nat.mul_le_mul (Nat.le_refl _) (by omega)
          omega
      rw [hquot] at identity
      omega

/-! ### The committed result read as an architectural word -/

theorem div_wrap_signed_int (bytes : WordBytes) (flag : Bool) :
    Arith.wrapSigned (divSignedInt bytes flag) = bytes.word := by
  have h := Arith.wrapSigned_sub bytes.value flag
  cases flag <;> simpa [divSignedInt, WordBytes.word] using h

theorem divu_result_word (row : DivRow) (holds : DivHolds row)
    (unsigned : row.isSigned = false) :
    row.quotient.word =
      Arith.divideUnsigned row.rs1Next.word row.rs2Next.word := by
  cases hzd : row.zeroDivisor with
  | true =>
    obtain ⟨hc, hq, _⟩ := div_zero_divisor_facts row holds hzd
    rw [(div_word_eq_zero_iff row.rs2Next).mpr hc, Arith.divideUnsigned_zero,
      WordBytes.word, hq, Arith.allOnesWord]
  | false =>
    obtain ⟨hq, _⟩ := div_unsigned_result row holds unsigned hzd
    have hnz : ¬ (row.rs2Next.word = zeroWord) := fun h =>
      holds.divisorNonzero hzd ((div_word_eq_zero_iff row.rs2Next).mp h)
    rw [Arith.divideUnsigned, if_neg hnz, Arith.unsignedValue,
      Arith.unsignedValue, WordBytes.word_toNat, WordBytes.word_toNat,
      WordBytes.word, hq]

theorem remu_result_word (row : DivRow) (holds : DivHolds row)
    (unsigned : row.isSigned = false) :
    row.remainder.word =
      Arith.remainderUnsigned row.rs1Next.word row.rs2Next.word := by
  cases hzd : row.zeroDivisor with
  | true =>
    obtain ⟨hc, _, hr⟩ := div_zero_divisor_facts row holds hzd
    rw [(div_word_eq_zero_iff row.rs2Next).mpr hc,
      Arith.remainderUnsigned_zero, WordBytes.word, hr, WordBytes.word]
  | false =>
    obtain ⟨_, hr⟩ := div_unsigned_result row holds unsigned hzd
    have hnz : ¬ (row.rs2Next.word = zeroWord) := fun h =>
      holds.divisorNonzero hzd ((div_word_eq_zero_iff row.rs2Next).mp h)
    rw [Arith.remainderUnsigned, if_neg hnz, Arith.unsignedValue,
      Arith.unsignedValue, WordBytes.word_toNat, WordBytes.word_toNat,
      WordBytes.word, hr]

theorem div_result_word (row : DivRow) (holds : DivHolds row)
    (signed : row.isSigned = true) :
    row.quotient.word =
      Arith.divideSigned row.rs1Next.word row.rs2Next.word := by
  cases hzd : row.zeroDivisor with
  | true =>
    obtain ⟨hc, hq, _⟩ := div_zero_divisor_facts row holds hzd
    rw [(div_word_eq_zero_iff row.rs2Next).mpr hc, Arith.divideSigned_zero,
      WordBytes.word, hq, Arith.allOnesWord]
  | false =>
    obtain ⟨hq, _⟩ := div_signed_result row holds signed hzd
    have hnz : ¬ (row.rs2Next.word = zeroWord) := fun h =>
      holds.divisorNonzero hzd ((div_word_eq_zero_iff row.rs2Next).mp h)
    rw [Arith.divideSigned, if_neg hnz, ← hq,
      div_wrap_signed_int row.quotient row.qSign]

theorem rem_result_word (row : DivRow) (holds : DivHolds row)
    (signed : row.isSigned = true) :
    row.remainder.word =
      Arith.remainderSigned row.rs1Next.word row.rs2Next.word := by
  cases hzd : row.zeroDivisor with
  | true =>
    obtain ⟨hc, _, hr⟩ := div_zero_divisor_facts row holds hzd
    rw [(div_word_eq_zero_iff row.rs2Next).mpr hc,
      Arith.remainderSigned_zero, WordBytes.word, hr, WordBytes.word]
  | false =>
    obtain ⟨_, hr⟩ := div_signed_result row holds signed hzd
    have hnz : ¬ (row.rs2Next.word = zeroWord) := fun h =>
      holds.divisorNonzero hzd ((div_word_eq_zero_iff row.rs2Next).mp h)
    rw [Arith.remainderSigned, if_neg hnz, ← hr,
      div_wrap_signed_int row.remainder (row.bSign && !row.rZero)]

end RiscvRefinement.Air.Family
