import RiscvRefinement.Publication.TeamB.Shifts.Constraints

/-! Bounded shift publication proof owner: LookupProjection. -/
namespace RiscvRefinement.Publication.TeamB.Shifts

open RiscvRefinement
open RiscvRefinement.Air
open RiscvRefinement.Air.Family
open RiscvRefinement.Air.Generated
open RiscvRefinement.Opcodes
open RiscvRefinement.Sail.Reviewed

def accessClockField (clock ordinal : Nat) : M31 :=
  (M31.reduce clock - 1) * M31.reduce 4 + M31.reduce ordinal

private def clockGapField (clock ordinal previous : Nat) : M31 :=
  accessClockField clock ordinal - M31.reduce previous - 1

private def clockLookup
    (eventOrdinal accessOrdinal clock previous : Nat) : EvaluatedLookup where
  ordinal := eventOrdinal
  domain := .rangeCheck20
  numerator := -(1 : M31)
  tuple := #[clockGapField clock accessOrdinal previous]
  role := .request
  tableId := some .rangeCheck20
  accessOrdinal := some accessOrdinal

private def carryLookup
    (eventOrdinal carry multiplier : Nat) : EvaluatedLookup where
  ordinal := eventOrdinal
  domain := .rangeCheck88
  numerator := -(1 : M31)
  tuple := #[
    M31.reduce carry,
    M31.reduce multiplier - 1 - M31.reduce carry
  ]
  role := .request
  tableId := some .rangeCheck88
  accessOrdinal := none

private def signLookup
    (eventOrdinal : Nat) (row : ShiftRow) : EvaluatedLookup where
  ordinal := eventOrdinal
  domain := .rangeCheckM31
  numerator := -(boolM31 (kindIs .sra row.kind))
  tuple := #[
    0,
    bitVecM31 row.rs1Next.limb3 -
      boolM31 row.rs1Sign * M31.reduce 128
  ]
  role := .request
  tableId := some .rangeCheckM31
  accessOrdinal := none

private def amountMaskLookup
    (row : ShiftsRegRow) : EvaluatedLookup where
  ordinal := 79
  domain := .rangeCheck20
  numerator := -(1 : M31)
  tuple := #[
    M31.reduce 7 -
      (bitVecM31 row.rs2Next.limb0 -
          M31.reduce row.semantic.shiftAmount) *
        M31.reduce 67108864
  ]
  role := .request
  tableId := some .rangeCheck20
  accessOrdinal := none

private theorem negOneLive :
    ((-(1 : M31)) != 0) = true := by
  decide

private theorem rangeCheck88RequestHolds_iff
    (ordinal : Nat)
    (low high : M31) :
    (EvaluatedLookup.fixedRequestHolds {
      ordinal
      domain := .rangeCheck88
      numerator := -(1 : M31)
      tuple := #[low, high]
      role := .request
      tableId := some .rangeCheck88
      accessOrdinal := none
    }) = true ↔ low.val < 256 ∧ high.val < 256 := by
  simp only [
    EvaluatedLookup.fixedRequestHolds,
    EvaluatedLookup.isLive,
    negOneLive,
    ↓reduceIte,
    EvaluatedLookup.fixedMembership,
    Option.map,
    Option.getD,
    FixedTableId.contains,
    M31.toNat,
    decide_eq_true_eq,
    Bool.and_eq_true,
    Nat.reducePow,
    Nat.reduceSub,
    and_assoc,
  ]

private theorem rangeCheckM31RequestHolds_iff
    (ordinal : Nat)
    (low high : M31) :
    (EvaluatedLookup.fixedRequestHolds {
      ordinal
      domain := .rangeCheckM31
      numerator := -(1 : M31)
      tuple := #[low, high]
      role := .request
      tableId := some .rangeCheckM31
      accessOrdinal := none
    }) = true ↔
      low.val < 256 ∧ high.val < 128 ∧
        low.val + 256 * high.val < 32767 := by
  simp only [
    EvaluatedLookup.fixedRequestHolds,
    EvaluatedLookup.isLive,
    negOneLive,
    ↓reduceIte,
    EvaluatedLookup.fixedMembership,
    Option.map,
    Option.getD,
    FixedTableId.contains,
    M31.toNat,
    decide_eq_true_eq,
    Bool.and_eq_true,
    Nat.reducePow,
    Nat.reduceSub,
    and_assoc,
  ]

structure ImmExactFixedProjection
    (row : ShiftsImmRow) (witness : ImmWitness row) : Prop where
  sourceClock :
    (immEvaluation row witness).lookup? 72 =
      some (clockLookup 72 1 row.clock row.rs1PreviousClock)
  carry0 :
    (immEvaluation row witness).lookup? 73 =
      some (carryLookup 73 row.semantic.carry0 row.semantic.multiplier)
  carry1 :
    (immEvaluation row witness).lookup? 74 =
      some (carryLookup 74 row.semantic.carry1 row.semantic.multiplier)
  carry2 :
    (immEvaluation row witness).lookup? 75 =
      some (carryLookup 75 row.semantic.carry2 row.semantic.multiplier)
  carry3 :
    (immEvaluation row witness).lookup? 76 =
      some (carryLookup 76 row.semantic.carry3 row.semantic.multiplier)
  destinationClock :
    (immEvaluation row witness).lookup? 81 =
      some (clockLookup 81 2 row.clock row.rdPreviousClock)
  sign :
    (immEvaluation row witness).lookup? 82 =
      some (signLookup 82 row.semantic)

structure RegExactFixedProjection
    (row : ShiftsRegRow) (witness : RegWitness row) : Prop where
  sourceClock :
    (regEvaluation row witness).lookup? 75 =
      some (clockLookup 75 1 row.clock row.rs1PreviousClock)
  secondSourceClock :
    (regEvaluation row witness).lookup? 78 =
      some (clockLookup 78 2 row.clock row.rs2PreviousClock)
  amountMask :
    (regEvaluation row witness).lookup? 79 =
      some (amountMaskLookup row)
  carry0 :
    (regEvaluation row witness).lookup? 80 =
      some (carryLookup 80 row.semantic.carry0 row.semantic.multiplier)
  carry1 :
    (regEvaluation row witness).lookup? 81 =
      some (carryLookup 81 row.semantic.carry1 row.semantic.multiplier)
  carry2 :
    (regEvaluation row witness).lookup? 82 =
      some (carryLookup 82 row.semantic.carry2 row.semantic.multiplier)
  carry3 :
    (regEvaluation row witness).lookup? 83 =
      some (carryLookup 83 row.semantic.carry3 row.semantic.multiplier)
  destinationClock :
    (regEvaluation row witness).lookup? 88 =
      some (clockLookup 88 3 row.clock row.rdPreviousClock)
  sign :
    (regEvaluation row witness).lookup? 89 =
      some (signLookup 89 row.semantic)

set_option maxRecDepth 30000 in
set_option maxHeartbeats 0 in
theorem imm_exactFixedProjection
    (row : ShiftsImmRow)
    (witness : ImmWitness row)
    (bitRange : row.semantic.bitIndex < 8) :
    ImmExactFixedProjection row witness := by
  refine {
    sourceClock := ?_
    carry0 := ?_
    carry1 := ?_
    carry2 := ?_
    carry3 := ?_
    destinationClock := ?_
    sign := ?_
  } <;>
  cases kind : row.semantic.kind <;>
  simp [
    immEvaluation, immProgram, kind,
    Programs.slli, Programs.srli, Programs.srai,
    Programs.slliSource, Programs.srliSource, Programs.sraiSource,
    LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
    LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
    LocalValues.getSymbolic, newestValueSymbolic,
    SymbolicEvaluation.lookup?, Event.evalSymbolic,
    EvaluatedEvent.lookup?, immColumns, kindIs, boolM31,
    bitMarkerMultiplier row.semantic.bitIndex bitRange,
    ShiftRow.multiplier,
    leftMultiplier, rightMultiplier,
    clockLookup, carryLookup, signLookup, clockGapField, accessClockField,
  ]

set_option maxRecDepth 30000 in
set_option maxHeartbeats 0 in
theorem reg_exactFixedProjection
    (row : ShiftsRegRow)
    (witness : RegWitness row)
    (bitRange : row.semantic.bitIndex < 8)
    (limbRange : row.semantic.limbIndex < 4) :
    RegExactFixedProjection row witness := by
  refine {
    sourceClock := ?_
    secondSourceClock := ?_
    amountMask := ?_
    carry0 := ?_
    carry1 := ?_
    carry2 := ?_
    carry3 := ?_
    destinationClock := ?_
    sign := ?_
  } <;>
  cases kind : row.semantic.kind <;>
  simp [
    regEvaluation, regProgram, kind,
    Programs.sll, Programs.srl, Programs.sra,
    Programs.sllSource, Programs.srlSource, Programs.sraSource,
    LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
    LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
    LocalValues.getSymbolic, newestValueSymbolic,
    SymbolicEvaluation.lookup?, Event.evalSymbolic,
    EvaluatedEvent.lookup?, regColumns, kindIs, boolM31,
    bitMarkerMultiplier row.semantic.bitIndex bitRange,
    bitMarkerIndex' row.semantic.bitIndex bitRange,
    limbMarkerIndex' row.semantic.limbIndex limbRange,
    ShiftRow.shiftAmount,
    ShiftRow.multiplier,
    Air.Bridge.TeamACommon.reduceMul,
    Air.Bridge.TeamACommon.reduceAdd,
    Nat.mul_comm,
    leftMultiplier, rightMultiplier,
    clockLookup, carryLookup, signLookup, amountMaskLookup,
    clockGapField, accessClockField,
  ]

theorem clockGapBoundOfLookup
    (evaluation : SymbolicEvaluation)
    (eventOrdinal accessOrdinal clock previous : Nat)
    (fixed : evaluation.fixedLookupsHold = true)
    (selected :
      evaluation.lookup? eventOrdinal =
        some (clockLookup eventOrdinal accessOrdinal clock previous)) :
    (clockGapField clock accessOrdinal previous).val < 2 ^ 20 := by
  have request :=
    SymbolicEvaluation.fixedRequestHolds_of_lookup
      evaluation eventOrdinal
      (clockLookup eventOrdinal accessOrdinal clock previous) fixed selected
  exact
    (Air.Bridge.TeamACommon.rangeCheck20RequestHolds_iff
      eventOrdinal (some accessOrdinal)
      (clockGapField clock accessOrdinal previous)).mp
      (by simpa [clockLookup] using request)

theorem amountMaskBoundOfLookup
    (row : ShiftsRegRow)
    (witness : RegWitness row)
    (fixed : (regEvaluation row witness).fixedLookupsHold = true)
    (selected :
      (regEvaluation row witness).lookup? 79 =
        some (amountMaskLookup row)) :
    (M31.reduce 7 -
        (bitVecM31 row.rs2Next.limb0 -
            M31.reduce row.semantic.shiftAmount) *
          M31.reduce 67108864).val < 2 ^ 20 := by
  have request :=
    SymbolicEvaluation.fixedRequestHolds_of_lookup
      (regEvaluation row witness) 79 (amountMaskLookup row)
      fixed selected
  exact
    (Air.Bridge.TeamACommon.rangeCheck20RequestHolds_iff
      79 none
      (M31.reduce 7 -
        (bitVecM31 row.rs2Next.limb0 -
            M31.reduce row.semantic.shiftAmount) *
          M31.reduce 67108864)).mp
      (by simpa [amountMaskLookup] using request)

/-!
`rs2_next_0` is a byte and the normalized shift amount is five bits.  This
arithmetic proof checks the exact production inverse-of-32 encoding, including
the field wrap. Quotient and remainder bounds avoid enumerating byte pairs.
-/
set_option maxRecDepth 100000 in
set_option maxHeartbeats 0 in
theorem amountMaskUnique :
    ∀ (byte : Byte) (shift : Fin 32),
      (M31.reduce 7 -
          (bitVecM31 byte - M31.reduce shift.val) *
            M31.reduce 67108864).val < 2 ^ 20 →
        ∃ high : Fin 8,
          byte.toNat = 32 * high.val + shift.val := by
  intro byte shift accepted
  have byteBound : byte.toNat < 256 := byte.isLt
  have shiftBound : shift.val < 32 := shift.isLt
  change ((7 % 2147483647 + 2147483647 -
    ((((byte.toNat % 2147483647 + 2147483647 - shift.val % 2147483647) % 2147483647) *
        (67108864 % 2147483647)) % 2147483647)) % 2147483647) < 2 ^ 20 at accepted
  simp only [Nat.reduceMod, Nat.reducePow,
    Nat.mod_eq_of_lt (by omega : byte.toNat < 2147483647),
    Nat.mod_eq_of_lt (by omega : shift.val < 2147483647)] at accepted
  by_cases ordered : shift.val ≤ byte.toNat
  · let difference := byte.toNat - shift.val
    have differenceBound : difference < 256 := by dsimp [difference]; omega
    have input : (byte.toNat + 2147483647 - shift.val) % 2147483647 = difference := by omega
    rw [input] at accepted
    have highBound : difference / 32 < 8 := by omega
    have lowBound : difference % 32 < 32 := Nat.mod_lt _ (by decide)
    have splitValue : difference = 32 * (difference / 32) + difference % 32 := by omega
    have residueBound : difference / 32 + difference % 32 * 67108864 < 2147483647 := by omega
    have product : difference * 67108864 =
        2147483647 * (difference / 32) + (difference / 32 + difference % 32 * 67108864) := by omega
    have residue : difference * 67108864 % 2147483647 =
        difference / 32 + difference % 32 * 67108864 := by
      rw [product]
      simp [Nat.add_mod, Nat.mod_eq_of_lt residueBound]
    rw [residue] at accepted
    have lowZero : difference % 32 = 0 := by
      by_cases zero : difference % 32 = 0
      · exact zero
      · have numeratorBound :
            7 + 2147483647 - (difference / 32 + difference % 32 * 67108864) < 2147483647 := by omega
        rw [Nat.mod_eq_of_lt numeratorBound] at accepted
        omega
    have byteEquation : byte.toNat = difference + shift.val := by dsimp [difference]; omega
    refine ⟨⟨difference / 32, highBound⟩, ?_⟩
    change byte.toNat = 32 * (difference / 32) + shift.val
    omega
  · let difference := shift.val - byte.toNat
    have positive : 0 < difference := by dsimp [difference]; omega
    have differenceBound : difference < 32 := by dsimp [difference]; omega
    have input : (byte.toNat + 2147483647 - shift.val) % 2147483647 = 2147483647 - difference := by omega
    rw [input] at accepted
    have residueBound : 2147483647 - difference * 67108864 < 2147483647 := by omega
    have product : (2147483647 - difference) * 67108864 =
        2147483647 * 67108863 + (2147483647 - difference * 67108864) := by omega
    have residue : (2147483647 - difference) * 67108864 % 2147483647 =
        2147483647 - difference * 67108864 := by
      rw [product]
      simp [Nat.add_mod, Nat.mod_eq_of_lt residueBound]
    rw [residue] at accepted
    have numeratorBound : 7 + 2147483647 - (2147483647 - difference * 67108864) < 2147483647 := by omega
    rw [Nat.mod_eq_of_lt numeratorBound] at accepted
    omega

theorem carryBoundsOfLookup
    (evaluation : SymbolicEvaluation)
    (ordinal carry multiplier : Nat)
    (fixed : evaluation.fixedLookupsHold = true)
    (selected :
      evaluation.lookup? ordinal =
        some (carryLookup ordinal carry multiplier)) :
    (M31.reduce carry).val < 256 ∧
      (M31.reduce multiplier - 1 - M31.reduce carry).val < 256 := by
  have request :=
    SymbolicEvaluation.fixedRequestHolds_of_lookup
      evaluation ordinal (carryLookup ordinal carry multiplier)
      fixed selected
  exact
    (rangeCheck88RequestHolds_iff ordinal
      (M31.reduce carry)
      (M31.reduce multiplier - 1 - M31.reduce carry)).mp
      (by simpa [carryLookup] using request)

theorem carryLtMultiplier
    (carry multiplier : Nat)
    (carryCanonical : carry < M31.modulus)
    (multiplierPositive : 0 < multiplier)
    (multiplierBound : multiplier ≤ 128)
    (bounds :
      (M31.reduce carry).val < 256 ∧
        (M31.reduce multiplier - 1 - M31.reduce carry).val < 256) :
    carry < multiplier := by
  have carryImage :
      (M31.reduce carry).val = carry :=
    M31.reduce_val_of_lt carry carryCanonical
  have multiplierCanonical : multiplier < M31.modulus := by
    rw [M31.modulus_eq]
    omega
  have multiplierImage :
      (M31.reduce multiplier).val = multiplier :=
    M31.reduce_val_of_lt multiplier multiplierCanonical
  have predecessorImage :
      (M31.reduce multiplier - 1).val = multiplier - 1 := by
    have ordered :
        (1 : M31).val ≤ (M31.reduce multiplier).val := by
      rw [multiplierImage]
      change 1 ≤ multiplier
      omega
    rw [M31.sub_val_of_le _ _ ordered, multiplierImage]
    change multiplier - 1 = multiplier - 1
    rfl
  have carryByte : carry < 256 := by
    rw [carryImage] at bounds
    exact bounds.1
  by_cases desired : carry < multiplier
  · exact desired
  · have wrapped :=
      M31.sub_val_of_lt
        (M31.reduce multiplier - 1) (M31.reduce carry)
        (by rw [predecessorImage, carryImage]; omega)
    rw [predecessorImage, carryImage] at wrapped
    rw [wrapped] at bounds
    simp [M31.modulus_eq] at bounds
    omega

theorem signBoundsOfLookup
    (evaluation : SymbolicEvaluation)
    (ordinal : Nat)
    (row : ShiftRow)
    (kind : row.kind = .sra)
    (fixed : evaluation.fixedLookupsHold = true)
    (selected :
      evaluation.lookup? ordinal = some (signLookup ordinal row)) :
    128 * row.signNat ≤ row.rs1Next.limb3.toNat ∧
      row.rs1Next.limb3.toNat < 128 * row.signNat + 128 := by
  have request :=
    SymbolicEvaluation.fixedRequestHolds_of_lookup
      evaluation ordinal (signLookup ordinal row) fixed selected
  have residueBound :
      (bitVecM31 row.rs1Next.limb3 -
          boolM31 row.rs1Sign * M31.reduce 128).val < 128 := by
    have normalized :
        EvaluatedLookup.fixedRequestHolds {
          ordinal
          domain := .rangeCheckM31
          numerator := -(1 : M31)
          tuple := #[
            0,
            bitVecM31 row.rs1Next.limb3 -
              boolM31 row.rs1Sign * M31.reduce 128
          ]
          role := .request
          tableId := some .rangeCheckM31
          accessOrdinal := none
        } = true := by
      simpa [signLookup, kind, kindIs, boolM31] using request
    have bounds :=
      (rangeCheckM31RequestHolds_iff ordinal 0
        (bitVecM31 row.rs1Next.limb3 -
          boolM31 row.rs1Sign * M31.reduce 128)).mp normalized
    exact bounds.2.1
  have byteImage :
      (bitVecM31 row.rs1Next.limb3).val =
        row.rs1Next.limb3.toNat := by
    exact M31.reduce_val_of_lt _ (byteBound row.rs1Next.limb3)
  cases sign : row.rs1Sign
  · simp only [ShiftRow.signNat, sign, ↓reduceIte, Nat.zero_mul,
      Nat.zero_add]
    have upper := residueBound
    simpa [sign, boolM31, byteImage] using upper
  · simp only [ShiftRow.signNat, sign, ↓reduceIte, Nat.one_mul]
    rw [sign] at residueBound
    simp only [boolM31, M31.one_mul] at residueBound
    have highAtLeast : 128 ≤ row.rs1Next.limb3.toNat := by
      by_cases below : row.rs1Next.limb3.toNat < 128
      · have wrapped :=
          M31.sub_val_of_lt
            (bitVecM31 row.rs1Next.limb3) (M31.reduce 128)
            (by
              rw [byteImage,
                M31.reduce_val_of_lt 128 (by decide)]
              exact below)
        rw [wrapped, byteImage,
          M31.reduce_val_of_lt 128 (by decide)] at residueBound
        simp [M31.modulus_eq] at residueBound
        omega
      · omega
    constructor
    · exact highAtLeast
    · have := row.rs1Next.limb3.isLt
      simp only [Nat.reducePow] at this
      omega

theorem validClockOfGap
    (clock ordinal previous : Nat)
    (clockPositive : 0 < clock)
    (clockBound : clock ≤ 2 ^ 24)
    (ordinalPositive : 0 < ordinal)
    (ordinalBound : ordinal ≤ 3)
    (previousBound : previous < 2 ^ 26)
    (gapBound : (clockGapField clock ordinal previous).val < 2 ^ 20) :
    validPreviousClock previous (accessClock clock ordinal) := by
  have currentBound : accessClock clock ordinal < 2 ^ 26 := by
    simp only [accessClock]
    omega
  have currentPositive : 0 < accessClock clock ordinal := by
    simp only [accessClock]
    omega
  have accessImage :
      (accessClockField clock ordinal).val = accessClock clock ordinal := by
    simpa [accessClockField,
      Air.Bridge.TeamACommon.accessClockField] using
      Air.Bridge.TeamACommon.accessClockField_val
        clock ordinal clockPositive clockBound (by omega)
  have accessEquality :
      accessClockField clock ordinal =
        M31.reduce (accessClock clock ordinal) := by
    apply M31.ext
    rw [accessImage,
      M31.reduce_val_of_lt _ (by
        rw [M31.modulus_eq]
        omega)]
  apply Air.Bridge.TeamACommon.validPreviousClock_of_gap
    previous (accessClock clock ordinal) currentPositive currentBound
    previousBound
  simpa [clockGapField, accessEquality] using gapBound

end RiscvRefinement.Publication.TeamB.Shifts
