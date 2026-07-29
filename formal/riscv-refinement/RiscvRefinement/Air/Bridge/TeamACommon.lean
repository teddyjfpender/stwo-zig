import RiscvRefinement.Air.Bridge.Lui

/-!
# Shared production-bridge lemmas for Team A

The remaining Team A families use the same destination-write gadget, byte
composition, access-clock formula, and `pc + 4` state transition.  This module
proves those facts once at the exact M31 representation used by the generated
programs.
-/

namespace RiscvRefinement.Air.Bridge.TeamACommon

open RiscvRefinement

abbrev bitVecM31 {width : Nat} (value : BitVec width) : M31 :=
  Lui.bitVecM31 value

abbrev boolM31 : Bool → M31 :=
  Lui.boolM31

def accessClockField (clock ordinal : Nat) : M31 :=
  (M31.reduce clock - 1) * M31.reduce 4 + M31.reduce ordinal

def clockGapField (clock ordinal previous : Nat) : M31 :=
  accessClockField clock ordinal - M31.reduce previous - 1

def wordBytesField (bytes : WordBytes) : M31 :=
  (((bitVecM31 bytes.limb3 * M31.reduce 256 +
        bitVecM31 bytes.limb2) *
      M31.reduce 256 +
        bitVecM31 bytes.limb1) *
    M31.reduce 256 +
      bitVecM31 bytes.limb0)

theorem reduceAdd (left right : Nat) :
    M31.reduce left + M31.reduce right =
      M31.reduce (left + right) := by
  apply M31.ext
  simp only [M31.reduce_val]
  exact (Nat.add_mod left right M31.modulus).symm

theorem reduceMul (left right : Nat) :
    M31.reduce left * M31.reduce right =
      M31.reduce (left * right) := by
  apply M31.ext
  simp only [M31.reduce_val]
  exact (Nat.mul_mod left right M31.modulus).symm

theorem wordBytesField_eq_reduce (bytes : WordBytes) :
    wordBytesField bytes = M31.reduce bytes.value := by
  simp only [wordBytesField, bitVecM31, Lui.bitVecM31]
  rw [
    reduceMul bytes.limb3.toNat 256,
    reduceAdd (bytes.limb3.toNat * 256) bytes.limb2.toNat,
    reduceMul (bytes.limb3.toNat * 256 + bytes.limb2.toNat) 256,
    reduceAdd
      ((bytes.limb3.toNat * 256 + bytes.limb2.toNat) * 256)
      bytes.limb1.toNat,
    reduceMul
      ((bytes.limb3.toNat * 256 + bytes.limb2.toNat) * 256 +
        bytes.limb1.toNat)
      256,
    reduceAdd
      (((bytes.limb3.toNat * 256 + bytes.limb2.toNat) * 256 +
        bytes.limb1.toNat) * 256)
      bytes.limb0.toNat,
  ]
  congr 1
  simp only [WordBytes.value]
  omega

theorem wordBytesField_val
    (bytes : WordBytes)
    (bound : bytes.value < M31.modulus) :
    (wordBytesField bytes).val = bytes.value := by
  rw [wordBytesField_eq_reduce]
  exact M31.reduce_val_of_lt bytes.value bound

theorem bitVecM31_injective_of_bounds
    {width : Nat}
    (left right : BitVec width)
    (leftBound : left.toNat < M31.modulus)
    (rightBound : right.toNat < M31.modulus)
    (equality : bitVecM31 left = bitVecM31 right) :
    left = right := by
  apply BitVec.eq_of_toNat_eq
  have values := congrArg M31.val equality
  rw [
    Lui.bitVecM31_val left leftBound,
    Lui.bitVecM31_val right rightBound,
  ] at values
  exact values

private theorem bitVecM31_eq_zero_of_bound
    {width : Nat}
    (value : BitVec width)
    (bound : value.toNat < M31.modulus)
    (equality : bitVecM31 value = 0) :
    value = BitVec.ofNat width 0 := by
  apply
    bitVecM31_injective_of_bounds
      value (BitVec.ofNat width 0) bound (by simp [M31.modulus_eq])
  simpa [bitVecM31, Lui.bitVecM31] using equality

private theorem byteM31Bound (value : Byte) :
    value.toNat < M31.modulus := by
  have := value.isLt
  simp [M31.modulus_eq] at *
  omega

private theorem byte_eq_of_bitVecM31_eq
    (left right : Byte)
    (equality : bitVecM31 left = bitVecM31 right) :
    left = right :=
  bitVecM31_injective_of_bounds
    left right (byteM31Bound left) (byteM31Bound right) equality

private theorem byte_eq_zero_of_bitVecM31
    (value : Byte)
    (equality : bitVecM31 value = 0) :
    value = BitVec.ofNat 8 0 :=
  bitVecM31_eq_zero_of_bound value (byteM31Bound value) equality

theorem destinationFlag_of_equations
    (rd : RegisterIndex)
    (nonzero : Bool)
    (inverse : M31)
    (zeroProduct :
      bitVecM31 rd * (1 - boolM31 nonzero) = 0)
    (inverseProduct :
      bitVecM31 rd * inverse - boolM31 nonzero = 0) :
    nonzero = decide (rd ≠ zeroRegister) := by
  cases flag : nonzero
  · have rdFieldZero : bitVecM31 rd = 0 := by
      simpa [flag, boolM31, Lui.boolM31] using zeroProduct
    have rdBound : rd.toNat < M31.modulus := by
      have := rd.isLt
      simp [M31.modulus_eq] at *
      omega
    have rdZero : rd = BitVec.ofNat 5 0 :=
      bitVecM31_eq_zero_of_bound rd rdBound rdFieldZero
    simp [zeroRegister, rdZero]
  · have inverseEquality :
        bitVecM31 rd * inverse = 1 :=
      (M31.sub_eq_zero_iff _ _).mp (by
        simpa [flag, boolM31, Lui.boolM31] using inverseProduct)
    have rdNonzero : rd ≠ zeroRegister := by
      intro rdZero
      rw [rdZero, zeroRegister] at inverseEquality
      have impossible : (0 : M31) = 1 := by
        simpa [bitVecM31, Lui.bitVecM31] using inverseEquality
      cases impossible
    simp [rdNonzero]

theorem destinationBytes_of_equations
    (next result : WordBytes)
    (nonzero : Bool)
    (limb0 :
      bitVecM31 next.limb0 -
          boolM31 nonzero * bitVecM31 result.limb0 = 0)
    (limb1 :
      bitVecM31 next.limb1 -
          boolM31 nonzero * bitVecM31 result.limb1 = 0)
    (limb2 :
      bitVecM31 next.limb2 -
          boolM31 nonzero * bitVecM31 result.limb2 = 0)
    (limb3 :
      bitVecM31 next.limb3 -
          boolM31 nonzero * bitVecM31 result.limb3 = 0) :
    next =
      if nonzero then result else WordBytes.zero := by
  apply WordBytes.eq_of_limbs
  · cases flag : nonzero
    · have fieldZero : bitVecM31 next.limb0 = 0 := by
        simpa [flag, boolM31, Lui.boolM31] using limb0
      have valueZero :=
        byte_eq_zero_of_bitVecM31 next.limb0 fieldZero
      simpa [flag, WordBytes.zero] using valueZero
    · have fieldEquality :
          bitVecM31 next.limb0 = bitVecM31 result.limb0 :=
        (M31.sub_eq_zero_iff _ _).mp (by
          simpa [flag, boolM31, Lui.boolM31] using limb0)
      simpa [flag] using
        byte_eq_of_bitVecM31_eq
          next.limb0 result.limb0 fieldEquality
  · cases flag : nonzero
    · have fieldZero : bitVecM31 next.limb1 = 0 := by
        simpa [flag, boolM31, Lui.boolM31] using limb1
      have valueZero :=
        byte_eq_zero_of_bitVecM31 next.limb1 fieldZero
      simpa [flag, WordBytes.zero] using valueZero
    · have fieldEquality :
          bitVecM31 next.limb1 = bitVecM31 result.limb1 :=
        (M31.sub_eq_zero_iff _ _).mp (by
          simpa [flag, boolM31, Lui.boolM31] using limb1)
      simpa [flag] using
        byte_eq_of_bitVecM31_eq
          next.limb1 result.limb1 fieldEquality
  · cases flag : nonzero
    · have fieldZero : bitVecM31 next.limb2 = 0 := by
        simpa [flag, boolM31, Lui.boolM31] using limb2
      have valueZero :=
        byte_eq_zero_of_bitVecM31 next.limb2 fieldZero
      simpa [flag, WordBytes.zero] using valueZero
    · have fieldEquality :
          bitVecM31 next.limb2 = bitVecM31 result.limb2 :=
        (M31.sub_eq_zero_iff _ _).mp (by
          simpa [flag, boolM31, Lui.boolM31] using limb2)
      simpa [flag] using
        byte_eq_of_bitVecM31_eq
          next.limb2 result.limb2 fieldEquality
  · cases flag : nonzero
    · have fieldZero : bitVecM31 next.limb3 = 0 := by
        simpa [flag, boolM31, Lui.boolM31] using limb3
      have valueZero :=
        byte_eq_zero_of_bitVecM31 next.limb3 fieldZero
      simpa [flag, WordBytes.zero] using valueZero
    · have fieldEquality :
          bitVecM31 next.limb3 = bitVecM31 result.limb3 :=
        (M31.sub_eq_zero_iff _ _).mp (by
          simpa [flag, boolM31, Lui.boolM31] using limb3)
      simpa [flag] using
        byte_eq_of_bitVecM31_eq
          next.limb3 result.limb3 fieldEquality

theorem nextPcToNat
    (pc : Word)
    (bound : pc.toNat + 4 < M31.modulus) :
    (nextPc pc).toNat = pc.toNat + 4 := by
  simp only [nextPc, BitVec.toNat_add, BitVec.toNat_ofNat, Nat.reducePow]
  rw [Nat.mod_eq_of_lt]
  have fieldBound := bound
  rw [M31.modulus_eq] at fieldBound
  omega

theorem nextPcField
    (pc : Word)
    (bound : pc.toNat + 4 < M31.modulus) :
    bitVecM31 pc + M31.reduce 4 =
      bitVecM31 (nextPc pc) := by
  apply M31.ext
  have pcBound : pc.toNat < M31.modulus := by omega
  have nextBound : (nextPc pc).toNat < M31.modulus := by
    rw [nextPcToNat pc bound]
    exact bound
  have sumBound :
      (bitVecM31 pc).val + (M31.reduce 4).val <
        M31.modulus := by
    rw [
      Lui.bitVecM31_val pc pcBound,
      M31.reduce_val_of_lt 4 (by decide),
    ]
    exact bound
  rw [
    M31.add_val_of_lt (bitVecM31 pc) (M31.reduce 4) sumBound,
    Lui.bitVecM31_val pc pcBound,
    M31.reduce_val_of_lt 4 (by decide),
    Lui.bitVecM31_val (nextPc pc) nextBound,
    nextPcToNat pc bound,
  ]

theorem nextClockField
    (clock : Nat)
    (bound : clock + 1 < M31.modulus) :
    M31.reduce clock + 1 = M31.reduce (clock + 1) := by
  apply M31.ext
  have clockBound : clock < M31.modulus := by omega
  have sumBound :
      (M31.reduce clock).val + (1 : M31).val <
        M31.modulus := by
    rw [M31.reduce_val_of_lt clock clockBound]
    exact bound
  rw [
    M31.add_val_of_lt (M31.reduce clock) 1 sumBound,
    M31.reduce_val_of_lt clock clockBound,
    M31.reduce_val_of_lt (clock + 1) bound,
  ]
  rfl

theorem accessClockField_val
    (clock ordinal : Nat)
    (clockPositive : 0 < clock)
    (clockBound : clock ≤ 2 ^ 24)
    (ordinalBound : ordinal ≤ 4) :
    (accessClockField clock ordinal).val =
      accessClock clock ordinal := by
  have clockFieldBound : clock < M31.modulus := by
    simp [M31.modulus_eq] at *
    omega
  have clockVal :
      (M31.reduce clock).val = clock :=
    M31.reduce_val_of_lt clock clockFieldBound
  have subVal :
      (M31.reduce clock - 1).val = clock - 1 := by
    rw [M31.sub_val_of_le]
    · rw [clockVal]
      change clock - 1 = clock - 1
      rfl
    · rw [clockVal]
      change 1 ≤ clock
      omega
  have fourVal : (M31.reduce 4).val = 4 :=
    M31.reduce_val_of_lt 4 (by decide)
  have productBound :
      (M31.reduce clock - 1).val * (M31.reduce 4).val <
        M31.modulus := by
    rw [subVal, fourVal]
    simp [M31.modulus_eq] at *
    omega
  have productVal :
      ((M31.reduce clock - 1) * M31.reduce 4).val =
        (clock - 1) * 4 := by
    rw [
      M31.mul_val_of_lt _ _ productBound,
      subVal,
      fourVal,
    ]
  have ordinalFieldBound : ordinal < M31.modulus := by
    simp [M31.modulus_eq] at *
    omega
  have sumBound :
      ((M31.reduce clock - 1) * M31.reduce 4).val +
          (M31.reduce ordinal).val <
        M31.modulus := by
    rw [
      productVal,
      M31.reduce_val_of_lt ordinal ordinalFieldBound,
    ]
    simp [M31.modulus_eq] at *
    omega
  rw [
    accessClockField,
    M31.add_val_of_lt _ _ sumBound,
    productVal,
    M31.reduce_val_of_lt ordinal ordinalFieldBound,
  ]
  rfl

theorem validPreviousClock_of_gap
    (previous current : Nat)
    (currentPositive : 0 < current)
    (currentBound : current < 2 ^ 26)
    (previousBound : previous < 2 ^ 26)
    (gapBound :
      (M31.reduce current - M31.reduce previous - 1).val < 2 ^ 20) :
    validPreviousClock previous current := by
  have currentModulusBound : current < M31.modulus := by
    simp [M31.modulus_eq] at *
    omega
  have previousModulusBound : previous < M31.modulus := by
    simp [M31.modulus_eq] at *
    omega
  have currentVal :
      (M31.reduce current).val = current :=
    M31.reduce_val_of_lt current currentModulusBound
  have previousVal :
      (M31.reduce previous).val = previous :=
    M31.reduce_val_of_lt previous previousModulusBound
  have ordered : previous < current := by
    by_cases isOrdered : previous < current
    · exact isOrdered
    have currentLePrevious : current ≤ previous :=
      Nat.le_of_not_gt isOrdered
    rcases Nat.eq_or_lt_of_le currentLePrevious with equal | less
    · subst previous
      have firstVal :
          (M31.reduce current - M31.reduce current).val = 0 := by
        rw [M31.sub_self]
        rfl
      have secondVal :=
        M31.sub_val_of_lt
          (M31.reduce current - M31.reduce current) 1
          (by rw [firstVal]; decide)
      rw [secondVal, firstVal] at gapBound
      change M31.modulus + 0 - 1 < 2 ^ 20 at gapBound
      simp [M31.modulus_eq] at gapBound
    · have firstVal :=
        M31.sub_val_of_lt
          (M31.reduce current) (M31.reduce previous)
          (by rw [currentVal, previousVal]; exact less)
      have firstPositive :
          1 ≤ (M31.reduce current - M31.reduce previous).val := by
        rw [firstVal, currentVal, previousVal]
        simp [M31.modulus_eq]
        omega
      have secondVal :=
        M31.sub_val_of_le
          (M31.reduce current - M31.reduce previous) 1
          firstPositive
      rw [secondVal, firstVal, currentVal, previousVal] at gapBound
      change M31.modulus + current - previous - 1 < 2 ^ 20 at gapBound
      simp [M31.modulus_eq] at gapBound
      omega
  constructor
  · exact ordered
  · have firstVal :=
      M31.sub_val_of_le
        (M31.reduce current) (M31.reduce previous)
        (by rw [currentVal, previousVal]; omega)
    have firstPositive :
        1 ≤ (M31.reduce current - M31.reduce previous).val := by
      rw [firstVal, currentVal, previousVal]
      omega
    have secondVal :=
      M31.sub_val_of_le
        (M31.reduce current - M31.reduce previous) 1
        firstPositive
    rw [secondVal, firstVal, currentVal, previousVal] at gapBound
    change current - previous - 1 < 2 ^ 20 at gapBound
    exact gapBound

private theorem negOneLive :
    ((-(1 : M31)) != 0) = true := by
  decide

theorem rangeCheck20RequestHolds_iff
    (ordinal : Nat)
    (accessOrdinal : Option Nat)
    (value : M31) :
    (EvaluatedLookup.fixedRequestHolds {
      ordinal
      domain := .rangeCheck20
      numerator := -(1 : M31)
      tuple := #[value]
      role := .request
      tableId := some .rangeCheck20
      accessOrdinal
    }) = true ↔ value.val < 2 ^ 20 := by
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
    decide_eq_true_eq,
  ]

end RiscvRefinement.Air.Bridge.TeamACommon
