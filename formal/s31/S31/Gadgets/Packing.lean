import S31.Gadgets.Signed
import S31.Semantics.Integers

namespace S31.Gadgets.Packing
open Words Radix

def bitsConstraint (word : Nat) (bits : List Nat) : Prop :=
  word < 65536 ∧ bits.length = 16 ∧ Bounded 2 bits ∧
    (word : Field.F) = (decode 2 bits : Field.F)

theorem bits_sound (word : Nat) (bits : List Nat) (h : bitsConstraint word bits) :
    word = decode 2 bits := by
  obtain ⟨hw, hl, hb, heq⟩ := h
  have hr : decode 2 bits < 65536 := by
    have := decode_lt 2 (by decide) bits hb
    simpa [hl] using this
  exact (Field.bounded_equation _ _ (by omega) (by omega)).mp heq

theorem bits_complete (word : Nat) (h : word < 65536) :
    bitsConstraint word (encode 2 16 word) := by
  refine ⟨h, encode_length _ _ _, encode_bounded _ (by decide) _ _, ?_⟩
  rw [decode_encode 2 (by decide) 16 word (by simpa using h)]

theorem bits_sound_complete (word : Nat) :
    (∃ bits, bitsConstraint word bits) ↔ word < 65536 :=
  ⟨fun ⟨_, h⟩ => h.1, fun h => ⟨_, bits_complete word h⟩⟩

def bytePairConstraint (low high limb : Nat) : Prop :=
  low < 256 ∧ high < 256 ∧ limb < 65536 ∧
    (limb : Field.F) = low + 256 * (high : Field.F)

theorem byte_pair_sound (low high limb : Nat) (h : bytePairConstraint low high limb) :
    limb = low + 256 * high := by
  obtain ⟨hl, hh, hw, heq⟩ := h
  exact (Field.bounded_equation _ _ (by omega) (by omega)).mp
    (by simpa only [Nat.cast_add, Nat.cast_mul] using heq)

theorem byte_pair_complete (limb : Nat) (h : limb < 65536) :
    bytePairConstraint (limb % 256) (limb / 256) limb := by
  refine ⟨Nat.mod_lt _ (by decide), ?_, h, ?_⟩
  · exact (Nat.div_lt_iff_lt_mul (by decide : 0 < 256)).mpr h
  · simpa only [Nat.cast_add, Nat.cast_mul] using
      congrArg (fun n : Nat => (n : Field.F)) (Nat.mod_add_div limb 256).symm

theorem byte_pair_unique (low high limb : Nat) (h : bytePairConstraint low high limb) :
    low = limb % 256 ∧ high = limb / 256 := by
  have heq := byte_pair_sound _ _ _ h
  rw [heq]
  constructor
  · simp [Nat.add_mul_mod_self_left, Nat.mod_eq_of_lt h.1]
  · rw [Nat.add_mul_div_left _ _ (by decide), Nat.div_eq_of_lt h.1]
    simp

theorem byte_pair_sound_complete (limb : Nat) :
    (∃ low high, bytePairConstraint low high limb) ↔ limb < 65536 :=
  ⟨fun ⟨_, _, h⟩ => h.2.2.1, fun h => ⟨_, _, byte_pair_complete limb h⟩⟩

theorem byte_pair_m31_sound_complete (low high : Nat) (hl : low < 256) (hh : high < 256)
    (output : M31) : bytePairConstraint low high output.val ↔
      output = RiscvRefinement.M31.reduce (low + 256 * high) := by
  have hr : low + 256 * high < 65536 := by omega
  have hp : low + 256 * high < 2147483647 := by omega
  constructor
  · intro h
    apply RiscvRefinement.M31.ext
    change output.val = (low + 256 * high) % 2147483647
    rw [Nat.mod_eq_of_lt hp]
    exact byte_pair_sound _ _ _ h
  · rintro rfl
    refine ⟨hl, hh, ?_, ?_⟩
    · change (low + 256 * high) % 2147483647 < 65536
      rw [Nat.mod_eq_of_lt hp]
      exact hr
    · change (((low + 256 * high) % 2147483647 : Nat) : Field.F) = _
      rw [Nat.mod_eq_of_lt hp]
      simp

theorem bytes_le_roundtrip (length value : Nat) (h : value < 256^length) :
    decode 256 (bytesLE length value) = value := decode_encode _ (by decide) _ _ h

theorem bytes_be_roundtrip (length value : Nat) (h : value < 256^length) :
    decode 256 (bytesBE length value).reverse = value := by
  simp only [bytesBE, List.reverse_reverse]
  exact bytes_le_roundtrip _ _ h

/-- The most significant bounded limb carries the sign of the entire value. -/
theorem top_limb_sign (base half top : Nat) (hb : base = 2 * half) (hh : 0 < half)
    (lowerLimbs : List Nat) (hp : Bounded base lowerLimbs) :
    decode base (lowerLimbs ++ [top]) ≥ base^lowerLimbs.length * half ↔ top ≥ half := by
  have hbase : 0 < base := by omega
  have hr := decode_lt base hbase lowerLimbs hp
  have hplace : 0 < base^lowerLimbs.length := Nat.pow_pos hbase
  simp only [decode_append, decode, Nat.mul_zero, Nat.add_zero]
  constructor
  · intro h
    by_contra ht
    have htop : top + 1 ≤ half := by omega
    nlinarith
  · intro h; nlinarith

theorem integer_layout (spec : IntegerSpec)
    (h : spec.width = 8 ∨ spec.width = 16 ∨ spec.width = 32 ∨ spec.width = 64 ∨ spec.width = 128) :
    spec.limit = (if spec.width = 8 then 256 else 65536)^spec.limbs ∧ 0 < spec.limbs := by
  rcases h with h | h | h | h | h <;>
    norm_num [IntegerSpec.limit, IntegerSpec.limbs, h]

/-- Canonical M31 reduction of a digest word is an integer quotient/remainder
fact. A bare equality in F would lose the quotient and cannot prove this. -/
def digestReduction (word : Nat) (output : M31) : Prop :=
  word < 2^32 ∧ ∃ quotient : Nat, quotient ≤ 2 ∧ word = output.val + 2147483647 * quotient

theorem digest_reduction_sound (word : Nat) (output : M31) (h : digestReduction word output) :
    output = RiscvRefinement.M31.reduce word := by
  obtain ⟨hw, quotient, hq, heq⟩ := h
  apply RiscvRefinement.M31.ext
  change output.val = word % 2147483647
  rw [heq]
  rw [Nat.add_mul_mod_self_left]
  exact (Nat.mod_eq_of_lt output.isLt).symm

theorem digest_reduction_complete (word : Nat) (h : word < 2^32) :
    digestReduction word (RiscvRefinement.M31.reduce word) := by
  refine ⟨h, word / 2147483647, ?_, ?_⟩
  · have := (Nat.div_lt_iff_lt_mul (by decide : 0 < 2147483647)).mpr
      (show word < 3 * 2147483647 by omega)
    omega
  · exact (Nat.mod_add_div _ _).symm

theorem digest_reduction_sound_complete (word : Nat) (output : M31) (h : word < 2^32) :
    digestReduction word output ↔ output = RiscvRefinement.M31.reduce word :=
  ⟨digest_reduction_sound _ _, fun heq => heq ▸ digest_reduction_complete word h⟩

end S31.Gadgets.Packing
