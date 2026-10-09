import S31.Gadgets.Boolean
import S31.Gadgets.Radix
import S31.Semantics.Graph

namespace S31.Gadgets.Word
open Words

def flag (b : Bool) : Field.F := encodeBool b

theorem flag_injective : Function.Injective flag := by
  intro a b h
  cases a <;> cases b <;> simp_all [flag, encodeBool]

def addConstraint (a b y : Word) : Prop := ∃ carry : Nat, carry ≤ 1 ∧
  a.toNat + b.toNat = y.toNat + 2^32 * carry

theorem add_sound_complete (a b y : Word) : addConstraint a b y ↔ y = a + b := by
  constructor
  · rintro ⟨carry, hc, h⟩
    apply BitVec.eq_of_toNat_eq
    rw [BitVec.toNat_add, h]
    simp [Nat.add_mul_mod_self_left, Nat.mod_eq_of_lt y.isLt]
  · rintro rfl
    refine ⟨(a.toNat + b.toNat) / 2^32, ?_, ?_⟩
    · have ha := a.isLt; have hb := b.isLt
      have h : a.toNat + b.toNat < 2 * 2^32 := by omega
      have := (Nat.div_lt_iff_lt_mul (by decide : 0 < 2^32)).mpr h
      omega
    · exact (Nat.mod_add_div _ _).symm

def xorConstraint (a b y : Word) : Prop := ∀ i, i < 32 →
  Gadgets.xorConstraint (flag (a.getLsbD i)) (flag (b.getLsbD i)) (flag (y.getLsbD i))
def andConstraint (a b y : Word) : Prop := ∀ i, i < 32 →
  Gadgets.andConstraint (flag (a.getLsbD i)) (flag (b.getLsbD i)) (flag (y.getLsbD i))
def notConstraint (a y : Word) : Prop := ∀ i, i < 32 →
  Gadgets.notConstraint (flag (a.getLsbD i)) (flag (y.getLsbD i))

theorem xor_sound_complete (a b y : Word) : xorConstraint a b y ↔ y = a ^^^ b := by
  constructor
  · intro h
    apply BitVec.eq_of_getLsbD_eq
    intro i hi
    apply flag_injective
    simpa [flag] using (Gadgets.xor_sound_complete (a.getLsbD i) (b.getLsbD i)
      (flag (y.getLsbD i))).mp (h i hi)
  · rintro rfl i hi
    apply (Gadgets.xor_sound_complete _ _ _).mpr
    simp [flag]

theorem and_sound_complete (a b y : Word) : andConstraint a b y ↔ y = a &&& b := by
  constructor
  · intro h
    apply BitVec.eq_of_getLsbD_eq
    intro i hi
    apply flag_injective
    simpa [flag] using (Gadgets.and_sound_complete (a.getLsbD i) (b.getLsbD i)
      (flag (y.getLsbD i))).mp (h i hi)
  · rintro rfl i hi
    apply (Gadgets.and_sound_complete _ _ _).mpr
    simp [flag]

theorem not_sound_complete (a y : Word) : notConstraint a y ↔ y = ~~~a := by
  constructor
  · intro h
    apply BitVec.eq_of_getLsbD_eq
    intro i hi
    apply flag_injective
    simpa [flag, hi] using (Gadgets.not_sound_complete (a.getLsbD i)
      (flag (y.getLsbD i))).mp (h i hi)
  · rintro rfl i hi
    apply (Gadgets.not_sound_complete _ _).mpr
    simp [flag, hi]

def rotationIndex (n i : Nat) : Nat :=
  if i < 32 - n % 32 then n % 32 + i else i - (32 - n % 32)

def rotrConstraint (a y : Word) (n : Nat) : Prop := ∀ i, i < 32 →
  flag (y.getLsbD i) = flag (a.getLsbD (rotationIndex n i))

theorem rotr_sound_complete (a y : Word) (n : Nat) :
    rotrConstraint a y n ↔ y = Words.rotr a n := by
  constructor
  · intro h
    apply BitVec.eq_of_getLsbD_eq
    intro i hi
    have := flag_injective (h i hi)
    by_cases route : i < 32 - n % 32 <;>
      simpa [Words.rotr, BitVec.getLsbD_rotateRight, rotationIndex, hi,
        Bool.cond_eq_ite, route] using this
  · rintro rfl i hi
    by_cases route : i < 32 - n % 32 <;>
      simp [Words.rotr, BitVec.getLsbD_rotateRight, rotationIndex, hi, Bool.cond_eq_ite,
        route, ← BitVec.getLsbD_eq_getElem]

def shrConstraint (a y : Word) (n : Nat) : Prop := ∀ i, i < 32 →
  flag (y.getLsbD i) = flag (a.getLsbD (n + i))

theorem shr_sound_complete (a y : Word) (n : Nat) :
    shrConstraint a y n ↔ y = a >>> n := by
  constructor
  · intro h
    apply BitVec.eq_of_getLsbD_eq
    intro i hi
    simpa [Nat.add_comm] using flag_injective (h i hi)
  · rintro rfl i hi
    simp [Nat.add_comm]

def primitive (op : Graph.WordOp) (args : List Word) (y : Word) : Prop :=
  let a := args.getD 0 0
  let b := args.getD 1 0
  match op with
  | .add => addConstraint a b y
  | .xor => xorConstraint a b y
  | .and => andConstraint a b y
  | .not => notConstraint a y
  | .rotr n => rotrConstraint a y n
  | .shr n => shrConstraint a y n

theorem primitive_sound_complete (op : Graph.WordOp) (args : List Word) (y : Word) :
    primitive op args y ↔ y = Graph.wordEval op args := by
  cases op <;> simp only [primitive, Graph.wordEval]
  · exact add_sound_complete _ _ _
  · exact xor_sound_complete _ _ _
  · exact and_sound_complete _ _ _
  · exact not_sound_complete _ _
  · exact rotr_sound_complete _ _ _
  · exact shr_sound_complete _ _ _

end S31.Gadgets.Word
