/-
Non-vacuity check: a concrete finite field (GF(2) = `Fin 2`) with a
`Lean.Grind.Field` and `FinEnum` instance, and instantiations of the generic
sumcheck / LogUp theorems on it. This does not say anything about QM31; it
only shows that the hypotheses of `sumcheck_sound` (`IndDeg`, `FinEnum`) and
of the LogUp theorems (the characteristic hypothesis) are satisfiable, i.e.
the theorems are not vacuously true.
-/
import TensorFrontend.LogUp

namespace TensorFrontend.Instance

open Lean.Grind TensorFrontend

instance : Inv (Fin 2) := ⟨fun a => a⟩
instance : Div (Fin 2) := ⟨fun a b => a * b⟩
instance : HPow (Fin 2) Int (Fin 2) := ⟨fun a n => if n = 0 then 1 else a⟩

instance gf2Field : Field (Fin 2) where
  div_eq_mul_inv := by intro a b; rfl
  zero_ne_one := by decide
  inv_zero := rfl
  mul_inv_cancel := by intro a h; revert a; decide
  zpow_zero := by intro a; rfl
  zpow_succ := by
    intro a n
    show (if ((n : Int) + 1) = 0 then 1 else a) = (if (n : Int) = 0 then 1 else a) * a
    have h1 : ((n : Int) + 1) ≠ 0 := by omega
    rw [if_neg h1]
    by_cases h : (n : Int) = 0
    · rw [if_pos h]; revert a; decide
    · rw [if_neg h]; revert a; decide
  zpow_neg := by
    intro a n
    show (if -n = 0 then 1 else a) = (if n = 0 then 1 else a)
    by_cases h : n = 0
    · rw [if_pos h, if_pos (by omega)]
    · rw [if_neg h, if_neg (by omega)]

instance gf2Enum : FinEnum (Fin 2) where
  elems := [0, 1]
  nodup := by decide
  complete := by intro x; revert x; decide

/-- `IndDeg` is satisfiable: the constant-zero function in one variable has
degree-0 round functions. -/
theorem indDeg_zero : IndDeg (F := Fin 2) 0 1 (fun _ => 0) :=
  ⟨⟨[0], by decide, by intro x; revert x; decide⟩, fun _ => trivial⟩

/-- `sumcheck_sound` instantiated: the false claim `1` about the zero
function (true sum `0`) is accepted on at most `1 * 0 * 2^0 = 0` challenges,
whatever the prover sends. -/
example (P : List (Fin 2) → List (Fin 2)) :
    (vecs (Fin 2) 1).countP (accepts 0 1 (fun _ => 0) 1 P) ≤ 0 :=
  sumcheck_sound 0 1 (fun _ => 0) indDeg_zero 1 (by decide) P

/-- The LogUp characteristic hypothesis holds on GF(2) with `p = 2`. -/
theorem gf2_char : ∀ k, 0 < k → k < 2 → (LogUp.ncast k : Fin 2) ≠ 0 := by
  intro k h0 h1
  have : k = 1 := by omega
  subst this; decide

/-- `logup_identity_sound` instantiated (non-vacuity of its hypotheses). -/
example (T : List (Fin 2 × Nat)) (A : List (Fin 2))
    (hT : ∀ z, LogUp.tcount T z < 2) (hA : ∀ z, LogUp.acount A z < 2)
    (hz : AllZero (LogUp.num (LogUp.group (LogUp.pairs T A)))) : LogUp.MultisetOK T A :=
  LogUp.logup_identity_sound 2 gf2_char T A hT hA hz

end TensorFrontend.Instance
