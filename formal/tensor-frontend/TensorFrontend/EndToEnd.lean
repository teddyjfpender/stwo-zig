/-
End-to-end statement for one matmul + requant + range op (zero-dependency).

The toy protocol for one output entry `y = requant_s(Σ_k x_k w_k)`:

* a LogUp range check (arity 1, one random point `x`) that the looked-up
  values (`y + 128`, the remainder `r`, ...) are in the table;
* a sumcheck (`n` rounds, degree `d`) that the committed identity
  polynomial sums to the claimed `c`, ending in one oracle query `f(ρ)`.

Assumptions, as explicit hypotheses (no axioms):

* `IdealOracle ans f`: the PCS is an ideal oracle, i.e. the opening the
  verifier receives at `ρ` is the committed polynomial's value. With a real
  PCS this is where the proximity / binding error enters (not modelled).
* `MatmulEncoding`: the encoding facts linking field-level checks to the
  integer statement: a valid LogUp multiset gives the integer range facts
  (table contents), and a true sumcheck claim gives the M31 remainder
  identity. These are properties of how the statement is laid out, not
  of the protocol's randomness.
* the bound conditions of `matmul_sound`, which `Bounds.validate_sound`
  discharges from the statement analysis.

`e2e_matmul`: for every prover, the number of challenge pairs `(x, ρ)` on
which the verifier accepts but `y != requant_s(x · w)` is at most
`(2U - 1) |F|^n + |F| · n d |F|^(n-1)`, i.e.

    Pr[accept ∧ relation false] <= (2U - 1)/|F| + n d/|F|,

the LogUp term plus the sumcheck term (`U` = distinct LogUp poles).
-/
import TensorFrontend.LogUp
import TensorFrontend.Kernel

namespace TensorFrontend.EndToEnd

open Lean.Grind TensorFrontend TensorFrontend.LogUp TensorFrontend.Kernel

variable {F : Type} [Field F] [DecidableEq F] [FinEnum F]

/-- The PCS as an ideal oracle: the verifier's query answer is the
committed function's value. -/
def IdealOracle (ans f : List F → F) : Prop := ∀ ρ, ans ρ = f ρ

/-- Encoding facts for the matmul statement (see the module header). -/
structure MatmulEncoding (T : List (F × Nat)) (A : List F) (n : Nat) (f : List F → F) (c : F)
    (s : Nat) (xs ws : List Int) (y r : Int) : Prop where
  range : MultisetOK T A → -128 ≤ y ∧ y < 128 ∧ 0 ≤ r ∧ r < 2 ^ s
  ident : c = hsum n f → FieldZero (dot xs ws + 2 ^ (s - 1) - 2 ^ s * y - r)

/-- All challenge pairs `(x, ρ)`. -/
def chal (F : Type) [FinEnum F] (n : Nat) : List (F × List F) :=
  (FinEnum.elems (F := F)).flatMap (fun x => (vecs F n).map (fun ρ => (x, ρ)))

omit [Field F] [DecidableEq F] in
theorem count_fst (n : Nat) (P : F × List F → Bool) (Q : F → Bool) (h : ∀ xρ, P xρ = true → Q xρ.1 = true) :
    (chal F n).countP P ≤ (FinEnum.elems (F := F)).countP Q * card F ^ n := by
  have h1 : (chal F n).countP P ≤ (chal F n).countP (fun xρ => Q xρ.1) := by
    induction (chal F n) with
    | nil => simp
    | cons y l ih =>
      simp only [List.countP_cons]
      cases hp : P y
      · simp only [Bool.false_eq_true, ite_false]; split <;> omega
      · simp only [h y hp, ite_true]; omega
  have h2 : (chal F n).countP (fun xρ => Q xρ.1) =
      ((FinEnum.elems (F := F)).map (fun x => if Q x then card F ^ n else 0)).sum := by
    simp only [chal, List.countP_flatMap, List.countP_map, Function.comp_def]
    congr 1; apply List.map_congr_left; intro x _
    cases hq : Q x
    · simp
    · simp [vecs_length]
  have h3 := sum_split (FinEnum.elems (F := F)) (fun x => if Q x then card F ^ n else 0) Q (card F ^ n) 0
    (by intro x _; cases Q x <;> simp)
  simp at h3
  omega

omit [Field F] [DecidableEq F] in
theorem count_snd (n : Nat) (P : F × List F → Bool) (R : List F → Bool) (h : ∀ xρ, P xρ = true → R xρ.2 = true) :
    (chal F n).countP P ≤ card F * (vecs F n).countP R := by
  have h1 : (chal F n).countP P ≤ (chal F n).countP (fun xρ => R xρ.2) := by
    induction (chal F n) with
    | nil => simp
    | cons y l ih =>
      simp only [List.countP_cons]
      cases hp : P y
      · simp only [Bool.false_eq_true, ite_false]; split <;> omega
      · simp only [h y hp, ite_true]; omega
  have h2 : (chal F n).countP (fun xρ => R xρ.2) =
      ((FinEnum.elems (F := F)).map (fun _ => (vecs F n).countP R)).sum := by
    simp only [chal, List.countP_flatMap, List.countP_map, Function.comp_def]
  rw [h2, sum_map_const] at h1
  exact h1

/-- **End-to-end soundness of one matmul + requant + range op**, ideal PCS. -/
theorem e2e_matmul (p : Nat) (hchar : ∀ k, 0 < k → k < p → (ncast k : F) ≠ 0)
    (T : List (F × Nat)) (A : List F) (hT : ∀ z, tcount T z < p) (hA : ∀ z, acount A z < p)
    (n d : Nat) (f ans : List F → F) (hdeg : IndDeg d n f) (horacle : IdealOracle ans f)
    (c : F) (Pr : List F → List F)
    (bx logK s : Nat) (xs ws : List Int) (y r : Int)
    (hbits : bx + 7 + logK ≤ 30) (hs1 : 1 ≤ s) (hs2 : s ≤ 22) (hK : xs.length = 2 ^ logK)
    (hx : ∀ a ∈ xs, a.natAbs ≤ 2 ^ bx) (hw : ∀ a ∈ ws, a.natAbs ≤ 2 ^ 7)
    (enc : MatmulEncoding T A n f c s xs ws y r) :
    (chal F n).countP (fun xρ =>
        decide (fsum (pairs T A) xρ.1 = 0) && accepts d n ans c Pr xρ.2 &&
          !decide (y = requant s (dot xs ws)))
      ≤ (2 * (dd (poles (pairs T A))).length - 1) * card F ^ n + card F * (n * d * card F ^ (n - 1)) := by
  have hans : ans = f := funext horacle
  subst hans
  by_cases hrel : y = requant s (dot xs ws)
  · have : (chal F n).countP (fun xρ =>
        decide (fsum (pairs T A) xρ.1 = 0) && accepts d n ans c Pr xρ.2 &&
          !decide (y = requant s (dot xs ws))) = 0 := by
      rw [List.countP_eq_zero]; intro _ _; simp [hrel]
    omega
  · by_cases hm : MultisetOK T A
    · -- range facts hold, so the identity is false: the sumcheck claim is false
      obtain ⟨hy0, hy1, hr0, hr1⟩ := enc.range hm
      have hc : c ≠ hsum n ans := fun e =>
        hrel (matmul_sound bx logK s xs ws y r hbits hs1 hs2 hK hx hw hy0 hy1 hr0 hr1 (enc.ident e))
      have h1 := count_snd n (fun xρ =>
          decide (fsum (pairs T A) xρ.1 = 0) && accepts d n ans c Pr xρ.2 &&
            !decide (y = requant s (dot xs ws))) (accepts d n ans c Pr) (by
        intro xρ hp; simp only [Bool.and_eq_true] at hp; exact hp.1.2)
      have h2 := sumcheck_sound d n ans hdeg c hc Pr
      have h3 := Nat.mul_le_mul_left (card F) h2
      omega
    · -- the multiset relation fails: the LogUp check is the bad event
      have h1 := count_fst n (fun xρ =>
          decide (fsum (pairs T A) xρ.1 = 0) && accepts d n ans c Pr xρ.2 &&
            !decide (y = requant s (dot xs ws)))
          (fun x => decide (x ∈ poles (pairs T A)) || decide (fsum (pairs T A) x = 0)) (by
        intro xρ hp; simp only [Bool.and_eq_true, decide_eq_true_eq] at hp
        simp [hp.1.1])
      have h2 := logup_random_sound p hchar T A hT hA hm
      have h3 := Nat.mul_le_mul_right (card F ^ n) h2
      omega

end TensorFrontend.EndToEnd
