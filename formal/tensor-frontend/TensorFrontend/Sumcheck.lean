/-
Sumcheck soundness (counting form, zero-dependency).

Model. `F` is a finite field given by an explicit duplicate-free list of all
its elements (`FinEnum`). A sumcheck instance is a function
`f : List F → F` on `n`-element points; its claimed value is the sum over the
Boolean hypercube `{0,1}^n`. The prover is an arbitrary *adaptive* strategy:
a function from the challenges drawn so far to the next round message (a
coefficient list). The verifier checks in each round that the message has at
most `d + 1` coefficients and that `g(0) + g(1)` equals the running claim,
replaces the claim by `g(r)`, and finally checks the claim against `f` at the
challenge point (the oracle query; in the protocol it becomes a PCS opening).

Theorem `sumcheck_sound`: if the initial claim is false, the number of
challenge vectors in `F^n` on which the verifier accepts is at most
`n * d * |F|^(n-1)`, i.e. acceptance probability `<= n d / |F|`.

Assumed hypothesis (stated, not derived): `IndDeg d n f`, i.e. every
partial-sum round function of `f` is a polynomial of degree `<= d`. This
holds for any polynomial of individual degree `<= d`; we take it as the
interface rather than building a multivariate polynomial type.
-/
import TensorFrontend.Poly

namespace TensorFrontend

open Lean.Grind

/-- A finite type with an explicit duplicate-free enumeration. -/
class FinEnum (F : Type) where
  elems : List F
  nodup : elems.Nodup
  complete : ∀ x, x ∈ elems

variable {F : Type} [Field F] [DecidableEq F] [FinEnum F]

/-- `|F|`. -/
def card (F : Type) [FinEnum F] : Nat := (FinEnum.elems (F := F)).length

/-- Sum of `f` over the Boolean hypercube `{0,1}^n` (first coordinate first). -/
def hsum : Nat → (List F → F) → F
  | 0, f => f []
  | n + 1, f => hsum n (fun r => f (0 :: r)) + hsum n (fun r => f (1 :: r))

/-- Every round function of `f` (fix a prefix, sum out the rest except the
next variable) is a univariate polynomial with at most `d + 1` coefficients. -/
def IndDeg (d : Nat) : Nat → (List F → F) → Prop
  | 0, _ => True
  | n + 1, f =>
    (∃ h : List F, h.length ≤ d + 1 ∧ ∀ x, eval h x = hsum n (fun r => f (x :: r))) ∧
    ∀ x, IndDeg d n (fun r => f (x :: r))

/-- The sumcheck verifier on challenge vector `rs`, against an adaptive prover
`P` (round message as a function of the challenges drawn so far). -/
def accepts (d : Nat) : Nat → (List F → F) → F → (List F → List F) → List F → Bool
  | 0, f, c, _, [] => decide (c = f [])
  | n + 1, f, c, P, r :: rs =>
    decide ((P []).length ≤ d + 1) && decide (eval (P []) 0 + eval (P []) 1 = c) &&
      accepts d n (fun t => f (r :: t)) (eval (P []) r) (fun pre => P (r :: pre)) rs
  | _, _, _, _, _ => false

/-- All challenge vectors of length `n`. -/
def vecs (F : Type) [FinEnum F] : Nat → List (List F)
  | 0 => [[]]
  | n + 1 => (FinEnum.elems (F := F)).flatMap (fun r => (vecs F n).map (r :: ·))

theorem sum_map_const {α : Type} (L : List α) (c : Nat) : (L.map (fun _ => c)).sum = L.length * c := by
  induction L with
  | nil => simp
  | cons a L ih => simp only [List.map_cons, List.sum_cons, List.length_cons, ih, Nat.succ_mul]; omega

omit [Field F] [DecidableEq F] in
theorem vecs_length (n : Nat) : (vecs F n).length = card F ^ n := by
  induction n with
  | zero => rfl
  | succ n ih =>
    simp only [vecs, List.length_flatMap, List.length_map, ih]
    rw [sum_map_const, Nat.pow_succ, card, Nat.mul_comm]

/-- Sum bound used for the per-challenge split. -/
theorem sum_split {α : Type} (L : List α) (g : α → Nat) (b : α → Bool) (A B : Nat)
    (h : ∀ r ∈ L, g r ≤ (if b r then A else 0) + B) :
    (L.map g).sum ≤ L.countP b * A + L.length * B := by
  induction L with
  | nil => simp
  | cons a L ih =>
    have ha := h a (List.mem_cons_self ..)
    have ih' := ih (fun r hr => h r (List.mem_cons_of_mem _ hr))
    simp only [List.map_cons, List.sum_cons, List.countP_cons, List.length_cons]
    cases hb : b a <;> simp [hb] at ha ⊢ <;>
      (simp only [Nat.add_mul, Nat.one_mul] at *; omega)

/-- **Round bound.** Two distinct polynomials with `<= d + 1` coefficients
agree on at most `d` points of `F`. Distinctness is witnessed by different
values of `g(0) + g(1)`. -/
theorem agree_count (d : Nat) (g h : List F) (hg : g.length ≤ d + 1) (hh : h.length ≤ d + 1)
    (hne : eval g 0 + eval g 1 ≠ eval h 0 + eval h 1) :
    (FinEnum.elems (F := F)).countP (fun r => decide (eval g r = eval h r)) ≤ d := by
  have hnz : ¬ AllZero (sub g h) := by
    intro hz
    apply hne
    have h0 := eval_allZero _ hz 0
    have h1 := eval_allZero _ hz 1
    rw [sub_eval] at h0 h1
    grind
  rw [List.countP_eq_length_filter]
  have hnd : ((FinEnum.elems (F := F)).filter (fun r => decide (eval g r = eval h r))).Nodup :=
    List.Nodup.sublist (List.filter_sublist) FinEnum.nodup
  have := roots_le (sub g h) hnz _ hnd (by
    intro x hx
    rw [List.mem_filter] at hx
    rw [sub_eval]
    have := _root_.of_decide_eq_true hx.2
    grind)
  rw [sub_length] at this
  omega

/-- **Sumcheck soundness.** For a false claim, at most `n * d * |F|^(n-1)` of
the `|F|^n` challenge vectors make the verifier accept, for every adaptive
prover. -/
theorem sumcheck_sound (d n : Nat) (f : List F → F) (hdeg : IndDeg d n f) (c : F)
    (hc : c ≠ hsum n f) (P : List F → List F) :
    (vecs F n).countP (accepts d n f c P) ≤ n * d * card F ^ (n - 1) := by
  induction n generalizing f c P with
  | zero =>
    simp only [vecs, List.countP_cons, List.countP_nil, accepts]
    simp only [decide_eq_true_eq]
    simp only [hsum] at hc
    simp [hc]
  | succ n ih =>
    obtain ⟨⟨h, hlen, hh⟩, hrest⟩ := hdeg
    have hsplit : (vecs F (n + 1)).countP (accepts d (n + 1) f c P) =
        ((FinEnum.elems (F := F)).map (fun r =>
          (vecs F n).countP (fun rs => accepts d (n + 1) f c P (r :: rs)))).sum := by
      simp only [vecs, List.countP_flatMap]
      congr 1
      apply List.map_congr_left
      intro r _
      simp only [Function.comp, List.countP_map]
      rfl
    rw [hsplit]
    let g := P []
    by_cases hv : g.length ≤ d + 1 ∧ eval g 0 + eval g 1 = c
    · -- the first message passes the round check; it differs from the true h
      have hne : eval g 0 + eval g 1 ≠ eval h 0 + eval h 1 := by
        rw [hv.2, hh 0, hh 1]; exact hc
      have hbad := agree_count d g h hv.1 hlen hne
      have hbound := sum_split (FinEnum.elems (F := F))
        (fun r => (vecs F n).countP (fun rs => accepts d (n + 1) f c P (r :: rs)))
        (fun r => decide (eval g r = eval h r)) (card F ^ n) (n * d * card F ^ (n - 1)) (by
          intro r _
          by_cases hr : eval g r = eval h r
          · simp only [hr, decide_true, ite_true]
            have := (List.countP_le_length (p := fun rs => accepts d (n + 1) f c P (r :: rs))
              (l := vecs F n))
            rw [vecs_length] at this
            omega
          · simp only [hr, decide_false]
            have hc' : eval g r ≠ hsum n (fun t => f (r :: t)) := by rw [← hh r]; exact hr
            have := ih (fun t => f (r :: t)) (hrest r) (eval g r) hc' (fun pre => P (r :: pre))
            have heq : (vecs F n).countP (fun rs => accepts d (n + 1) f c P (r :: rs)) =
                (vecs F n).countP (accepts d n (fun t => f (r :: t)) (eval g r)
                  (fun pre => P (r :: pre))) := by
              congr 1
              funext rs
              simp only [accepts, g] at hv ⊢
              simp [hv.1, hv.2]
            simp only [Bool.false_eq_true, ite_false, Nat.zero_add]
            omega)
      have hq : card F * (n * d * card F ^ (n - 1)) ≤ n * d * card F ^ n := by
        cases n with
        | zero => simp
        | succ k =>
          simp only [Nat.add_sub_cancel, Nat.pow_succ]
          rw [Nat.mul_comm (card F) _, Nat.mul_assoc]
          exact Nat.le_refl _
      have hm : (FinEnum.elems (F := F)).countP (fun r => decide (eval g r = eval h r)) * card F ^ n
          ≤ d * card F ^ n := Nat.mul_le_mul_right _ hbad
      have hL : (FinEnum.elems (F := F)).length = card F := rfl
      rw [hL] at hbound
      simp only [Nat.add_sub_cancel]
      have hsplit2 : (n + 1) * d * card F ^ n = d * card F ^ n + n * d * card F ^ n := by
        rw [Nat.succ_mul, Nat.add_mul, Nat.add_comm]
      rw [hsplit2]
      omega
    · -- the first message already fails: nothing is accepted
      have hz : ∀ r ∈ FinEnum.elems (F := F),
          (vecs F n).countP (fun rs => accepts d (n + 1) f c P (r :: rs)) = 0 := by
        intro r _
        rw [List.countP_eq_zero]
        intro rs _
        simp only [accepts]
        intro hacc
        simp only [Bool.and_eq_true, decide_eq_true_eq] at hacc
        exact hv ⟨hacc.1.1, hacc.1.2⟩
      rw [List.map_congr_left hz, sum_map_const]
      simp

end TensorFrontend
