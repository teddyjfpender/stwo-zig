/-
Univariate polynomials as coefficient lists (low degree first) over a field,
and the root bound: a polynomial with coefficient list of length `n` that is
not identically zero (as a coefficient list) has at most `n - 1` roots among
any list of pairwise-distinct points. Zero-dependency (Lean core `grind`).
-/
namespace TensorFrontend

open Lean.Grind

variable {F : Type} [Field F]

/-- Horner evaluation, coefficients low degree first. -/
def eval : List F → F → F
  | [], _ => 0
  | c :: p, x => c + x * eval p x

/-- Every coefficient is zero. -/
def AllZero (p : List F) : Prop := ∀ c ∈ p, c = 0

/-- Synthetic division by `(X - a)`: quotient (length `p.length - 1`) and
remainder. -/
def divLin : List F → F → List F × F
  | [], _ => ([], 0)
  | [c], _ => ([], c)
  | c :: d :: p, a =>
    let qr := divLin (d :: p) a
    (qr.2 :: qr.1, c + a * qr.2)

theorem divLin_length (p : List F) (a : F) : (divLin p a).1.length = p.length - 1 := by
  match p with
  | [] => rfl
  | [_] => rfl
  | c :: d :: p =>
    have ih := divLin_length (d :: p) a
    simp only [divLin, List.length_cons] at ih ⊢
    omega

theorem divLin_eval (p : List F) (a x : F) :
    eval p x = (x - a) * eval (divLin p a).1 x + (divLin p a).2 := by
  match p with
  | [] => simp only [divLin, eval]; grind
  | [c] => simp only [divLin, eval]; grind
  | c :: d :: p =>
    have ih := divLin_eval (d :: p) a x
    simp only [divLin, eval] at ih ⊢
    rw [ih]
    grind

theorem divLin_rem (p : List F) (a : F) : (divLin p a).2 = eval p a := by
  have h := divLin_eval p a a
  grind

/-- If the quotient and remainder are zero, so is the polynomial. -/
theorem divLin_allZero (p : List F) (a : F)
    (hq : AllZero (divLin p a).1) (hr : (divLin p a).2 = 0) : AllZero p := by
  match p with
  | [] => intro c hc; cases hc
  | [c] =>
    intro x hx
    simp [divLin] at hr
    simp at hx
    rw [hx, hr]
  | c :: d :: p =>
    simp only [divLin] at hq hr
    have hq0 : (divLin (d :: p) a).2 = 0 := hq _ (List.mem_cons_self ..)
    have hq1 : AllZero (divLin (d :: p) a).1 := fun y hy => hq y (List.mem_cons_of_mem _ hy)
    have ih := divLin_allZero (d :: p) a hq1 hq0
    have hc : c = 0 := by rw [hq0] at hr; grind
    intro y hy
    cases hy with
    | head => exact hc
    | tail _ h => exact ih y h

/-- **Root bound.** A polynomial that is not identically zero vanishes on at
most `p.length - 1` points of any list of pairwise-distinct points. -/
theorem roots_le (p : List F) (hp : ¬ AllZero p) (L : List F) (hL : L.Nodup)
    (hroot : ∀ x ∈ L, eval p x = 0) : L.length ≤ p.length - 1 := by
  induction L generalizing p with
  | nil => exact Nat.zero_le _
  | cons a L ih =>
    have hnd := List.nodup_cons.mp hL
    have hq : ¬ AllZero (divLin p a).1 := by
      intro hq
      apply hp
      apply divLin_allZero p a hq
      rw [divLin_rem]
      exact hroot a (List.mem_cons_self ..)
    have hqroot : ∀ x ∈ L, eval (divLin p a).1 x = 0 := by
      intro x hx
      have h1 := divLin_eval p a x
      have h2 : eval p x = 0 := hroot x (List.mem_cons_of_mem _ hx)
      have h3 : (divLin p a).2 = 0 := by
        rw [divLin_rem]; exact hroot a (List.mem_cons_self ..)
      have hxa : x ≠ a := fun h => hnd.1 (h ▸ hx)
      have hxa' : x - a ≠ 0 := fun h => hxa (by grind)
      rw [h2, h3] at h1
      grind
    have := ih _ hq hnd.2 hqroot
    rw [divLin_length] at this
    have hlen : (divLin p a).1.length ≥ 1 := by
      cases h : (divLin p a).1 with
      | nil => rw [h] at hq; exact absurd (fun c hc => by cases hc) hq
      | cons _ _ => simp
    rw [divLin_length] at hlen
    simp only [List.length_cons]
    omega

/-- Coefficientwise difference (padding the shorter list with zeros). -/
def sub : List F → List F → List F
  | [], [] => []
  | c :: p, [] => c :: sub p []
  | [], d :: q => (0 - d) :: sub [] q
  | c :: p, d :: q => (c - d) :: sub p q

theorem sub_eval (p q : List F) (x : F) : eval (sub p q) x = eval p x - eval q x := by
  match p, q with
  | [], [] => simp [sub, eval]; grind
  | c :: p, [] => have := sub_eval p [] x; simp only [sub, eval] at this ⊢; rw [this]; grind
  | [], d :: q => have := sub_eval [] q x; simp only [sub, eval] at this ⊢; rw [this]; grind
  | c :: p, d :: q => have := sub_eval p q x; simp only [sub, eval] at this ⊢; rw [this]; grind

theorem sub_length (p q : List F) : (sub p q).length = max p.length q.length := by
  match p, q with
  | [], [] => simp [sub]
  | c :: p, [] => have := sub_length p []; simp only [sub, List.length_cons, List.length_nil] at this ⊢; omega
  | [], d :: q => have := sub_length [] q; simp only [sub, List.length_cons, List.length_nil] at this ⊢; omega
  | c :: p, d :: q => have := sub_length p q; simp only [sub, List.length_cons] at this ⊢; omega

theorem eval_allZero (p : List F) (h : AllZero p) (x : F) : eval p x = 0 := by
  induction p with
  | nil => rfl
  | cons c p ih =>
    simp only [eval]
    rw [h c (List.mem_cons_self ..), ih (fun y hy => h y (List.mem_cons_of_mem _ hy))]
    grind

end TensorFrontend
