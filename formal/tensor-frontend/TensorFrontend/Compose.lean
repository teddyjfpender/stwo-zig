/-
Sequential composition of round-by-round sound steps (zero-dependency).

A protocol is a list of steps. Step `i` draws a challenge uniformly from a
finite list `Ω_i` and maps the verifier state `s` to `next_i s ω`. A state
is either "good" (its claim is true / the verifier would accept) or bad.
If from every bad state step `i` reaches a good state for at most a
fraction `e_i / D` of its challenges, then from a bad initial state the
whole run ends good for at most a fraction `(Σ e_i) / D` of the challenge
tuples. This is the union bound over rounds that security.zig's `summary`
sums (`sum_with`), in the sequential (round-by-round) form needed for
interactive protocols: the bound of step `i` holds for every state the
earlier steps can produce, which covers an adaptive prover when the state
carries the transcript.
-/
namespace TensorFrontend.Compose

/-- A step: challenge list, transition, error numerator (over a common `D`). -/
structure Step (S α : Type) where
  Ω : List α
  next : S → α → S
  err : Nat

/-- All challenge tuples, one challenge per step. -/
def space {S α : Type} : List (Step S α) → List (List α)
  | [] => [[]]
  | st :: rest => st.Ω.flatMap (fun a => (space rest).map (a :: ·))

/-- Run the steps on a challenge tuple. -/
def run {S α : Type} : List (Step S α) → S → List α → S
  | [], s, _ => s
  | st :: rest, s, a :: as => run rest (st.next s a) as
  | _ :: _, s, [] => s

/-- Sum of the step errors. -/
def errSum {S α : Type} (steps : List (Step S α)) : Nat := (steps.map (·.err)).sum

theorem sum_map_const' {β : Type} (L : List β) (c : Nat) : (L.map (fun _ => c)).sum = L.length * c := by
  induction L with
  | nil => simp
  | cons a L ih => simp only [List.map_cons, List.sum_cons, List.length_cons, ih, Nat.succ_mul]; omega

theorem space_length {S α : Type} (st : Step S α) (rest : List (Step S α)) :
    (space (st :: rest)).length = st.Ω.length * (space rest).length := by
  simp only [space, List.length_flatMap, List.length_map]
  rw [sum_map_const']

/-- Per-element split with a common denominator. -/
theorem sum_split_D {β : Type} (L : List β) (g : β → Nat) (b : β → Bool) (A B D : Nat)
    (h : ∀ r ∈ L, g r * D ≤ (if b r then A * D else 0) + B) :
    (L.map g).sum * D ≤ L.countP b * (A * D) + L.length * B := by
  induction L with
  | nil => simp
  | cons a L ih =>
    have ha := h a (List.mem_cons_self ..)
    have ih' := ih (fun r hr => h r (List.mem_cons_of_mem _ hr))
    simp only [List.map_cons, List.sum_cons, List.countP_cons, List.length_cons, Nat.add_mul]
    cases hb : b a
    · simp only [hb, Bool.false_eq_true, ite_false] at ha ⊢
      omega
    · simp only [hb, ite_true] at ha ⊢
      rw [Nat.one_mul, Nat.one_mul]
      omega

/-- **Sequential composition (union bound over rounds).** -/
theorem chain_sound {S α : Type} (Good : S → Bool) (D : Nat) :
    ∀ (steps : List (Step S α)) (s0 : S),
    Good s0 = false →
    (∀ st ∈ steps, ∀ s, Good s = false →
      st.Ω.countP (fun a => Good (st.next s a)) * D ≤ st.err * st.Ω.length) →
    (space steps).countP (fun as => Good (run steps s0 as)) * D ≤ errSum steps * (space steps).length
  | [], s0, hbad, _ => by simp [space, run, hbad]
  | st :: rest, s0, hbad, hstep => by
    have hsplit : (space (st :: rest)).countP (fun as => Good (run (st :: rest) s0 as)) =
        (st.Ω.map (fun a => (space rest).countP (fun as => Good (run rest (st.next s0 a) as)))).sum := by
      simp only [space, List.countP_flatMap]
      congr 1
      apply List.map_congr_left
      intro a _
      simp only [Function.comp, List.countP_map]
      rfl
    rw [hsplit, space_length]
    have hrest : ∀ st' ∈ rest, ∀ s, Good s = false →
        st'.Ω.countP (fun a => Good (st'.next s a)) * D ≤ st'.err * st'.Ω.length :=
      fun st' h => hstep st' (List.mem_cons_of_mem _ h)
    have hb := sum_split_D st.Ω
      (fun a => (space rest).countP (fun as => Good (run rest (st.next s0 a) as)))
      (fun a => Good (st.next s0 a)) (space rest).length (errSum rest * (space rest).length) D (by
        intro a _
        cases hg : Good (st.next s0 a)
        · have := chain_sound Good D rest (st.next s0 a) hg hrest
          simp only [Bool.false_eq_true, ite_false, Nat.zero_add]
          exact this
        · simp only [ite_true]
          have := List.countP_le_length (p := fun as => Good (run rest (st.next s0 a) as)) (l := space rest)
          exact Nat.le_trans (Nat.mul_le_mul_right D this) (Nat.le_add_right _ _))
    have h1 := hstep st (List.mem_cons_self ..) s0 hbad
    have h2 : st.Ω.countP (fun a => Good (st.next s0 a)) * ((space rest).length * D) ≤
        st.err * st.Ω.length * (space rest).length := by
      rw [Nat.mul_comm (space rest).length D, ← Nat.mul_assoc]
      exact Nat.mul_le_mul_right _ h1
    simp only [errSum, List.map_cons, List.sum_cons] at hb ⊢
    have e1 : ((st.err + (rest.map (·.err)).sum) * (st.Ω.length * (space rest).length)) =
        st.err * st.Ω.length * (space rest).length +
          st.Ω.length * ((rest.map (·.err)).sum * (space rest).length) := by
      rw [Nat.add_mul, ← Nat.mul_assoc, Nat.mul_left_comm, Nat.mul_assoc]
    rw [e1]
    omega

end TensorFrontend.Compose
