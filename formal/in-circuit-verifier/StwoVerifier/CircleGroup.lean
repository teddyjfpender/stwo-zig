/-
**Group algebra of the circle law.** `CPoint.add` is complex multiplication
restricted to the unit circle; its commutativity and associativity are
polynomial identities over any commutative ring, so they hold for all
points (on the circle or not): `(CPoint α, add, zero)` is a commutative
monoid. The binary-ladder `smul` is the monoid power, giving the
additivity `smul p (a + b) = (smul p a).add (smul p b)` that the
query-selection gadget proof needs (the domain point is built generator
power by generator power from the index bits).
-/
import StwoVerifier.Circle
import StwoVerifier.Algebra

namespace StwoVerifier.CPoint

variable {α : Type} [CommRing α]

@[ext] theorem ext' {p q : CPoint α} (hx : p.x = q.x) (hy : p.y = q.y) : p = q := by
  cases p; cases q; simp_all

instance : CommMonoid (CPoint α) where
  mul := add
  one := zero
  mul_assoc p q r := by
    show (p.add q).add r = p.add (q.add r)
    ext <;> simp only [add] <;> ring
  one_mul p := by
    show zero.add p = p
    ext <;> simp only [add, zero] <;> ring
  mul_one p := by
    show p.add zero = p
    ext <;> simp only [add, zero] <;> ring
  mul_comm p q := by
    show p.add q = q.add p
    ext <;> simp only [add] <;> ring

theorem mul_def (p q : CPoint α) : p * q = p.add q := rfl
theorem one_def : (1 : CPoint α) = zero := rfl

theorem double_eq_sq (p : CPoint α) : p.double = p * p := rfl

/-- The binary ladder computes the monoid power. -/
theorem smul_eq_pow (p : CPoint α) : ∀ n, p.smul n = p ^ n := by
  intro n
  induction n using Nat.strong_induction_on with
  | _ n ih =>
    match n with
    | 0 => simp [smul, one_def]
    | n + 1 =>
      rw [smul, ih ((n + 1) / 2) (by omega), double_eq_sq, ← pow_add]
      by_cases hodd : (n + 1) % 2 = 1
      · rw [if_pos hodd, ← mul_def, ← pow_succ,
          show (n + 1) / 2 + (n + 1) / 2 + 1 = n + 1 by omega]
      · rw [if_neg hodd, show (n + 1) / 2 + (n + 1) / 2 = n + 1 by omega]

/-- `smul` additivity: index arithmetic lands on point addition. -/
theorem smul_add_idx (p : CPoint α) (a b : ℕ) :
    p.smul (a + b) = (p.smul a).add (p.smul b) := by
  rw [smul_eq_pow, smul_eq_pow, smul_eq_pow, ← mul_def, pow_add]

/-- `repeatedDouble` is multiplication of the index by `2^n`. -/
theorem repeatedDouble_eq_smul (p : CPoint α) (n : ℕ) :
    ∀ k, (p.smul k).repeatedDouble n = p.smul (k * 2 ^ n) := by
  induction n with
  | zero => intro k; simp [repeatedDouble]
  | succ n ih =>
    intro k
    show ((p.smul k).repeatedDouble n).double = _
    rw [ih k, double_eq_sq, smul_eq_pow, smul_eq_pow, ← pow_add]
    congr 1
    ring

theorem conj_mul (p q : CPoint α) :
    (p * q).conjugate = p.conjugate * q.conjugate := by
  show (p.add q).conjugate = p.conjugate.add q.conjugate
  unfold add conjugate
  ext <;> simp <;> ring

theorem conj_one : (1 : CPoint α).conjugate = 1 := by
  show zero.conjugate = zero
  unfold zero conjugate
  ext <;> simp

theorem conj_smul (p : CPoint α) (k : ℕ) :
    (p.smul k).conjugate = p.conjugate.smul k := by
  rw [smul_eq_pow, smul_eq_pow]
  induction k with
  | zero => simpa using conj_one
  | succ k ih => rw [pow_succ, pow_succ, conj_mul, ih]

end StwoVerifier.CPoint
