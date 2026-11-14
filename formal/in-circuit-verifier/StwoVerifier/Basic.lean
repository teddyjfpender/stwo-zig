import Mathlib

namespace StwoVerifier

/-- The Mersenne-31 prime. -/
def P : ℕ := 2 ^ 31 - 1

/-- `2^31 − 1` is a Mersenne prime; certified by the Lucas–Lehmer test. -/
theorem P_prime : Nat.Prime P :=
  show (mersenne 31).Prime from lucas_lehmer_sufficiency 31 (by norm_num) (by norm_num)

instance : Fact (Nat.Prime P) := ⟨P_prime⟩

end StwoVerifier
