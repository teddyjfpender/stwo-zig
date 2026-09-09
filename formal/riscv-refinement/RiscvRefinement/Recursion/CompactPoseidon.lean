import RiscvRefinement.Field.M31

namespace RiscvRefinement.Recursion.CompactPoseidon

/-- Exact canonical M31 representative of the source S-box polynomial x^5. -/
def fifthPower (x : M31) : M31 := M31.reduce (x.val ^ 5)

/-- `Fill.sbox`: square=x.square(); fifth=x.mul(square.square()). -/
def lowered (x : M31) : M31 := x * ((x * x) * (x * x))

/-- `Evaluate.sbox`: both committed witness residuals must vanish. -/
def accepts (x square fifth : M31) : Prop :=
  square - x * x = 0 ∧ fifth - x * (square * square) = 0

/-- No primality or inverse assumption is required: this is polynomial equality
in the repository's concrete arithmetic modulo 2147483647. -/
theorem lowered_eq_fifthPower (x : M31) : lowered x = fifthPower x := by
  apply M31.ext
  change (x.val * (((x.val * x.val) % M31.modulus *
    ((x.val * x.val) % M31.modulus)) % M31.modulus)) % M31.modulus =
    x.val ^ 5 % M31.modulus
  simp only [Nat.mul_mod_mod, Nat.mod_mul_mod, Nat.pow_succ, Nat.pow_zero,
    Nat.one_mul, Nat.mul_assoc]

/-- The two degree-three-or-lower residuals uniquely determine the same S-box
output as x^5. In particular, there is no enabler premise on this implication. -/
theorem accepted_output (x square fifth : M31) (h : accepts x square fifth) :
    fifth = fifthPower x := by
  obtain ⟨hs, hf⟩ := h
  have hs' := (M31.sub_eq_zero_iff square (x * x)).mp hs
  have hf' := (M31.sub_eq_zero_iff fifth (x * (square * square))).mp hf
  rw [hs'] at hf'
  exact hf'.trans (lowered_eq_fifthPower x)

/-- Honest witnesses satisfy both residuals for every canonical input. -/
theorem honest_witness (x : M31) : accepts x (x * x) (lowered x) := by
  exact ⟨M31.sub_self _, M31.sub_self _⟩

/-- Replacing the local lowering by x^5 preserves every unchanged enclosing
context. The Zig schedule/matrix correspondence is source-mapped separately;
this theorem does not formalize a Zig compiler or whole permutation program. -/
theorem unchanged_context {α : Type} (context : (M31 → M31) → α) :
    context lowered = context fifthPower := by
  exact congrArg context (funext lowered_eq_fifthPower)

end RiscvRefinement.Recursion.CompactPoseidon
