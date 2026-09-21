import RiscvRefinement.Field.M31

namespace RiscvRefinement.Recursion.FrameworkBoundary

private theorem add_assoc (a b c : M31) : (a + b) + c = a + (b + c) := by
  apply M31.ext
  change ((a.val + b.val) % M31.modulus + c.val) % M31.modulus =
    (a.val + (b.val + c.val) % M31.modulus) % M31.modulus
  simp only [Nat.mod_add_mod, Nat.add_mod_mod, Nat.add_assoc]

private theorem add_comm (a b : M31) : a + b = b + a := by
  apply M31.ext
  change (a.val + b.val) % M31.modulus = (b.val + a.val) % M31.modulus
  rw [Nat.add_comm]

private theorem sub_add_cancel (a b : M31) : (a - b) + b = a := by
  apply M31.ext
  change ((a - b).val + b.val) % M31.modulus = a.val
  by_cases h : b.val ≤ a.val
  · rw [M31.sub_val_of_le a b h, Nat.sub_add_cancel h]
    exact Nat.mod_eq_of_lt a.isLt
  · have h' : a.val < b.val := Nat.lt_of_not_ge h
    rw [M31.sub_val_of_lt a b h']
    have sum : M31.modulus + a.val - b.val + b.val = M31.modulus + a.val := by
      have bound : b.val < M31.modulus := b.isLt
      omega
    rw [sum, Nat.add_mod_left]
    exact Nat.mod_eq_of_lt a.isLt

private theorem add_right_cancel (a b c : M31) (h : a + c = b + c) : a = b := by
  apply M31.ext
  have values := congrArg M31.val h
  change (a.val + c.val) % 2147483647 = (b.val + c.val) % 2147483647 at values
  have ha : a.val < 2147483647 := a.isLt
  have hb : b.val < 2147483647 := b.isLt
  have hc : c.val < 2147483647 := c.isLt
  omega

private theorem chained_difference (a b c : M31) : (a - b) + (b - c) = a - c := by
  apply add_right_cancel _ _ c
  rw [add_assoc, sub_add_cancel, sub_add_cancel, sub_add_cancel]

private theorem add_four (a b c d : M31) : (a + b) + (c + d) = (a + c) + (b + d) := by
  rw [add_assoc a b (c + d), ← add_assoc b c d, add_comm b c,
    add_assoc c b d, ← add_assoc a c (b + d)]

/-- Logical-order prefix sum. Physical bit reversal is outside this model. -/
def sum (f : Nat → M31) : Nat → M31
  | 0 => 0
  | n + 1 => sum f n + f n

/-- Adjacent cumulative differences cancel without referencing other rows. -/
theorem telescope (accum : Nat → M31) (n : Nat) :
    sum (fun i => accum (i + 1) - accum i) n = accum n - accum 0 := by
  induction n with
  | zero => simp [sum]
  | succ n ih =>
    rw [sum, ih, add_comm, chained_difference]

/-- Nonfinal batches are same-row cumulative differences. Only the final
batch subtracts the previous row and adds the claim shift. -/
theorem row_boundary (accum : Nat → M31) (n : Nat) (h0 : accum 0 = 0)
    (current previous shift : M31) :
    sum (fun i => accum (i + 1) - accum i) n +
      ((current - previous - accum n) + shift) = current - previous + shift := by
  rw [telescope, h0, M31.sub_zero, ← add_assoc,
    add_comm (accum n) (current - previous - accum n), sub_add_cancel]

private theorem sum_add (f g : Nat → M31) (n : Nat) :
    sum (fun i => f i + g i) n = sum f n + sum g n := by
  induction n with
  | zero => simp [sum]
  | succ n ih => rw [sum, ih, sum, sum, add_four]

/-- A cyclic final-column boundary makes every row contribute exactly one
shift. The common offset may be nonzero: the AIR constrains differences,
whereas the witness generator chooses the representative ending at zero. -/
theorem rows_boundary (accum : Nat → M31) (n : Nat) (shift : M31)
    (cyclic : accum n = accum 0) :
    sum (fun i => (accum (i + 1) - accum i) + shift) n =
      sum (fun _ => shift) n := by
  rw [sum_add, telescope, cyclic, M31.sub_self, M31.zero_add]

/-- Repeated addition is multiplication by the canonical trace-size scalar. -/
theorem sum_constant (shift : M31) (n : Nat) :
    sum (fun _ => shift) n = M31.reduce n * shift := by
  have reduced : sum (fun _ => shift) n = M31.reduce (n * shift.val) := by
    induction n with
    | zero => simp [sum]
    | succ n ih =>
      rw [sum, ih]
      apply M31.ext
      change ((n * shift.val) % M31.modulus + shift.val) % M31.modulus =
        ((n + 1) * shift.val) % M31.modulus
      simp only [Nat.mod_add_mod, Nat.add_mul, Nat.one_mul]
  rw [reduced]
  apply M31.ext
  change (n * shift.val) % M31.modulus =
    ((n % M31.modulus) * shift.val) % M31.modulus
  rw [Nat.mod_mul_mod]

/-- The division/field-inverse obligation is explicit: the caller supplies
N*(claim/N)=claim. This boundary theorem does not assume it unconditionally. -/
theorem claim_boundary (accum : Nat → M31) (n : Nat) (shift claim : M31)
    (cyclic : accum n = accum 0)
    (normalized : M31.reduce n * shift = claim) :
    sum (fun i => (accum (i + 1) - accum i) + shift) n = claim := by
  rw [rows_boundary accum n shift cyclic, sum_constant, normalized]

/-- QM31 addition/subtraction act on four M31 coordinates; the boundary
identity consequently holds componentwise without assuming extension-field
multiplication, inversion, or LogUp soundness. -/
theorem secure_claim_boundary (accum : Nat → Fin 4 → M31) (n : Nat)
    (shift claim : Fin 4 → M31)
    (cyclic : ∀ k, accum n k = accum 0 k)
    (normalized : ∀ k, M31.reduce n * shift k = claim k) :
    ∀ k, sum (fun i => (accum (i + 1) k - accum i k) + shift k) n = claim k := by
  intro k
  exact claim_boundary (fun i => accum i k) n (shift k) (claim k) (cyclic k) (normalized k)

end RiscvRefinement.Recursion.FrameworkBoundary
