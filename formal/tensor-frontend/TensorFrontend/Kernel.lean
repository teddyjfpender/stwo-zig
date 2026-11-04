/-
Integer kernel semantics vs M31 field semantics (zero-dependency).

The protocol proves identities in M31 = Z / p, p = 2^31 - 1. A field identity
`E = 0` of an integer expression `E` in the (signed) representatives of the
witness means `E ≡ 0 (mod p)`; it means the integer identity `E = 0` only when
`|E| < p`. This file proves, for the relations the tensor frontend uses, that
the statement-level bounds enforced by `src/tensor/bounds.zig` make every
such identity wrap-free, and characterises the integer functions they define:

* `requant`        : protocol.zig `requant`, floor((acc + 2^(s-1)) / 2^s);
* `requant_unique` : remainder in [0, 2^s) => the quotient is `requant`;
* `matmul_sound`   : bounds.zig matmul rule (bx + 7 + logK <= 30, s <= 22)
                     => the M31 remainder identity forces Y = requant_s(X.W);
* `requant_einsum_sound` : ext requant einsum rule (|acc| <= 2^29,
                     s + out_bits <= 30) => same conclusion;
* `exact_einsum_sound`   : EXACT_MAX_BITS = 29 rule => an exact einsum's
                     field identity is the integer identity y = sum a b;
* `lineq_sound`    : exprMagnitude < p => a linear relation is integral;
* `softmax_div_unique`   : 0 <= 2acc + den - 2 o den < 2 den => o is the
                     round-half-up quotient floor((2acc + den) / (2 den)),
                     as transformer.zig computes it, and is unique;
* `softmax_div_sound`    : the two range-checked slacks of transformer.zig,
                     with the field identities and bounds, imply it.
-/
namespace TensorFrontend.Kernel

/-- The M31 modulus. -/
def P : Int := 2147483647

theorem P_eq : P = 2 ^ 31 - 1 := by decide

/-- A field identity of an integer expression: `e ≡ 0 (mod p)`. -/
def FieldZero (e : Int) : Prop := e % P = 0

/-- Wrap-freedom: a field zero of magnitude below `p` is an integer zero. -/
theorem fieldZero_small (e : Int) (h : FieldZero e) (hb : e.natAbs < 2147483647) : e = 0 := by
  unfold FieldZero P at h
  omega

/-- requant_s(acc) = floor((acc + 2^(s-1)) / 2^s) (protocol.zig `requant`;
Lean's `Int` division by a positive divisor is floor division). -/
def requant (s : Nat) (acc : Int) : Int := (acc + 2 ^ (s - 1)) / 2 ^ s

theorem ipow_le {a b : Nat} (h : a ≤ b) : (2 : Int) ^ a ≤ 2 ^ b := by
  have := Nat.pow_le_pow_right (n := 2) (by decide) h
  have e1 : ((2 ^ a : Nat) : Int) = (2 : Int) ^ a := Int.natCast_pow 2 a
  have e2 : ((2 ^ b : Nat) : Int) = (2 : Int) ^ b := Int.natCast_pow 2 b
  rw [← e1, ← e2]; exact Int.ofNat_le.mpr this

theorem two_pow_pos (s : Nat) : (0 : Int) < 2 ^ s := Int.pow_pos (by decide)

/-- **Remainder range => unique quotient.** -/
theorem requant_unique (s : Nat) (acc y r : Int)
    (hid : acc + 2 ^ (s - 1) - 2 ^ s * y - r = 0) (hr0 : 0 ≤ r) (hr1 : r < 2 ^ s) :
    y = requant s acc ∧ r = (acc + 2 ^ (s - 1)) % 2 ^ s := by
  have := (Int.ediv_emod_unique (a := acc + 2 ^ (s - 1)) (q := y) (r := r) (two_pow_pos s)).mpr
    ⟨by omega, hr0, hr1⟩
  exact ⟨this.1.symm, this.2.symm⟩

/-- Integer dot product. -/
def dot : List Int → List Int → Int
  | x :: xs, w :: ws => x * w + dot xs ws
  | _, _ => 0

theorem dot_bound (xs ws : List Int) (X W : Nat) (hx : ∀ a ∈ xs, a.natAbs ≤ X)
    (hw : ∀ a ∈ ws, a.natAbs ≤ W) : (dot xs ws).natAbs ≤ xs.length * (X * W) := by
  induction xs generalizing ws with
  | nil => simp [dot]
  | cons x xs ih =>
    cases ws with
    | nil => simp [dot]
    | cons w ws =>
      simp only [dot, List.length_cons]
      have h1 := Int.natAbs_add_le (x * w) (dot xs ws)
      have h2 : (x * w).natAbs ≤ X * W := by
        rw [Int.natAbs_mul]
        exact Nat.mul_le_mul (hx x (List.mem_cons_self ..)) (hw w (List.mem_cons_self ..))
      have h3 := ih ws (fun a ha => hx a (List.mem_cons_of_mem _ ha))
        (fun a ha => hw a (List.mem_cons_of_mem _ ha))
      rw [Nat.succ_mul]
      omega

theorem natAbs_two_pow (s : Nat) : ((2 : Int) ^ s).natAbs = 2 ^ s := by
  rw [Int.natAbs_pow]; rfl

/-- **Matmul / requant soundness (bounds.zig, matmul check).** With
|x| <= 2^bx, int8 weights (|w| <= 2^7), K = 2^logK, bx + 7 + logK <= 30,
shift 1 <= s <= 22 (StatementShift), Y range-checked to [-128, 128) and the
virtual remainder range-checked to [0, 2^s): the M31 remainder identity
implies Y = requant_s(X . W) exactly (no wrap). -/
theorem matmul_sound (bx logK s : Nat) (xs ws : List Int) (y r : Int)
    (hbits : bx + 7 + logK ≤ 30) (hs1 : 1 ≤ s) (hs2 : s ≤ 22)
    (hK : xs.length = 2 ^ logK)
    (hx : ∀ a ∈ xs, a.natAbs ≤ 2 ^ bx) (hw : ∀ a ∈ ws, a.natAbs ≤ 2 ^ 7)
    (hy0 : -128 ≤ y) (hy1 : y < 128) (hr0 : 0 ≤ r) (hr1 : r < 2 ^ s)
    (hfield : FieldZero (dot xs ws + 2 ^ (s - 1) - 2 ^ s * y - r)) :
    y = requant s (dot xs ws) := by
  have hacc : (dot xs ws).natAbs ≤ 2 ^ 30 := by
    have := dot_bound xs ws _ _ hx hw
    rw [hK, ← Nat.pow_add, ← Nat.pow_add] at this
    exact Nat.le_trans this (Nat.pow_le_pow_right (by decide) (by omega))
  have hD : (2 : Int) ^ s ≤ 2 ^ 22 := ipow_le hs2
  have hH : (2 : Int) ^ (s - 1) ≤ 2 ^ 21 := ipow_le (by omega)
  have hH0 : (0 : Int) < 2 ^ (s - 1) := two_pow_pos _
  have hDy : (2 ^ s * y).natAbs ≤ 2 ^ 22 * 128 := by
    rw [Int.natAbs_mul, natAbs_two_pow]
    have : (2 : Nat) ^ s ≤ 2 ^ 22 := Nat.pow_le_pow_right (by decide) hs2
    exact Nat.mul_le_mul this (by omega)
  have hz := fieldZero_small _ hfield (by
    have : (2 : Int) ^ (22 : Nat) = 4194304 := by decide
    have : (2 : Int) ^ (21 : Nat) = 2097152 := by decide
    have : (2 : Nat) ^ (30 : Nat) = 1073741824 := by decide
    have : (2 : Nat) ^ (22 : Nat) = 4194304 := by decide
    omega)
  exact (requant_unique s _ y r hz hr0 hr1).1

/-- **Hadamard requant soundness** (bounds.zig, hadamard check ba + bb <= 30). -/
theorem hadamard_sound (ba bb s : Nat) (a b y r : Int)
    (hbits : ba + bb ≤ 30) (hs1 : 1 ≤ s) (hs2 : s ≤ 22)
    (ha : a.natAbs ≤ 2 ^ ba) (hb : b.natAbs ≤ 2 ^ bb)
    (hy0 : -128 ≤ y) (hy1 : y < 128) (hr0 : 0 ≤ r) (hr1 : r < 2 ^ s)
    (hfield : FieldZero (a * b + 2 ^ (s - 1) - 2 ^ s * y - r)) :
    y = requant s (a * b) := by
  have hab : (a * b).natAbs ≤ 2 ^ 30 := by
    rw [Int.natAbs_mul]
    exact Nat.le_trans (Nat.mul_le_mul ha hb)
      (by rw [← Nat.pow_add]; exact Nat.pow_le_pow_right (by decide) hbits)
  have hD : (2 : Int) ^ s ≤ 2 ^ 22 := ipow_le hs2
  have hH : (2 : Int) ^ (s - 1) ≤ 2 ^ 21 := ipow_le (by omega)
  have hH0 : (0 : Int) < 2 ^ (s - 1) := two_pow_pos _
  have hDy : (2 ^ s * y).natAbs ≤ 2 ^ 22 * 128 := by
    rw [Int.natAbs_mul, natAbs_two_pow]
    have : (2 : Nat) ^ s ≤ 2 ^ 22 := Nat.pow_le_pow_right (by decide) hs2
    exact Nat.mul_le_mul this (by omega)
  have hz := fieldZero_small _ hfield (by
    have : (2 : Int) ^ (22 : Nat) = 4194304 := by decide
    have : (2 : Int) ^ (21 : Nat) = 2097152 := by decide
    have : (2 : Nat) ^ (30 : Nat) = 1073741824 := by decide
    have : (2 : Nat) ^ (22 : Nat) = 4194304 := by decide
    omega)
  exact (requant_unique s _ y r hz hr0 hr1).1

/-- `REQUANT_MAX_BITS` in bounds.zig. -/
def REQUANT_MAX_BITS : Nat := 29
/-- `EXACT_MAX_BITS` in bounds.zig. -/
def EXACT_MAX_BITS : Nat := 29

/-- **Requant einsum soundness** (bounds.zig ext einsum check, shift > 0:
accumulator bound b <= REQUANT_MAX_BITS and shift + out_bits <= 30; the
output key proves Y + 2^(ob-1) in [0, 2^ob)). -/
theorem requant_einsum_sound (b s ob : Nat) (acc y r : Int)
    (hb : b ≤ REQUANT_MAX_BITS) (hs1 : 1 ≤ s) (hob : 1 ≤ ob) (hso : s + ob ≤ 30)
    (hacc : acc.natAbs ≤ 2 ^ b)
    (hy0 : 0 ≤ y + 2 ^ (ob - 1)) (hy1 : y + 2 ^ (ob - 1) < 2 ^ ob)
    (hr0 : 0 ≤ r) (hr1 : r < 2 ^ s)
    (hfield : FieldZero (acc + 2 ^ (s - 1) - 2 ^ s * y - r)) :
    y = requant s acc := by
  unfold REQUANT_MAX_BITS at hb
  have hacc' : acc.natAbs ≤ 2 ^ 29 := Nat.le_trans hacc (Nat.pow_le_pow_right (by decide) hb)
  -- |y| <= 2^(ob-1), so |2^s y| <= 2^(s + ob - 1) <= 2^29
  have hyabs : y.natAbs ≤ 2 ^ (ob - 1) := by
    have : (2 : Int) ^ ob = 2 * 2 ^ (ob - 1) := by
      rw [← Int.pow_succ']; congr 1; omega
    have e1 : ((2 ^ (ob - 1) : Nat) : Int) = (2 : Int) ^ (ob - 1) := Int.natCast_pow 2 _
    have e2 : ((2 : Nat) : Int) ^ (ob - 1) = (2 : Int) ^ (ob - 1) := rfl
    omega
  have hDy : (2 ^ s * y).natAbs ≤ 2 ^ 29 := by
    rw [Int.natAbs_mul, natAbs_two_pow]
    refine Nat.le_trans (Nat.mul_le_mul (Nat.le_refl _) hyabs) ?_
    rw [← Nat.pow_add]; exact Nat.pow_le_pow_right (by decide) (by omega)
  have hD : (2 : Int) ^ s ≤ 2 ^ 29 := ipow_le (by omega)
  have hH : (2 : Int) ^ (s - 1) ≤ 2 ^ 28 := ipow_le (by omega)
  have hH0 : (0 : Int) < 2 ^ (s - 1) := two_pow_pos _
  have hz := fieldZero_small _ hfield (by
    have : (2 : Int) ^ (29 : Nat) = 536870912 := by decide
    have : (2 : Int) ^ (28 : Nat) = 268435456 := by decide
    have : (2 : Nat) ^ (29 : Nat) = 536870912 := by decide
    omega)
  exact (requant_unique s _ y r hz hr0 hr1).1

/-- Integer sum of pairwise products (one einsum output entry). -/
def sumProd : List (Int × Int) → Int
  | [] => 0
  | (a, b) :: t => a * b + sumProd t

theorem sumProd_bound (L : List (Int × Int)) (A B : Nat)
    (h : ∀ ab ∈ L, ab.1.natAbs ≤ A ∧ ab.2.natAbs ≤ B) :
    (sumProd L).natAbs ≤ L.length * (A * B) := by
  induction L with
  | nil => simp [sumProd]
  | cons ab t ih =>
    obtain ⟨a, b⟩ := ab
    simp only [sumProd, List.length_cons]
    have h1 := Int.natAbs_add_le (a * b) (sumProd t)
    have hab := h (a, b) (List.mem_cons_self ..)
    have h2 : (a * b).natAbs ≤ A * B := by
      rw [Int.natAbs_mul]; exact Nat.mul_le_mul hab.1 hab.2
    have h3 := ih (fun x hx => h x (List.mem_cons_of_mem _ hx))
    rw [Nat.succ_mul]; omega

theorem sumProd_zero (t : List (Int × Int)) (h : ∀ x ∈ t, x.1 = 0) : sumProd t = 0 := by
  induction t with
  | nil => rfl
  | cons x t ih =>
    obtain ⟨c, e⟩ := x
    have hc : c = 0 := h (c, e) (List.mem_cons_self ..)
    subst hc
    simp only [sumProd, Int.zero_mul, Int.zero_add]
    exact ih (fun y hy => h y (List.mem_cons_of_mem _ hy))

/-- The bounds.zig exact-einsum rule (`einsumBound`, generic case):
y gets bound ba + bb + n_k, admitted only if <= EXACT_MAX_BITS. -/
def exactRule (ba bb nk : Nat) : Bool := decide (ba + bb + nk ≤ EXACT_MAX_BITS)

/-- **Exact einsum soundness.** If the rule admits the einsum, then every
output entry's true integer value is within 2^29, and the witness entry `y`
(any integer of magnitude < p/2, e.g. the signed representative of a field
element) satisfying the field identity y = sum a b is that integer. -/
theorem exact_einsum_sound (ba bb nk : Nat) (L : List (Int × Int)) (y : Int)
    (hrule : exactRule ba bb nk = true) (hlen : L.length = 2 ^ nk)
    (hops : ∀ ab ∈ L, ab.1.natAbs ≤ 2 ^ ba ∧ ab.2.natAbs ≤ 2 ^ bb)
    (hy : y.natAbs ≤ 1073741823)
    (hfield : FieldZero (y - sumProd L)) :
    y = sumProd L ∧ (sumProd L).natAbs ≤ 2 ^ EXACT_MAX_BITS := by
  unfold exactRule EXACT_MAX_BITS at hrule
  have hr := of_decide_eq_true hrule
  have hs : (sumProd L).natAbs ≤ 2 ^ 29 := by
    have := sumProd_bound L _ _ hops
    rw [hlen, ← Nat.pow_add, ← Nat.pow_add] at this
    exact Nat.le_trans this (Nat.pow_le_pow_right (by decide) (by omega))
  have h29 : (2 : Nat) ^ (29 : Nat) = 536870912 := by decide
  refine ⟨?_, hs⟩
  have := fieldZero_small _ hfield (by omega)
  omega

/-- One-hot selector case of `einsumBound`: a Boolean operand with at most
one nonzero entry over the contracted index gives |y| <= 2^bb. -/
theorem onehot_bound (L : List (Int × Int)) (bb : Nat)
    (hbool : ∀ ab ∈ L, ab.1 = 0 ∨ ab.1 = 1)
    (hone : (L.filter (fun ab => ab.1 != 0)).length ≤ 1)
    (hb : ∀ ab ∈ L, ab.2.natAbs ≤ 2 ^ bb) :
    (sumProd L).natAbs ≤ 2 ^ bb := by
  induction L with
  | nil => simp [sumProd]
  | cons ab t ih =>
    obtain ⟨a, b⟩ := ab
    simp only [sumProd]
    have ha := hbool (a, b) (List.mem_cons_self ..)
    have hbt : ∀ x ∈ t, x.2.natAbs ≤ 2 ^ bb := fun x hx => hb x (List.mem_cons_of_mem _ hx)
    have hboolt : ∀ x ∈ t, x.1 = 0 ∨ x.1 = 1 := fun x hx => hbool x (List.mem_cons_of_mem _ hx)
    rcases ha with ha | ha
    · subst ha
      simp only [List.filter_cons, bne_self_eq_false, Bool.false_eq_true, ite_false] at hone
      have := ih hboolt hone hbt
      simp only [Int.zero_mul, Int.zero_add]; exact this
    · subst ha
      simp only [List.filter_cons] at hone
      have h1 : ((1 : Int) != 0) = true := by decide
      simp only [h1, ite_true, List.length_cons] at hone
      have hnil : t.filter (fun ab => ab.1 != 0) = [] := List.eq_nil_of_length_eq_zero (by omega)
      have hall : ∀ x ∈ t, x.1 = 0 := by
        intro x hx
        have := List.filter_eq_nil_iff.mp hnil x hx
        simpa using this
      have hz : sumProd t = 0 := sumProd_zero t hall
      rw [hz, Int.one_mul, Int.add_zero]
      exact hb (1, b) (List.mem_cons_self ..)

/-- Sum of a list. -/
def lsum : List Int → Int
  | [] => 0
  | x :: t => x + lsum t

/-- Sum of magnitudes. -/
def magnitude : List Int → Nat
  | [] => 0
  | x :: t => x.natAbs + magnitude t

theorem lsum_natAbs_le (L : List Int) : (lsum L).natAbs ≤ magnitude L := by
  induction L with
  | nil => simp [lsum, magnitude]
  | cons x t ih =>
    simp only [lsum, magnitude]
    have := Int.natAbs_add_le x (lsum t)
    omega

/-- **Linear relation soundness** (bounds.zig `lineq` / `exprCheck`): when the
sum of term magnitudes (exprMagnitude: |coeff| 2^(bound + #SUM labels) per
term, plus |constant|) is below p, the field identity is an integer one. -/
theorem lineq_sound (terms : List Int) (hmag : magnitude terms < 2147483647)
    (hfield : FieldZero (lsum terms)) : lsum terms = 0 :=
  fieldZero_small _ hfield (Nat.lt_of_le_of_lt (lsum_natAbs_le terms) hmag)

/-- **Softmax division, integer characterisation.** For den > 0 the
inequality 0 <= 2acc + den - 2 o den < 2 den holds for exactly one o, namely
floor((2acc + den) / (2 den)) (transformer.zig: @divFloor(2x + dn, 2dn)),
the round-half-up quotient acc / den. -/
theorem softmax_div_unique (acc den o : Int) (hden : 0 < den)
    (h0 : 0 ≤ 2 * acc + den - 2 * o * den) (h1 : 2 * acc + den - 2 * o * den < 2 * den) :
    o = (2 * acc + den) / (2 * den) := by
  have := (Int.ediv_emod_unique (a := 2 * acc + den) (b := 2 * den) (q := o)
    (r := 2 * acc + den - 2 * o * den) (by omega)).mpr
    ⟨by rw [Int.mul_assoc] at h0 ⊢; rw [Int.mul_assoc, Int.mul_comm den o]; omega, h0, h1⟩
  exact this.1.symm

/-- Half-up rounding reading: -den < 2 (o den - acc) <= den, so |2 (o den - acc)| <= den (the property the
transformer test checks), as a consequence of the inequality. -/
theorem softmax_div_err (acc den o : Int)
    (h0 : 0 ≤ 2 * acc + den - 2 * o * den) (h1 : 2 * acc + den - 2 * o * den < 2 * den) :
    -den < 2 * (o * den - acc) ∧ 2 * (o * den - acc) ≤ den := by
  rw [Int.mul_assoc] at h0 h1
  constructor <;> rw [Int.mul_sub] <;> omega

/-- **Softmax division, field semantics** (transformer.zig: od = o * den is an
exact einsum; the slacks u = 2acc + den - 2od and v = den - 2acc + 2od - 1
are range-checked to [0, 2^(lt+9))). With the integer bounds the statement
analysis derives (|acc| <= 2^29 - ..., here: |acc|, |od| <= 2^28 and
0 < den <= 2^28), the two field identities are integer identities, so o is
the round-half-up quotient. `lt <= 19` keeps 2^(lt+9) <= 2^28. -/
theorem softmax_div_sound (lt : Nat) (acc den o od u v : Int) (hlt : lt ≤ 19)
    (hden : 0 < den) (hden1 : den ≤ 2 ^ 28)
    (hacc : acc.natAbs ≤ 2 ^ 28) (hod : od.natAbs ≤ 2 ^ 28)
    (hodint : od = o * den)
    (hu0 : 0 ≤ u) (hu1 : u < 2 ^ (lt + 9)) (hv0 : 0 ≤ v) (hv1 : v < 2 ^ (lt + 9))
    (hfu : FieldZero (u - (2 * acc + den - 2 * od)))
    (hfv : FieldZero (v - (den - 2 * acc + 2 * od - 1))) :
    o = (2 * acc + den) / (2 * den) := by
  have hR : (2 : Int) ^ (lt + 9) ≤ 2 ^ 28 := ipow_le (by omega)
  have h28 : (2 : Int) ^ (28 : Nat) = 268435456 := by decide
  have h28n : (2 : Nat) ^ (28 : Nat) = 268435456 := by decide
  have eu := fieldZero_small _ hfu (by omega)
  have ev := fieldZero_small _ hfv (by omega)
  subst hodint
  apply softmax_div_unique acc den o hden
  · rw [Int.mul_assoc]; omega
  · rw [Int.mul_assoc]; omega

end TensorFrontend.Kernel
