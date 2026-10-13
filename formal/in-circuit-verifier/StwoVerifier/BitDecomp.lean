/-
**The mathematics of `extract_bits`**
(`src/frontends/circuit/builder/extract_bits.zig`, stwo-zig `4afa09dbf`),
per lane.

Each round guesses a bit `b_k`, enforces `b_k² = b_k`, and continues with
`v_{k+1} = (v_k − b_k)·2⁻¹`; the final value is the top bit. The gates
therefore enforce exactly the facts `decomp_sound` consumes, and it
concludes `v₀ = Σ bitᵢ·2ⁱ` **in F** with every `bitᵢ ∈ {0, 1}`.

Over `F = ℤ/(2³¹ − 1)`, a 31-bit pattern determines its value mod P only
up to the single collision `0 ≡ 2³¹ − 1` (all ones). `validate_extract_bits`
adds `(v₀·aux − 1)·b₀ = 0`, which forces `b₀ = 0` when `v₀ = 0`; since the
all-ones pattern has an odd value and hence `b₀ = 1`, `canonical_31`
concludes the extracted bits are **the** binary digits of the canonical
value `v₀.val`. This is the canonicity argument the query-selection gadget
needs (open question 1 of the brief: `extract_bits` is a prover-supplied
hint that needs a canonicity constraint, and the circuit carries it).
-/
import StwoVerifier.Algebra

namespace StwoVerifier.BitDecomp

open StwoVerifier Finset

theorem two_ne_zero : (2 : F) ≠ 0 := by
  intro h
  have h2 : ((2 : ℕ) : F) = 0 := by exact_mod_cast h
  have hv := ZMod.val_cast_of_lt (show (2 : ℕ) < P by unfold P; norm_num)
  rw [h2] at hv
  simp at hv

/-- A squared-equals-self field element is a bit. -/
theorem bit_of_sq {b : F} (h : b * b = b) : b = 0 ∨ b = 1 := by
  have h0 : b * (b - 1) = 0 := by linear_combination h
  rcases mul_eq_zero.mp h0 with h | h
  · exact Or.inl h
  · exact Or.inr (by linear_combination h)

/-- The bit sequence `extract_bits` produces: the guessed bits below the
top round, then the final halved value. -/
def bitAt (n : ℕ) (v b : ℕ → F) (i : ℕ) : F :=
  if i = n - 1 then v (n - 1) else b i

/-- **Field-level soundness of the extraction rounds.** From the gate facts
(each guessed bit squares to itself, each round halves after subtracting
it, the final value squares to itself), the input is the bit polynomial of
the outputs. -/
theorem decomp_sound (n : ℕ) (hn : 1 ≤ n) (v b : ℕ → F)
    (hbit : ∀ k, k + 1 < n → b k * b k = b k)
    (hrec : ∀ k, k + 1 < n → v (k + 1) = (v k - b k) * (2 : F)⁻¹)
    (hlast : v (n - 1) * v (n - 1) = v (n - 1)) :
    (∀ i, i < n → bitAt n v b i = 0 ∨ bitAt n v b i = 1) ∧
      v 0 = ∑ i ∈ range n, bitAt n v b i * 2 ^ i := by
  constructor
  · intro i hi
    by_cases h : i = n - 1
    · simpa [bitAt, h] using bit_of_sq hlast
    · have : i + 1 < n := by omega
      simpa [bitAt, h] using bit_of_sq (hbit i this)
  · -- `v (n−1−j) = Σ_{i ≤ j} bit (n−1−j+i) · 2^i`, upward in `j`.
    have key : ∀ j, j ≤ n - 1 →
        v (n - 1 - j) = ∑ i ∈ range (j + 1), bitAt n v b (n - 1 - j + i) * 2 ^ i := by
      intro j
      induction j with
      | zero => intro _; simp [bitAt]
      | succ j ih =>
        intro hj
        have hj' : j ≤ n - 1 := by omega
        have hk : n - 1 - (j + 1) + 1 < n := by omega
        have harith : n - 1 - (j + 1) + 1 = n - 1 - j := by omega
        have hv := hrec _ hk
        rw [harith] at hv
        have hstep : v (n - 1 - (j + 1)) = b (n - 1 - (j + 1)) + 2 * v (n - 1 - j) := by
          rw [hv]
          have h2 : (2 : F)⁻¹ * 2 = 1 := inv_mul_cancel₀ two_ne_zero
          linear_combination (b (n - 1 - (j + 1)) - v (n - 1 - (j + 1))) * h2
        rw [hstep, ih hj',
          Finset.sum_range_succ' (fun i => bitAt n v b (n - 1 - (j + 1) + i) * 2 ^ i) (j + 1)]
        have hne : n - 1 - (j + 1) ≠ n - 1 := by omega
        have hb0 : bitAt n v b (n - 1 - (j + 1) + 0) = b (n - 1 - (j + 1)) := by
          simp only [Nat.add_zero, bitAt, if_neg hne]
        have hre : ∀ i, bitAt n v b (n - 1 - (j + 1) + (i + 1)) * 2 ^ (i + 1)
            = 2 * (bitAt n v b (n - 1 - j + i) * 2 ^ i) := by
          intro i
          have hidx : n - 1 - (j + 1) + (i + 1) = n - 1 - j + i := by omega
          rw [hidx, pow_succ]; ring
        rw [Finset.sum_congr rfl (fun i _ => hre i), hb0, ← Finset.mul_sum]
        ring
    have hfin := key (n - 1) le_rfl
    simp only [Nat.sub_self, Nat.zero_add] at hfin
    rwa [show n - 1 + 1 = n by omega] at hfin

/-- The natural number a bit pattern denotes. -/
def natOf (bits : ℕ → F) (n : ℕ) : ℕ :=
  ∑ i ∈ range n, (bits i).val * 2 ^ i

theorem val_one : (1 : F).val = 1 := by
  rw [ZMod.val_one_eq_one_mod]
  unfold P; norm_num

theorem sum_two_pow (n : ℕ) : ∑ i ∈ range n, 2 ^ i = 2 ^ n - 1 := by
  induction n with
  | zero => simp
  | succ n ih =>
    rw [Finset.sum_range_succ, ih]
    have := Nat.one_le_two_pow (n := n)
    omega

theorem bitVal_le {b : F} (hb : b = 0 ∨ b = 1) : b.val ≤ 1 := by
  rcases hb with h | h <;> simp [h, val_one]

theorem natOf_lt (bits : ℕ → F) (n : ℕ)
    (hbits : ∀ i, i < n → bits i = 0 ∨ bits i = 1) :
    natOf bits n < 2 ^ n := by
  have hle : ∀ i ∈ range n, (bits i).val * 2 ^ i ≤ 1 * 2 ^ i := fun i hi =>
    Nat.mul_le_mul_right _ (bitVal_le (hbits i (mem_range.mp hi)))
  have h1 : natOf bits n ≤ ∑ i ∈ range n, 1 * 2 ^ i := Finset.sum_le_sum hle
  have h2 : ∑ i ∈ range n, 1 * 2 ^ i = 2 ^ n - 1 := by simpa using sum_two_pow n
  have h3 : (0 : ℕ) < 2 ^ n := Nat.two_pow_pos n
  omega

/-- The field value of a bit pattern is the cast of its natural value. -/
theorem cast_natOf (bits : ℕ → F) (n : ℕ) :
    ((natOf bits n : ℕ) : F) = ∑ i ∈ range n, bits i * 2 ^ i := by
  unfold natOf
  push_cast
  refine Finset.sum_congr rfl fun i _ => ?_
  rw [ZMod.natCast_val, ZMod.cast_id]

/-- The low bit is the parity of the natural value. -/
theorem natOf_parity (bits : ℕ → F) (n : ℕ) (hn : 1 ≤ n) :
    natOf bits n % 2 = (bits 0).val % 2 := by
  unfold natOf
  obtain ⟨m, rfl⟩ : ∃ m, n = m + 1 := ⟨n - 1, by omega⟩
  rw [Finset.sum_range_succ' (fun i => (bits i).val * 2 ^ i) m]
  have heven : 2 ∣ ∑ i ∈ range m, (bits (i + 1)).val * 2 ^ (i + 1) :=
    Finset.dvd_sum fun i _ =>
      Dvd.dvd.mul_left (dvd_pow_self 2 (Nat.succ_ne_zero i)) _
  obtain ⟨c, hc⟩ := heven
  simp only [pow_zero, mul_one, hc]
  omega

/-- **31-bit canonicity.** Bits summing (in F) to `x`, with the
`validate_extract_bits` fact `x = 0 → bits 0 = 0`, denote exactly `x.val`:
the hint is canonical. -/
theorem canonical_31 (bits : ℕ → F) (x : F)
    (hbits : ∀ i, i < 31 → bits i = 0 ∨ bits i = 1)
    (hsum : x = ∑ i ∈ range 31, bits i * 2 ^ i)
    (hzero : x = 0 → bits 0 = 0) :
    natOf bits 31 = x.val := by
  have hlt : natOf bits 31 < 2 ^ 31 := natOf_lt bits 31 hbits
  have hcast : ((natOf bits 31 : ℕ) : F) = x := by
    rw [cast_natOf bits 31, hsum]
  by_cases hP : natOf bits 31 = P
  · -- The all-ones pattern: value ≡ 0, but P is odd so its low bit is 1.
    exfalso
    have hx0 : x = 0 := by
      rw [← hcast, hP]
      exact_mod_cast ZMod.natCast_self P
    have hb0 : (bits 0).val = 0 := by rw [hzero hx0]; simp
    have hpar := natOf_parity bits 31 (by norm_num)
    rw [hP, hb0] at hpar
    unfold P at hpar
    omega
  · have hltP : natOf bits 31 < P := by unfold P at *; omega
    rw [← hcast, ZMod.val_cast_of_lt hltP]

/-- The low `L` bits of a bit pattern denote its value mod `2^L`. -/
theorem natOf_mod (bits : ℕ → F) (n L : ℕ) (hL : L ≤ n)
    (hbits : ∀ i, i < n → bits i = 0 ∨ bits i = 1) :
    natOf bits L = natOf bits n % 2 ^ L := by
  have hsplit : natOf bits n = natOf bits L +
      2 ^ L * ∑ j ∈ range (n - L), (bits (L + j)).val * 2 ^ j := by
    unfold natOf
    rw [← Finset.sum_range_add_sum_Ico _ hL,
      Finset.sum_Ico_eq_sum_range]
    congr 1
    rw [Finset.mul_sum]
    exact Finset.sum_congr rfl fun j _ => by
      rw [pow_add]
      ring
  have hlt : natOf bits L < 2 ^ L :=
    natOf_lt bits L (fun i hi => hbits i (by omega))
  rw [hsplit, Nat.add_mul_mod_self_left, Nat.mod_eq_of_lt hlt]

theorem bitVal_eq {x : F} (hx : x = 0 ∨ x = 1) :
    x.val = if x = 0 then 0 else 1 := by
  rcases hx with h | h
  · rw [if_pos h, h]; simp
  · rw [if_neg (by rw [h]; exact one_ne_zero), h, val_one]

end StwoVerifier.BitDecomp
