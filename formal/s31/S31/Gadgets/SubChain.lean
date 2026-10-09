import S31.Gadgets.AddChain

namespace S31.Gadgets.Radix
open Words

inductive SubChain (base : Nat) : List Nat → List Nat → List Nat → Nat → Nat → Prop where
  | nil {cin} : cin ≤ 1 → SubChain base [] [] [] cin cin
  | cons {a b cin digit next cout xs ys rs} :
      subConstraint base a b cin digit next →
      SubChain base xs ys rs next cout →
      SubChain base (a :: xs) (b :: ys) (digit :: rs) cin cout

theorem sub_chain_lengths {base xs ys rs cin cout} (h : SubChain base xs ys rs cin cout) :
    xs.length = ys.length ∧ xs.length = rs.length := by
  induction h with
  | nil => simp
  | cons hlocal htail ih => simpa using ih

theorem sub_chain_bounded {base xs ys rs cin cout} (h : SubChain base xs ys rs cin cout) :
    Bounded base rs ∧ cout ≤ 1 := by
  induction h with
  | nil hc => exact ⟨by simp [Bounded], hc⟩
  | cons hlocal htail ih =>
    refine ⟨?_, ih.2⟩
    intro d hd
    simp only [List.mem_cons] at hd
    rcases hd with rfl | hd
    · exact hlocal.2.2.2.1
    · exact ih.1 _ hd

theorem sub_chain_equation {base xs ys rs cin cout} (hbase : base = 256 ∨ base = 65536)
    (h : SubChain base xs ys rs cin cout) :
    decode base xs + base^xs.length * cout = decode base ys + decode base rs + cin := by
  induction h with
  | nil hc => simp [decode]
  | cons hlocal htail ih =>
    have heq := sub_integer_equation _ _ _ _ _ _ hbase hlocal
    simp only [decode, List.length_cons, Nat.pow_succ]
    nlinarith

theorem sub_chain_complete (base : Nat) (hbase : 1 < base) (xs ys : List Nat)
    (hx : Bounded base xs) (hy : Bounded base ys) (hlen : xs.length = ys.length)
    (cin : Nat) (hc : cin ≤ 1) : ∃ rs cout, SubChain base xs ys rs cin cout := by
  induction xs generalizing ys cin with
  | nil =>
    have : ys = [] := by simpa using hlen.symm
    subst ys
    exact ⟨[], cin, .nil hc⟩
  | cons a xs ih =>
    cases ys with
    | nil => simp at hlen
    | cons b ys =>
      have localGate := sub_complete base a b cin hbase
        (hx a (by simp)) (hy b (by simp)) hc
      obtain ⟨rs, cout, htail⟩ := ih ys
        (fun d h => hx d (by simp [h])) (fun d h => hy d (by simp [h]))
        (by simpa using hlen) _ localGate.2.2.2.2.1
      exact ⟨_, cout, .cons localGate htail⟩

theorem sub_chain_wrapping_sound {base xs ys rs cin cout} (hbase : base = 256 ∨ base = 65536)
    (h : SubChain base xs ys rs cin cout) :
    (decode base rs : Int) =
      ((decode base xs : Int) - decode base ys - cin) % (base^xs.length : Nat) := by
  have hb : 0 < base := by rcases hbase with rfl | rfl <;> decide
  have hl := (sub_chain_lengths h).2
  have hr : decode base rs < base^xs.length := by
    rw [hl]; exact decode_lt base hb rs (sub_chain_bounded h).1
  have heq : (decode base xs : Int) - decode base ys - cin =
      (decode base rs : Int) - (base^xs.length : Nat) * cout := by
    have hn := sub_chain_equation hbase h
    have hz := congrArg (fun n : Nat => (n : Int)) hn
    simp only [Nat.cast_add, Nat.cast_mul] at hz
    linarith
  rw [heq, Int.sub_mul_emod_self_left]
  exact (Int.emod_eq_of_lt (by omega) (by exact_mod_cast hr)).symm

theorem sub_chain_wrapping_sound_complete (base : Nat) (hbase : base = 256 ∨ base = 65536)
    (xs ys rs : List Nat) (hx : Bounded base xs) (hy : Bounded base ys)
    (hr : Bounded base rs) (hxy : xs.length = ys.length) (hxr : xs.length = rs.length) :
    (∃ cout, SubChain base xs ys rs 0 cout) ↔
      (decode base rs : Int) = ((decode base xs : Int) - decode base ys) % (base^xs.length : Nat) := by
  constructor
  · rintro ⟨cout, h⟩; simpa using sub_chain_wrapping_sound hbase h
  · intro heq
    have hb : 1 < base := by rcases hbase with rfl | rfl <;> decide
    obtain ⟨honest, cout, h⟩ := sub_chain_complete base hb xs ys hx hy hxy 0 (by decide)
    have hval := sub_chain_wrapping_sound hbase h
    have hsame : honest = rs := decode_injective base (by omega) honest rs
      (sub_chain_bounded h).1 hr ((sub_chain_lengths h).2.symm.trans hxr)
      (by have he := hval.trans (by simpa using heq.symm); exact_mod_cast he)
    subst honest
    exact ⟨cout, h⟩

theorem sub_chain_checked_sound_complete (base : Nat) (hbase : base = 256 ∨ base = 65536)
    (xs ys rs : List Nat) (hx : Bounded base xs) (hy : Bounded base ys)
    (hr : Bounded base rs) (hxy : xs.length = ys.length) (hxr : xs.length = rs.length) :
    SubChain base xs ys rs 0 0 ↔ decode base xs = decode base ys + decode base rs := by
  constructor
  · intro h; simpa using sub_chain_equation hbase h
  · intro heq
    have hb : 1 < base := by rcases hbase with rfl | rfl <;> decide
    have hp : 0 < base^xs.length := Nat.pow_pos (by omega)
    have hrange : decode base rs < base^xs.length := by
      rw [hxr]; exact decode_lt base (by omega) rs hr
    have hwrap : (decode base rs : Int) =
        ((decode base xs : Int) - decode base ys) % (base^xs.length : Nat) := by
      rw [heq, Nat.cast_add, add_sub_cancel_left]
      exact (Int.emod_eq_of_lt (by omega) (by exact_mod_cast hrange)).symm
    obtain ⟨cout, h⟩ := (sub_chain_wrapping_sound_complete base hbase xs ys rs hx hy hr hxy hxr).mpr hwrap
    have hcout : cout = 0 := by
      have := sub_chain_equation hbase h
      nlinarith
    simpa [hcout] using h

/-- With incoming borrow zero this is ≤; with incoming borrow one it is <.
Comparisons in the compiler subtract the operands in the opposite order. -/
theorem sub_chain_comparison {base xs ys rs cin cout} (hbase : base = 256 ∨ base = 65536)
    (h : SubChain base xs ys rs cin cout) :
    cout = 0 ↔ decode base ys + cin ≤ decode base xs := by
  have hb : 0 < base := by rcases hbase with rfl | rfl <;> decide
  have hl := (sub_chain_lengths h).2
  have hr : decode base rs < base^xs.length := by
    rw [hl]; exact decode_lt base hb rs (sub_chain_bounded h).1
  have hc := (sub_chain_bounded h).2
  have heq := sub_chain_equation hbase h
  rcases (by omega : cout = 0 ∨ cout = 1) with rfl | rfl <;> simp_all
  omega

end S31.Gadgets.Radix
