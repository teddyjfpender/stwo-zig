import S31.Gadgets.Radix

namespace S31.Gadgets.Radix
open Words

inductive AddChain (base : Nat) : List Nat → List Nat → List Nat → Nat → Nat → Prop where
  | nil {cin} : cin ≤ 1 → AddChain base [] [] [] cin cin
  | cons {a b cin digit next cout xs ys rs} :
      addConstraint base a b cin digit next →
      AddChain base xs ys rs next cout →
      AddChain base (a :: xs) (b :: ys) (digit :: rs) cin cout

theorem add_chain_lengths {base xs ys rs cin cout} (h : AddChain base xs ys rs cin cout) :
    xs.length = ys.length ∧ xs.length = rs.length := by
  induction h with
  | nil => simp
  | cons hlocal htail ih => simpa using ih

theorem add_chain_bounded {base xs ys rs cin cout} (h : AddChain base xs ys rs cin cout) :
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

theorem add_chain_equation {base xs ys rs cin cout} (hbase : base = 256 ∨ base = 65536)
    (h : AddChain base xs ys rs cin cout) :
    decode base xs + decode base ys + cin = decode base rs + base^xs.length * cout := by
  induction h with
  | nil hc => simp [decode]
  | cons hlocal htail ih =>
    have heq := add_integer_equation _ _ _ _ _ _ hbase hlocal
    simp only [decode, List.length_cons, Nat.pow_succ]
    nlinarith

theorem add_chain_complete (base : Nat) (hbase : 1 < base) (xs ys : List Nat)
    (hx : Bounded base xs) (hy : Bounded base ys) (hlen : xs.length = ys.length)
    (cin : Nat) (hc : cin ≤ 1) : ∃ rs cout, AddChain base xs ys rs cin cout := by
  induction xs generalizing ys cin with
  | nil =>
    have : ys = [] := by simpa using hlen.symm
    subst ys
    exact ⟨[], cin, .nil hc⟩
  | cons a xs ih =>
    cases ys with
    | nil => simp at hlen
    | cons b ys =>
      have localGate := add_complete base a b cin hbase
        (hx a (by simp)) (hy b (by simp)) hc
      obtain ⟨rs, cout, htail⟩ := ih ys
        (fun d h => hx d (by simp [h])) (fun d h => hy d (by simp [h]))
        (by simpa using hlen) _ localGate.2.2.2.2.1
      exact ⟨_, cout, .cons localGate htail⟩

theorem add_chain_wrapping_sound {base xs ys rs cin cout} (hbase : base = 256 ∨ base = 65536)
    (h : AddChain base xs ys rs cin cout) :
    decode base rs = (decode base xs + decode base ys + cin) % base^xs.length := by
  have hp : 0 < base := by rcases hbase with rfl | rfl <;> decide
  have hl := (add_chain_lengths h).2
  have hr : decode base rs < base^xs.length := by
    rw [hl]; exact decode_lt base hp rs (add_chain_bounded h).1
  have := congrArg (· % base^xs.length) (add_chain_equation hbase h)
  simpa [Nat.add_mul_mod_self_left, Nat.mod_eq_of_lt hr] using this.symm

theorem add_chain_wrapping_sound_complete (base : Nat) (hbase : base = 256 ∨ base = 65536)
    (xs ys rs : List Nat) (hx : Bounded base xs) (hy : Bounded base ys)
    (hr : Bounded base rs) (hxy : xs.length = ys.length) (hxr : xs.length = rs.length) :
    (∃ cout, AddChain base xs ys rs 0 cout) ↔
      decode base rs = (decode base xs + decode base ys) % base^xs.length := by
  constructor
  · rintro ⟨cout, h⟩; simpa using add_chain_wrapping_sound hbase h
  · intro heq
    have hb : 1 < base := by rcases hbase with rfl | rfl <;> decide
    obtain ⟨honest, cout, h⟩ := add_chain_complete base hb xs ys hx hy hxy 0 (by decide)
    have hval := add_chain_wrapping_sound hbase h
    have hsame : honest = rs := decode_injective base (by omega) honest rs
      (add_chain_bounded h).1 hr ((add_chain_lengths h).2.symm.trans hxr)
      (by simpa using hval.trans heq.symm)
    subst honest
    exact ⟨cout, h⟩

theorem add_chain_checked_sound_complete (base : Nat) (hbase : base = 256 ∨ base = 65536)
    (xs ys rs : List Nat) (hx : Bounded base xs) (hy : Bounded base ys)
    (hr : Bounded base rs) (hxy : xs.length = ys.length) (hxr : xs.length = rs.length) :
    AddChain base xs ys rs 0 0 ↔ decode base rs = decode base xs + decode base ys := by
  constructor
  · intro h; simpa using (add_chain_equation hbase h).symm
  · intro heq
    have hb : 1 < base := by rcases hbase with rfl | rfl <;> decide
    have hp : 0 < base^xs.length := Nat.pow_pos (by omega)
    have hrange : decode base rs < base^xs.length := by
      rw [hxr]; exact decode_lt base (by omega) rs hr
    have hwrap : decode base rs = (decode base xs + decode base ys) % base^xs.length := by
      rw [← heq, Nat.mod_eq_of_lt hrange]
    obtain ⟨cout, h⟩ := (add_chain_wrapping_sound_complete base hbase xs ys rs hx hy hr hxy hxr).mpr hwrap
    have hcout : cout = 0 := by
      have := add_chain_equation hbase h
      nlinarith
    simpa [hcout] using h

end S31.Gadgets.Radix
