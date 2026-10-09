import S31.Semantics.Words
import S31.Gadgets.Field

namespace S31.Gadgets.Radix
open Words

def Bounded (base : Nat) (digits : List Nat) : Prop := ∀ d ∈ digits, d < base

theorem decode_lt (base : Nat) (_hbase : 0 < base) (digits : List Nat)
    (h : Bounded base digits) : decode base digits < base ^ digits.length := by
  induction digits with
  | nil => simp [decode]
  | cons x xs ih =>
    have hx := h x (by simp)
    have ht : Bounded base xs := fun d hd => h d (by simp [hd])
    have hi := ih ht
    simp only [decode, List.length_cons, Nat.pow_succ]
    nlinarith

theorem encode_bounded (base : Nat) (hbase : 0 < base) (n x : Nat) :
    Bounded base (encode base n x) := by
  induction n generalizing x with
  | zero => simp [encode, Bounded]
  | succ n ih =>
    intro d hd
    simp only [encode, List.mem_cons] at hd
    rcases hd with rfl | hd
    · exact Nat.mod_lt _ hbase
    · exact ih _ d hd

theorem decode_encode (base : Nat) (hbase : 0 < base) (n x : Nat)
    (hx : x < base^n) : decode base (encode base n x) = x := by
  induction n generalizing x with
  | zero =>
    simp only [Nat.pow_zero] at hx
    have : x = 0 := by omega
    simp [encode, decode, this]
  | succ n ih =>
    have hq : x / base < base^n := by
      apply (Nat.div_lt_iff_lt_mul hbase).mpr
      simpa [Nat.pow_succ, Nat.mul_comm] using hx
    simp only [encode, decode, ih _ hq]
    exact Nat.mod_add_div x base

theorem decode_injective (base : Nat) (hbase : 0 < base)
    (xs ys : List Nat) (hx : Bounded base xs) (hy : Bounded base ys)
    (hlen : xs.length = ys.length) (heq : decode base xs = decode base ys) : xs = ys := by
  induction xs generalizing ys with
  | nil => simpa using hlen.symm
  | cons x xs ih =>
    cases ys with
    | nil => simp at hlen
    | cons y ys =>
      have hxl := hx x (by simp)
      have hyl := hy y (by simp)
      have hd : x = y := by
        have := congrArg (· % base) heq
        simpa [decode, Nat.add_mul_mod_self_left, Nat.mod_eq_of_lt hxl,
          Nat.mod_eq_of_lt hyl] using this
      subst y
      have ht : decode base xs = decode base ys := by
        simp only [decode] at heq
        nlinarith
      congr 1
      exact ih ys (fun d h => hx d (by simp [h]))
        (fun d h => hy d (by simp [h])) (by simpa using hlen) ht

theorem decode_append (base : Nat) (xs ys : List Nat) :
    decode base (xs ++ ys) = decode base xs + base^xs.length * decode base ys := by
  induction xs with
  | nil => simp [decode]
  | cons x xs ih => simp [decode, ih, Nat.pow_succ]; ring

theorem decode_zeros (base n : Nat) : decode base (List.replicate n 0) = 0 := by
  induction n with
  | zero => rfl
  | succ n ih => simp [List.replicate_succ, decode, ih]

theorem zero_prefix (base n : Nat) (xs : List Nat) :
    decode base (List.replicate n 0 ++ xs) = base^n * decode base xs := by
  simp [decode_append, decode_zeros]

theorem decode_drop (base : Nat) (hb : 0 < base) (xs : List Nat)
    (hx : Bounded base xs) (k : Nat) (hk : k ≤ xs.length) :
    decode base (xs.drop k) = decode base xs / base^k := by
  have ht : Bounded base (xs.take k) := fun d hd => hx d (List.mem_of_mem_take hd)
  have hl : (xs.take k).length = k := by simp [List.length_take, Nat.min_eq_left hk]
  have hr : decode base (xs.take k) < base^k := by
    simpa only [hl] using decode_lt base hb _ ht
  have heq : decode base xs = decode base (xs.take k) + base^k * decode base (xs.drop k) := by
    calc
      decode base xs = decode base (xs.take k ++ xs.drop k) := by rw [List.take_append_drop]
      _ = decode base (xs.take k) + base^(xs.take k).length * decode base (xs.drop k) :=
        decode_append base _ _
      _ = _ := by rw [hl]
  rw [heq, Nat.add_mul_div_left _ _ (Nat.pow_pos hb), Nat.div_eq_of_lt hr]
  simp

/-- The actual byte-range equation: word*256=scaled, both wires u16. -/
def byteConstraint (word scaled : Nat) : Prop :=
  word < 65536 ∧ scaled < 65536 ∧ (word : Field.F) * 256 = (scaled : Field.F)

theorem byte_sound (word scaled : Nat) (h : byteConstraint word scaled) : word < 256 := by
  obtain ⟨hw, hs, h⟩ := h
  have heq : word * 256 = scaled := (Field.bounded_equation _ _
    (by omega) (by omega)).mp (by simpa using h)
  omega

theorem byte_complete (word : Nat) (h : word < 256) : byteConstraint word (word * 256) := by
  refine ⟨by omega, by omega, ?_⟩
  push_cast
  rfl

theorem byte_sound_complete (word : Nat) : (∃ scaled, byteConstraint word scaled) ↔ word < 256 :=
  ⟨fun ⟨scaled, h⟩ => byte_sound word scaled h, fun h => ⟨_, byte_complete word h⟩⟩

/-- One base-256 or base-65536 carry equation. The range premises are not
implicit in the field equality: removing them makes the statement false. -/
def addConstraint (base a b cin digit cout : Nat) : Prop :=
  a < base ∧ b < base ∧ cin ≤ 1 ∧ digit < base ∧ cout ≤ 1 ∧
    (a : Field.F) + b + cin = digit + (base : Field.F) * cout

theorem add_integer_equation (base a b cin digit cout : Nat)
    (hbase : base = 256 ∨ base = 65536) (h : addConstraint base a b cin digit cout) :
    a + b + cin = digit + base * cout := by
  obtain ⟨ha, hb, hc, hd, ho, h⟩ := h
  apply (Field.bounded_equation _ _ (by rcases hbase with rfl | rfl <;> omega)
    (by rcases hbase with rfl | rfl <;> omega)).mp
  simpa only [Nat.cast_add, Nat.cast_mul] using h

theorem add_digit_sound (base a b cin digit cout : Nat) (hd : digit < base)
    (heq : a + b + cin = digit + base * cout) :
    digit = (a + b + cin) % base ∧ cout = (a + b + cin) / base := by
  rw [heq]
  constructor
  · simp [Nat.add_mul_mod_self_left, Nat.mod_eq_of_lt hd]
  · rw [Nat.add_mul_div_left _ _ (by omega), Nat.div_eq_of_lt hd]
    simp

theorem add_complete (base a b cin : Nat) (hbase : 1 < base)
    (ha : a < base) (hb : b < base) (hc : cin ≤ 1) :
    addConstraint base a b cin ((a + b + cin) % base) ((a + b + cin) / base) := by
  have hp : 0 < base := by omega
  have hs : a + b + cin < 2 * base := by omega
  refine ⟨ha, hb, hc, Nat.mod_lt _ hp, ?_, ?_⟩
  · have := (Nat.div_lt_iff_lt_mul hp).mpr hs
    omega
  · have heq := Nat.mod_add_div (a + b + cin) base
    simpa only [Nat.cast_add, Nat.cast_mul] using
      congrArg (fun n : Nat => (n : Field.F)) heq.symm

def subConstraint (base a b cin digit cout : Nat) : Prop :=
  a < base ∧ b < base ∧ cin ≤ 1 ∧ digit < base ∧ cout ≤ 1 ∧
    (a : Field.F) + (base : Field.F) * cout = b + cin + digit

theorem sub_integer_equation (base a b cin digit cout : Nat)
    (hbase : base = 256 ∨ base = 65536) (h : subConstraint base a b cin digit cout) :
    a + base * cout = b + cin + digit := by
  obtain ⟨ha, hb, hc, hd, ho, h⟩ := h
  apply (Field.bounded_equation _ _ (by rcases hbase with rfl | rfl <;> omega)
    (by rcases hbase with rfl | rfl <;> omega)).mp
  simpa only [Nat.cast_add, Nat.cast_mul] using h

def borrow (a b cin : Nat) : Nat := if a < b + cin then 1 else 0
def difference (base a b cin : Nat) : Nat := a + base * borrow a b cin - (b + cin)

theorem sub_complete (base a b cin : Nat) (_hbase : 1 < base)
    (ha : a < base) (hb : b < base) (hc : cin ≤ 1) :
    subConstraint base a b cin (difference base a b cin) (borrow a b cin) := by
  by_cases h : a < b + cin
  · simp only [difference, borrow, if_pos h, Nat.mul_one]
    refine ⟨ha, hb, hc, by omega, by omega, ?_⟩
    have heq : a + base = b + cin + (a + base - (b + cin)) := by omega
    simpa only [Nat.cast_add, Nat.cast_one, Nat.cast_mul, mul_one] using
      congrArg (fun n : Nat => (n : Field.F)) heq
  · simp only [difference, borrow, if_neg h, Nat.mul_zero, Nat.add_zero]
    refine ⟨ha, hb, hc, by omega, by omega, ?_⟩
    have heq : a = b + cin + (a - (b + cin)) := by omega
    simpa only [Nat.cast_add, Nat.cast_zero, Nat.cast_mul, mul_zero, add_zero] using
      congrArg (fun n : Nat => (n : Field.F)) heq

theorem sub_borrow_sound (base a b cin digit cout : Nat) (hd : digit < base)
    (hc : cout ≤ 1) (heq : a + base * cout = b + cin + digit) :
    cout = borrow a b cin := by
  rcases (by omega : cout = 0 ∨ cout = 1) with rfl | rfl
  · simp only [Nat.mul_zero, Nat.add_zero] at heq
    simp [borrow, show ¬a < b + cin by omega]
  · simp only [Nat.mul_one] at heq
    simp [borrow, show a < b + cin by omega]

end S31.Gadgets.Radix
