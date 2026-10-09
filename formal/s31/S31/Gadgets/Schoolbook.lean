import S31.Gadgets.Radix

namespace S31.Gadgets.Schoolbook
open Words Radix

/-- Coefficient addition, with zero padding, before carry normalization. -/
def addPad : List Nat → List Nat → List Nat
  | [], ys => ys
  | xs, [] => xs
  | x :: xs, y :: ys => (x + y) :: addPad xs ys

def convolve : List Nat → List Nat → List Nat
  | [], _ => []
  | x :: xs, ys => addPad (ys.map (x * ·)) (0 :: convolve xs ys)

theorem addPad_decode (base : Nat) (xs ys : List Nat) :
    decode base (addPad xs ys) = decode base xs + decode base ys := by
  induction xs generalizing ys with
  | nil => simp [addPad, decode]
  | cons x xs ih =>
    cases ys <;> simp [addPad, decode, ih] <;> ring

theorem scale_decode (base scale : Nat) (xs : List Nat) :
    decode base (xs.map (scale * ·)) = scale * decode base xs := by
  induction xs <;> simp_all [decode] <;> ring

theorem convolution_decode (base : Nat) (xs ys : List Nat) :
    decode base (convolve xs ys) = decode base xs * decode base ys := by
  induction xs with
  | nil => simp [convolve, decode]
  | cons x xs ih =>
    simp [convolve, addPad_decode, scale_decode, decode, ih]
    ring

theorem addPad_bound (xs ys : List Nat) (left right : Nat)
    (hx : ∀ x ∈ xs, x ≤ left) (hy : ∀ y ∈ ys, y ≤ right) :
    ∀ z ∈ addPad xs ys, z ≤ left + right := by
  induction xs generalizing ys with
  | nil => intro z hz; exact le_trans (hy z hz) (by omega)
  | cons x xs ih =>
    cases ys with
    | nil => intro z hz; exact le_trans (hx z hz) (by omega)
    | cons y ys =>
      intro z hz
      simp only [addPad, List.mem_cons] at hz
      rcases hz with rfl | hz
      · have ha := hx x (by simp); have hb := hy y (by simp); omega
      · exact ih ys (fun x h => hx x (by simp [h])) (fun y h => hy y (by simp [h])) z hz

theorem convolution_bound (xs ys : List Nat) (hx : Bounded 256 xs) (hy : Bounded 256 ys) :
    ∀ z ∈ convolve xs ys, z ≤ xs.length * 255^2 := by
  induction xs with
  | nil => simp [convolve]
  | cons x xs ih =>
    have hxv : x ≤ 255 := by have := hx x (by simp); omega
    have ht : Bounded 256 xs := fun d h => hx d (by simp [h])
    have hm : ∀ z ∈ ys.map (x * ·), z ≤ 255^2 := by
      intro z hz
      obtain ⟨y, hym, rfl⟩ := List.mem_map.mp hz
      have hyv : y ≤ 255 := by have := hy y hym; omega
      nlinarith
    have hb : ∀ z ∈ 0 :: convolve xs ys, z ≤ xs.length * 255^2 := by
      intro z hz
      simp only [List.mem_cons] at hz
      rcases hz with rfl | hz
      · omega
      · exact ih ht _ hz
    intro z hz
    have h := addPad_bound _ _ _ _ hm hb z hz
    simpa [convolve, List.length_cons, Nat.add_mul, Nat.add_comm] using h

def coefficientLimit : Nat := 32 * 255^2 + 255

theorem product_coefficients_bounded (q d r : List Nat) (hq : Bounded 256 q)
    (hd : Bounded 256 d) (hr : Bounded 256 r) (hlen : q.length ≤ 32) :
    ∀ c ∈ addPad (convolve q d) r, c ≤ coefficientLimit := by
  have hq' := convolution_bound q d hq hd
  have hr' : ∀ c ∈ r, c ≤ 255 := fun c h => by have := hr c h; omega
  intro c hc
  have h := addPad_bound _ _ _ _ hq' hr' c hc
  unfold coefficientLimit
  nlinarith

/-- A production multiplication column has ≤32 byte products, one remainder
byte, and a u16 incoming carry. Both sides are below p before reduction. -/
def columnConstraint (coefficient incoming digit outgoing : Nat) : Prop :=
  coefficient ≤ coefficientLimit ∧ incoming < 65536 ∧ digit < 256 ∧ outgoing < 65536 ∧
    (coefficient : Field.F) + incoming = digit + (outgoing : Field.F) * 256

theorem column_sound (coefficient incoming digit outgoing : Nat)
    (h : columnConstraint coefficient incoming digit outgoing) :
    coefficient + incoming = digit + 256 * outgoing := by
  obtain ⟨hc, hi, hd, ho, h⟩ := h
  have hl : coefficient + incoming < 2147483647 := by unfold coefficientLimit at hc; omega
  have hr : digit + 256 * outgoing < 2147483647 := by omega
  apply (Field.bounded_equation _ _ hl hr).mp
  simpa [Nat.cast_add, Nat.cast_mul, mul_comm] using h

theorem column_complete (coefficient incoming : Nat) (hc : coefficient ≤ coefficientLimit)
    (hi : incoming < 65536) :
    columnConstraint coefficient incoming ((coefficient + incoming) % 256)
      ((coefficient + incoming) / 256) := by
  refine ⟨hc, hi, Nat.mod_lt _ (by decide), ?_, ?_⟩
  · apply (Nat.div_lt_iff_lt_mul (by decide : 0 < 256)).mpr
    unfold coefficientLimit at hc
    omega
  · have h := congrArg (fun n : Nat => (n : Field.F)) (Nat.mod_add_div (coefficient + incoming) 256).symm
    simpa [Nat.cast_add, Nat.cast_mul, mul_comm] using h

inductive Columns : List Nat → List Nat → Nat → Nat → Prop where
  | nil {incoming} : incoming < 65536 → Columns [] [] incoming incoming
  | cons {coefficient coefficients incoming digit digits next outgoing} :
      columnConstraint coefficient incoming digit next →
      Columns coefficients digits next outgoing →
      Columns (coefficient :: coefficients) (digit :: digits) incoming outgoing

theorem columns_lengths {coefficients digits incoming outgoing}
    (h : Columns coefficients digits incoming outgoing) : coefficients.length = digits.length := by
  induction h <;> simp_all

theorem columns_bounded {coefficients digits incoming outgoing}
    (h : Columns coefficients digits incoming outgoing) : Bounded 256 digits ∧ outgoing < 65536 := by
  induction h with
  | nil hi => exact ⟨by simp [Bounded], hi⟩
  | cons hlocal htail ih =>
    refine ⟨?_, ih.2⟩
    intro d hd
    simp only [List.mem_cons] at hd
    rcases hd with rfl | hd
    · exact hlocal.2.2.1
    · exact ih.1 _ hd

theorem columns_equation {coefficients digits incoming outgoing}
    (h : Columns coefficients digits incoming outgoing) :
    decode 256 coefficients + incoming = decode 256 digits + 256^coefficients.length * outgoing := by
  induction h with
  | nil hi => simp [decode]
  | cons hlocal htail ih =>
    have heq := column_sound _ _ _ _ hlocal
    simp only [decode, List.length_cons, Nat.pow_succ]
    nlinarith

theorem columns_complete (coefficients : List Nat)
    (hc : ∀ c ∈ coefficients, c ≤ coefficientLimit) (incoming : Nat) (hi : incoming < 65536) :
    ∃ digits outgoing, Columns coefficients digits incoming outgoing := by
  induction coefficients generalizing incoming with
  | nil => exact ⟨[], incoming, .nil hi⟩
  | cons c cs ih =>
    have localGate := column_complete c incoming (hc c (by simp)) hi
    obtain ⟨digits, outgoing, htail⟩ := ih (fun c h => hc c (by simp [h])) _ localGate.2.2.2.1
    exact ⟨_, outgoing, .cons localGate htail⟩

/-- Zero terminal carry is essential: it is what excludes a truncated product. -/
theorem columns_sound_complete (coefficients digits : List Nat)
    (hc : ∀ c ∈ coefficients, c ≤ coefficientLimit) (hd : Bounded 256 digits)
    (hlen : coefficients.length = digits.length) :
    Columns coefficients digits 0 0 ↔ decode 256 coefficients = decode 256 digits := by
  constructor
  · intro h; simpa using columns_equation h
  · intro heq
    obtain ⟨honest, outgoing, h⟩ := columns_complete coefficients hc 0 (by decide)
    have hrange : decode 256 honest < 256^coefficients.length := by
      rw [columns_lengths h]
      exact decode_lt 256 (by decide) _ (columns_bounded h).1
    have drange : decode 256 digits < 256^coefficients.length := by
      rw [hlen]; exact decode_lt 256 (by decide) _ hd
    have hp : 0 < 256^coefficients.length := Nat.pow_pos (by decide)
    have he := columns_equation h
    have hz : outgoing = 0 := by nlinarith
    have hdv : decode 256 honest = decode 256 digits := by simp_all
    have heql : honest = digits := decode_injective 256 (by decide) honest digits
      (columns_bounded h).1 hd ((columns_lengths h).symm.trans hlen) hdv
    simpa [hz, heql] using h

theorem schoolbook_product_sound_complete (q d r n : List Nat)
    (hc : ∀ c ∈ addPad (convolve q d) r, c ≤ coefficientLimit)
    (hn : Bounded 256 n) (hlen : (addPad (convolve q d) r).length = n.length) :
    Columns (addPad (convolve q d) r) n 0 0 ↔
      decode 256 q * decode 256 d + decode 256 r = decode 256 n := by
  rw [columns_sound_complete _ _ hc hn hlen, addPad_decode, convolution_decode]

end S31.Gadgets.Schoolbook
