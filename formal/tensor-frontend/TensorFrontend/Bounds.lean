/-
A Lean model of bounds.zig `validateStatementBounds` on a fragment of the
op graph, and its soundness: if it accepts, every op's field identity is
its integer identity (zero-dependency).

Model (`Op`): core `matmul` and `hadamard` (int8 requant outputs), `range8`,
and the ext einsums: `exact` (shift = 0: y = Σ a b over 2^nk terms) and
`requant` (shift > 0, output key of `ob` bits). The bound state maps a
tensor id to `some b` (|entry| <= 2^b) or `none` (bounds.zig `UNB`).

Algorithm, as in bounds.zig:
1. seed (`seedOp`): matmul / hadamard outputs and range8 inputs get 7
   (`s.setb(.., 7)`); a requant einsum output gets `ob - 1`
   (`s.setb(e.y, e.out_bits - 1)`);
2. fixpoint (`pass`, iterated `fuel` times): an exact einsum whose operands
   are bounded gets `ba + bb + nk` if `<= EXACT_MAX_BITS`
   (`einsumBound`, `if (b <= EXACT_MAX_BITS) s.setb(..)`); `setb` ignores
   values `> 30` and only ever lowers a bound;
3. final checks (`checkOp`): matmul `bx + 7 + logK <= 30`, hadamard
   `ba + bb <= 30`, shift in `[1, 22]` (`StatementShift`), exact einsum
   bound `<= EXACT_MAX_BITS`, requant einsum bound `<= REQUANT_MAX_BITS` and
   `shift + out_bits <= 30`; an unbounded operand fails
   (`StatementUnboundedOperand`).

Soundness does not depend on the number of fixpoint passes: every pass
preserves "every recorded bound is true of the witness" (`Sound`), so the
theorem holds for every `fuel`, in particular bounds.zig's
`ext.ops.len + 3` cap and its early exit.

Not modelled (each only adds bound facts, and each would need its own
justification): lookups / glu / product core ops, key-derived bounds
(`coveringTerm`), linear-equation derivation (`deriveLineq`), slices and
one-hot facts, Boolean einsums, publics. The witness facts the LogUp range
checks provide (int8 outputs, remainders in `[0, 2^s)`, output keys) and
the weight key's int8 weights are hypotheses of `OpHolds`.
-/
import TensorFrontend.Kernel

namespace TensorFrontend.Bounds

open TensorFrontend.Kernel

/-- The modelled op fragment. Tensor ids are `Nat`. -/
inductive Op where
  | matmul (x y logK shift : Nat)
  | hadamard (a b y shift : Nat)
  | range8 (t : Nat)
  | exact (a b y nk : Nat)
  | requant (a b y nk shift ob : Nat)

/-- Bound state: `some b` means every entry has magnitude `<= 2^b`. -/
abbrev BState := Nat → Option Nat

/-- bounds.zig `State.setb`: ignore `v > 30`, only lower. -/
def better (o : Option Nat) (v : Nat) : Bool :=
  match o with
  | none => true
  | some c => decide (v < c)

def setb (s : BState) (t v : Nat) : BState :=
  fun u => if u = t ∧ v ≤ 30 ∧ better (s t) v = true then some v else s u

/-- Seed bounds from range-checked outputs. -/
def seedOp (s : BState) : Op → BState
  | .matmul _ y _ _ => setb s y 7
  | .hadamard _ _ y _ => setb s y 7
  | .range8 t => setb s t 7
  | .exact .. => s
  | .requant _ _ y _ _ ob => setb s y (ob - 1)

/-- `einsumBound`, generic case: `ba + bb + nk`. -/
def einsumBound (s : BState) (a b nk : Nat) : Option Nat :=
  match s a, s b with
  | some ba, some bb => some (ba + bb + nk)
  | _, _ => none

/-- One fixpoint pass over the exact einsums. -/
def passOp (s : BState) : Op → BState
  | .exact a b y nk =>
    match einsumBound s a b nk with
    | some v => if v ≤ EXACT_MAX_BITS then setb s y v else s
    | none => s
  | _ => s

def pass (ops : List Op) (s : BState) : BState := ops.foldl passOp s

def iter (ops : List Op) : Nat → BState → BState
  | 0, s => s
  | n + 1, s => iter ops n (pass ops s)

/-- Final per-op checks. -/
def checkOp (s : BState) : Op → Bool
  | .matmul x _ logK sh =>
    match s x with
    | some bx => decide (bx + 7 + logK ≤ 30 ∧ 1 ≤ sh ∧ sh ≤ 22)
    | none => false
  | .hadamard a b _ sh =>
    match s a, s b with
    | some ba, some bb => decide (ba + bb ≤ 30 ∧ 1 ≤ sh ∧ sh ≤ 22)
    | _, _ => false
  | .range8 _ => true
  | .exact a b _ nk =>
    match einsumBound s a b nk with
    | some v => decide (v ≤ EXACT_MAX_BITS)
    | none => false
  | .requant a b _ nk sh ob =>
    match einsumBound s a b nk with
    | some v => decide (v ≤ REQUANT_MAX_BITS ∧ 1 ≤ sh ∧ 1 ≤ ob ∧ sh + ob ≤ 30)
    | none => false

/-- The bound state after seeding and `fuel` passes. -/
def bounds (ops : List Op) (fuel : Nat) : BState :=
  iter ops fuel (ops.foldl seedOp (fun _ => none))

/-- `validateStatementBounds` on the fragment. -/
def validate (ops : List Op) (fuel : Nat) : Bool :=
  ops.all (checkOp (bounds ops fuel))

/-! ### Semantics -/

/-- Witness: tensor id -> entry index -> signed representative. -/
abbrev Witness := Nat → Nat → Int

/-- Pairs drawn from the entries of tensors `a` and `b`. -/
def FromAB (W : Witness) (a b : Nat) (L : List (Int × Int)) : Prop :=
  ∀ ab ∈ L, (∃ j, ab.1 = W a j) ∧ (∃ j, ab.2 = W b j)

/-- What the proof checks per op: the M31 field identity plus the range
facts the LogUp lookups (and the weight key) establish. -/
def OpHolds (W : Witness) : Op → Prop
  | .matmul x y logK s => ∀ i, ∃ (xs ws : List Int) (r : Int),
      xs.length = 2 ^ logK ∧ (∀ a ∈ xs, ∃ j, a = W x j) ∧ (∀ w ∈ ws, w.natAbs ≤ 2 ^ 7) ∧
      -128 ≤ W y i ∧ W y i < 128 ∧ 0 ≤ r ∧ r < 2 ^ s ∧
      FieldZero (dot xs ws + 2 ^ (s - 1) - 2 ^ s * W y i - r)
  | .hadamard a b y s => ∀ i, ∃ r : Int,
      -128 ≤ W y i ∧ W y i < 128 ∧ 0 ≤ r ∧ r < 2 ^ s ∧
      FieldZero (W a i * W b i + 2 ^ (s - 1) - 2 ^ s * W y i - r)
  | .range8 t => ∀ i, -128 ≤ W t i ∧ W t i < 128
  | .exact a b y nk => ∀ i, ∃ L : List (Int × Int),
      L.length = 2 ^ nk ∧ FromAB W a b L ∧ (W y i).natAbs ≤ 1073741823 ∧ FieldZero (W y i - sumProd L)
  | .requant a b y nk s ob => ∀ i, ∃ (L : List (Int × Int)) (r : Int),
      L.length = 2 ^ nk ∧ FromAB W a b L ∧
      0 ≤ W y i + 2 ^ (ob - 1) ∧ W y i + 2 ^ (ob - 1) < 2 ^ ob ∧ 0 ≤ r ∧ r < 2 ^ s ∧
      FieldZero (sumProd L + 2 ^ (s - 1) - 2 ^ s * W y i - r)

/-- The integer semantics: each output is the requantised / exact integer
value (the relation the statement is meant to prove). -/
def OpInt (W : Witness) : Op → Prop
  | .matmul x y logK s => ∀ i, ∃ (xs ws : List Int),
      xs.length = 2 ^ logK ∧ (∀ a ∈ xs, ∃ j, a = W x j) ∧ (∀ w ∈ ws, w.natAbs ≤ 2 ^ 7) ∧
      W y i = requant s (dot xs ws)
  | .hadamard a b y s => ∀ i, W y i = requant s (W a i * W b i)
  | .range8 t => ∀ i, -128 ≤ W t i ∧ W t i < 128
  | .exact a b y nk => ∀ i, ∃ L : List (Int × Int),
      L.length = 2 ^ nk ∧ FromAB W a b L ∧ W y i = sumProd L
  | .requant a b y nk s _ => ∀ i, ∃ L : List (Int × Int),
      L.length = 2 ^ nk ∧ FromAB W a b L ∧ W y i = requant s (sumProd L)

/-- Every recorded bound is true of the witness. -/
def Sound (W : Witness) (s : BState) : Prop := ∀ t b, s t = some b → ∀ i, (W t i).natAbs ≤ 2 ^ b

theorem sound_setb (W : Witness) (s : BState) (t v : Nat) (hs : Sound W s)
    (hv : ∀ i, (W t i).natAbs ≤ 2 ^ v) : Sound W (setb s t v) := by
  intro u b hu i
  simp only [setb] at hu
  by_cases h : u = t ∧ v ≤ 30 ∧ better (s t) v = true
  · rw [if_pos h] at hu; rw [h.1]; cases hu; exact hv i
  · rw [if_neg h] at hu; exact hs u b hu i

theorem foldl_inv {α β : Type} (P : β → Prop) (f : β → α → β) (L : List α) (init : β)
    (h : ∀ s, ∀ x ∈ L, P s → P (f s x)) (h0 : P init) : P (L.foldl f init) := by
  induction L generalizing init with
  | nil => exact h0
  | cons x L ih =>
    exact ih (f init x) (fun s y hy => h s y (List.mem_cons_of_mem _ hy)) (h init x (List.mem_cons_self ..) h0)

theorem int8_abs (y : Int) (h0 : -128 ≤ y) (h1 : y < 128) : y.natAbs ≤ 2 ^ 7 := by
  have : (2 : Nat) ^ 7 = 128 := by decide
  rw [this]; omega

theorem key_abs (ob : Nat) (y : Int) (h0 : 0 ≤ y + 2 ^ (ob - 1)) (h1 : y + 2 ^ (ob - 1) < 2 ^ ob) :
    y.natAbs ≤ 2 ^ (ob - 1) := by
  have hc : ((2 ^ (ob - 1) : Nat) : Int) = (2 : Int) ^ (ob - 1) := Int.natCast_pow 2 (ob - 1)
  cases ob with
  | zero => simp at h0 h1 ⊢; omega
  | succ k =>
    simp only [Nat.add_sub_cancel] at h0 h1 hc ⊢
    have e : (2 : Int) ^ (k + 1) = 2 * 2 ^ k := by rw [Int.pow_succ, Int.mul_comm]
    rw [e] at h1
    omega

theorem sound_seed (W : Witness) (ops : List Op) (hops : ∀ op ∈ ops, OpHolds W op) :
    Sound W (ops.foldl seedOp (fun _ => none)) := by
  apply foldl_inv (Sound W) seedOp ops
  · intro s op hop hs
    have hh := hops op hop
    cases op with
    | matmul x y logK sh =>
      apply sound_setb W s y 7 hs
      intro i
      obtain ⟨_, _, _, _, _, _, h0, h1, _⟩ := hh i
      exact int8_abs _ h0 h1
    | hadamard a b y sh =>
      apply sound_setb W s y 7 hs
      intro i; obtain ⟨_, h0, h1, _⟩ := hh i; exact int8_abs _ h0 h1
    | range8 t =>
      apply sound_setb W s t 7 hs
      intro i; obtain ⟨h0, h1⟩ := hh i; exact int8_abs _ h0 h1
    | exact => exact hs
    | requant a b y nk sh ob =>
      apply sound_setb W s y (ob - 1) hs
      intro i; obtain ⟨_, _, _, _, h0, h1, _⟩ := hh i; exact key_abs ob _ h0 h1
  · intro t b h; cases h

theorem pow3 (ba bb nk : Nat) : 2 ^ nk * (2 ^ ba * 2 ^ bb) = 2 ^ (ba + bb + nk) := by
  rw [← Nat.pow_add, ← Nat.pow_add]; congr 1; omega

/-- The exact-einsum propagation rule is sound: operand bounds `ba, bb`
give `|y| <= 2^(ba + bb + nk)` when the rule admits it. -/
theorem exact_bound (W : Witness) (s : BState) (hs : Sound W s) (a b y nk ba bb : Nat)
    (ha : s a = some ba) (hb : s b = some bb) (hrule : ba + bb + nk ≤ EXACT_MAX_BITS)
    (hh : OpHolds W (.exact a b y nk)) : ∀ i, (W y i).natAbs ≤ 2 ^ (ba + bb + nk) := by
  intro i
  obtain ⟨L, hlen, hfrom, hy, hf⟩ := hh i
  have hops : ∀ ab ∈ L, ab.1.natAbs ≤ 2 ^ ba ∧ ab.2.natAbs ≤ 2 ^ bb := by
    intro ab hab
    obtain ⟨⟨j1, e1⟩, ⟨j2, e2⟩⟩ := hfrom ab hab
    exact ⟨e1 ▸ hs a ba ha j1, e2 ▸ hs b bb hb j2⟩
  have hr : exactRule ba bb nk = true := by unfold exactRule; exact decide_eq_true hrule
  obtain ⟨e, _⟩ := exact_einsum_sound ba bb nk L (W y i) hr hlen hops hy hf
  rw [e]
  have := sumProd_bound L (2 ^ ba) (2 ^ bb) hops
  rw [hlen, pow3] at this
  exact this

theorem sound_pass (W : Witness) (ops : List Op) (hops : ∀ op ∈ ops, OpHolds W op)
    (s : BState) (hs : Sound W s) : Sound W (pass ops s) := by
  apply foldl_inv (Sound W) passOp ops _ _ hs
  intro s op hop hs
  cases op with
  | exact a b y nk =>
    simp only [passOp]
    cases he : einsumBound s a b nk with
    | none => exact hs
    | some v =>
      simp only
      split
      · rename_i hv
        apply sound_setb W s y v hs
        simp only [einsumBound] at he
        split at he
        · rename_i ba bb ha hb
          cases he
          exact exact_bound W s hs a b y nk ba bb ha hb hv (hops _ hop)
        · cases he
      · exact hs
  | _ => exact hs

theorem sound_iter (W : Witness) (ops : List Op) (hops : ∀ op ∈ ops, OpHolds W op) :
    ∀ (fuel : Nat) (s : BState), Sound W s → Sound W (iter ops fuel s)
  | 0, _, hs => hs
  | n + 1, s, hs => sound_iter W ops hops n _ (sound_pass W ops hops s hs)

theorem sound_bounds (W : Witness) (ops : List Op) (hops : ∀ op ∈ ops, OpHolds W op) (fuel : Nat) :
    Sound W (bounds ops fuel) :=
  sound_iter W ops hops fuel _ (sound_seed W ops hops)

/-- **Statement-level no-wrap.** If the modelled `validateStatementBounds`
accepts the op graph (any number of fixpoint passes), every op whose field
identity and range facts hold satisfies its integer identity: the hypotheses
of `matmul_sound`, `hadamard_sound`, `exact_einsum_sound` and
`requant_einsum_sound` are discharged from the computed bounds. -/
theorem validate_sound (ops : List Op) (fuel : Nat) (hv : validate ops fuel = true)
    (W : Witness) (hops : ∀ op ∈ ops, OpHolds W op) : ∀ op ∈ ops, OpInt W op := by
  have hs := sound_bounds W ops hops fuel
  intro op hop
  have hc : checkOp (bounds ops fuel) op = true := List.all_eq_true.mp hv op hop
  have hh := hops op hop
  cases op with
  | matmul x y logK sh =>
    simp only [checkOp] at hc
    split at hc
    · rename_i bx hx
      have hc' := of_decide_eq_true hc
      intro i
      obtain ⟨xs, ws, r, hlen, hxs, hws, hy0, hy1, hr0, hr1, hf⟩ := hh i
      refine ⟨xs, ws, hlen, hxs, hws, ?_⟩
      exact matmul_sound bx logK sh xs ws (W y i) r hc'.1 hc'.2.1 hc'.2.2 hlen
        (fun a ha => by obtain ⟨j, e⟩ := hxs a ha; rw [e]; exact hs x bx hx j) hws hy0 hy1 hr0 hr1 hf
    · cases hc
  | hadamard a b y sh =>
    simp only [checkOp] at hc
    split at hc
    · rename_i ba bb ha hb
      have hc' := of_decide_eq_true hc
      intro i
      obtain ⟨r, hy0, hy1, hr0, hr1, hf⟩ := hh i
      exact hadamard_sound ba bb sh (W a i) (W b i) (W y i) r hc'.1 hc'.2.1 hc'.2.2
        (hs a ba ha i) (hs b bb hb i) hy0 hy1 hr0 hr1 hf
    · cases hc
  | range8 t => exact hh
  | exact a b y nk =>
    simp only [checkOp] at hc
    split at hc
    · rename_i v he
      simp only [einsumBound] at he
      split at he
      · rename_i ba bb ha hb
        cases he
        have hc' := of_decide_eq_true hc
        intro i
        obtain ⟨L, hlen, hfrom, hy, hf⟩ := hh i
        refine ⟨L, hlen, hfrom, ?_⟩
        have hops' : ∀ ab ∈ L, ab.1.natAbs ≤ 2 ^ ba ∧ ab.2.natAbs ≤ 2 ^ bb := by
          intro ab hab
          obtain ⟨⟨j1, e1⟩, ⟨j2, e2⟩⟩ := hfrom ab hab
          exact ⟨e1 ▸ hs a ba ha j1, e2 ▸ hs b bb hb j2⟩
        exact (exact_einsum_sound ba bb nk L (W y i) (by unfold exactRule; exact decide_eq_true hc')
          hlen hops' hy hf).1
      · cases he
    · cases hc
  | requant a b y nk sh ob =>
    simp only [checkOp] at hc
    split at hc
    · rename_i v he
      simp only [einsumBound] at he
      split at he
      · rename_i ba bb ha hb
        cases he
        have hc' := of_decide_eq_true hc
        intro i
        obtain ⟨L, r, hlen, hfrom, hy0, hy1, hr0, hr1, hf⟩ := hh i
        refine ⟨L, hlen, hfrom, ?_⟩
        have hops' : ∀ ab ∈ L, ab.1.natAbs ≤ 2 ^ ba ∧ ab.2.natAbs ≤ 2 ^ bb := by
          intro ab hab
          obtain ⟨⟨j1, e1⟩, ⟨j2, e2⟩⟩ := hfrom ab hab
          exact ⟨e1 ▸ hs a ba ha j1, e2 ▸ hs b bb hb j2⟩
        have hacc : (sumProd L).natAbs ≤ 2 ^ (ba + bb + nk) := by
          have := sumProd_bound L (2 ^ ba) (2 ^ bb) hops'
          rw [hlen, pow3] at this
          exact this
        exact requant_einsum_sound (ba + bb + nk) sh ob (sumProd L) (W y i) r hc'.1 hc'.2.1 hc'.2.2.1
          hc'.2.2.2 hacc hy0 hy1 hr0 hr1 hf
      · cases he
    · cases hc

/-! ### Rule constants (checked against bounds.zig by `decide`) -/

/-- bounds.zig: `EXACT_MAX_BITS = 29`, `REQUANT_MAX_BITS = 29`, the 30-bit
accumulator cap, shifts in `[1, 22]`, int8 seed 7. A concrete accepted
graph: x (range8) -> matmul (K = 2^16) -> exact einsum with itself. -/
example : validate [.range8 0, .matmul 0 1 16 8, .exact 1 1 2 10] 3 = true := by decide

/-- ... and a rejected one (accumulator 7 + 7 + 17 > 30). -/
example : validate [.range8 0, .matmul 0 1 17 8] 3 = false := by decide

end TensorFrontend.Bounds
