/-
**The SIMD wire layer** (`src/frontends/circuit/builder/simd.zig`,
stwo-zig `4afa09dbf`): vectors of M31 lanes packed four per QM31 wire.

`[a, b, c, d, e, f]` is two wires `a + b·i + c·u + d·iu` and `e + f·i`;
the unused coordinates of a partial last wire are unconstrained, so
`Simd::eq` masks them (`(a − b) ⊙ first_ones = 0`).

The model: a `SimdReg` is the wire registers plus the lane count; lane `j`
of an assignment is coordinate `j % 4` of wire `j / 4`. Soundness lemmas
relate the emitted gates to per-lane facts on the first `len` lanes only —
exactly what the circuit enforces.
-/
import StwoVerifier.Gates
import StwoVerifier.Algebra
import StwoVerifier.BitDecomp

namespace StwoVerifier.Gadgets

open StwoVerifier StwoVerifier.Gates

/-- Coordinate `c` (0–3) of a QM31 in stwo's order. -/
def coord (x : QM31) : Nat → F
  | 0 => x.c0.a
  | 1 => x.c0.b
  | 2 => x.c1.a
  | _ => x.c1.b

@[simp] theorem coord_pmul (x y : QM31) (c : Nat) (hc : c < 4) :
    coord (pmulQ x y) c = coord x c * coord y c := by
  interval_cases c <;> rfl

/-- A SIMD vector: `⌈len/4⌉` wire registers. -/
structure SimdReg where
  data : List ℕ
  len : ℕ
  deriving Repr

/-- Lane `j` under an assignment. -/
def SimdReg.lane (ρ : ℕ → QM31) (s : SimdReg) (j : ℕ) : F :=
  coord (ρ (s.data.getD (j / 4) 0)) (j % 4)

/-- A base element seen on every coordinate (`Simd::repeat`'s constant,
`(v, v, v, v)`). -/
def splat (v : F) : QM31 := ⟨⟨v, v⟩, ⟨v, v⟩⟩

@[simp] theorem coord_splat (v : F) (c : Nat) (hc : c < 4) :
    coord (splat v) c = v := by
  interval_cases c <;> rfl

/-- Multiplying by a base element scales every coordinate. -/
theorem mul_base_eq (s : F) (x : QM31) :
    QM31.fromBase s * x = ⟨⟨s * x.c0.a, s * x.c0.b⟩, ⟨s * x.c1.a, s * x.c1.b⟩⟩ := by
  ext <;> simp [QM31.fromBase, CM31.fromBase, QM31.R] <;> ring

theorem coord_mul_base (s : F) (x : QM31) (c : Nat) (hc : c < 4) :
    coord (QM31.fromBase s * x) c = s * coord x c := by
  rw [mul_base_eq]
  interval_cases c <;> rfl

/-- `IsBase` values are `fromBase` of their base coordinate. -/
theorem isBase_eq_fromBase {x : QM31} (h : Gates.IsBase x) :
    x = QM31.fromBase x.c0.a := by
  obtain ⟨hb, hc1⟩ := h
  cases x with
  | mk c0 c1 =>
    cases c0
    simp_all [QM31.fromBase, CM31.fromBase, CM31.zero]

/-! ### Per-wire gate facts, per-lane

`Simd::eq` constrains whole wires with `eq` gates and a partial last wire
with `(a − b) ⊙ first_ones(r) = 0`. Either way, the first `len` lanes
agree; nothing is said about the tail lanes. These lemmas extract exactly
that. -/

/-- `first_ones r` for `r = 1, 2, 3`. -/
def firstOnes : Nat → QM31
  | 1 => QM31.fromM31s 1 0 0 0
  | 2 => QM31.fromM31s 1 1 0 0
  | _ => QM31.fromM31s 1 1 1 0

theorem coord_firstOnes {r c : Nat} (hr1 : 1 ≤ r) (hr : r ≤ 3) (hc : c < 4) :
    coord (firstOnes r) c = if c < r then 1 else 0 := by
  interval_cases r <;> interval_cases c <;> rfl

/-- A full-wire `eq` gate gives all four lane equalities. -/
theorem eq_wire_lanes {x y : QM31} (h : x = y) (c : Nat) (hc : c < 4) :
    coord x c = coord y c := by rw [h]

/-- The masked partial-wire constraint
`(x − y) ⊙ first_ones(r) = 0` gives the first `r` lane equalities. -/
theorem eq_masked_lanes {x y : QM31} {r : Nat} (hr1 : 1 ≤ r) (hr : r ≤ 3)
    (h : pmulQ (x - y) (firstOnes r) = 0) (c : Nat) (hc : c < r) :
    coord x c = coord y c := by
  have hc4 : c < 4 := by omega
  have hcoord : coord (pmulQ (x - y) (firstOnes r)) c = coord (0 : QM31) c := by
    rw [h]
  rw [coord_pmul _ _ c hc4, coord_firstOnes hr1 hr hc4, if_pos hc] at hcoord
  have hsub : coord (x - y) c = coord x c - coord y c := by
    interval_cases c <;> rfl
  have hzero : coord (0 : QM31) c = 0 := by interval_cases c <;> rfl
  rw [hsub, hzero] at hcoord
  have h0 : coord x c - coord y c = 0 := by simpa using hcoord
  exact sub_eq_zero.mp h0

/-! ### Coordinate homomorphisms -/

@[simp] theorem coord_sub (x y : QM31) (c : Nat) (hc : c < 4) :
    coord (x - y) c = coord x c - coord y c := by
  interval_cases c <;> rfl

@[simp] theorem coord_add (x y : QM31) (c : Nat) (hc : c < 4) :
    coord (x + y) c = coord x c + coord y c := by
  interval_cases c <;> rfl

@[simp] theorem coord_zero (c : Nat) (hc : c < 4) : coord (0 : QM31) c = 0 := by
  interval_cases c <;> rfl

/-! ### Lane-wise emitters (`simd.zig`)

A lane-wise binary operation emits one gate per wire pair, allocating one
fresh output wire each. The soundness lemmas give the per-wire semantic
equation, and `lane`-level corollaries follow from the coordinate
homomorphisms. -/

/-- One gate per wire pair, fresh outputs `n, n+1, …`. -/
def lanewise2 (g : ℕ → ℕ → ℕ → Op) : List ℕ → List ℕ → ℕ → Out (List ℕ)
  | [], _, n => ⟨[], [], n⟩
  | _, [], n => ⟨[], [], n⟩
  | a :: as, b :: bs, n =>
    let rest := lanewise2 g as bs (n + 1)
    ⟨g n a b :: rest.ops, n :: rest.res, rest.next⟩

/-- Wire-level soundness of a lane-wise emitter, for any gate former whose
`Holds` is `ρ o = f (ρ x) (ρ y)`. -/
theorem lanewise2_sound (f : QM31 → QM31 → QM31) (g : ℕ → ℕ → ℕ → Op)
    (hg : ∀ ρ o x y, Holds ρ (g o x y) → ρ o = f (ρ x) (ρ y))
    {ρ : ℕ → QM31} :
    ∀ (as bs : List ℕ) (n : ℕ), AllHold ρ (lanewise2 g as bs n).ops →
      ∀ k, ∀ ha : k < (lanewise2 g as bs n).res.length,
        ρ ((lanewise2 g as bs n).res.getD k 0)
          = f (ρ (as.getD k 0)) (ρ (bs.getD k 0)) := by
  intro as
  induction as with
  | nil => intro bs n _ k hk; simp [lanewise2] at hk
  | cons a as ih =>
    intro bs n h k hk
    cases bs with
    | nil => simp [lanewise2] at hk
    | cons b bs =>
      rw [show (lanewise2 g (a :: as) (b :: bs) n).ops
        = g n a b :: (lanewise2 g as bs (n + 1)).ops from rfl, allHold_cons] at h
      obtain ⟨h1, hrest⟩ := h
      have hres : (lanewise2 g (a :: as) (b :: bs) n).res
          = n :: (lanewise2 g as bs (n + 1)).res := rfl
      cases k with
      | zero =>
        rw [hres]
        simpa using hg ρ n a b h1
      | succ k =>
        rw [hres] at hk ⊢
        have hk' : k < (lanewise2 g as bs (n + 1)).res.length := by
          simpa using hk
        simpa using ih bs (n + 1) hrest k hk'

/-- `Simd::sub`. -/
def simdSub (a b : SimdReg) (n : ℕ) : Out SimdReg :=
  let w := lanewise2 .sub a.data b.data n
  ⟨w.ops, ⟨w.res, a.len⟩, w.next⟩

/-- `Simd::mul` (lane-wise, a pointwise product per wire). -/
def simdMul (a b : SimdReg) (n : ℕ) : Out SimdReg :=
  let w := lanewise2 .pmul a.data b.data n
  ⟨w.ops, ⟨w.res, a.len⟩, w.next⟩

theorem simdSub_wire {ρ : ℕ → QM31} {a b : SimdReg} {n : ℕ}
    (h : AllHold ρ (simdSub a b n).ops) (k : ℕ)
    (hk : k < (simdSub a b n).res.data.length) :
    ρ ((simdSub a b n).res.data.getD k 0)
      = ρ (a.data.getD k 0) - ρ (b.data.getD k 0) :=
  lanewise2_sound (· - ·) .sub (fun _ _ _ _ h => h) a.data b.data n h k hk

theorem simdMul_wire {ρ : ℕ → QM31} {a b : SimdReg} {n : ℕ}
    (h : AllHold ρ (simdMul a b n).ops) (k : ℕ)
    (hk : k < (simdMul a b n).res.data.length) :
    ρ ((simdMul a b n).res.data.getD k 0)
      = pmulQ (ρ (a.data.getD k 0)) (ρ (b.data.getD k 0)) :=
  lanewise2_sound pmulQ .pmul (fun _ _ _ _ h => h) a.data b.data n h k hk

/-- `Simd::scalar_mul` by an M31 wire `s`: one `mul` gate per wire. -/
def simdScalarMul (a : SimdReg) (s : ℕ) (n : ℕ) : Out SimdReg :=
  let w := lanewise2 (fun o x y => .mul o x y) a.data (a.data.map fun _ => s) n
  ⟨w.ops, ⟨w.res, a.len⟩, w.next⟩

theorem simdScalarMul_wire {ρ : ℕ → QM31} {a : SimdReg} {s n : ℕ}
    (h : AllHold ρ (simdScalarMul a s n).ops) (k : ℕ)
    (hk : k < (simdScalarMul a s n).res.data.length)
    (hklen : k < a.data.length) :
    ρ ((simdScalarMul a s n).res.data.getD k 0)
      = ρ (a.data.getD k 0) * ρ s := by
  have hmap : (a.data.map fun _ => s).getD k 0 = s := by
    rw [List.getD_eq_getElem?_getD, List.getElem?_map,
      List.getElem?_eq_getElem hklen]
    rfl
  have := lanewise2_sound (· * ·) (fun o x y => .mul o x y)
    (fun _ _ _ _ h => h) a.data (a.data.map fun _ => s) n h k hk
  rwa [hmap] at this

/-! ### `Simd::eq` -/

/-- One `eq` gate per wire pair. -/
def eqWires : List ℕ → List ℕ → List Op
  | a :: as, b :: bs => .eq a b :: eqWires as bs
  | _, _ => []

theorem eqWires_sound {ρ : ℕ → QM31} :
    ∀ (as bs : List ℕ), AllHold ρ (eqWires as bs) →
      ∀ k, k < as.length → k < bs.length →
        ρ (as.getD k 0) = ρ (bs.getD k 0) := by
  intro as
  induction as with
  | nil => intro bs _ k hk _; simp at hk
  | cons a as ih =>
    intro bs h k hka hkb
    cases bs with
    | nil => simp at hkb
    | cons b bs =>
      rw [show eqWires (a :: as) (b :: bs) = .eq a b :: eqWires as bs from rfl,
        allHold_cons] at h
      obtain ⟨h1, hrest⟩ := h
      cases k with
      | zero =>
        simp only [Holds] at h1
        simpa using h1
      | succ k =>
        simpa using ih bs hrest k (by simpa using hka) (by simpa using hkb)

/-- `Simd::eq`: `len/4` full-wire `eq` gates, and for a partial last wire
`r = len % 4 ≠ 0`, the masked constraint
`(a_w − b_w) ⊙ first_ones(r) = 0` via `sub`, `const`, `pmul`, `eq zero`. -/
def simdEq (zero : ℕ) (a b : SimdReg) (n : ℕ) : Out Unit :=
  let full := eqWires (a.data.take (a.len / 4)) (b.data.take (a.len / 4))
  let r := a.len % 4
  if r = 0 then ⟨full, (), n⟩
  else
    ⟨full ++
      [.sub n (a.data.getD (a.len / 4) 0) (b.data.getD (a.len / 4) 0),
       .const (n + 1) (firstOnes r),
       .pmul (n + 2) n (n + 1),
       .eq (n + 2) zero],
     (), n + 3⟩

/-- Per-lane soundness of `Simd::eq`: the first `len` lanes agree. -/
theorem simdEq_sound {ρ : ℕ → QM31} {zero : ℕ} {a b : SimdReg} {n : ℕ}
    (hzero : ρ zero = 0)
    (hlena : a.len ≤ 4 * a.data.length) (hlenb : a.len ≤ 4 * b.data.length)
    (h : AllHold ρ (simdEq zero a b n).ops) :
    ∀ j, j < a.len → SimdReg.lane ρ a j = SimdReg.lane ρ b j := by
  intro j hj
  have hc4 : j % 4 < 4 := Nat.mod_lt _ (by norm_num)
  by_cases hw : j / 4 < a.len / 4
  · -- A fully constrained wire.
    have hfull : AllHold ρ (eqWires (a.data.take (a.len / 4)) (b.data.take (a.len / 4))) := by
      unfold simdEq at h
      by_cases hr : a.len % 4 = 0
      · simpa [hr] using h
      · rw [if_neg hr, allHold_append] at h
        exact h.1
    have hka : j / 4 < (a.data.take (a.len / 4)).length := by
      rw [List.length_take]
      have : a.len / 4 ≤ a.data.length := by omega
      omega
    have hkb : j / 4 < (b.data.take (a.len / 4)).length := by
      rw [List.length_take]
      have : a.len / 4 ≤ b.data.length := by omega
      omega
    have hwire := eqWires_sound _ _ hfull (j / 4) hka hkb
    have hta : (a.data.take (a.len / 4)).getD (j / 4) 0 = a.data.getD (j / 4) 0 := by
      rw [List.getD_eq_getElem?_getD, List.getD_eq_getElem?_getD,
        List.getElem?_take, if_pos hw]
    have htb : (b.data.take (a.len / 4)).getD (j / 4) 0 = b.data.getD (j / 4) 0 := by
      rw [List.getD_eq_getElem?_getD, List.getD_eq_getElem?_getD,
        List.getElem?_take, if_pos hw]
    rw [hta, htb] at hwire
    exact eq_wire_lanes hwire _ hc4
  · -- The partial last wire; `j`'s coordinate is below `len % 4`.
    have hwlast : j / 4 = a.len / 4 := by omega
    have hr0 : a.len % 4 ≠ 0 := by omega
    have hcr : j % 4 < a.len % 4 := by omega
    unfold simdEq at h
    rw [if_neg hr0, allHold_append, allHold_cons, allHold_cons, allHold_cons,
      allHold_cons] at h
    obtain ⟨-, hsub, hconst, hpmul, heq, -⟩ := h
    simp only [Holds] at hsub hconst hpmul heq
    have hr1 : 1 ≤ a.len % 4 := by omega
    have hr3 : a.len % 4 ≤ 3 := by omega
    have hmasked : pmulQ (ρ (a.data.getD (a.len / 4) 0) - ρ (b.data.getD (a.len / 4) 0))
        (firstOnes (a.len % 4)) = 0 := by
      rw [← hsub, ← hconst, ← hpmul, heq, hzero]
    have := eq_masked_lanes hr1 hr3 hmasked (j % 4) hcr
    unfold SimdReg.lane
    rw [hwlast]
    exact this

/-! ### Lengths and lane-level corollaries -/

theorem lanewise2_length (g : ℕ → ℕ → ℕ → Op) :
    ∀ (as bs : List ℕ) (n : ℕ),
      (lanewise2 g as bs n).res.length = min as.length bs.length := by
  intro as
  induction as with
  | nil => intro bs n; cases bs <;> simp [lanewise2]
  | cons a as ih =>
    intro bs n
    cases bs with
    | nil => simp [lanewise2]
    | cons b bs =>
      show (lanewise2 g as bs (n + 1)).res.length + 1 = _
      rw [ih bs (n + 1), List.length_cons, List.length_cons]
      omega

/-- Wires-cover-lanes invariant: `len ≤ 4 · #wires` (`⌈len/4⌉` wires). -/
def SimdReg.Covers (a : SimdReg) : Prop := a.len ≤ 4 * a.data.length

theorem simdSub_covers {a b : SimdReg} {n : ℕ} (ha : a.Covers)
    (hb : a.len ≤ 4 * b.data.length) : (simdSub a b n).res.Covers := by
  show a.len ≤ 4 * (lanewise2 Op.sub a.data b.data n).res.length
  rw [lanewise2_length]
  have h1 : a.len ≤ 4 * a.data.length := ha
  omega

theorem simdMul_covers {a b : SimdReg} {n : ℕ} (ha : a.Covers)
    (hb : a.len ≤ 4 * b.data.length) : (simdMul a b n).res.Covers := by
  show a.len ≤ 4 * (lanewise2 Op.pmul a.data b.data n).res.length
  rw [lanewise2_length]
  have h1 : a.len ≤ 4 * a.data.length := ha
  omega

theorem simdScalarMul_covers {a : SimdReg} {s n : ℕ} (ha : a.Covers) :
    (simdScalarMul a s n).res.Covers := by
  show a.len ≤ 4 * (lanewise2 (fun o x y => Op.mul o x y) a.data
    (a.data.map fun _ => s) n).res.length
  rw [lanewise2_length, List.length_map]
  have h1 : a.len ≤ 4 * a.data.length := ha
  omega

/-- Lane-level `sub`. -/
theorem simdSub_lane {ρ : ℕ → QM31} {a b : SimdReg} {n : ℕ}
    (ha : a.Covers) (hb : a.len ≤ 4 * b.data.length)
    (h : AllHold ρ (simdSub a b n).ops) (j : ℕ) (hj : j < a.len) :
    SimdReg.lane ρ (simdSub a b n).res j
      = SimdReg.lane ρ a j - SimdReg.lane ρ b j := by
  have hc4 : j % 4 < 4 := Nat.mod_lt _ (by norm_num)
  have hk : j / 4 < (simdSub a b n).res.data.length := by
    show j / 4 < (lanewise2 Op.sub a.data b.data n).res.length
    rw [lanewise2_length]
    unfold SimdReg.Covers at ha
    omega
  have := simdSub_wire h (j / 4) hk
  unfold SimdReg.lane
  rw [this, coord_sub _ _ _ hc4]

/-- Lane-level lane-wise `mul`. -/
theorem simdMul_lane {ρ : ℕ → QM31} {a b : SimdReg} {n : ℕ}
    (ha : a.Covers) (hb : a.len ≤ 4 * b.data.length)
    (h : AllHold ρ (simdMul a b n).ops) (j : ℕ) (hj : j < a.len) :
    SimdReg.lane ρ (simdMul a b n).res j
      = SimdReg.lane ρ a j * SimdReg.lane ρ b j := by
  have hc4 : j % 4 < 4 := Nat.mod_lt _ (by norm_num)
  have hk : j / 4 < (simdMul a b n).res.data.length := by
    show j / 4 < (lanewise2 Op.pmul a.data b.data n).res.length
    rw [lanewise2_length]
    unfold SimdReg.Covers at ha
    omega
  have := simdMul_wire h (j / 4) hk
  unfold SimdReg.lane
  rw [this, coord_pmul _ _ _ hc4]

/-- Lane-level scalar `mul` by a base-pinned wire. -/
theorem simdScalarMul_lane {ρ : ℕ → QM31} {a : SimdReg} {s n : ℕ} {v : F}
    (ha : a.Covers) (hs : ρ s = QM31.fromBase v)
    (h : AllHold ρ (simdScalarMul a s n).ops) (j : ℕ) (hj : j < a.len) :
    SimdReg.lane ρ (simdScalarMul a s n).res j = v * SimdReg.lane ρ a j := by
  have hc4 : j % 4 < 4 := Nat.mod_lt _ (by norm_num)
  have hklen : j / 4 < a.data.length := by
    unfold SimdReg.Covers at ha; omega
  have hk : j / 4 < (simdScalarMul a s n).res.data.length := by
    show j / 4 < (lanewise2 (fun o x y => Op.mul o x y) a.data
      (a.data.map fun _ => s) n).res.length
    rw [lanewise2_length, List.length_map]
    omega
  have hwire := simdScalarMul_wire h (j / 4) hk hklen
  unfold SimdReg.lane
  rw [hwire, hs, mul_comm, coord_mul_base _ _ _ hc4]

/-! ### `assert_bits` and `guess_lsb` -/

/-- `assert_bits`: `a ⊙ a` then `Simd::eq a (a ⊙ a)`. -/
def assertBits (zero : ℕ) (a : SimdReg) (n : ℕ) : Out Unit :=
  let sq := simdMul a a n
  let eqo := simdEq zero a sq.res sq.next
  ⟨sq.ops ++ eqo.ops, (), eqo.next⟩

theorem assertBits_sound {ρ : ℕ → QM31} {zero : ℕ} {a : SimdReg} {n : ℕ}
    (hzero : ρ zero = 0) (ha : a.Covers)
    (h : AllHold ρ (assertBits zero a n).ops) (j : ℕ) (hj : j < a.len) :
    SimdReg.lane ρ a j = 0 ∨ SimdReg.lane ρ a j = 1 := by
  unfold assertBits at h
  rw [allHold_append] at h
  obtain ⟨hmul, heq⟩ := h
  have hsq : (simdMul a a n).res.Covers := simdMul_covers ha (by
    unfold SimdReg.Covers at ha; omega)
  have hlen : a.len = (simdMul a a n).res.len := rfl
  have heqs := simdEq_sound hzero (by exact ha) (by
    have := hsq
    unfold SimdReg.Covers at this
    omega) heq j hj
  have hm := simdMul_lane ha (by unfold SimdReg.Covers at ha; omega) hmul j hj
  rw [hm] at heqs
  -- `x = x·x` means `x` is a bit.
  have : SimdReg.lane ρ a j * SimdReg.lane ρ a j = SimdReg.lane ρ a j := heqs.symm
  have h0 : SimdReg.lane ρ a j * (SimdReg.lane ρ a j - 1) = 0 := by
    linear_combination this
  rcases mul_eq_zero.mp h0 with h | h
  · exact Or.inl h
  · exact Or.inr (by linear_combination h)

/-- Fresh guess wires for `⌈len/4⌉` wires. -/
def guessWires (count len n : ℕ) : Out SimdReg :=
  ⟨(List.range count).map fun i => .guess (n + i),
   ⟨(List.range count).map fun i => n + i, len⟩, n + count⟩

theorem guessWires_covers {count len n : ℕ} (h : len ≤ 4 * count) :
    (guessWires count len n).res.Covers := by
  unfold SimdReg.Covers guessWires
  simpa using h

/-- `guess_lsb`: fresh guesses constrained to bits. -/
def guessLsb (zero : ℕ) (a : SimdReg) (n : ℕ) : Out SimdReg :=
  let g := guessWires a.data.length a.len n
  let ab := assertBits zero g.res g.next
  ⟨g.ops ++ ab.ops, g.res, ab.next⟩

theorem guessLsb_covers {zero : ℕ} {a : SimdReg} {n : ℕ} (ha : a.Covers) :
    (guessLsb zero a n).res.Covers :=
  guessWires_covers (by unfold SimdReg.Covers at ha; exact ha)

theorem guessLsb_len {zero : ℕ} {a : SimdReg} {n : ℕ} :
    (guessLsb zero a n).res.len = a.len := rfl

theorem guessLsb_sound {ρ : ℕ → QM31} {zero : ℕ} {a : SimdReg} {n : ℕ}
    (hzero : ρ zero = 0) (ha : a.Covers)
    (h : AllHold ρ (guessLsb zero a n).ops) (j : ℕ) (hj : j < a.len) :
    SimdReg.lane ρ (guessLsb zero a n).res j = 0 ∨
      SimdReg.lane ρ (guessLsb zero a n).res j = 1 := by
  unfold guessLsb at h
  rw [allHold_append] at h
  exact assertBits_sound hzero (guessLsb_covers ha) h.2 j hj

/-! ### The `extract_bits` rounds

Each round guesses the LSB (constrained to bits), subtracts it and halves
by the interned `2⁻¹` constant wire. `rounds_sound` is the gadget-level
counterpart of `BitDecomp.decomp_sound`: the input lane is the bit
polynomial of the produced lanes plus `2^k` times the residue. -/

def dummySimd : SimdReg := ⟨[], 0⟩

/-- `k` extraction rounds from `value`. Returns the LSB vectors in round
order and the final residue. -/
def rounds (zero invTwo : ℕ) : SimdReg → Nat → ℕ → Out (List SimdReg × SimdReg)
  | value, 0, n => ⟨[], ([], value), n⟩
  | value, k + 1, n =>
    let lsb := guessLsb zero value n
    let sub := simdSub value lsb.res lsb.next
    let half := simdScalarMul sub.res invTwo sub.next
    let rest := rounds zero invTwo half.res k half.next
    ⟨lsb.ops ++ (sub.ops ++ (half.ops ++ rest.ops)),
     (lsb.res :: rest.res.1, rest.res.2), rest.next⟩

theorem rounds_head_data {zero invTwo : ℕ} {value : SimdReg} {k n : ℕ}
    (hk : 0 < k) :
    ((rounds zero invTwo value k n).res.1.getD 0 dummySimd).data.length
      = value.data.length := by
  cases k with
  | zero => omega
  | succ k => simp [rounds, guessLsb, guessWires]

theorem rounds_sound {ρ : ℕ → QM31} {zero invTwo : ℕ}
    (hzero : ρ zero = 0) (hinv : ρ invTwo = QM31.fromBase (2 : F)⁻¹) :
    ∀ (k : Nat) (value : SimdReg) (n : ℕ), value.Covers →
      AllHold ρ (rounds zero invTwo value k n).ops →
      (rounds zero invTwo value k n).res.1.length = k ∧
      (rounds zero invTwo value k n).res.2.Covers ∧
      (rounds zero invTwo value k n).res.2.len = value.len ∧
      ∀ j, j < value.len →
        (∀ i, i < k →
          SimdReg.lane ρ ((rounds zero invTwo value k n).res.1.getD i dummySimd) j = 0 ∨
          SimdReg.lane ρ ((rounds zero invTwo value k n).res.1.getD i dummySimd) j = 1) ∧
        SimdReg.lane ρ value j =
          (∑ i ∈ Finset.range k,
            SimdReg.lane ρ ((rounds zero invTwo value k n).res.1.getD i dummySimd) j * 2 ^ i)
          + 2 ^ k * SimdReg.lane ρ (rounds zero invTwo value k n).res.2 j := by
  intro k
  induction k with
  | zero =>
    intro value n hcov _
    refine ⟨rfl, hcov, rfl, fun j hj => ⟨fun i hi => by omega, ?_⟩⟩
    simp [rounds]
  | succ k ih =>
    intro value n hcov h
    rw [show (rounds zero invTwo value (k + 1) n).ops =
      (guessLsb zero value n).ops ++
        ((simdSub value (guessLsb zero value n).res (guessLsb zero value n).next).ops ++
          (((simdScalarMul (simdSub value (guessLsb zero value n).res
              (guessLsb zero value n).next).res invTwo
              (simdSub value (guessLsb zero value n).res (guessLsb zero value n).next).next).ops) ++
            (rounds zero invTwo
              (simdScalarMul (simdSub value (guessLsb zero value n).res
                (guessLsb zero value n).next).res invTwo
                (simdSub value (guessLsb zero value n).res (guessLsb zero value n).next).next).res
              k
              (simdScalarMul (simdSub value (guessLsb zero value n).res
                (guessLsb zero value n).next).res invTwo
                (simdSub value (guessLsb zero value n).res (guessLsb zero value n).next).next).next).ops))
        from rfl, allHold_append, allHold_append, allHold_append] at h
    obtain ⟨hlsb, hsub, hhalf, hrest⟩ := h
    -- Shapes.
    set lsb := guessLsb zero value n with hlsbdef
    set sub := simdSub value lsb.res lsb.next with hsubdef
    set half := simdScalarMul sub.res invTwo sub.next with hhalfdef
    have hlsbcov : lsb.res.Covers := guessLsb_covers hcov
    have hlsblen : lsb.res.len = value.len := rfl
    have hlsbdata : lsb.res.data.length = value.data.length := by
      simp [hlsbdef, guessLsb, guessWires]
    have hsubcov : sub.res.Covers := simdSub_covers hcov (by
      rw [hlsbdata]; exact hcov)
    have hsublen : sub.res.len = value.len := rfl
    have hhalfcov : half.res.Covers := simdScalarMul_covers hsubcov
    have hhalflen : half.res.len = value.len := rfl
    have ihr := ih half.res half.next hhalfcov hrest
    obtain ⟨ihlen, ihcov, ihfinlen, ihlane⟩ := ihr
    refine ⟨by simp [rounds, ← hlsbdef, ← hsubdef, ← hhalfdef, ihlen], ?_, ?_, ?_⟩
    · exact ihcov
    · rw [show (rounds zero invTwo value (k + 1) n).res.2
        = (rounds zero invTwo half.res k half.next).res.2 from rfl, ihfinlen, hhalflen]
    intro j hj
    have hjh : j < half.res.len := by rw [hhalflen]; exact hj
    obtain ⟨ihbits, ihsum⟩ := ihlane j hjh
    have hlsbbit := guessLsb_sound hzero hcov hlsb j hj
    have hsublane := simdSub_lane hcov (by rw [hlsbdata]; exact hcov) hsub j hj
    have hhalflane := simdScalarMul_lane hsubcov hinv hhalf j (by
      rw [hsublen]; exact hj)
    -- `value = lsb + 2 · half` on lane `j`.
    have htwo : (2 : F) * (2 : F)⁻¹ = 1 := mul_inv_cancel₀ StwoVerifier.BitDecomp.two_ne_zero
    have hvalue : SimdReg.lane ρ value j =
        SimdReg.lane ρ lsb.res j + 2 * SimdReg.lane ρ half.res j := by
      rw [hhalflane, hsublane]
      have expand : (2 : F) * ((2 : F)⁻¹ * (SimdReg.lane ρ value j - SimdReg.lane ρ lsb.res j))
          = (2 * (2 : F)⁻¹) * (SimdReg.lane ρ value j - SimdReg.lane ρ lsb.res j) := by ring
      rw [expand, htwo]
      ring
    have hbitslist : (rounds zero invTwo value (k + 1) n).res.1
        = lsb.res :: (rounds zero invTwo half.res k half.next).res.1 := rfl
    have hfin : (rounds zero invTwo value (k + 1) n).res.2
        = (rounds zero invTwo half.res k half.next).res.2 := rfl
    constructor
    · intro i hi
      rw [hbitslist]
      cases i with
      | zero => simpa using hlsbbit
      | succ i => simpa using ihbits i (by omega)
    · rw [hbitslist, hfin, Finset.sum_range_succ'
        (fun i => SimdReg.lane ρ ((lsb.res ::
          (rounds zero invTwo half.res k half.next).res.1).getD i dummySimd) j * 2 ^ i) k]
      simp only [List.getD_cons_succ, List.getD_cons_zero, pow_zero, mul_one, pow_succ]
      have hsum2 : (2 : F) * (∑ i ∈ Finset.range k,
          SimdReg.lane ρ ((rounds zero invTwo half.res k half.next).res.1.getD i dummySimd) j * 2 ^ i)
          = ∑ i ∈ Finset.range k,
            SimdReg.lane ρ ((rounds zero invTwo half.res k half.next).res.1.getD i dummySimd) j
              * (2 ^ i * 2) := by
        rw [Finset.mul_sum]
        exact Finset.sum_congr rfl fun i _ => by ring
      rw [hvalue, ihsum, mul_add, hsum2]
      ring

/-! ### `extract_bits` at 31 bits, with `validate_extract_bits` -/

/-- A constant-splat SIMD vector: one `const` wire replicated. -/
def constSplat (v : F) (count len n : ℕ) : Out SimdReg :=
  ⟨[.const n (splat v)], ⟨List.replicate count n, len⟩, n + 1⟩

theorem constSplat_lane {ρ : ℕ → QM31} {v : F} {count len n : ℕ}
    (h : AllHold ρ (constSplat v count len n).ops) (j : ℕ)
    (hj : j / 4 < count) :
    SimdReg.lane ρ (constSplat v count len n).res j = v := by
  have hc := h _ (List.mem_cons_self ..)
  simp only [Holds] at hc
  unfold SimdReg.lane
  have hget : (List.replicate count n).getD (j / 4) 0 = n := by
    rw [List.getD_eq_getElem?_getD, List.getElem?_replicate, if_pos hj]
    rfl
  show coord (ρ ((List.replicate count n).getD (j / 4) 0)) (j % 4) = v
  rw [hget, hc]
  exact coord_splat v _ (Nat.mod_lt _ (by norm_num))

theorem constSplat_covers {v : F} {count len n : ℕ} (h : len ≤ 4 * count) :
    (constSplat v count len n).res.Covers := by
  show len ≤ 4 * (List.replicate count n).length
  simpa using h

/-- `extract_bits(input, 31)` plus `validate_extract_bits`: 30 LSB rounds,
the top bit asserted, and the canonicity constraint
`(input·aux − 1)·bits₀ = 0`. The interned `2⁻¹` constant is emitted first. -/
def extractBits31 (zero : ℕ) (input : SimdReg) (n : ℕ) : Out (List SimdReg) :=
  let invTwo := n
  let r := rounds zero invTwo input 30 (n + 1)
  let ab := assertBits zero r.res.2 r.next
  -- validate_extract_bits
  let zeroS := constSplat 0 input.data.length input.len ab.next
  let oneS := constSplat 1 input.data.length input.len zeroS.next
  let aux := guessWires input.data.length input.len oneS.next
  let prod := simdMul input aux.res aux.next
  let shifted := simdSub prod.res oneS.res prod.next
  let lsb0 := r.res.1.getD 0 dummySimd
  let constr := simdMul shifted.res lsb0 shifted.next
  let eqz := simdEq zero constr.res zeroS.res constr.next
  ⟨.const invTwo (QM31.fromBase (2 : F)⁻¹) ::
    (r.ops ++ ab.ops ++ zeroS.ops ++ oneS.ops ++ aux.ops ++ prod.ops ++
      shifted.ops ++ constr.ops ++ eqz.ops),
   r.res.1 ++ [r.res.2], eqz.next⟩

/-- **Soundness of 31-bit extraction** (per lane): the 31 output lanes are
bits, and they are **the** binary digits of the input lane's canonical
value. This is the canonicity statement query selection consumes, and the
answer to the brief's open question 1 for this hint. -/
theorem extractBits31_sound {ρ : ℕ → QM31} {zero : ℕ} {input : SimdReg} {n : ℕ}
    (hzero : ρ zero = 0) (hcov : input.Covers)
    (h : AllHold ρ (extractBits31 zero input n).ops) (j : ℕ) (hj : j < input.len) :
    (∀ i, i < 31 →
      SimdReg.lane ρ ((extractBits31 zero input n).res.getD i dummySimd) j = 0 ∨
      SimdReg.lane ρ ((extractBits31 zero input n).res.getD i dummySimd) j = 1) ∧
    BitDecomp.natOf
      (fun i => SimdReg.lane ρ ((extractBits31 zero input n).res.getD i dummySimd) j) 31
      = (SimdReg.lane ρ input j).val := by
  -- Unpack the op list.
  rw [show (extractBits31 zero input n).ops =
    .const n (QM31.fromBase (2 : F)⁻¹) :: _ from rfl, allHold_cons] at h
  obtain ⟨hinv', h⟩ := h
  simp only [Holds] at hinv'
  rw [allHold_append, allHold_append, allHold_append, allHold_append,
    allHold_append, allHold_append, allHold_append, allHold_append] at h
  obtain ⟨⟨⟨⟨⟨⟨⟨⟨hr, hab⟩, hzeroS⟩, honeS⟩, _haux⟩, hprod⟩, hshift⟩, hconstr⟩, heqz⟩ := h
  set invTwo := n with hinvdef
  set r := rounds zero invTwo input 30 (n + 1) with hrdef
  obtain ⟨hrlen, hrcov, hrfinlen, hrlane⟩ :=
    rounds_sound hzero hinv' 30 input (n + 1) hcov hr
  obtain ⟨hbitslow, hsumlow⟩ := hrlane j hj
  -- The top bit.
  have htop := assertBits_sound hzero hrcov hab j (by rw [hrfinlen]; exact hj)
  -- The produced bit list.
  have hreslist : (extractBits31 zero input n).res = r.res.1 ++ [r.res.2] := rfl
  have hlistlen : r.res.1.length = 30 := hrlen
  have hgetlow : ∀ i, i < 30 →
      (r.res.1 ++ [r.res.2]).getD i dummySimd = r.res.1.getD i dummySimd := by
    intro i hi
    rw [List.getD_eq_getElem?_getD, List.getD_eq_getElem?_getD,
      List.getElem?_append_left (by omega)]
  have hgettop : (r.res.1 ++ [r.res.2]).getD 30 dummySimd = r.res.2 := by
    rw [List.getD_eq_getElem?_getD, List.getElem?_append_right (by omega)]
    simp [hlistlen]
  have hbits : ∀ i, i < 31 →
      SimdReg.lane ρ ((r.res.1 ++ [r.res.2]).getD i dummySimd) j = 0 ∨
      SimdReg.lane ρ ((r.res.1 ++ [r.res.2]).getD i dummySimd) j = 1 := by
    intro i hi
    by_cases h30 : i = 30
    · rw [h30, hgettop]; exact htop
    · rw [hgetlow i (by omega)]; exact hbitslow i (by omega)
  -- The sum over all 31 bits.
  have hsum : SimdReg.lane ρ input j = ∑ i ∈ Finset.range 31,
      SimdReg.lane ρ ((r.res.1 ++ [r.res.2]).getD i dummySimd) j * 2 ^ i := by
    rw [Finset.sum_range_succ, hgettop,
      Finset.sum_congr rfl (fun i hi => by
        rw [hgetlow i (Finset.mem_range.mp hi)]), hsumlow]
    ring
  -- The canonicity constraint.
  have hzerocase : SimdReg.lane ρ input j = 0 →
      SimdReg.lane ρ ((r.res.1 ++ [r.res.2]).getD 0 dummySimd) j = 0 := by
    intro hin0
    set zeroS := constSplat 0 input.data.length input.len
      (assertBits zero r.res.2 r.next).next with hzsdef
    set oneS := constSplat 1 input.data.length input.len zeroS.next with hosdef
    set aux := guessWires input.data.length input.len oneS.next with hauxdef
    set prod := simdMul input aux.res aux.next with hproddef
    set shifted := simdSub prod.res oneS.res prod.next with hshiftdef
    set lsb0 := r.res.1.getD 0 dummySimd with hlsb0def
    set constr := simdMul shifted.res lsb0 shifted.next with hconstrdef
    -- Shape facts.
    have hwires4 : input.len ≤ 4 * input.data.length := hcov
    have hauxdata : aux.res.data.length = input.data.length := by
      simp [hauxdef, guessWires]
    have hprodcov : prod.res.Covers := simdMul_covers hcov (by
      rw [hauxdata]; exact hwires4)
    have honedata : oneS.res.data.length = input.data.length := by
      simp [hosdef, constSplat]
    have hshiftcov : shifted.res.Covers := simdSub_covers hprodcov (by
      show prod.res.len ≤ 4 * oneS.res.data.length
      rw [honedata]; exact hwires4)
    have hlsb0data : lsb0.data.length = input.data.length := by
      rw [hlsb0def]
      exact rounds_head_data (by norm_num)
    have hconstrcov : constr.res.Covers := simdMul_covers hshiftcov (by
      show shifted.res.len ≤ 4 * lsb0.data.length
      rw [hlsb0data]; exact hwires4)
    have hzerodata : zeroS.res.data.length = input.data.length := by
      simp [hzsdef, constSplat]
    -- Lane values through the chain.
    have hj4 : j / 4 < input.data.length := by
      unfold SimdReg.Covers at hcov; omega
    have honelane : SimdReg.lane ρ oneS.res j = 1 := constSplat_lane honeS j hj4
    have hzerolane : SimdReg.lane ρ zeroS.res j = 0 := constSplat_lane hzeroS j hj4
    have hprodlane := simdMul_lane hcov (by rw [hauxdata]; exact hwires4) hprod j hj
    have hshiftlane := simdSub_lane hprodcov (by
      show prod.res.len ≤ 4 * oneS.res.data.length
      rw [honedata]; exact hwires4) hshift j hj
    have hconstrlane := simdMul_lane hshiftcov (by
      show shifted.res.len ≤ 4 * lsb0.data.length
      rw [hlsb0data]; exact hwires4) hconstr j hj
    have heqlane := simdEq_sound hzero hconstrcov (by
      show constr.res.len ≤ 4 * zeroS.res.data.length
      rw [hzerodata]; exact hwires4) heqz j hj
    -- `(input·aux − 1)·lsb₀ = 0`, with `input = 0`.
    rw [hconstrlane, hshiftlane, hprodlane, hin0, hzerolane, honelane] at heqlane
    have : (0 * SimdReg.lane ρ aux.res j - 1) * SimdReg.lane ρ lsb0 j = 0 := heqlane
    have hlsb0 : SimdReg.lane ρ lsb0 j = 0 := by
      have h1 : (-1 : F) * SimdReg.lane ρ lsb0 j = 0 := by linear_combination this
      linear_combination -h1
    rw [hgetlow 0 (by omega)]
    exact hlsb0
  refine ⟨by rw [hreslist] at *; exact hbits, ?_⟩
  rw [hreslist]
  exact BitDecomp.canonical_31 _ _ hbits hsum hzerocase

end StwoVerifier.Gadgets
