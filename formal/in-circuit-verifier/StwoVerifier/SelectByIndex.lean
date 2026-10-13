/-
**The wire multiplexer** (`src/frontends/circuit/builder/select.zig`
`select_by_index`, stwo-zig `4afa09dbf`): a layered 2-to-1 mux tree over
`2^n` wires driven by `n` bit wires, least significant first. Used by
`validate_query_position_in_coset` in the FRI decommit to pin each query
value to the witness coset slot its position bits select.

`selectByIndexG_sound`: with the bits boolean, the output register holds
the input register at the bits' binary index.
-/
import StwoVerifier.Gates
import StwoVerifier.Algebra

namespace StwoVerifier.Gadgets

open StwoVerifier StwoVerifier.Gates

theorem qone_ne_zero : (1 : QM31) ≠ 0 := by
  intro h
  have h0 : (1 : QM31).c0 = (0 : QM31).c0 := congrArg QM31.c0 h
  have h1 : (1 : F) = 0 := congrArg CM31.a h0
  exact absurd h1 (by norm_num)

/-- One mux layer: for each pair, `(1−b)·left + b·right`. -/
def muxLayer (oneMinus bit : ℕ) : List ℕ → ℕ → Out (List ℕ)
  | v0 :: v1 :: rest, n =>
    let tail := muxLayer oneMinus bit rest (n + 3)
    ⟨.mul n oneMinus v0 :: .mul (n + 1) bit v1 :: .add (n + 2) n (n + 1) ::
      tail.ops, (n + 2) :: tail.res, tail.next⟩
  | _, n => ⟨[], [], n⟩

theorem muxLayer_length (oneMinus bit : ℕ) :
    ∀ (vs : List ℕ) (n : ℕ),
      (muxLayer oneMinus bit vs n).res.length = vs.length / 2 := by
  intro vs n
  induction vs, n using muxLayer.induct oneMinus bit with
  | case1 v0 v1 rest n ih =>
    show (muxLayer oneMinus bit rest (n + 3)).res.length + 1 = _
    rw [ih]
    simp only [List.length_cons]
    omega
  | case2 vs n h =>
    match vs, h with
    | [], _ => rfl
    | [v], _ => simp [muxLayer]
    | v0 :: v1 :: rest, h => exact absurd rfl (h v0 v1 rest)

/-- Layer soundness: entry `k` holds the bit-selected half of pair `k`. -/
theorem muxLayer_sound {ρ : ℕ → QM31} {oneMinus bit : ℕ}
    (hbit : ρ bit = 0 ∨ ρ bit = 1) (hom : ρ oneMinus = 1 - ρ bit) :
    ∀ (vs : List ℕ) (n : ℕ), AllHold ρ (muxLayer oneMinus bit vs n).ops →
      ∀ k, 2 * k + 1 < vs.length →
        ρ ((muxLayer oneMinus bit vs n).res.getD k 0)
          = if ρ bit = 0 then ρ (vs.getD (2 * k) 0) else ρ (vs.getD (2 * k + 1) 0) := by
  intro vs n
  induction vs, n using muxLayer.induct oneMinus bit with
  | case1 v0 v1 rest n ih =>
    intro h k hk
    rw [show (muxLayer oneMinus bit (v0 :: v1 :: rest) n).ops =
      .mul n oneMinus v0 :: .mul (n + 1) bit v1 :: .add (n + 2) n (n + 1) ::
        (muxLayer oneMinus bit rest (n + 3)).ops from rfl,
      allHold_cons, allHold_cons, allHold_cons] at h
    obtain ⟨h1, h2, h3, hrest⟩ := h
    simp only [Holds] at h1 h2 h3
    cases k with
    | zero =>
      show ρ (n + 2) = _
      rcases hbit with hb | hb
      · rw [if_pos hb, h3, h1, h2, hom, hb]
        simp
      · rw [if_neg (by rw [hb]; exact qone_ne_zero), h3, h1, h2, hom, hb]
        simp
    | succ k =>
      have hk' : 2 * k + 1 < rest.length := by
        simp only [List.length_cons] at hk
        omega
      have hrec := ih hrest k hk'
      show ρ ((muxLayer oneMinus bit rest (n + 3)).res.getD k 0) = _
      rw [hrec]
      have hL : (v0 :: v1 :: rest).getD (2 * (k + 1)) 0 = rest.getD (2 * k) 0 := by
        rw [show 2 * (k + 1) = 2 * k + 1 + 1 from by omega]
        simp [List.getD_cons_succ]
      have hR : (v0 :: v1 :: rest).getD (2 * (k + 1) + 1) 0
          = rest.getD (2 * k + 1) 0 := by
        rw [show 2 * (k + 1) + 1 = (2 * k + 1 + 1) + 1 from by omega]
        simp [List.getD_cons_succ]
      rw [hL, hR]
  | case2 vs n hshape =>
    intro _ k hk
    match vs, hshape with
    | [], _ => simp at hk
    | [v], _ => simp at hk
    | v0 :: v1 :: rest, hshape => exact absurd rfl (hshape v0 v1 rest)

/-- `select_by_index`: one `1 − bit` wire per level, then the mux layers. -/
def selectByIndexG (one : ℕ) : List ℕ → List ℕ → ℕ → Out ℕ
  | values, [], n => ⟨[], values.headD 0, n⟩
  | values, bit :: bits, n =>
    let layer := muxLayer n bit values (n + 1)
    let rest := selectByIndexG one layer.res bits layer.next
    ⟨.sub n one bit :: (layer.ops ++ rest.ops), rest.res, rest.next⟩

/-- The binary index of a bit assignment, least significant first. -/
def idxOf (ρ : ℕ → QM31) : List ℕ → ℕ
  | [] => 0
  | b :: bs => (if ρ b = 0 then 0 else 1) + 2 * idxOf ρ bs

theorem idxOf_lt (ρ : ℕ → QM31) : ∀ bits : List ℕ, idxOf ρ bits < 2 ^ bits.length
  | [] => by simp [idxOf]
  | b :: bs => by
    have := idxOf_lt ρ bs
    unfold idxOf
    simp only [List.length_cons, pow_succ]
    by_cases hb : ρ b = 0 <;> simp [hb] <;> omega

theorem selectByIndexG_sound {ρ : ℕ → QM31} {one : ℕ} (hone : ρ one = 1) :
    ∀ (bits values : List ℕ) (n : ℕ),
      values.length = 2 ^ bits.length →
      (∀ b ∈ bits, ρ b = 0 ∨ ρ b = 1) →
      AllHold ρ (selectByIndexG one values bits n).ops →
      ρ (selectByIndexG one values bits n).res
        = ρ (values.getD (idxOf ρ bits) 0) := by
  intro bits
  induction bits with
  | nil =>
    intro values n hlen _ _
    match values, hlen with
    | [v], _ =>
      show ρ v = _
      rfl
  | cons bit bits ih =>
    intro values n hlen hbits h
    rw [show (selectByIndexG one values (bit :: bits) n).ops =
      .sub n one bit :: ((muxLayer n bit values (n + 1)).ops ++
        (selectByIndexG one (muxLayer n bit values (n + 1)).res bits
          (muxLayer n bit values (n + 1)).next).ops) from rfl,
      allHold_cons, allHold_append] at h
    obtain ⟨hsub, hlayer, hrest⟩ := h
    simp only [Holds] at hsub
    have hbit := hbits bit List.mem_cons_self
    have hom : ρ n = 1 - ρ bit := by rw [hsub, hone]
    have hlaylen : (muxLayer n bit values (n + 1)).res.length
        = 2 ^ bits.length := by
      rw [muxLayer_length, hlen]
      simp only [List.length_cons]
      omega
    have hres := ih (muxLayer n bit values (n + 1)).res
      (muxLayer n bit values (n + 1)).next hlaylen
      (fun b hb => hbits b (List.mem_cons_of_mem _ hb)) hrest
    show ρ (selectByIndexG one (muxLayer n bit values (n + 1)).res bits
      (muxLayer n bit values (n + 1)).next).res = _
    rw [hres]
    have hidxlt : idxOf ρ bits < 2 ^ bits.length := idxOf_lt ρ bits
    have hlane := muxLayer_sound hbit hom values (n + 1) hlayer (idxOf ρ bits)
      (by rw [hlen]; simp only [List.length_cons]; omega)
    rw [hlane]
    show _ = ρ (values.getD ((if ρ bit = 0 then 0 else 1) + 2 * idxOf ρ bits) 0)
    rcases hbit with hb | hb
    · rw [if_pos hb, if_pos hb,
        show (0 : ℕ) + 2 * idxOf ρ bits = 2 * idxOf ρ bits from by omega]
    · rw [if_neg (by rw [hb]; exact qone_ne_zero), if_neg (by rw [hb]; exact qone_ne_zero),
        show (1 : ℕ) + 2 * idxOf ρ bits = 2 * idxOf ρ bits + 1 from by omega]

/-- `validate_query_position_in_coset`, one query: the mux over the
witness coset, then an `eq` gate against the claimed layer value. -/
def validateQueryInCoset (one : ℕ) (coset : List ℕ) (bits : List ℕ)
    (layerValue n : ℕ) : Out Unit :=
  let sel := selectByIndexG one coset bits n
  ⟨sel.ops ++ [.eq layerValue sel.res], (), sel.next⟩

/-- The claimed layer value is the coset entry the query bits select. -/
theorem validateQueryInCoset_sound {ρ : ℕ → QM31} {one : ℕ}
    {coset bits : List ℕ} {layerValue n : ℕ} (hone : ρ one = 1)
    (hlen : coset.length = 2 ^ bits.length)
    (hbits : ∀ b ∈ bits, ρ b = 0 ∨ ρ b = 1)
    (h : AllHold ρ (validateQueryInCoset one coset bits layerValue n).ops) :
    ρ layerValue = ρ (coset.getD (idxOf ρ bits) 0) := by
  unfold validateQueryInCoset at h
  rw [allHold_append, allHold_cons] at h
  obtain ⟨hsel, heq, -⟩ := h
  simp only [Holds] at heq
  rw [heq]
  exact selectByIndexG_sound hone bits coset n hlen hbits hsel

end StwoVerifier.Gadgets
