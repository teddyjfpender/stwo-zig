/-
**`check_relation_uses`** (`stark_verifier/verify.zig`): no relation can
be used `P` times or more. Per relation, the circuit computes
`Σ over components (⌊2^log / 2^16⌋ + 1) · uses_per_row` from the
component-size bits (`combine_bits` of bits `16..`, plus one), packs the
per-relation sums into SIMD lanes and range-checks them to 15 bits.

`checkRelUsesG_sound`: with one-hot size bits at each component's log
size (what `extract_bits` of `2^log` gives), the gates force the spec's
`relationUsesOk`. The relation-id bookkeeping is the static table
`relationUsesPerRow`; `relationUsesOk_iff` evaluates the spec's
string-keyed totals into the explicit per-relation term lists `relTerms`
(the per-relation slot order is immaterial: every slot is range-checked).
-/
import StwoVerifier.StatementGadgets
import StwoVerifier.OodsResponses
import StwoVerifier.CircuitVerify

namespace StwoVerifier.Gadgets

open StwoVerifier StwoVerifier.Gates Finset CircuitVerify

/-! ### The static relation table -/

/-- Per relation (spec `eraseDups` order), its `(component, uses)` terms. -/
def relTerms : List (List (ℕ × ℕ)) :=
  [ [(0, 2), (1, 2), (2, 3), (3, 1), (4, 6)], [(2, 8), (4, 6)], [(3, 3)], [(4, 2)],
    [(4, 2)], [(4, 2)], [(4, 2)], [(4, 2)] ]

/-- The shifted row bound of one component. -/
def nOf (l : ℕ) : ℕ := 2 ^ l / 2 ^ 16 + 1

theorem ids_eq : (relationUsesPerRow.flatMap (·.map (·.1))).eraseDups =
    ["Gate", "VerifyBitwiseXor_8", "RangeCheck_16", "VerifyBitwiseXor_12",
     "VerifyBitwiseXor_4", "VerifyBitwiseXor_7", "VerifyBitwiseXor_8_B",
     "VerifyBitwiseXor_9"] := by decide

/-- The spec check, evaluated on the static table. -/
theorem relationUsesOk_iff (l0 l1 l2 l3 l4 l5 l6 l7 l8 l9 l10 : ℕ) :
    relationUsesOk [l0, l1, l2, l3, l4, l5, l6, l7, l8, l9, l10] = true ↔
    ∀ ts ∈ relTerms, (ts.map fun (iu : ℕ × ℕ) =>
      iu.2 * nOf ([l0, l1, l2, l3, l4, l5, l6, l7, l8, l9, l10].getD iu.1 0)).sum
        < 2 ^ 15 := by
  unfold relationUsesOk
  rw [ids_eq]
  simp [relationUsesPerRow, relTerms, nOf]

/-! ### `combine_bits` -/

/-- `combine_bits`: Horner from the top bit (`res·2 + bitᵢ`). -/
def combineG (two : ℕ) : List SimdReg → ℕ → Out SimdReg
  | [], n => ⟨[], dummySimd, n⟩
  | [b], n => ⟨[], b, n⟩
  | b :: b' :: bs, n =>
    let r := combineG two (b' :: bs) n
    let m := simdScalarMul r.res two r.next
    let a := simdAdd m.res b m.next
    ⟨r.ops ++ m.ops ++ a.ops, a.res, a.next⟩

theorem sum_cons_shift (f : SimdReg → F) (b : SimdReg) (bs : List SimdReg) :
    ∑ t ∈ range (b :: bs).length, f ((b :: bs).getD t dummySimd) * 2 ^ t
      = f b + 2 * ∑ t ∈ range bs.length, f (bs.getD t dummySimd) * 2 ^ t := by
  rw [List.length_cons, Finset.sum_range_succ', Finset.mul_sum]
  simp only [List.getD_cons_succ, List.getD_cons_zero, pow_zero, mul_one]
  rw [add_comm]
  congr 1
  refine Finset.sum_congr rfl fun t _ => ?_
  rw [pow_succ]
  ring

theorem combineG_sound {ρ : ℕ → QM31} {two count len : ℕ} (htwo : ρ two = QM31.fromBase 2)
    (hcl : len ≤ 4 * count) (j : ℕ) (hj : j < len) :
    ∀ (bits : List SimdReg) (n : ℕ), bits ≠ [] → (∀ b ∈ bits, BitShape b len count) →
      AllHold ρ (combineG two bits n).ops →
      (combineG two bits n).res.len = len ∧ (combineG two bits n).res.data.length = count ∧
      SimdReg.lane ρ (combineG two bits n).res j
        = ∑ t ∈ range bits.length, SimdReg.lane ρ (bits.getD t dummySimd) j * 2 ^ t := by
  intro bits
  induction bits with
  | nil => intro n hne; exact absurd rfl hne
  | cons b bs ih =>
    intro n _ hshape h
    have hb := hshape b List.mem_cons_self
    cases bs with
    | nil =>
      refine ⟨hb.lenEq, hb.dataEq, ?_⟩
      show SimdReg.lane ρ b j = _
      simp
    | cons b' bs =>
      set r := combineG two (b' :: bs) n with hrdef
      set m := simdScalarMul r.res two r.next with hmdef
      rw [show (combineG two (b :: b' :: bs) n).ops =
        r.ops ++ m.ops ++ (simdAdd m.res b m.next).ops from rfl,
        allHold_append, allHold_append] at h
      obtain ⟨⟨hr, hm⟩, ha⟩ := h
      obtain ⟨hrl, hrd, hrv⟩ := ih n (List.cons_ne_nil _ _)
        (fun b'' hb'' => hshape b'' (List.mem_cons_of_mem _ hb'')) hr
      have hrcov : r.res.Covers := by unfold SimdReg.Covers; rw [hrl, hrd]; exact hcl
      have hmcov : m.res.Covers := simdScalarMul_covers hrcov
      have hmlane := simdScalarMul_lane hrcov htwo hm j (by rw [hrl]; exact hj)
      have halane := simdAdd_lane hmcov (by
        show r.res.len ≤ 4 * b.data.length
        rw [hrl, hb.dataEq]; exact hcl) ha j (by show j < r.res.len; rw [hrl]; exact hj)
      have hmd : m.res.data.length = count := by
        show (lanewise2 (fun o x y => Op.mul o x y) r.res.data
          (r.res.data.map fun _ => two) r.next).res.length = count
        rw [lanewise2_length, List.length_map, hrd, Nat.min_self]
      refine ⟨by show r.res.len = len; exact hrl, ?_, ?_⟩
      · show (lanewise2 Op.add m.res.data b.data m.next).res.length = count
        rw [lanewise2_length, hmd, hb.dataEq, Nat.min_self]
      · show SimdReg.lane ρ (simdAdd m.res b m.next).res j = _
        rw [halane, hmlane, hrv]
        rw [sum_cons_shift (fun s => SimdReg.lane ρ s j) b (b' :: bs)]
        ring

/-! ### `simd.pack` -/

/-- One packed wire: `acc + e_j · lane_j` for the remaining lanes. -/
def packChunk (basis : ℕ) : ℕ → ℕ → List ℕ → ℕ → Out ℕ
  | acc, _, [], n => ⟨[], acc, n⟩
  | acc, j, l :: ls, n =>
    let r := packChunk basis (n + 1) (j + 1) ls (n + 2)
    ⟨[.mul n (basis + j) l, .add (n + 1) acc n] ++ r.ops, r.res, r.next⟩

/-- `pack`: the four basis constants, then one chunk per four lanes. -/
def packAll (basis : ℕ) : ℕ → List ℕ → ℕ → Out (List ℕ)
  | 0, _, n => ⟨[], [], n⟩
  | _, [], n => ⟨[], [], n⟩
  | f + 1, a :: rest, n =>
    let c := packChunk basis a 1 (rest.take 3) n
    let r := packAll basis f (rest.drop 3) c.next
    ⟨c.ops ++ r.ops, c.res :: r.res, r.next⟩

def packG (lanes : List ℕ) (n : ℕ) : Out SimdReg :=
  let p := packAll n lanes.length lanes (n + 4)
  ⟨(List.range 4).map (fun c => .const (n + c) (unitVec c)) ++ p.ops,
   ⟨p.res, lanes.length⟩, p.next⟩

theorem coord_unit_base (c c' : ℕ) (hc : c < 4) (hc' : c' < 4) (v : F) :
    coord (unitVec c * QM31.fromBase v) c' = if c' = c then v else 0 := by
  rw [mul_comm, coord_mul_base _ _ _ hc']
  interval_cases c <;> interval_cases c' <;> simp [unitVec, coord, QM31.fromM31s]

theorem packChunk_sound {ρ : ℕ → QM31} {basis : ℕ}
    (hbasis : ∀ c, c < 4 → ρ (basis + c) = unitVec c) :
    ∀ (ls : List ℕ) (acc j n : ℕ), j + ls.length ≤ 4 →
      AllHold ρ (packChunk basis acc j ls n).ops →
      ρ (packChunk basis acc j ls n).res
        = ρ acc + ∑ t ∈ range ls.length, unitVec (j + t) * ρ (ls.getD t 0) := by
  intro ls
  induction ls with
  | nil => intro acc j n _ _; simp [packChunk]
  | cons l ls ih =>
    intro acc j n hj h
    rw [show (packChunk basis acc j (l :: ls) n).ops =
      [.mul n (basis + j) l, .add (n + 1) acc n] ++
        (packChunk basis (n + 1) (j + 1) ls (n + 2)).ops from rfl,
      allHold_append] at h
    obtain ⟨h1, h2⟩ := h
    have hm : ρ n = ρ (basis + j) * ρ l := h1 _ List.mem_cons_self
    have ha : ρ (n + 1) = ρ acc + ρ n := h1 _ (List.mem_cons_of_mem _ List.mem_cons_self)
    have := ih (n + 1) (j + 1) (n + 2) (by simp at hj; omega) h2
    show ρ (packChunk basis (n + 1) (j + 1) ls (n + 2)).res = _
    rw [this, ha, hm, hbasis j (by simp at hj; omega), List.length_cons,
      Finset.sum_range_succ']
    simp only [List.getD_cons_succ, List.getD_cons_zero, Nat.add_zero]
    rw [Finset.sum_congr rfl (fun t _ => by rw [show j + 1 + t = j + (t + 1) by omega])]
    ring

theorem coord_sum_range (f : ℕ → QM31) (c : ℕ) (hc : c < 4) :
    ∀ m, coord (∑ t ∈ range m, f t) c = ∑ t ∈ range m, coord (f t) c
  | 0 => by simp [coord_zero c hc]
  | m + 1 => by
    rw [Finset.sum_range_succ, coord_add _ _ _ hc, coord_sum_range f c hc m,
      Finset.sum_range_succ]

/-- One chunk's coordinates are its lanes' values. -/
theorem chunk_coord {ρ : ℕ → QM31} {basis : ℕ}
    (hbasis : ∀ c, c < 4 → ρ (basis + c) = unitVec c) (v : ℕ → F)
    (chunk : List ℕ) (hlen : chunk.length ≤ 4) (hne : chunk ≠ [])
    (hv : ∀ t, t < chunk.length → ρ (chunk.getD t 0) = QM31.fromBase (v t)) (n : ℕ)
    (h : AllHold ρ (packChunk basis (chunk.getD 0 0) 1 chunk.tail n).ops)
    (c : ℕ) (hc : c < chunk.length) :
    coord (ρ (packChunk basis (chunk.getD 0 0) 1 chunk.tail n).res) c = v c := by
  have hc4 : c < 4 := by omega
  obtain ⟨a, rest, rfl⟩ := List.exists_cons_of_ne_nil hne
  simp only [List.getD_cons_zero, List.tail_cons] at h ⊢
  rw [packChunk_sound hbasis rest a 1 n (by simp at hlen ⊢; omega) h]
  rw [coord_add _ _ _ hc4, coord_sum_range _ c hc4]
  have ha := hv 0 (by simp)
  simp only [List.getD_cons_zero] at ha
  have hterm : ∀ t ∈ range rest.length, coord (unitVec (1 + t) * ρ (rest.getD t 0)) c
      = if c = 1 + t then v (1 + t) else 0 := by
    intro t ht
    have ht' := Finset.mem_range.mp ht
    have hvt := hv (t + 1) (by simp; omega)
    simp only [List.getD_cons_succ] at hvt
    rw [hvt, coord_unit_base (1 + t) c (by simp at hlen; omega) hc4,
      show t + 1 = 1 + t by omega]
  rw [Finset.sum_congr rfl hterm, ha]
  rcases c with _ | c
  · rw [Finset.sum_eq_zero (fun t _ => if_neg (by omega)), add_zero]
    rfl
  · have hc3 : c < 3 := by omega
    have hc0 : coord (QM31.fromBase (v 0)) (c + 1) = 0 := by
      interval_cases c <;> rfl
    rw [hc0, zero_add, Finset.sum_eq_single c (fun t _ ht => if_neg (by omega))
      (fun hn => absurd (Finset.mem_range.mpr (by simp at hc; omega)) hn),
      if_pos (by omega), add_comm]

theorem packAll_sound {ρ : ℕ → QM31} {basis : ℕ}
    (hbasis : ∀ c, c < 4 → ρ (basis + c) = unitVec c) :
    ∀ (f : ℕ) (lanes : List ℕ) (v : ℕ → F) (n : ℕ), lanes.length ≤ 4 * f →
      (∀ k, k < lanes.length → ρ (lanes.getD k 0) = QM31.fromBase (v k)) →
      AllHold ρ (packAll basis f lanes n).ops →
      lanes.length ≤ 4 * (packAll basis f lanes n).res.length ∧
      ∀ j, j < lanes.length →
        coord (ρ ((packAll basis f lanes n).res.getD (j / 4) 0)) (j % 4) = v j := by
  intro f
  induction f with
  | zero =>
    intro lanes v n hl _ _
    have : lanes = [] := List.eq_nil_of_length_eq_zero (by omega)
    subst this
    exact ⟨by simp, fun j hj => absurd hj (by simp)⟩
  | succ f ih =>
    intro lanes v n hl hv h
    cases lanes with
    | nil => exact ⟨by simp, fun j hj => absurd hj (by simp)⟩
    | cons a rest =>
      set c := packChunk basis a 1 (rest.take 3) n with hcdef
      rw [show (packAll basis (f + 1) (a :: rest) n).ops =
        c.ops ++ (packAll basis f (rest.drop 3) c.next).ops from rfl, allHold_append] at h
      obtain ⟨hc, hr⟩ := h
      obtain ⟨ihl, ihv⟩ := ih (rest.drop 3) (fun k => v (k + 4)) c.next
        (by simp at hl ⊢; omega)
        (fun k hk => by
          have := hv (k + 4) (by simp at hk ⊢; omega)
          rw [List.getD_eq_getElem?_getD, List.getElem?_drop]
          rw [List.getD_eq_getElem?_getD, show k + 4 = (3 + k) + 1 by omega,
            List.getElem?_cons_succ] at this
          rwa [show 3 + k + 1 = k + 4 by omega] at this) hr
      have hres : (packAll basis (f + 1) (a :: rest) n).res
          = c.res :: (packAll basis f (rest.drop 3) c.next).res := rfl
      refine ⟨?_, ?_⟩
      · rw [hres, List.length_cons]
        simp at ihl ⊢
        all_goals omega
      · intro j hj
        rw [hres]
        by_cases hj4 : j < 4
        · rw [show j / 4 = 0 by omega, List.getD_cons_zero, show j % 4 = j by omega]
          have hjc : j < (a :: rest.take 3).length := by
            simp at hj ⊢; omega
          have := chunk_coord hbasis v (a :: rest.take 3) (by simp)
            (List.cons_ne_nil _ _) (fun t ht => by
              rcases t with _ | t
              · exact hv 0 (by simp)
              · have := hv (t + 1) (by simp at ht ⊢; omega)
                simp only [List.getD_cons_succ] at this ⊢
                rw [List.getD_eq_getElem?_getD, List.getElem?_take, if_pos (by simp at ht; omega),
                  ← List.getD_eq_getElem?_getD]
                exact this) n hc j hjc
          exact this
        · rw [show j / 4 = (j - 4) / 4 + 1 by omega, List.getD_cons_succ,
            show j % 4 = (j - 4) % 4 by omega]
          have := ihv (j - 4) (by simp at hj ⊢; omega)
          rw [show j - 4 + 4 = j by omega] at this
          exact this

/-- **`pack`**: lane `j` of the packed vector is lane value `j`. -/
theorem packG_sound {ρ : ℕ → QM31} {lanes : List ℕ} {n : ℕ} (v : ℕ → F)
    (hv : ∀ k, k < lanes.length → ρ (lanes.getD k 0) = QM31.fromBase (v k))
    (h : AllHold ρ (packG lanes n).ops) :
    (packG lanes n).res.Covers ∧ (packG lanes n).res.len = lanes.length ∧
    ∀ j, j < lanes.length → SimdReg.lane ρ (packG lanes n).res j = v j := by
  rw [show (packG lanes n).ops = (List.range 4).map (fun c => Op.const (n + c) (unitVec c))
    ++ (packAll n lanes.length lanes (n + 4)).ops from rfl, allHold_append] at h
  obtain ⟨hb, hp⟩ := h
  have hbasis : ∀ c, c < 4 → ρ (n + c) = unitVec c := fun c hc =>
    hb _ (List.mem_map.mpr ⟨c, List.mem_range.mpr hc, rfl⟩)
  obtain ⟨hl, hval⟩ := packAll_sound hbasis lanes.length lanes v (n + 4) (by omega) hv hp
  exact ⟨hl, rfl, fun j hj => hval j hj⟩

/-! ### The per-relation sums -/

/-- One relation's slot: `Σ size_p1(i) · uses`, accumulated from `acc`. -/
def relSumG (sRegs : List ℕ) : ℕ → List (ℕ × ℕ) → ℕ → Out ℕ
  | acc, [], n => ⟨[], acc, n⟩
  | acc, iu :: ts, n =>
    let r := relSumG sRegs (n + 2) ts (n + 3)
    ⟨[.const n (QM31.fromBase ((iu.2 : ℕ) : F)), .mul (n + 1) (sRegs.getD iu.1 0) n,
      .add (n + 2) acc (n + 1)] ++ r.ops, r.res, r.next⟩

theorem relSumG_sound {ρ : ℕ → QM31} {sRegs : List ℕ} (N : ℕ → ℕ) :
    ∀ (ts : List (ℕ × ℕ)) (acc n : ℕ) (a : ℕ),
      (∀ iu ∈ ts, ρ (sRegs.getD iu.1 0) = QM31.fromBase ((N iu.1 : ℕ) : F)) →
      ρ acc = QM31.fromBase ((a : ℕ) : F) →
      AllHold ρ (relSumG sRegs acc ts n).ops →
      ρ (relSumG sRegs acc ts n).res
        = QM31.fromBase (((a + (ts.map fun iu => iu.2 * N iu.1).sum : ℕ)) : F) := by
  intro ts
  induction ts with
  | nil => intro acc n a _ ha _; show ρ acc = _; simpa using ha
  | cons iu ts ih =>
    intro acc n a hs ha h
    rw [show (relSumG sRegs acc (iu :: ts) n).ops =
      [.const n (QM31.fromBase ((iu.2 : ℕ) : F)), .mul (n + 1) (sRegs.getD iu.1 0) n,
        .add (n + 2) acc (n + 1)] ++ (relSumG sRegs (n + 2) ts (n + 3)).ops from rfl,
      allHold_append] at h
    obtain ⟨h1, h2⟩ := h
    have hc : ρ n = QM31.fromBase ((iu.2 : ℕ) : F) := h1 _ List.mem_cons_self
    have hm : ρ (n + 1) = ρ (sRegs.getD iu.1 0) * ρ n :=
      h1 _ (List.mem_cons_of_mem _ List.mem_cons_self)
    have hadd : ρ (n + 2) = ρ acc + ρ (n + 1) :=
      h1 _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ List.mem_cons_self))
    have hacc : ρ (n + 2) = QM31.fromBase (((a + iu.2 * N iu.1 : ℕ)) : F) := by
      rw [hadd, hm, hc, hs iu List.mem_cons_self, ha, fromBase_mul']
      show baseHom _ + baseHom _ = baseHom _
      rw [← map_add]
      congr 1
      push_cast; ring
    show ρ (relSumG sRegs (n + 2) ts (n + 3)).res = _
    rw [ih (n + 2) (n + 3) _ (fun x hx => hs x (List.mem_cons_of_mem _ hx)) hacc h2,
      List.map_cons, List.sum_cons, Nat.add_assoc]

/-- All slots, in `relTerms` order, each accumulated from the zero wire. -/
def slotsG (zero : ℕ) (sRegs : List ℕ) : List (List (ℕ × ℕ)) → ℕ → Out (List ℕ)
  | [], n => ⟨[], [], n⟩
  | ts :: rest, n =>
    let r := relSumG sRegs zero ts n
    let t := slotsG zero sRegs rest r.next
    ⟨r.ops ++ t.ops, r.res :: t.res, t.next⟩

theorem slotsG_sound {ρ : ℕ → QM31} {zero : ℕ} {sRegs : List ℕ} (N : ℕ → ℕ)
    (hzero : ρ zero = 0) :
    ∀ (tss : List (List (ℕ × ℕ))) (n : ℕ),
      (∀ ts ∈ tss, ∀ iu ∈ ts, ρ (sRegs.getD iu.1 0) = QM31.fromBase ((N iu.1 : ℕ) : F)) →
      AllHold ρ (slotsG zero sRegs tss n).ops →
      (slotsG zero sRegs tss n).res.length = tss.length ∧
      ∀ k, k < tss.length → ρ ((slotsG zero sRegs tss n).res.getD k 0)
        = QM31.fromBase ((((tss.getD k []).map fun iu => iu.2 * N iu.1).sum : ℕ) : F) := by
  intro tss
  induction tss with
  | nil => intro n _ _; exact ⟨rfl, fun k hk => absurd hk (by simp)⟩
  | cons ts rest ih =>
    intro n hs h
    rw [show (slotsG zero sRegs (ts :: rest) n).ops =
      (relSumG sRegs zero ts n).ops ++ (slotsG zero sRegs rest (relSumG sRegs zero ts n).next).ops
      from rfl, allHold_append] at h
    obtain ⟨h1, h2⟩ := h
    obtain ⟨ihl, ihv⟩ := ih _ (fun t ht => hs t (List.mem_cons_of_mem _ ht)) h2
    refine ⟨by show _ + 1 = _; rw [ihl]; rfl, fun k hk => ?_⟩
    rcases k with _ | k
    · show ρ (relSumG sRegs zero ts n).res = _
      rw [relSumG_sound N ts zero n 0 (hs ts List.mem_cons_self) (by rw [hzero]; rfl) h1,
        Nat.zero_add]
      rfl
    · show ρ ((slotsG zero sRegs rest _).res.getD k 0) = _
      rw [ihv k (by simp at hk; omega)]
      rfl

/-! ### The whole check -/

/-- `check_relation_uses` (for `K > 16` size bits): shifted sizes plus one,
unpacked per component, the per-relation slots, packed and range-checked
to `31 − 16 = 15` bits. -/
noncomputable def checkRelUsesG (zero : ℕ) (bits : List SimdReg) (count len : ℕ) (n : ℕ) :
    Out Unit :=
  let one := constSplat 1 count len n
  let sh := combineG (n + 1) (bits.drop 16) (n + 2)
  let p1 := simdAdd sh.res one.res sh.next
  let ss := unpackFrom p1.res len 0 p1.next
  let sl := slotsG zero ss.res relTerms ss.next
  let pk := packG sl.res sl.next
  let eb := extractBitsK zero pk.res 15 pk.next
  ⟨one.ops ++ [.const (n + 1) (QM31.fromBase 2)] ++ sh.ops ++ p1.ops ++ ss.ops ++ sl.ops ++
    pk.ops ++ eb.ops, (), eb.next⟩

theorem shifted_sum (l K : ℕ) (hl : l < K) (hK : 16 < K) (b : ℕ → F)
    (hb : ∀ t, t < K → b t = if t = l then 1 else 0) :
    ∑ t ∈ range (K - 16), b (16 + t) * 2 ^ t = ((2 ^ l / 2 ^ 16 : ℕ) : F) := by
  by_cases h16 : 16 ≤ l
  · rw [Finset.sum_eq_single (l - 16)]
    · rw [hb _ (by omega), if_pos (by omega), one_mul,
        show 2 ^ l = 2 ^ 16 * 2 ^ (l - 16) by rw [← pow_add]; congr 1; omega,
        Nat.mul_div_cancel_left _ (by norm_num)]
      push_cast; rfl
    · intro t htm ht
      rw [hb _ (by have := Finset.mem_range.mp htm; omega), if_neg (by omega), zero_mul]
    · intro hn; exact absurd (Finset.mem_range.mpr (by omega)) hn
  · rw [Finset.sum_eq_zero (fun t ht => by
      rw [hb _ (by have := Finset.mem_range.mp ht; omega), if_neg (by omega), zero_mul]),
      Nat.div_eq_of_lt (Nat.pow_lt_pow_right (by norm_num) (by omega))]
    simp

theorem relTerms_uses_le : ∀ ts ∈ relTerms, (ts.map fun iu : ℕ × ℕ => iu.2).sum ≤ 14 := by
  decide

theorem relTerms_comp_lt : ∀ ts ∈ relTerms, ∀ iu ∈ ts, iu.1 < 11 := by decide

theorem nOf_le {l : ℕ} (hl : l < 32) : nOf l ≤ 2 ^ 15 + 1 := by
  unfold nOf
  have : 2 ^ l ≤ 2 ^ 31 := Nat.pow_le_pow_right (by norm_num) (by omega)
  have : 2 ^ l / 2 ^ 16 ≤ 2 ^ 31 / 2 ^ 16 := Nat.div_le_div_right this
  norm_num at this ⊢; omega

theorem sum_nOf_le (N : ℕ → ℕ) (hN : ∀ i, i < 11 → N i ≤ 2 ^ 15 + 1) :
    ∀ ts : List (ℕ × ℕ), (∀ iu ∈ ts, iu.1 < 11) →
      (ts.map fun iu => iu.2 * N iu.1).sum ≤ (2 ^ 15 + 1) * (ts.map fun iu => iu.2).sum
  | [], _ => by simp
  | iu :: ts, h => by
    simp only [List.map_cons, List.sum_cons]
    have := sum_nOf_le N hN ts (fun x hx => h x (List.mem_cons_of_mem _ hx))
    have h1 := hN iu.1 (h iu List.mem_cons_self)
    have : iu.2 * N iu.1 ≤ iu.2 * (2 ^ 15 + 1) := Nat.mul_le_mul_left _ h1
    nlinarith

set_option maxHeartbeats 1600000 in
/-- **`check_relation_uses` forces the spec's relation-use bound.** -/
theorem checkRelUsesG_sound {ρ : ℕ → QM31} {zero : ℕ} {bits : List SimdReg}
    {count n : ℕ} (logs : ℕ → ℕ)
    (hzero : ρ zero = 0) (hcl : 11 ≤ 4 * count)
    (hK : 16 < bits.length) (hK31 : bits.length ≤ 31)
    (hshape : ∀ b ∈ bits, BitShape b 11 count)
    (hlogs : ∀ j, j < 11 → logs j < bits.length)
    (honehot : ∀ j, j < 11 → ∀ t, t < bits.length →
      SimdReg.lane ρ (bits.getD t dummySimd) j = if t = logs j then 1 else 0)
    (h : AllHold ρ (checkRelUsesG zero bits count 11 n).ops) :
    relationUsesOk ((List.range 11).map logs) = true := by
  set one := constSplat 1 count 11 n with honedef
  set sh := combineG (n + 1) (bits.drop 16) (n + 2) with hshdef
  set p1 := simdAdd sh.res one.res sh.next with hp1def
  set ss := unpackFrom p1.res 11 0 p1.next with hssdef
  set sl := slotsG zero ss.res relTerms ss.next with hsldef
  set pk := packG sl.res sl.next with hpkdef
  rw [show (checkRelUsesG zero bits count 11 n).ops =
    one.ops ++ [.const (n + 1) (QM31.fromBase 2)] ++ sh.ops ++ p1.ops ++ ss.ops ++ sl.ops ++
      pk.ops ++ (extractBitsK zero pk.res 15 pk.next).ops from rfl] at h
  simp only [allHold_append] at h
  obtain ⟨⟨⟨⟨⟨⟨⟨hone, htwo⟩, hsh⟩, hp1⟩, hss⟩, hsl⟩, hpk⟩, heb⟩ := h
  have htwo' : ρ (n + 1) = QM31.fromBase 2 := htwo _ List.mem_cons_self
  have hdrop_ne : bits.drop 16 ≠ [] := by
    intro he; have := congrArg List.length he; simp at this; omega
  have hdshape : ∀ b ∈ bits.drop 16, BitShape b 11 count :=
    fun b hb => hshape b (List.mem_of_mem_drop hb)
  -- Shifted sizes plus one, lane by lane.
  have hlogs32 : ∀ j, j < 11 → logs j < 32 := fun j hj => by
    have := hlogs j hj; omega
  have hp1lane : ∀ j, j < 11 → SimdReg.lane ρ p1.res j = ((nOf (logs j) : ℕ) : F) := by
    intro j hj
    obtain ⟨hshl, hshd, hshv⟩ := combineG_sound htwo' hcl j hj (bits.drop 16) (n + 2)
      hdrop_ne hdshape hsh
    have hshcov : sh.res.Covers := by unfold SimdReg.Covers; rw [hshl, hshd]; exact hcl
    have := simdAdd_lane hshcov (by rw [hshl]; simp [honedef, constSplat]; exact hcl) hp1 j
      (by rw [hshl]; exact hj)
    rw [this, hshv, constSplat_lane hone j (by omega)]
    rw [List.length_drop]
    rw [Finset.sum_congr rfl (fun t ht => by
      rw [List.getD_eq_getElem?_getD, List.getElem?_drop, ← List.getD_eq_getElem?_getD,
        honehot j hj (16 + t) (by have := Finset.mem_range.mp ht; omega)])]
    rw [shifted_sum (logs j) bits.length (hlogs j hj) hK (fun t => if t = logs j then 1 else 0)
      (fun t _ => rfl)]
    unfold nOf; push_cast; rfl
  -- Unpacked per component.
  obtain ⟨hssl, hssv⟩ := unpackFrom_sound 11 0 p1.next hss
  have hsreg : ∀ ts ∈ relTerms, ∀ iu ∈ ts,
      ρ (ss.res.getD iu.1 0) = QM31.fromBase ((nOf (logs iu.1) : ℕ) : F) := by
    intro ts hts iu hiu
    have hi := relTerms_comp_lt ts hts iu hiu
    rw [hssv iu.1 hi, Nat.zero_add, hp1lane iu.1 hi]
  obtain ⟨hsll, hslv⟩ := slotsG_sound (fun i => nOf (logs i)) hzero relTerms ss.next hsreg hsl
  set sums : ℕ → ℕ := fun k => ((relTerms.getD k []).map fun iu => iu.2 * nOf (logs iu.1)).sum
    with hsums
  obtain ⟨hpkcov, hpklen, hpkv⟩ := packG_sound (lanes := sl.res) (n := sl.next)
    (fun k => ((sums k : ℕ) : F)) (fun k hk => hslv k (by rw [hsll] at hk; exact hk)) hpk
  have hsum_lt : ∀ k, k < 8 → sums k < 2 ^ 15 := by
    intro k hk
    have hk' : k < pk.res.len := by rw [hpklen, hsll]; exact hk
    obtain ⟨hbits, hnat⟩ := extractBitsK_sound hzero hpkcov (by norm_num) (by norm_num) heb k hk'
    have hlt := BitDecomp.natOf_lt _ 15 hbits
    rw [hnat, hpkv k (by rw [hsll]; exact hk)] at hlt
    have hts : relTerms.getD k [] ∈ relTerms := by
      rw [List.getD_eq_getElem?_getD, List.getElem?_eq_getElem
        (by rw [show relTerms.length = 8 from rfl]; exact hk)]
      exact List.getElem_mem _
    have hbound : sums k ≤ (2 ^ 15 + 1) * 14 := by
      have h1 := sum_nOf_le (fun i => nOf (logs i)) (fun i hi => nOf_le (hlogs32 i hi))
        (relTerms.getD k []) (relTerms_comp_lt _ hts)
      have h2 := relTerms_uses_le _ hts
      have : (2 ^ 15 + 1) * ((relTerms.getD k []).map fun iu : ℕ × ℕ => iu.2).sum
          ≤ (2 ^ 15 + 1) * 14 := Nat.mul_le_mul_left _ h2
      exact le_trans h1 this
    rw [ZMod.val_cast_of_lt (by unfold P; omega)] at hlt
    exact hlt
  show relationUsesOk [logs 0, logs 1, logs 2, logs 3, logs 4, logs 5, logs 6, logs 7,
    logs 8, logs 9, logs 10] = true
  rw [relationUsesOk_iff]
  intro ts hts
  obtain ⟨k, hk, rfl⟩ := List.getElem_of_mem hts
  have hk8 : k < 8 := by rw [show relTerms.length = 8 from rfl] at hk; exact hk
  have := hsum_lt k hk8
  rw [hsums] at this
  simp only at this
  rw [List.getD_eq_getElem?_getD, List.getElem?_eq_getElem hk] at this
  simp only [Option.getD_some] at this
  have heq : (relTerms[k].map fun (iu : ℕ × ℕ) => iu.2 * nOf ([logs 0, logs 1, logs 2,
      logs 3, logs 4, logs 5, logs 6, logs 7, logs 8, logs 9, logs 10].getD iu.1 0))
      = (relTerms[k].map fun iu => iu.2 * nOf (logs iu.1)) := by
    refine List.map_congr_left fun iu hiu => ?_
    have hi := relTerms_comp_lt _ (List.getElem_mem hk) iu hiu
    congr 2
    interval_cases h : iu.1 <;> rfl
  exact lt_of_eq_of_lt (congrArg List.sum heq) this

end StwoVerifier.Gadgets
