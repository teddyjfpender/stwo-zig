/-
**Phase 6 of the in-circuit `verify`: the FRI decommitment**
(`fri.zig` `friDecommit`, fold step 1, last-layer degree bound 0).

`phase6G`: the twiddle chain from the query points and bits (one circle
twiddle, then one line twiddle per further layer), the twiddles and
alphas per query, the coset Merkle check per (layer, query), and the
fold walk with its last-layer battery. `phase6G_sound` turns the gates
into the per-layer, per-query facts `FriBatch` consumes.
-/
import StwoVerifier.TwiddleSpec
import StwoVerifier.MerklePathBridge
import StwoVerifier.FriBatch
import StwoVerifier.PhaseTranscript

namespace StwoVerifier.Bridge

open StwoVerifier StwoVerifier.Gadgets StwoVerifier.Gates Finset

theorem baseSeq_take (P : PointF) :
    ∀ (d : ℕ) (l : List ℕ) (k : ℕ),
      Gadgets.baseSeq P d (l.take k) = (Gadgets.baseSeq P d l).take k
  | _, [], k => by simp [Gadgets.baseSeq]
  | _, _ :: _, 0 => by simp [Gadgets.baseSeq]
  | d, b :: rest, k + 1 => by
    simp only [List.take_succ_cons, Gadgets.baseSeq]
    rw [baseSeq_take _ 1 rest k]

theorem getD_take' {α : Type} (l : List α) (d : α) {k i : ℕ} (hi : i < k) :
    (l.take k).getD i d = l.getD i d := by
  rw [List.getD_eq_getElem?_getD, List.getElem?_take, if_pos hi, ← List.getD_eq_getElem?_getD]

set_option maxHeartbeats 1600000 in
/-- `twiddleChain1_spec` for a chain over a prefix of the line bits
(the circuit stops one layer before the last line bit). -/
theorem twiddleChain1_spec' {ρ : ℕ → QM31} {zero count len : ℕ}
    {bit0 : SimdReg} {points : PointSimd} {bits : List SimdReg} {n : ℕ}
    {L : ℕ} (hL2 : 2 ≤ L) (hL30 : L ≤ 30)
    (hzero : ρ zero = 0)
    (hb0 : BitShape bit0 len count) (hp : points.Shape len count)
    (hshapes : ∀ r ∈ bits, BitShape r len count)
    (hlen : bits.length ≤ L - 1)
    (h : AllHold ρ (twiddleChain1 zero count len bit0 points bits n).ops)
    (q : ℕ) (hq : q < len)
    (b : ℕ → ℕ) (hb : ∀ i, b i ≤ 1)
    (hbit0lane : SimdReg.lane ρ bit0 q = 0 ∨ SimdReg.lane ρ bit0 q = 1)
    (hbitslane : ∀ r ∈ bits, SimdReg.lane ρ r q = 0 ∨ SimdReg.lane ρ r q = 1)
    (hb0def : bitNat ρ bit0 q = b 0)
    (hbtdef : ∀ t, t < bits.length →
      bitNat ρ (bits.getD t dummySimd) q = b (t + 1))
    (hpoint : PointSimd.lane ρ points q
      = (canonicDomain L).at' (bitReverseIndex
          (∑ i ∈ range L, b i * 2 ^ i) L)) :
    ∀ ℓ, ℓ < bits.length + 1 →
      SimdReg.lane ρ ((twiddleChain1 zero count len bit0 points bits n).res.getD
          ℓ dummySimd) q
        * specFoldCoord b L ℓ = 1 := by
  have hcirc : OnCircle (PointSimd.lane ρ points q) := by
    rw [hpoint]
    exact onCircle_toPoint _
  obtain ⟨hlenT, hval⟩ := twiddleChain1_sound hzero hb0 hp hshapes h
  obtain ⟨h0, hinner⟩ := hval q hq hbit0lane hbitslane hcirc
  have hsel : (if SimdReg.lane ρ bit0 q = 0 then PointSimd.lane ρ points q
      else (PointSimd.lane ρ points q).conjugate)
      = (canonicDomain L).at' (bitReverseIndex
          (∑ i ∈ range L, (if i = 0 then 0 else b i) * 2 ^ i) L) := by
    rw [hpoint, ← Gadgets.base0_eq_evenPoint hb hL2 hL30]
    rcases hbit0lane with hl0 | hl1
    · have hb00 : b 0 = 0 := by
        rw [← hb0def]
        unfold bitNat
        rw [if_pos hl0]
      rw [if_pos hl0, if_pos hb00]
    · have hb01 : b 0 = 1 := by
        rw [← hb0def]
        unfold bitNat
        rw [if_neg (by rw [hl1]; norm_num)]
      rw [if_neg (by rw [hl1]; norm_num), if_neg (by rw [hb01]; norm_num)]
  have hlist : (bits.map fun r => bitNat ρ r q)
      = ((List.range (L - 1)).map fun t => b (t + 1)).take bits.length := by
    refine List.ext_getElem (by simp; omega) ?_
    intro i h1 h2
    rw [List.getElem_map, List.getElem_take, List.getElem_map, List.getElem_range]
    have hi : i < bits.length := by simpa using h1
    have := hbtdef i hi
    rw [← this, List.getD_eq_getElem?_getD, List.getElem?_eq_getElem hi]
    rfl
  intro ℓ hℓ
  cases ℓ with
  | zero =>
    have := h0
    rw [hsel] at this
    exact this
  | succ ℓ =>
    have hℓ' : ℓ < bits.length := by omega
    have := hinner ℓ hℓ'
    rw [hsel, evenPoint_eq_smul hb hL2 hL30, hlist, baseSeq_take,
      getD_take' _ _ hℓ', baseSeq_eq_lineFoldPoints hb hL2 hL30 ℓ (by omega)] at this
    exact this

/-! ### Position digits and the spec fold coordinates -/

theorem digitSum (p : ℕ) : ∀ M, ∑ t ∈ range M, p / 2 ^ t % 2 * 2 ^ t = p % 2 ^ M
  | 0 => by simp [Nat.mod_one]
  | M + 1 => by
    rw [Finset.sum_range_succ, digitSum p M, Nat.mod_pow_succ]
    ring

theorem shiftSum (p s M : ℕ) :
    ∑ t ∈ range M, p / 2 ^ (t + s) % 2 * 2 ^ (t + 1) = 2 * (p / 2 ^ s % 2 ^ M) := by
  rw [← digitSum (p / 2 ^ s) M, Finset.mul_sum]
  refine Finset.sum_congr rfl fun t _ => ?_
  rw [pow_add, mul_comm (2 ^ t) (2 ^ s), ← Nat.div_div_eq_div_mul, pow_succ]
  ring

theorem circleSum {p L : ℕ} (hp : p < 2 ^ L) (hL : 1 ≤ L) :
    ∑ i ∈ range L, (if i = 0 then 0 else p / 2 ^ i % 2) * 2 ^ i = p / 2 * 2 := by
  obtain ⟨M, rfl⟩ : ∃ M, L = M + 1 := ⟨L - 1, by omega⟩
  rw [Finset.sum_range_succ']
  simp only [Nat.add_one_ne_zero, if_false, if_true, zero_mul, add_zero]
  have := shiftSum p 1 M
  rw [show (∑ t ∈ range M, p / 2 ^ (t + 1) % 2 * 2 ^ (t + 1))
    = ∑ t ∈ range M, p / 2 ^ (t + 1) % 2 * 2 ^ (t + 1) from rfl, this, pow_one,
    Nat.mod_eq_of_lt (by rw [Nat.div_lt_iff_lt_mul (by norm_num), ← pow_succ]; exact hp)]
  ring

/-- The circle-layer coordinate at a position's digits. -/
theorem specFoldCoord_circle {p L : ℕ} (hp : p < 2 ^ L) (hL : 1 ≤ L) :
    specFoldCoord (fun i => p / 2 ^ i % 2) L 0
      = ((canonicDomain L).at' (bitReverseIndex (p / 2 * 2) L)).y := by
  show ((canonicDomain L).at' (bitReverseIndex
      (∑ i ∈ range L, (if i = 0 then 0 else p / 2 ^ i % 2) * 2 ^ i) L)).y = _
  rw [circleSum hp hL]

/-- Line layer `ℓ + 1`'s coordinate at a position's digits. -/
theorem specFoldCoord_line {p L ℓ : ℕ} (hp : p < 2 ^ L) (hℓ : ℓ + 2 ≤ L) :
    specFoldCoord (fun i => p / 2 ^ i % 2) L (ℓ + 1)
      = ((LineDomain.double^[ℓ] ⟨Coset.halfOdds (L - 1)⟩).coset.indexAt
          (bitReverseIndex (p / 2 ^ (ℓ + 1) / 2 * 2) (L - (ℓ + 1)))).toPoint.x := by
  show ((LineDomain.double^[ℓ] ⟨Coset.halfOdds (L - 1)⟩).coset.indexAt
      (bitReverseIndex
        (∑ t ∈ range (L - 1 - (ℓ + 1)), p / 2 ^ (t + (ℓ + 1) + 1) % 2 * 2 ^ (t + 1))
        (L - (ℓ + 1)))).toPoint.x = _
  rw [show (∑ t ∈ range (L - 1 - (ℓ + 1)), p / 2 ^ (t + (ℓ + 1) + 1) % 2 * 2 ^ (t + 1))
    = ∑ t ∈ range (L - 1 - (ℓ + 1)), p / 2 ^ (t + (ℓ + 2)) % 2 * 2 ^ (t + 1) from
      Finset.sum_congr rfl fun t _ => by rw [show t + (ℓ + 1) + 1 = t + (ℓ + 2) by omega],
    shiftSum, Nat.mod_eq_of_lt, Nat.div_div_eq_div_mul, ← pow_succ]
  · ring_nf
  · rw [Nat.div_lt_iff_lt_mul (by positivity), ← pow_add,
      show L - 1 - (ℓ + 1) + (ℓ + 2) = L by omega]
    exact hp

/-- The layer chain, layer by layer. -/
theorem chain1_get {ρ : ℕ → QM31} :
    ∀ {layers : List (ℕ × List (ℕ × ℕ × ℕ × ℕ))} {xss : List (List F)} {vals out : List ℕ},
      Chain1 ρ layers xss vals out →
      ∃ V : ℕ → List ℕ, V 0 = vals ∧ V layers.length = out ∧
        ∀ l, l < layers.length →
          (layers.getD l default).2.length = (V l).length ∧
          (V (l + 1)).length = (layers.getD l default).2.length ∧
          (∀ i, i < (layers.getD l default).2.length →
            ρ ((V l).getD i 0)
              = (if ρ (((layers.getD l default).2.getD i default).2.2.1) = 0
                 then ρ ((layers.getD l default).2.getD i default).1
                 else ρ ((layers.getD l default).2.getD i default).2.1)) ∧
          (∀ i, i < (layers.getD l default).2.length →
            Fri.foldLinePair (ρ ((layers.getD l default).2.getD i default).1)
              (ρ ((layers.getD l default).2.getD i default).2.1)
              (ρ (layers.getD l default).1) ((xss.getD l []).getD i 0)
              = .ok (ρ ((V (l + 1)).getD i 0)))
  | _, _, _, _, .nil vals => ⟨fun _ => vals, rfl, rfl, fun l hl => absurd hl (by simp)⟩
  | _, _, _, _, .cons alpha qs xs rest xss vals nxt out hql hnl hsel hfold hrest => by
    obtain ⟨V, hV0, hVL, hV⟩ := chain1_get hrest
    refine ⟨fun l => match l with | 0 => vals | l + 1 => V l, rfl, by simpa using hVL, ?_⟩
    intro l hl
    cases l with
    | zero =>
      refine ⟨hql, ?_, hsel, ?_⟩
      · show (V 0).length = qs.length
        rw [hV0, hnl]
      · intro i hi
        have := hfold i hi
        rw [← hV0] at this
        exact this
    | succ l =>
      exact hV l (by simpa using hl)

/-! ### The emitter -/

/-- Unpack each twiddle vector to `nq` scalars. -/
noncomputable def unpackAllG (nq : ℕ) : List SimdReg → ℕ → Out (List (List ℕ))
  | [], n => ⟨[], [], n⟩
  | r :: rest, n =>
    (unpackFrom r nq 0 n).seq fun u n =>
    (unpackAllG nq rest n).seq fun us n => ⟨[], u :: us, n⟩

theorem unpackAllG_sound {ρ : ℕ → QM31} {nq : ℕ} :
    ∀ (rs : List SimdReg) (n : ℕ), AllHold ρ (unpackAllG nq rs n).ops →
      (unpackAllG nq rs n).res.length = rs.length ∧
      ∀ l, l < rs.length → ∀ i, i < nq →
        ρ (((unpackAllG nq rs n).res.getD l []).getD i 0)
          = QM31.fromBase (SimdReg.lane ρ (rs.getD l dummySimd) i)
  | [], _, _ => ⟨rfl, fun l hl => absurd hl (by simp)⟩
  | r :: rest, n, h => by
    unfold unpackAllG at h ⊢
    rw [allHold_seq] at h
    obtain ⟨hu, h⟩ := h
    rw [allHold_seq] at h
    obtain ⟨hr, -⟩ := h
    obtain ⟨hul, huv⟩ := unpackFrom_sound nq 0 n hu
    obtain ⟨ihl, ihv⟩ := unpackAllG_sound rest _ hr
    rw [seq_res, seq_res]
    refine ⟨by simp [ihl], fun l hl i hi => ?_⟩
    cases l with
    | zero =>
      show ρ ((unpackFrom r nq 0 n).res.getD i 0) = _
      rw [huv i hi, Nat.zero_add]; rfl
    | succ l =>
      show ρ (((unpackAllG nq rest _).res.getD l []).getD i 0) = _
      rw [ihv l (by simpa using hl) i hi]; rfl

/-- The path bits of query `i` at layer `l`: bits `l+1 ..< L`. -/
def friPathBits (sbits : List (List ℕ)) (L l i : ℕ) : List ℕ :=
  (List.range (L - 1 - l)).map fun t => (sbits.getD (l + 1 + t) []).getD i 0

/-- Every (layer, query) pair. -/
def friItems (K nq : ℕ) : List (ℕ × ℕ) :=
  (List.range K).flatMap fun l => (List.range nq).map fun i => (l, i)

/-- The coset Merkle checks. -/
noncomputable def cosetLoopG (wit : ℕ → ℕ → ℕ × ℕ) (pbits : ℕ → ℕ → List ℕ)
    (roots : List (List ℕ)) (auth : ℕ → ℕ → List (List ℕ)) : List (ℕ × ℕ) → ℕ → Out Unit
  | [], n => ⟨[], (), n⟩
  | (l, i) :: rest, n =>
    (friCosetG (wit l i).1 (wit l i).2 (pbits l i) (roots.getD l []) (auth l i) n).seq fun _ n =>
    cosetLoopG wit pbits roots auth rest n

theorem cosetLoopG_sound {ρ : ℕ → QM31} {wit : ℕ → ℕ → ℕ × ℕ} {pbits : ℕ → ℕ → List ℕ}
    {roots : List (List ℕ)} {auth : ℕ → ℕ → List (List ℕ)}
    (P : ℕ × ℕ → Prop) (wr : ℕ → List Blake2s.Word) (sws : ℕ → ℕ → List (List Blake2s.Word))
    (hroot : ∀ x, P x → RegsWords ρ (roots.getD x.1 []) (wr x.1) ∧ (wr x.1).length = 8)
    (hsl : ∀ x, P x → (auth x.1 x.2).length = (sws x.1 x.2).length)
    (hsibs : ∀ x, P x → ∀ k, k < (auth x.1 x.2).length →
      RegsWords ρ ((auth x.1 x.2).getD k []) ((sws x.1 x.2).getD k []) ∧
        ((sws x.1 x.2).getD k []).length = 8)
    (hbits : ∀ x, P x → ∀ b ∈ pbits x.1 x.2, ρ b = 0 ∨ ρ b = 1) :
    ∀ (items : List (ℕ × ℕ)) (n : ℕ), (∀ x ∈ items, P x) →
      AllHold ρ (cosetLoopG wit pbits roots auth items n).ops →
      ∀ x ∈ items, wordsBytes (wr x.1) = pathRoot
        (Merkle.nodeHash (FriBatch.lq (ρ (wit x.1 x.2).1)) (FriBatch.lq (ρ (wit x.1 x.2).2)))
        ((pbits x.1 x.2).map fun b => qbit (ρ b)) ((sws x.1 x.2).map wordsBytes)
  | [], _, _, _ => fun x hx => absurd hx (by simp)
  | (l, i) :: rest, n, hP, h => by
    unfold cosetLoopG at h
    rw [allHold_seq] at h
    obtain ⟨h1, h2⟩ := h
    intro x hx
    rcases List.mem_cons.mp hx with rfl | hx
    · have hp := hP (l, i) List.mem_cons_self
      exact friCosetG_sound (hroot _ hp).1 (hroot _ hp).2 (hsl _ hp) (hsibs _ hp)
        (hbits _ hp) h1
    · exact cosetLoopG_sound P wr sws hroot hsl hsibs hbits rest _
        (fun y hy => hP y (List.mem_cons_of_mem _ hy)) h2 x hx

/-- The fold walk's layers. -/
def friLayersOf (alphas : List ℕ) (wit : ℕ → ℕ → ℕ × ℕ) (sbits tw : List (List ℕ))
    (K nq : ℕ) : List (ℕ × List (ℕ × ℕ × ℕ × ℕ)) :=
  (List.range K).map fun l => (alphas.getD l 0, (List.range nq).map fun i =>
    ((wit l i).1, (wit l i).2, (sbits.getD l []).getD i 0, (tw.getD l []).getD i 0))

/-- **Phase 6**: twiddles, their unpack, the coset Merkle checks, the
fold walk and the last-layer battery. -/
noncomputable def phase6G (zero one L nq : ℕ) (bits : List SimdReg) (points : PointSimd)
    (sbits : List (List ℕ)) (input alphas : List ℕ) (wit : ℕ → ℕ → ℕ × ℕ)
    (roots : List (List ℕ)) (auth : ℕ → ℕ → List (List ℕ)) (lastCoef n : ℕ) : Out Unit :=
  (twiddleChain1 zero points.x.data.length nq (bits.getD 0 dummySimd) points
    ((bits.drop 1).take (L - 2)) n).seq fun tws n =>
  (unpackAllG nq tws n).seq fun tw n =>
  (cosetLoopG wit (friPathBits sbits L) roots auth (friItems (L - 1) nq) n).seq fun _ n =>
  friDecommit1 one (friLayersOf alphas wit sbits tw (L - 1) nq) input lastCoef n

/-! ### Soundness -/

theorem getD_rmap {β : Type} (f : ℕ → β) (d : β) {m k : ℕ} (hk : k < m) :
    ((List.range m).map f).getD k d = f k := by
  rw [List.getD_eq_getElem?_getD, List.getElem?_map, List.getElem?_range hk]; rfl

theorem mem_friItems {K nq : ℕ} {x : ℕ × ℕ} (hx : x ∈ friItems K nq) : x.1 < K ∧ x.2 < nq := by
  unfold friItems at hx
  obtain ⟨l, hl, hx⟩ := List.mem_flatMap.mp hx
  obtain ⟨i, hi, rfl⟩ := List.mem_map.mp hx
  exact ⟨List.mem_range.mp hl, List.mem_range.mp hi⟩

theorem fromBase_bit {x : F} (hx : x = 0 ∨ x = 1) :
    (QM31.fromBase x = 0 ↔ x = 0) := by
  rcases hx with rfl | rfl
  · exact ⟨fun _ => rfl, fun _ => rfl⟩
  · exact ⟨fun h => absurd h (fromBase_ne_zero one_ne_zero), fun h => absurd h one_ne_zero⟩

theorem fromBase_bit01 {x : F} (hx : x = 0 ∨ x = 1) :
    QM31.fromBase x = 0 ∨ QM31.fromBase x = 1 := by
  rcases hx with rfl | rfl
  · exact Or.inl rfl
  · exact Or.inr rfl

/-- What phase 6 establishes, per layer `l < L − 1` and query `i < nq`:
the layer values `V`, from the FRI input to the last-layer constant,
each bit-selected from its coset, which folds at the spec coordinate
into the next value and hashes to the layer root along the position's
upper digits. -/
def P6Facts (ρ : ℕ → QM31) (L nq : ℕ) (pos : ℕ → ℕ) (input alphas : List ℕ)
    (wit : ℕ → ℕ → ℕ × ℕ) (lastCoef : ℕ) (wr : ℕ → List Blake2s.Word)
    (sws : ℕ → ℕ → List (List Blake2s.Word)) : Prop :=
  ∃ V : ℕ → ℕ → QM31,
    (∀ i, i < nq → V 0 i = ρ (input.getD i 0)) ∧
    (∀ i, i < nq → V (L - 1) i = ρ lastCoef) ∧
    ∀ l, l < L - 1 → ∀ i, i < nq →
      V l i = (if pos i / 2 ^ l % 2 = 0 then ρ (wit l i).1 else ρ (wit l i).2) ∧
      Fri.foldLinePair (ρ (wit l i).1) (ρ (wit l i).2) (ρ (alphas.getD l 0))
        (specFoldCoord (fun t => pos i / 2 ^ t % 2) L l) = .ok (V (l + 1) i) ∧
      wordsBytes (wr l) = pathRoot
        (Merkle.nodeHash (FriBatch.lq (ρ (wit l i).1)) (FriBatch.lq (ρ (wit l i).2)))
        ((List.range (L - 1 - l)).map fun t => pos i / 2 ^ (l + 1 + t) % 2)
        ((sws l i).map wordsBytes)

set_option maxHeartbeats 16000000 in
theorem phase6G_sound {ρ : ℕ → QM31} {zero one L nq : ℕ} {bits : List SimdReg}
    {points : PointSimd} {sbits : List (List ℕ)} {input alphas : List ℕ}
    {wit : ℕ → ℕ → ℕ × ℕ} {roots : List (List ℕ)} {auth : ℕ → ℕ → List (List ℕ)}
    {lastCoef n : ℕ} (pos : ℕ → ℕ) (wr : ℕ → List Blake2s.Word)
    (sws : ℕ → ℕ → List (List Blake2s.Word))
    (hzero : ρ zero = 0) (hone : ρ one = 1) (hL2 : 2 ≤ L) (hL30 : L ≤ 30)
    (hbl : L ≤ bits.length)
    (hshapes : ∀ b ∈ bits, BitShape b nq points.x.data.length)
    (hp : points.Shape nq points.x.data.length)
    (hlanes : ∀ t, t < L → ∀ i, i < nq →
      SimdReg.lane ρ (bits.getD t dummySimd) i = 0 ∨ SimdReg.lane ρ (bits.getD t dummySimd) i = 1)
    (hbitd : ∀ t, t < L → ∀ i, i < nq → bitNat ρ (bits.getD t dummySimd) i = pos i / 2 ^ t % 2)
    (hposL : ∀ i, i < nq → pos i < 2 ^ L)
    (hpoint : ∀ i, i < nq → PointSimd.lane ρ points i
      = (canonicDomain L).at' (bitReverseIndex (pos i) L))
    (hsb : ∀ t, t < L → ∀ i, i < nq →
      ρ ((sbits.getD t []).getD i 0) = QM31.fromBase (SimdReg.lane ρ (bits.getD t dummySimd) i))
    (hinput : input.length = nq)
    (hroot : ∀ l, l < L - 1 → RegsWords ρ (roots.getD l []) (wr l) ∧ (wr l).length = 8)
    (hsl : ∀ l, l < L - 1 → ∀ i, i < nq → (auth l i).length = (sws l i).length)
    (hsibs : ∀ l, l < L - 1 → ∀ i, i < nq → ∀ k, k < (auth l i).length →
      RegsWords ρ ((auth l i).getD k []) ((sws l i).getD k []) ∧ ((sws l i).getD k []).length = 8)
    (h : AllHold ρ (phase6G zero one L nq bits points sbits input alphas wit roots auth
      lastCoef n).ops) :
    P6Facts ρ L nq pos input alphas wit lastCoef wr sws := by
  unfold phase6G at h
  set TC := twiddleChain1 zero points.x.data.length nq (bits.getD 0 dummySimd) points
    ((bits.drop 1).take (L - 2)) n with hTCdef
  rw [allHold_seq] at h
  obtain ⟨hTC, h⟩ := h
  beta_reduce at h
  set UA := unpackAllG nq TC.res TC.next with hUAdef
  rw [allHold_seq] at h
  obtain ⟨hUA, h⟩ := h
  beta_reduce at h
  rw [allHold_seq] at h
  obtain ⟨hCL, hFD⟩ := h
  beta_reduce at hFD
  -- Bit facts.
  have hbit01 : ∀ t, t < L → ∀ i, i < nq →
      ρ ((sbits.getD t []).getD i 0) = 0 ∨ ρ ((sbits.getD t []).getD i 0) = 1 := by
    intro t ht i hi
    rw [hsb t ht i hi]
    exact fromBase_bit01 (hlanes t ht i hi)
  have hbitz : ∀ t, t < L → ∀ i, i < nq →
      (ρ ((sbits.getD t []).getD i 0) = 0 ↔ pos i / 2 ^ t % 2 = 0) := by
    intro t ht i hi
    rw [hsb t ht i hi, fromBase_bit (hlanes t ht i hi), ← hbitd t ht i hi]
    unfold bitNat
    by_cases hz : SimdReg.lane ρ (bits.getD t dummySimd) i = 0 <;> simp [hz]
  have hqbit : ∀ t, t < L → ∀ i, i < nq →
      qbit (ρ ((sbits.getD t []).getD i 0)) = pos i / 2 ^ t % 2 := by
    intro t ht i hi
    have hd : pos i / 2 ^ t % 2 < 2 := Nat.mod_lt _ (by norm_num)
    unfold qbit
    by_cases hz : ρ ((sbits.getD t []).getD i 0) = 0
    · rw [if_pos hz]; exact ((hbitz t ht i hi).mp hz).symm
    · rw [if_neg hz]
      have := mt (hbitz t ht i hi).mpr hz
      omega
  -- The twiddles.
  have hrestl : ((bits.drop 1).take (L - 2)).length = L - 2 := by
    simp; omega
  have hrestget : ∀ t, t < L - 2 →
      ((bits.drop 1).take (L - 2)).getD t dummySimd = bits.getD (t + 1) dummySimd := by
    intro t ht
    rw [getD_take' _ _ ht, List.getD_eq_getElem?_getD, List.getElem?_drop,
      ← List.getD_eq_getElem?_getD, Nat.add_comm]
  have hrestmem : ∀ r ∈ (bits.drop 1).take (L - 2), ∃ t, t < L - 2 ∧ r = bits.getD (t + 1) dummySimd := by
    intro r hr
    obtain ⟨t, ht, rfl⟩ := List.getElem_of_mem hr
    rw [hrestl] at ht
    refine ⟨t, ht, ?_⟩
    rw [← hrestget t ht, List.getD_eq_getElem?_getD, List.getElem?_eq_getElem (by rw [hrestl]; exact ht)]
    rfl
  have hb0mem : bits.getD 0 dummySimd ∈ bits := by
    rw [List.getD_eq_getElem?_getD, List.getElem?_eq_getElem (by omega)]
    exact List.getElem_mem _
  have hbtmem : ∀ t, t < bits.length → bits.getD t dummySimd ∈ bits := by
    intro t ht
    rw [List.getD_eq_getElem?_getD, List.getElem?_eq_getElem ht]
    exact List.getElem_mem _
  obtain ⟨hTCl, -⟩ := twiddleChain1_sound hzero (hshapes _ hb0mem) hp
    (fun r hr => by obtain ⟨t, ht, rfl⟩ := hrestmem r hr; exact hshapes _ (hbtmem _ (by omega))) hTC
  rw [hrestl] at hTCl
  have htw : ∀ l, l < L - 1 → ∀ i, i < nq →
      SimdReg.lane ρ (TC.res.getD l dummySimd) i
        * specFoldCoord (fun t => pos i / 2 ^ t % 2) L l = 1 := by
    intro l hl i hi
    have hdig : ∀ t, pos i / 2 ^ t % 2 ≤ 1 := fun t => by omega
    exact twiddleChain1_spec' hL2 hL30 hzero (hshapes _ hb0mem) hp
      (fun r hr => by obtain ⟨t, ht, rfl⟩ := hrestmem r hr; exact hshapes _ (hbtmem _ (by omega)))
      (by rw [hrestl]; omega) hTC i hi _ hdig (hlanes 0 (by omega) i hi)
      (fun r hr => by obtain ⟨t, ht, rfl⟩ := hrestmem r hr; exact hlanes _ (by omega) i hi)
      (hbitd 0 (by omega) i hi)
      (fun t ht => by rw [hrestl] at ht; rw [hrestget t ht]; exact hbitd _ (by omega) i hi)
      (by rw [hpoint i hi, digitSum, Nat.mod_eq_of_lt (hposL i hi)]) l (by rw [hrestl]; omega)
  obtain ⟨-, huav⟩ := unpackAllG_sound TC.res TC.next hUA
  -- The coset checks.
  have hcl := cosetLoopG_sound (fun x => x.1 < L - 1 ∧ x.2 < nq) wr sws
    (fun x hx => hroot x.1 hx.1) (fun x hx => hsl x.1 hx.1 x.2 hx.2)
    (fun x hx => hsibs x.1 hx.1 x.2 hx.2)
    (fun x hx b hb => by
      unfold friPathBits at hb
      obtain ⟨t, ht, rfl⟩ := List.mem_map.mp hb
      exact hbit01 _ (by have := List.mem_range.mp ht; omega) _ hx.2)
    (friItems (L - 1) nq) _ (fun x hx => mem_friItems hx) hCL
  -- The fold walk.
  unfold friDecommit1 at hFD
  rw [allHold_append] at hFD
  obtain ⟨hW, hE⟩ := hFD
  set layers := friLayersOf alphas wit sbits UA.res (L - 1) nq with hlayersdef
  have hlget : ∀ l, l < L - 1 → layers.getD l default = (alphas.getD l 0, (List.range nq).map fun i =>
      ((wit l i).1, (wit l i).2, (sbits.getD l []).getD i 0, (UA.res.getD l []).getD i 0)) :=
    fun l hl => getD_rmap _ _ hl
  have hqget : ∀ l, l < L - 1 → ∀ i, i < nq → (layers.getD l default).2.getD i default
      = ((wit l i).1, (wit l i).2, (sbits.getD l []).getD i 0, (UA.res.getD l []).getD i 0) := by
    intro l hl i hi
    rw [hlget l hl]
    exact getD_rmap _ _ hi
  have hll : layers.length = L - 1 := by simp [hlayersdef, friLayersOf]
  set xss := (List.range (L - 1)).map fun l => (List.range nq).map fun i =>
    specFoldCoord (fun t => pos i / 2 ^ t % 2) L l with hxssdef
  obtain ⟨hchain, hwl⟩ := friLayers1_sound hone layers xss input _
    (by rw [hll]; simp [hxssdef]) hinput
    (fun l hl => by rw [hll] at hl; rw [hlget l hl]; simp)
    (fun l hl i hi => by
      rw [hll] at hl; rw [hqget l hl i hi]; exact hbit01 l (by omega) i hi)
    (fun l hl i hi => by
      rw [hll] at hl; rw [hqget l hl i hi]
      show ρ ((UA.res.getD l []).getD i 0) * QM31.fromBase ((xss.getD l []).getD i 0) = 1
      rw [hxssdef, getD_rmap _ _ hl, getD_rmap _ _ hi]
      exact scalar_inverts (huav l (by rw [hTCl]; omega) i hi) (htw l hl i hi))
    hW
  obtain ⟨V, hV0, hVL, hV⟩ := chain1_get hchain
  have hlast := lastLayerEqs_sound hE
  refine ⟨fun l i => ρ ((V l).getD i 0), fun i hi => by beta_reduce; rw [hV0], fun i hi => ?_, ?_⟩
  · beta_reduce
    rw [← hll, hVL]
    refine hlast _ ?_
    rw [List.getD_eq_getElem?_getD, List.getElem?_eq_getElem (by rw [hwl]; exact hi)]
    exact List.getElem_mem _
  intro l hl i hi
  obtain ⟨hl1, -, hsel, hfold⟩ := hV l (by rw [hll]; exact hl)
  have hlen : i < (layers.getD l default).2.length := by rw [hlget l hl]; simpa using hi
  beta_reduce
  refine ⟨?_, ?_, ?_⟩
  · have := hsel i hlen
    rw [hqget l hl i hi] at this
    simp only at this
    rw [this]
    by_cases hz : ρ ((sbits.getD l []).getD i 0) = 0
    · rw [if_pos hz, if_pos ((hbitz l (by omega) i hi).mp hz)]
    · rw [if_neg hz, if_neg (mt (hbitz l (by omega) i hi).mpr hz)]
  · have := hfold i hlen
    rw [hqget l hl i hi, hlget l hl, hxssdef, getD_rmap _ _ hl, getD_rmap _ _ hi] at this
    exact this
  · have := hcl (l, i) (by
      unfold friItems
      exact List.mem_flatMap.mpr ⟨l, List.mem_range.mpr hl, List.mem_map.mpr ⟨i, List.mem_range.mpr hi, rfl⟩⟩)
    rw [this]
    unfold friPathBits
    rw [List.map_map]
    congr 1
    refine List.map_congr_left fun t ht => ?_
    exact hqbit _ (by have := List.mem_range.mp ht; omega) i hi

end StwoVerifier.Bridge
