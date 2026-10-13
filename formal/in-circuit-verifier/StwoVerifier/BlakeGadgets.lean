/-
**The in-circuit Blake2s, part 1: the round walk**
(`src/frontends/circuit/builder/blake.zig`, stwo-zig `4afa09dbf`).

`blake2s_u32s` runs the compression in dedicated gates: one `BlakeGGate`
per G application (the whole RFC 7693 mixing function on `u32` limb
wires), ten rounds of eight, then a `TripleXor` per chaining word. The
gates' semantics (`Circuit::check`) are stated against the spec's
`Blake2s.mix`, so the round walk here is index bookkeeping: the
register state list tracks the spec's working vector word for word
(`RegsWords`), `gStepG` is `gStep`, and `stepsG k` is `steps k`.
-/
import StwoVerifier.Gates

namespace StwoVerifier.Gadgets

open StwoVerifier StwoVerifier.Gates

/-! ### Words and limb registers -/

theorem packW_isU32 (w : Blake2s.Word) : IsU32 (packW w) := by
  refine ⟨?_, ?_, rfl⟩
  · show (((w.toNat % 65536 : ℕ) : F)).val < 65536
    rw [ZMod.val_cast_of_lt (by unfold P; omega)]
    omega
  · show (((w.toNat / 65536 : ℕ) : F)).val < 65536
    have hlt := w.isLt
    rw [ZMod.val_cast_of_lt (by unfold P; omega)]
    omega

theorem wordOf_packW (w : Blake2s.Word) : wordOf (packW w) = w := by
  have hlt := w.isLt
  show BitVec.ofNat 32 ((((w.toNat % 65536 : ℕ) : F)).val
    + 65536 * (((w.toNat / 65536 : ℕ) : F)).val) = w
  rw [ZMod.val_cast_of_lt (by unfold P; omega),
    ZMod.val_cast_of_lt (by unfold P; omega),
    Nat.mod_add_div, BitVec.ofNat_toNat, BitVec.setWidth_eq]

/-! ### `getD` through `set` -/

theorem getD_set_self {α : Type} {l : List α} {i : ℕ} {a d : α}
    (h : i < l.length) : (l.set i a).getD i d = a := by
  simp [List.getD_eq_getElem?_getD, List.getElem?_set, h]

theorem getD_set_ne {α : Type} {l : List α} {i j : ℕ} {a d : α}
    (h : i ≠ j) : (l.set i a).getD j d = l.getD j d := by
  simp [List.getD_eq_getElem?_getD, List.getElem?_set, h]

/-! ### The gates -/

/-- One `TripleXor` gate. -/
def tripleXorG (a b c n : ℕ) : Out ℕ := ⟨[.tripleXor n a b c], n, n + 1⟩

theorem tripleXorG_sound {ρ : ℕ → QM31} {a b c n : ℕ}
    (h : AllHold ρ (tripleXorG a b c n).ops) :
    ρ (tripleXorG a b c n).res
      = packW (wordOf (ρ a) ^^^ wordOf (ρ b) ^^^ wordOf (ρ c)) := by
  have h1 := h (.tripleXor n a b c) List.mem_cons_self
  exact h1.2.2.2

/-! ### The register ↔ word state correspondence -/

/-- The register list carries exactly these words, limb-packed. -/
structure RegsWords (ρ : ℕ → QM31) (regs : List ℕ) (ws : List Blake2s.Word) :
    Prop where
  len : regs.length = ws.length
  val : ∀ j, j < regs.length → ρ (regs.getD j 0) = packW (ws.getD j 0)

/-- The G-indices are in range and pairwise distinct. -/
theorem gIdx_facts : ∀ g, g < 8 →
    (Blake2s.gIdx g).1 < 16 ∧ (Blake2s.gIdx g).2.1 < 16 ∧
    (Blake2s.gIdx g).2.2.1 < 16 ∧ (Blake2s.gIdx g).2.2.2 < 16 ∧
    (Blake2s.gIdx g).1 ≠ (Blake2s.gIdx g).2.1 ∧
    (Blake2s.gIdx g).1 ≠ (Blake2s.gIdx g).2.2.1 ∧
    (Blake2s.gIdx g).1 ≠ (Blake2s.gIdx g).2.2.2 ∧
    (Blake2s.gIdx g).2.1 ≠ (Blake2s.gIdx g).2.2.1 ∧
    (Blake2s.gIdx g).2.1 ≠ (Blake2s.gIdx g).2.2.2 ∧
    (Blake2s.gIdx g).2.2.1 ≠ (Blake2s.gIdx g).2.2.2 := by
  decide

theorem sigma_lt : ∀ r, r < 10 → ∀ i, i < 16 → Blake2s.sigma r i < 16 := by
  decide

/-! ### One G application -/

/-- One `BlakeGGate` application at round `r`, position `g`
(`blake2s_u32s`' inner loop body): the four state registers at the
G-indices and the two scheduled message registers in, four fresh
output registers written back. -/
def gStepG (vRegs mRegs : List ℕ) (r g n : ℕ) : Out (List ℕ) :=
  ⟨[.blakeG n (vRegs.getD (Blake2s.gIdx g).1 0)
      (vRegs.getD (Blake2s.gIdx g).2.1 0)
      (vRegs.getD (Blake2s.gIdx g).2.2.1 0)
      (vRegs.getD (Blake2s.gIdx g).2.2.2 0)
      (mRegs.getD (Blake2s.sigma r (2 * g)) 0)
      (mRegs.getD (Blake2s.sigma r (2 * g + 1)) 0)],
   ((((vRegs.set (Blake2s.gIdx g).1 n).set (Blake2s.gIdx g).2.1 (n + 1)).set
      (Blake2s.gIdx g).2.2.1 (n + 2)).set (Blake2s.gIdx g).2.2.2 (n + 3)),
   n + 4⟩

theorem gStepG_sound {ρ : ℕ → QM31} {vRegs mRegs : List ℕ}
    {ws ms : List Blake2s.Word} {r g n : ℕ}
    (hv : RegsWords ρ vRegs ws) (hm : RegsWords ρ mRegs ms)
    (h16 : ws.length = 16) (hm16 : ms.length = 16)
    (hr : r < 10) (hg : g < 8)
    (h : AllHold ρ (gStepG vRegs mRegs r g n).ops) :
    RegsWords ρ (gStepG vRegs mRegs r g n).res
      (Blake2s.gStep (fun i => ms.getD i 0) ws r g) := by
  obtain ⟨hia, hib, hic, hid, hab, hac, had, hbc, hbd, hcd⟩ := gIdx_facts g hg
  have hvlen : vRegs.length = 16 := by rw [hv.len, h16]
  have hgate := h (.blakeG n (vRegs.getD (Blake2s.gIdx g).1 0)
      (vRegs.getD (Blake2s.gIdx g).2.1 0)
      (vRegs.getD (Blake2s.gIdx g).2.2.1 0)
      (vRegs.getD (Blake2s.gIdx g).2.2.2 0)
      (mRegs.getD (Blake2s.sigma r (2 * g)) 0)
      (mRegs.getD (Blake2s.sigma r (2 * g + 1)) 0)) List.mem_cons_self
  obtain ⟨-, -, -, -, -, -, ho0, ho1, ho2, ho3⟩ := hgate
  -- The gate's input words are the spec state's words.
  have hwa : wordOf (ρ (vRegs.getD (Blake2s.gIdx g).1 0))
      = ws.getD (Blake2s.gIdx g).1 0 := by
    rw [hv.val _ (by omega), wordOf_packW]
  have hwb : wordOf (ρ (vRegs.getD (Blake2s.gIdx g).2.1 0))
      = ws.getD (Blake2s.gIdx g).2.1 0 := by
    rw [hv.val _ (by omega), wordOf_packW]
  have hwc : wordOf (ρ (vRegs.getD (Blake2s.gIdx g).2.2.1 0))
      = ws.getD (Blake2s.gIdx g).2.2.1 0 := by
    rw [hv.val _ (by omega), wordOf_packW]
  have hwd : wordOf (ρ (vRegs.getD (Blake2s.gIdx g).2.2.2 0))
      = ws.getD (Blake2s.gIdx g).2.2.2 0 := by
    rw [hv.val _ (by omega), wordOf_packW]
  have hmlen : mRegs.length = 16 := by rw [hm.len, hm16]
  have hs0 : Blake2s.sigma r (2 * g) < 16 := sigma_lt r hr _ (by omega)
  have hs1 : Blake2s.sigma r (2 * g + 1) < 16 := sigma_lt r hr _ (by omega)
  have hwf0 : wordOf (ρ (mRegs.getD (Blake2s.sigma r (2 * g)) 0))
      = ms.getD (Blake2s.sigma r (2 * g)) 0 := by
    rw [hm.val _ (by omega), wordOf_packW]
  have hwf1 : wordOf (ρ (mRegs.getD (Blake2s.sigma r (2 * g + 1)) 0))
      = ms.getD (Blake2s.sigma r (2 * g + 1)) 0 := by
    rw [hm.val _ (by omega), wordOf_packW]
  rw [hwa, hwb, hwc, hwd, hwf0, hwf1] at ho0 ho1 ho2 ho3
  have hspec : Blake2s.gStep (fun i => ms.getD i 0) ws r g
      = ((((ws.set (Blake2s.gIdx g).1
            (Blake2s.mix (ws.getD (Blake2s.gIdx g).1 0)
              (ws.getD (Blake2s.gIdx g).2.1 0) (ws.getD (Blake2s.gIdx g).2.2.1 0)
              (ws.getD (Blake2s.gIdx g).2.2.2 0)
              (ms.getD (Blake2s.sigma r (2 * g)) 0)
              (ms.getD (Blake2s.sigma r (2 * g + 1)) 0)).1).set
          (Blake2s.gIdx g).2.1
            (Blake2s.mix (ws.getD (Blake2s.gIdx g).1 0)
              (ws.getD (Blake2s.gIdx g).2.1 0) (ws.getD (Blake2s.gIdx g).2.2.1 0)
              (ws.getD (Blake2s.gIdx g).2.2.2 0)
              (ms.getD (Blake2s.sigma r (2 * g)) 0)
              (ms.getD (Blake2s.sigma r (2 * g + 1)) 0)).2.1).set
          (Blake2s.gIdx g).2.2.1
            (Blake2s.mix (ws.getD (Blake2s.gIdx g).1 0)
              (ws.getD (Blake2s.gIdx g).2.1 0) (ws.getD (Blake2s.gIdx g).2.2.1 0)
              (ws.getD (Blake2s.gIdx g).2.2.2 0)
              (ms.getD (Blake2s.sigma r (2 * g)) 0)
              (ms.getD (Blake2s.sigma r (2 * g + 1)) 0)).2.2.1).set
          (Blake2s.gIdx g).2.2.2
            (Blake2s.mix (ws.getD (Blake2s.gIdx g).1 0)
              (ws.getD (Blake2s.gIdx g).2.1 0) (ws.getD (Blake2s.gIdx g).2.2.1 0)
              (ws.getD (Blake2s.gIdx g).2.2.2 0)
              (ms.getD (Blake2s.sigma r (2 * g)) 0)
              (ms.getD (Blake2s.sigma r (2 * g + 1)) 0)).2.2.2) := rfl
  rw [hspec]
  constructor
  · show ((((vRegs.set _ n).set _ (n + 1)).set _ (n + 2)).set _ (n + 3)).length
      = _
    simp [hvlen, h16]
  · intro j hj
    have hj16 : j < 16 := by
      have hlen : (gStepG vRegs mRegs r g n).res.length = 16 := by
        show ((((vRegs.set _ n).set _ (n + 1)).set _ (n + 2)).set
          _ (n + 3)).length = 16
        simp [hvlen]
      omega
    show ρ ((((((vRegs.set (Blake2s.gIdx g).1 n).set (Blake2s.gIdx g).2.1
      (n + 1)).set (Blake2s.gIdx g).2.2.1 (n + 2)).set (Blake2s.gIdx g).2.2.2
      (n + 3))).getD j 0) = _
    by_cases h3 : j = (Blake2s.gIdx g).2.2.2
    · subst h3
      rw [getD_set_self (by simp [hvlen]; omega),
        getD_set_self (by simp [h16]; omega)]
      exact ho3
    · rw [getD_set_ne (fun he => h3 he.symm),
        getD_set_ne (fun he => h3 he.symm)]
      by_cases h2 : j = (Blake2s.gIdx g).2.2.1
      · subst h2
        rw [getD_set_self (by simp [hvlen]; omega),
          getD_set_self (by simp [h16]; omega)]
        exact ho2
      · rw [getD_set_ne (fun he => h2 he.symm),
          getD_set_ne (fun he => h2 he.symm)]
        by_cases h1 : j = (Blake2s.gIdx g).2.1
        · subst h1
          rw [getD_set_self (by simp [hvlen]; omega),
            getD_set_self (by simp [h16]; omega)]
          exact ho1
        · rw [getD_set_ne (fun he => h1 he.symm),
            getD_set_ne (fun he => h1 he.symm)]
          by_cases h0 : j = (Blake2s.gIdx g).1
          · subst h0
            rw [getD_set_self (by omega), getD_set_self (by rw [h16]; omega)]
            exact ho0
          · rw [getD_set_ne (fun he => h0 he.symm),
              getD_set_ne (fun he => h0 he.symm)]
            exact hv.val j (by omega)

/-- `gStep` keeps the state length. -/
theorem gStep_length (m : ℕ → Blake2s.Word) (v : List Blake2s.Word)
    (r g : ℕ) : (Blake2s.gStep m v r g).length = v.length := by
  show ((((v.set (Blake2s.gIdx g).1 _).set (Blake2s.gIdx g).2.1 _).set
    (Blake2s.gIdx g).2.2.1 _).set (Blake2s.gIdx g).2.2.2 _).length = v.length
  simp

/-! ### The 80-step round walk -/

/-- The first `k` G applications (`blake2s_u32s`' round loops,
flattened: step `k` is round `k / 8`, position `k % 8`). -/
def stepsG (mRegs : List ℕ) : ℕ → List ℕ → ℕ → Out (List ℕ)
  | 0, vRegs, n => ⟨[], vRegs, n⟩
  | k + 1, vRegs, n =>
    let prev := stepsG mRegs k vRegs n
    let st := gStepG prev.res mRegs (k / 8) (k % 8) prev.next
    ⟨prev.ops ++ st.ops, st.res, st.next⟩

theorem stepsG_sound {ρ : ℕ → QM31} {mRegs : List ℕ}
    {ms : List Blake2s.Word} (hm : RegsWords ρ mRegs ms)
    (hm16 : ms.length = 16) :
    ∀ (k : ℕ) (vRegs : List ℕ) (ws : List Blake2s.Word) (n : ℕ),
      k ≤ 80 → RegsWords ρ vRegs ws → ws.length = 16 →
      AllHold ρ (stepsG mRegs k vRegs n).ops →
      RegsWords ρ (stepsG mRegs k vRegs n).res
        (Blake2s.steps (fun i => ms.getD i 0) ws k) ∧
      (Blake2s.steps (fun i => ms.getD i 0) ws k).length = 16
  | 0, vRegs, ws, n, _, hv, h16, _ => ⟨hv, h16⟩
  | k + 1, vRegs, ws, n, hk, hv, h16, h => by
    rw [show (stepsG mRegs (k + 1) vRegs n).ops =
      (stepsG mRegs k vRegs n).ops ++
        (gStepG (stepsG mRegs k vRegs n).res mRegs (k / 8) (k % 8)
          (stepsG mRegs k vRegs n).next).ops from rfl,
      allHold_append] at h
    obtain ⟨hprev, hst⟩ := h
    obtain ⟨ihrw, ihlen⟩ := stepsG_sound hm hm16 k vRegs ws n (by omega)
      hv h16 hprev
    have hstep := gStepG_sound ihrw hm ihlen hm16 (by omega) (by omega) hst
    refine ⟨hstep, ?_⟩
    show (Blake2s.gStep _ _ _ _).length = 16
    rw [gStep_length, ihlen]

/-! ### One block's compression -/

theorem getD_map' {α β : Type} [Inhabited α] (f : α → β) (dflt : β)
    (l : List α) (i : ℕ) (hi : i < l.length) :
    (l.map f).getD i dflt = f (l.getD i default) := by
  rw [List.getD_eq_getElem?_getD, List.getElem?_map,
    List.getElem?_eq_getElem hi, List.getD_eq_getElem?_getD,
    List.getElem?_eq_getElem hi]
  rfl

private theorem list_ext_getD {l1 l2 : List Blake2s.Word}
    (hlen : l1.length = l2.length)
    (h : ∀ j, j < l1.length → l1.getD j 0 = l2.getD j 0) : l1 = l2 := by
  refine List.ext_getElem hlen fun j h1 h2 => ?_
  have h' := h j h1
  rw [List.getD_eq_getElem?_getD, List.getElem?_eq_getElem h1] at h'
  rw [List.getD_eq_getElem?_getD, List.getElem?_eq_getElem h2] at h'
  simpa using h'

/-- The constant working-vector words `v[8..16]` (`blake2s_u32s`' IV
constants with the byte counter and final flag folded in; `t1 = 0`). -/
def ivInit (t : ℕ) (f : Bool) (j : ℕ) : Blake2s.Word :=
  if j = 12 then Blake2s.IV 4 ^^^ BitVec.ofNat 32 t
  else if j = 13 then Blake2s.IV 5 ^^^ BitVec.ofNat 32 (t / 2 ^ 32)
  else if j = 14 then Blake2s.IV 6 ^^^ (if f then BitVec.allOnes 32 else 0)
  else Blake2s.IV (j - 8)

theorem initV_getD (hFun : ℕ → Blake2s.Word) (t : ℕ) (f : Bool) (j : ℕ)
    (hj : j < 16) :
    (Blake2s.initV hFun t f).getD j 0
      = if j < 8 then hFun j else ivInit t f j := by
  unfold Blake2s.initV
  rw [getD_map' _ (0 : Blake2s.Word) (List.range 16) j (by simpa using hj),
    show (List.range 16).getD j default = j from by
      rw [List.getD_eq_getElem?_getD,
        List.getElem?_eq_getElem (by simpa using hj)]
      simp]
  rfl

/-- The chaining xor row: `h'[i] = prev_h[i] ^^^ v[i] ^^^ v[i + 8]`. -/
def xorChain (hRegs vRegs : List ℕ) : List ℕ → ℕ → Out (List ℕ)
  | [], n => ⟨[], [], n⟩
  | i :: rest, n =>
    let x := tripleXorG (hRegs.getD i 0) (vRegs.getD i 0)
      (vRegs.getD (i + 8) 0) n
    let r := xorChain hRegs vRegs rest x.next
    ⟨x.ops ++ r.ops, x.res :: r.res, r.next⟩

theorem xorChain_sound {ρ : ℕ → QM31} {hRegs vRegs : List ℕ}
    {hws vws : List Blake2s.Word}
    (hh : RegsWords ρ hRegs hws) (hv : RegsWords ρ vRegs vws) :
    ∀ (idxs : List ℕ) (n : ℕ),
      (∀ i ∈ idxs, i < hRegs.length ∧ i + 8 < vRegs.length) →
      AllHold ρ (xorChain hRegs vRegs idxs n).ops →
      (xorChain hRegs vRegs idxs n).res.length = idxs.length ∧
      ∀ p, p < idxs.length →
        ρ ((xorChain hRegs vRegs idxs n).res.getD p 0)
          = packW (hws.getD (idxs.getD p 0) 0
              ^^^ vws.getD (idxs.getD p 0) 0
              ^^^ vws.getD (idxs.getD p 0 + 8) 0)
  | [], n, _, _ => ⟨rfl, fun p hp => absurd hp (by simp)⟩
  | i :: rest, n, hbound, h => by
    rw [show (xorChain hRegs vRegs (i :: rest) n).ops =
      (tripleXorG (hRegs.getD i 0) (vRegs.getD i 0)
        (vRegs.getD (i + 8) 0) n).ops ++
        (xorChain hRegs vRegs rest
          (tripleXorG (hRegs.getD i 0) (vRegs.getD i 0)
            (vRegs.getD (i + 8) 0) n).next).ops from rfl,
      allHold_append] at h
    obtain ⟨hx, hrest⟩ := h
    obtain ⟨hi1, hi2⟩ := hbound i List.mem_cons_self
    obtain ⟨ihlen, ihval⟩ := xorChain_sound hh hv rest _
      (fun i' hi' => hbound i' (List.mem_cons_of_mem _ hi')) hrest
    refine ⟨?_, fun p hp => ?_⟩
    · show (xorChain hRegs vRegs rest _).res.length + 1 = rest.length + 1
      rw [ihlen]
    cases p with
    | zero =>
      show ρ (tripleXorG (hRegs.getD i 0) (vRegs.getD i 0)
        (vRegs.getD (i + 8) 0) n).res = _
      rw [tripleXorG_sound hx, hh.val i hi1, hv.val i (by omega),
        hv.val (i + 8) hi2, wordOf_packW, wordOf_packW, wordOf_packW]
      rfl
    | succ p =>
      show ρ ((xorChain hRegs vRegs rest _).res.getD p 0) = _
      exact ihval p (by simpa using hp)

/-- One block (`blake2s_u32s`' loop body): the IV constants, the 80 G
steps, the chaining xors. -/
noncomputable def compressG (hRegs mRegs : List ℕ) (t : ℕ) (f : Bool)
    (n : ℕ) : Out (List ℕ) :=
  let consts : List Op :=
    (List.range 8).map fun j => .const (n + j) (packW (ivInit t f (8 + j)))
  let v0 : List ℕ := hRegs ++ (List.range 8).map fun j => n + j
  let st := stepsG mRegs 80 v0 (n + 8)
  let xs := xorChain hRegs st.res (List.range 8) st.next
  ⟨consts ++ st.ops ++ xs.ops, xs.res, xs.next⟩

set_option maxHeartbeats 1000000 in
/-- **One block computes the spec's compression**: the output registers
carry `Blake2s.compress` of the carried chaining and message words. -/
theorem compressG_sound {ρ : ℕ → QM31} {hRegs mRegs : List ℕ}
    {hws ms : List Blake2s.Word} {t n : ℕ} {f : Bool}
    (hh : RegsWords ρ hRegs hws) (hm : RegsWords ρ mRegs ms)
    (hh8 : hws.length = 8) (hm16 : ms.length = 16)
    (h : AllHold ρ (compressG hRegs mRegs t f n).ops) :
    (compressG hRegs mRegs t f n).res.length = 8 ∧
    ∀ i, i < 8 →
      ρ ((compressG hRegs mRegs t f n).res.getD i 0)
        = packW (Blake2s.compress (fun j => hws.getD j 0)
            (fun j => ms.getD j 0) t f i) := by
  replace h : AllHold ρ
      (((List.range 8).map fun j =>
          Op.const (n + j) (packW (ivInit t f (8 + j)))) ++
        (stepsG mRegs 80 (hRegs ++ (List.range 8).map fun j => n + j)
          (n + 8)).ops ++
        (xorChain hRegs
          (stepsG mRegs 80 (hRegs ++ (List.range 8).map fun j => n + j)
            (n + 8)).res (List.range 8)
          (stepsG mRegs 80 (hRegs ++ (List.range 8).map fun j => n + j)
            (n + 8)).next).ops) := h
  rw [allHold_append, allHold_append] at h
  obtain ⟨⟨hconsts, hsteps⟩, hxors⟩ := h
  have hhlen : hRegs.length = 8 := by rw [hh.len, hh8]
  -- The initial working vector's words.
  have hws0 : RegsWords ρ (hRegs ++ (List.range 8).map fun j => n + j)
      (hws ++ (List.range 8).map fun j => ivInit t f (8 + j)) := by
    refine ⟨by simp [hhlen, hh8], fun j hj => ?_⟩
    rw [List.length_append, List.length_map, List.length_range, hhlen] at hj
    by_cases hj8 : j < 8
    · rw [List.getD_eq_getElem?_getD, List.getElem?_append_left (by omega),
        ← List.getD_eq_getElem?_getD,
        List.getD_eq_getElem?_getD (l := hws ++ _),
        List.getElem?_append_left (by omega), ← List.getD_eq_getElem?_getD]
      exact hh.val j (by omega)
    · have hj' : j - 8 < 8 := by omega
      rw [List.getD_eq_getElem?_getD,
        List.getElem?_append_right (by omega),
        List.getElem?_map, hhlen,
        List.getElem?_range (by omega : j - 8 < 8)]
      rw [List.getD_eq_getElem?_getD (l := hws ++ _),
        List.getElem?_append_right (by omega), hh8,
        List.getElem?_map, List.getElem?_range (by omega : j - 8 < 8)]
      have hc := hconsts (.const (n + (j - 8)) (packW (ivInit t f (8 + (j - 8)))))
        (List.mem_map.mpr ⟨j - 8, by simp [hj'], rfl⟩)
      simp only [Holds] at hc
      simpa using hc
  -- The words list is the spec's initial vector.
  have hinit : hws ++ ((List.range 8).map fun j => ivInit t f (8 + j))
      = Blake2s.initV (fun j => hws.getD j 0) t f := by
    refine list_ext_getD (by simp [hh8, Blake2s.initV]) fun j h1 => ?_
    have hj16 : j < 16 := by
      have h1' := h1
      rw [List.length_append, List.length_map, List.length_range, hh8] at h1'
      omega
    rw [initV_getD _ t f j hj16]
    by_cases hj8 : j < 8
    · rw [if_pos hj8, List.getD_eq_getElem?_getD,
        List.getElem?_append_left (by omega), ← List.getD_eq_getElem?_getD]
    · rw [if_neg hj8, List.getD_eq_getElem?_getD,
        List.getElem?_append_right (by omega), hh8,
        List.getElem?_map, List.getElem?_range (by omega : j - 8 < 8)]
      simp only [Option.map_some, Option.getD_some]
      rw [show 8 + (j - 8) = j from by omega]
  obtain ⟨hstw, hstlen⟩ := stepsG_sound hm hm16 80
    (hRegs ++ (List.range 8).map fun j => n + j)
    (hws ++ (List.range 8).map fun j => ivInit t f (8 + j)) (n + 8)
    (by omega) hws0 (by simp [hh8]) hsteps
  rw [hinit] at hstw hstlen
  have hvlen : (stepsG mRegs 80 (hRegs ++ (List.range 8).map fun j => n + j)
      (n + 8)).res.length = 16 := by rw [hstw.len, hstlen]
  obtain ⟨hxlen, hxval⟩ := xorChain_sound hh hstw (List.range 8)
    (stepsG mRegs 80 (hRegs ++ (List.range 8).map fun j => n + j)
      (n + 8)).next
    (fun i hi => ⟨by rw [hhlen]; exact (List.mem_range.mp hi),
      by rw [hvlen]; have := List.mem_range.mp hi; omega⟩) hxors
  refine ⟨by rw [show (compressG hRegs mRegs t f n).res
      = (xorChain hRegs (stepsG mRegs 80
          (hRegs ++ (List.range 8).map fun j => n + j) (n + 8)).res
        (List.range 8) (stepsG mRegs 80
          (hRegs ++ (List.range 8).map fun j => n + j) (n + 8)).next).res
      from rfl, hxlen, List.length_range], fun i hi => ?_⟩
  have hri : (List.range 8).getD i 0 = i := by
    rw [List.getD_eq_getElem?_getD, List.getElem?_range hi]
    rfl
  have := hxval i (by simpa using hi)
  rw [hri] at this
  show ρ ((xorChain hRegs (stepsG mRegs 80
      (hRegs ++ (List.range 8).map fun j => n + j) (n + 8)).res
      (List.range 8) (stepsG mRegs 80
      (hRegs ++ (List.range 8).map fun j => n + j) (n + 8)).next).res.getD
      i 0) = _
  rw [this]
  rfl

/-! ### The block loop -/

/-- The word-level block chain, over the eight chaining words as a
list: per block the spec compression of the 16-word slice, the byte
counter at `min nBytes (64·(i+1))`, the final flag on the last block
(`blake2s_u32s`' loop, words instead of bytes). -/
def hashWordsL (ws : List Blake2s.Word) (nBytes : ℕ) :
    ℕ → ℕ → List Blake2s.Word → List Blake2s.Word
  | 0, _, hl => hl
  | k + 1, i, hl =>
    hashWordsL ws nBytes k (i + 1)
      ((List.range 8).map fun j =>
        Blake2s.compress (fun l => hl.getD l 0)
          (fun l => ((ws.drop (16 * i)).take 16).getD l 0)
          (min nBytes ((i + 1) * 64)) (k = 0) j)

theorem hashWordsL_length (ws : List Blake2s.Word) (nBytes : ℕ) :
    ∀ (k i : ℕ) (hl : List Blake2s.Word), hl.length = 8 →
      (hashWordsL ws nBytes k i hl).length = 8
  | 0, _, _, h8 => h8
  | k + 1, i, hl, _ => by
    show (hashWordsL ws nBytes k (i + 1) _).length = 8
    exact hashWordsL_length ws nBytes k (i + 1) _ (by simp)

/-- A contiguous slice of a tracked register list is tracked. -/
theorem regsWords_slice {ρ : ℕ → QM31} {regs : List ℕ}
    {ws : List Blake2s.Word} (h : RegsWords ρ regs ws) (a b : ℕ) :
    RegsWords ρ ((regs.drop a).take b) ((ws.drop a).take b) := by
  refine ⟨by simp [h.len], fun j hj => ?_⟩
  rw [List.length_take, List.length_drop] at hj
  have hjb : j < b := by omega
  have hja : a + j < regs.length := by omega
  rw [List.getD_eq_getElem?_getD, List.getElem?_take, if_pos hjb,
    List.getElem?_drop, ← List.getD_eq_getElem?_getD]
  rw [List.getD_eq_getElem?_getD (l := (ws.drop a).take b),
    List.getElem?_take, if_pos hjb, List.getElem?_drop,
    ← List.getD_eq_getElem?_getD]
  exact h.val (a + j) hja

/-- The block loop: `k` remaining blocks from index `i`. -/
noncomputable def blocksG (padded : List ℕ) (nBytes : ℕ) :
    ℕ → ℕ → List ℕ → ℕ → Out (List ℕ)
  | 0, _, hRegs, n => ⟨[], hRegs, n⟩
  | k + 1, i, hRegs, n =>
    let c := compressG hRegs ((padded.drop (16 * i)).take 16)
      (min nBytes ((i + 1) * 64)) (k = 0) n
    let r := blocksG padded nBytes k (i + 1) c.res c.next
    ⟨c.ops ++ r.ops, r.res, r.next⟩

theorem blocksG_sound {ρ : ℕ → QM31} {padded : List ℕ}
    {ws : List Blake2s.Word} {nBytes : ℕ}
    (hp : RegsWords ρ padded ws) :
    ∀ (k i : ℕ) (hRegs : List ℕ) (hws : List Blake2s.Word) (n : ℕ),
      RegsWords ρ hRegs hws → hws.length = 8 →
      16 * (i + k) ≤ ws.length →
      AllHold ρ (blocksG padded nBytes k i hRegs n).ops →
      RegsWords ρ (blocksG padded nBytes k i hRegs n).res
        (hashWordsL ws nBytes k i hws)
  | 0, i, hRegs, hws, n, hh, _, _, _ => hh
  | k + 1, i, hRegs, hws, n, hh, hh8, hlen, h => by
    rw [show (blocksG padded nBytes (k + 1) i hRegs n).ops =
      (compressG hRegs ((padded.drop (16 * i)).take 16)
        (min nBytes ((i + 1) * 64)) (k = 0) n).ops ++
        (blocksG padded nBytes k (i + 1)
          (compressG hRegs ((padded.drop (16 * i)).take 16)
            (min nBytes ((i + 1) * 64)) (k = 0) n).res
          (compressG hRegs ((padded.drop (16 * i)).take 16)
            (min nBytes ((i + 1) * 64)) (k = 0) n).next).ops from rfl,
      allHold_append] at h
    obtain ⟨hc, hr⟩ := h
    have hslice := regsWords_slice hp (16 * i) 16
    have hslen : ((ws.drop (16 * i)).take 16).length = 16 := by
      rw [List.length_take, List.length_drop]
      omega
    obtain ⟨hclen, hcval⟩ := compressG_sound hh hslice hh8 hslen hc
    have hcrw : RegsWords ρ
        (compressG hRegs ((padded.drop (16 * i)).take 16)
          (min nBytes ((i + 1) * 64)) (k = 0) n).res
        ((List.range 8).map fun j =>
          Blake2s.compress (fun l => hws.getD l 0)
            (fun l => ((ws.drop (16 * i)).take 16).getD l 0)
            (min nBytes ((i + 1) * 64)) (k = 0) j) := by
      refine ⟨by simp [hclen], fun j hj => ?_⟩
      have hj8 : j < 8 := by omega
      rw [getD_map' _ (0 : Blake2s.Word) (List.range 8) j (by simpa using hj8),
        show (List.range 8).getD j default = j from by
          rw [List.getD_eq_getElem?_getD, List.getElem?_range hj8]; rfl]
      exact hcval j hj8
    have ih := blocksG_sound hp k (i + 1) _ _ _ hcrw (by simp)
      (by omega) hr
    show RegsWords ρ (blocksG padded nBytes k (i + 1) _ _).res _
    exact ih

end StwoVerifier.Gadgets