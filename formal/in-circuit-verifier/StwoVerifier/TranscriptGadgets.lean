/-
**Transcript-phase channel gadgets** of `stark_verifier/verify.zig`:
`draw_qm31`, `fri_commit`'s root/alpha loop, the query-selection draws
(`get_query_selection_input_from_channel`), and the output-digest claim
(`unpack_qm31s_to_u32_words` then `mix_u32s`).

Channel states correspond through `ChDigest` (digest wires) plus the
static draw counter, exactly as for the single methods
(`ChannelGadgets.lean`).
-/
import StwoVerifier.PowGadget
import StwoVerifier.SelectQueries

namespace StwoVerifier.Gadgets

open StwoVerifier StwoVerifier.Gates

/-- The draw hash at state `s`. -/
def drawH (s : Channel.St) : Channel.Bytes :=
  Channel.chHash true (s.digest ++ Channel.u32Le s.nDraws ++ [0])

/-- Draw word `k` at state `s`. -/
def dw (s : Channel.St) (k : ℕ) : ℕ := Channel.wordAt (drawH s) k

theorem dw_lt (s : Channel.St) {k : ℕ} (hk : k < 8) : dw s k < P := by
  unfold dw drawH
  rw [chHash_wordAt _ hk]
  exact Nat.mod_lt _ (by unfold P; norm_num)

set_option maxHeartbeats 1000000 in
/-- The two drawn felts, coordinate by coordinate. -/
theorem drawTwo_vals {ρ : ℕ → QM31} {low high n : ℕ} {s : Channel.St}
    (hd : ChDigest ρ low high s.digest) (hdlen : s.digest.length = 32)
    (hnd : s.nDraws < P) (h : AllHold ρ (drawTwoQm31sG low high s.nDraws n).ops) :
    ρ (drawTwoQm31sG low high s.nDraws n).res.1
      = QM31.fromM31s ((dw s 0 : ℕ) : F) ((dw s 1 : ℕ) : F) ((dw s 2 : ℕ) : F)
          ((dw s 3 : ℕ) : F) ∧
    ρ (drawTwoQm31sG low high s.nDraws n).res.2
      = QM31.fromM31s ((dw s 4 : ℕ) : F) ((dw s 5 : ℕ) : F) ((dw s 6 : ℕ) : F)
          ((dw s 7 : ℕ) : F) := by
  have hdraw := drawTwoQm31sG_sound hd hdlen hnd h
  rw [drawSecureFelts_two] at hdraw
  simp only [Option.some.injEq, Prod.mk.injEq, List.cons.injEq, and_true] at hdraw
  exact ⟨hdraw.1.symm, hdraw.2.symm⟩

/-- **`draw_qm31`** is `drawSecureFelt`. -/
theorem drawQm31_sound {ρ : ℕ → QM31} {low high n : ℕ} {s : Channel.St}
    (hd : ChDigest ρ low high s.digest) (hdlen : s.digest.length = 32)
    (hnd : s.nDraws < P) (h : AllHold ρ (drawTwoQm31sG low high s.nDraws n).ops) :
    Channel.drawSecureFelt true s
      = some (ρ (drawTwoQm31sG low high s.nDraws n).res.1, ⟨s.digest, s.nDraws + 1⟩) := by
  rw [drawSecureFelt_m31, (drawTwo_vals hd hdlen hnd h).1]
  rfl

/-! ### `fri_commit`'s layer loop -/

/-- Per layer root: `mix_commitment`, then `draw_qm31` (counter 0). -/
noncomputable def friLoopG : ℕ → ℕ → List (List ℕ) → ℕ → Out ((ℕ × ℕ) × List ℕ)
  | low, high, [], n => ⟨[], ((low, high), []), n⟩
  | low, high, r :: rs, n =>
    let m := mixCommitmentG low high r n
    let d := drawTwoQm31sG m.res.1 m.res.2 0 m.next
    let t := friLoopG m.res.1 m.res.2 rs d.next
    ⟨m.ops ++ d.ops ++ t.ops, (t.res.1, d.res.1 :: t.res.2), t.next⟩

/-- The spec transcript of the layer loop. -/
def friTr : Channel.St → List Channel.Bytes → List QM31 × Channel.St
  | s, [] => ([], s)
  | s, r :: rs =>
    match Channel.drawSecureFelt true (Channel.mixRoot true s r) with
    | some (a, s2) => let t := friTr s2 rs; (a :: t.1, t.2)
    | none => ([], s)

theorem mixRoot_len (s : Channel.St) (r : Channel.Bytes) :
    (Channel.mixRoot true s r).digest.length = 32 := chHash_true_length _

/-- The root registers of a 32-byte root. -/
def RootRegs (ρ : ℕ → QM31) (regs : List ℕ) (root : Channel.Bytes) : Prop :=
  root.length = 32 ∧ RegsWords ρ regs ((Channel.digestWords root).map (BitVec.ofNat 32))

theorem friLoopG_sound {ρ : ℕ → QM31} :
    ∀ (roots : List Channel.Bytes) (rregs : List (List ℕ)) (low high n : ℕ)
      (s : Channel.St),
      rregs.length = roots.length →
      (∀ i, i < roots.length → RootRegs ρ (rregs.getD i []) (roots.getD i [])) →
      ChDigest ρ low high s.digest → s.digest.length = 32 →
      AllHold ρ (friLoopG low high rregs n).ops →
      ChDigest ρ (friLoopG low high rregs n).res.1.1 (friLoopG low high rregs n).res.1.2
        (friTr s roots).2.digest ∧
      (friTr s roots).2.digest.length = 32 ∧
      (friLoopG low high rregs n).res.2.map ρ = (friTr s roots).1
  | [], [], low, high, n, s, _, _, hd, hdl, _ => ⟨hd, hdl, rfl⟩
  | [], _ :: _, _, _, _, _, hl, _, _, _, _ => by simp at hl
  | _ :: _, [], _, _, _, _, hl, _, _, _, _ => by simp at hl
  | r :: rs, rr :: rrs, low, high, n, s, hl, hroots, hd, hdl, h => by
    set m := mixCommitmentG low high rr n with hm
    set d := drawTwoQm31sG m.res.1 m.res.2 0 m.next with hdd
    rw [show (friLoopG low high (rr :: rrs) n).ops =
      m.ops ++ d.ops ++ (friLoopG m.res.1 m.res.2 rrs d.next).ops from rfl,
      allHold_append, allHold_append] at h
    obtain ⟨⟨hmh, hdh⟩, ht⟩ := h
    obtain ⟨hr32, hrr⟩ := hroots 0 (by simp)
    have hmix := mixCommitmentG_sound hd hdl hr32 hrr hmh
    set s1 := Channel.mixRoot true s r with hs1
    have hs1d : ChDigest ρ m.res.1 m.res.2 (⟨s1.digest, 0⟩ : Channel.St).digest := hmix
    have hdraw : Channel.drawSecureFelt true s1 = some (ρ d.res.1, ⟨s1.digest, 1⟩) :=
      drawQm31_sound (s := ⟨s1.digest, 0⟩) hs1d (mixRoot_len s r) (by unfold P; norm_num) hdh
    obtain ⟨ihd, ihl, ihv⟩ := friLoopG_sound rs rrs m.res.1 m.res.2 d.next
      ⟨s1.digest, 1⟩ (by simpa using hl)
      (fun i hi => hroots (i + 1) (by simp; omega)) hmix (mixRoot_len s r) ht
    have htr : friTr s (r :: rs) = (ρ d.res.1 :: (friTr ⟨s1.digest, 1⟩ rs).1,
        (friTr ⟨s1.digest, 1⟩ rs).2) := by
      show (match Channel.drawSecureFelt true s1 with
        | some (a, s2) => let t := friTr s2 rs; (a :: t.1, t.2)
        | none => ([], s)) = _
      rw [hdraw]
    rw [htr]
    refine ⟨ihd, ihl, ?_⟩
    show (d.res.1 :: (friLoopG m.res.1 m.res.2 rrs d.next).res.2).map ρ = _
    rw [List.map_cons, ihv]

/-! ### The query-selection draws -/

/-- `k` successive `draw_two_qm31s` from counter `start`. -/
noncomputable def queryDrawsG (low high : ℕ) : ℕ → ℕ → ℕ → Out (List ℕ)
  | 0, _, n => ⟨[], [], n⟩
  | k + 1, start, n =>
    let d := drawTwoQm31sG low high start n
    let r := queryDrawsG low high k (start + 1) d.next
    ⟨d.ops ++ r.ops, d.res.1 :: d.res.2 :: r.res, r.next⟩

theorem queryDrawsG_sound {ρ : ℕ → QM31} {low high : ℕ} {s : Channel.St}
    (hd : ChDigest ρ low high s.digest) (hdlen : s.digest.length = 32) :
    ∀ (k start n : ℕ), start + k < P →
      AllHold ρ (queryDrawsG low high k start n).ops →
      (queryDrawsG low high k start n).res.length = 2 * k ∧
      ∀ j, j < 8 * k →
        coord (ρ ((queryDrawsG low high k start n).res.getD (j / 4) 0)) (j % 4)
          = ((dw ⟨s.digest, start + j / 8⟩ (j % 8) : ℕ) : F) := by
  intro k
  induction k with
  | zero => intro start n _ _; exact ⟨rfl, fun j hj => absurd hj (by omega)⟩
  | succ k ih =>
    intro start n hk h
    set d := drawTwoQm31sG low high start n with hdd
    rw [show (queryDrawsG low high (k + 1) start n).ops =
      d.ops ++ (queryDrawsG low high k (start + 1) d.next).ops from rfl,
      allHold_append] at h
    obtain ⟨hdh, hr⟩ := h
    obtain ⟨ihl, ihv⟩ := ih (start + 1) d.next (by omega) hr
    have hv := drawTwo_vals (s := ⟨s.digest, start⟩) hd hdlen (show start < P by omega) hdh
    have hres : (queryDrawsG low high (k + 1) start n).res
        = d.res.1 :: d.res.2 :: (queryDrawsG low high k (start + 1) d.next).res := rfl
    refine ⟨by rw [hres]; simp [ihl]; ring, fun j hj => ?_⟩
    rw [hres]
    by_cases h8 : j < 8
    · by_cases h4 : j < 4
      · rw [show j / 4 = 0 by omega, List.getD_cons_zero, hv.1,
          show j / 8 = 0 by omega, Nat.add_zero, show j % 8 = j by omega]
        interval_cases j <;> rfl
      · rw [show j / 4 = 1 by omega, show (1 : ℕ) = 0 + 1 from rfl, List.getD_cons_succ,
          List.getD_cons_zero, hv.2, show j / 8 = 0 by omega, Nat.add_zero]
        interval_cases j <;> rfl
    · rw [show j / 4 = (j - 8) / 4 + 2 by omega, List.getD_cons_succ, List.getD_cons_succ,
        show j % 4 = (j - 8) % 4 by omega]
      rw [ihv (j - 8) (by omega), show start + 1 + (j - 8) / 8 = start + j / 8 by omega,
        show (j - 8) % 8 = j % 8 by omega]

end StwoVerifier.Gadgets
