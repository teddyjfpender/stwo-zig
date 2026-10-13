/-
**The statement's LogUp checks** (`circuit_statement.zig`
`publicLogupSum`, `stark_verifier/logup.zig` `combineTerm`,
`verify.zig` `validateLogupSum`).

`publicLogupG_sound`: with the output digest wires carrying the
statement's words in limb form and the `u` wire pinned, the emitted
gates make the spec's `publicLogupSum` succeed (every combined term is
nonzero — the `inv` gates force it) with the sum register's value.
`logupSumG_sound`: the closing check is the spec's
`pub + Σ claimed = 0`.
-/
import StwoVerifier.OodsResponses
import StwoVerifier.PowGadget
import StwoVerifier.CircuitVerify
import StwoVerifier.MerkleBatch

namespace StwoVerifier.Gadgets

open StwoVerifier StwoVerifier.Gates CircuitVerify

/-! ### `combine_term` -/

/-- Horner from the last element (`value·α + eᵢ`, top down). -/
def hornerG (alpha : ℕ) : List ℕ → ℕ → Out ℕ
  | [], n => ⟨[], 0, n⟩
  | [e], n => ⟨[], e, n⟩
  | e :: e' :: es, n =>
    let r := hornerG alpha (e' :: es) n
    ⟨r.ops ++ [.mul r.next r.res alpha, .add (r.next + 1) r.next e], r.next + 1, r.next + 2⟩

/-- The Horner value of an element. -/
def hornerVal (alpha : QM31) : List QM31 → QM31
  | [] => 0
  | [e] => e
  | e :: e' :: es => hornerVal alpha (e' :: es) * alpha + e

theorem hornerG_sound {ρ : ℕ → QM31} {alpha : ℕ} :
    ∀ (es : List ℕ) (n : ℕ), es ≠ [] → AllHold ρ (hornerG alpha es n).ops →
      ρ (hornerG alpha es n).res = hornerVal (ρ alpha) (es.map ρ)
  | [], _, hne, _ => absurd rfl hne
  | [e], _, _, _ => rfl
  | e :: e' :: es, n, _, h => by
    rw [show (hornerG alpha (e :: e' :: es) n).ops =
      (hornerG alpha (e' :: es) n).ops ++
        [.mul (hornerG alpha (e' :: es) n).next (hornerG alpha (e' :: es) n).res alpha,
         .add ((hornerG alpha (e' :: es) n).next + 1) (hornerG alpha (e' :: es) n).next e]
      from rfl, allHold_append] at h
    obtain ⟨h1, h2⟩ := h
    have hm := h2 _ List.mem_cons_self
    have ha := h2 _ (List.mem_cons_of_mem _ List.mem_cons_self)
    simp only [Holds] at hm ha
    show ρ ((hornerG alpha (e' :: es) n).next + 1) = _
    rw [ha, hm, hornerG_sound (e' :: es) n (List.cons_ne_nil _ _) h1]
    rfl

/-- The spec's reversed-fold `combineTerm` is Horner minus `z`. -/
theorem foldl_rev_horner (alpha : QM31) :
    ∀ (l : List QM31), l ≠ [] →
      (match l.reverse with
        | [] => (0 : QM31)
        | v :: rest => rest.foldl (fun acc e => acc * alpha + e) v) = hornerVal alpha l
  | [], h => absurd rfl h
  | [e], _ => rfl
  | e :: e' :: es, _ => by
    have ih := foldl_rev_horner alpha (e' :: es) (List.cons_ne_nil _ _)
    rw [List.reverse_cons]
    revert ih
    cases hr : (e' :: es).reverse with
    | nil => simp at hr
    | cons v rest =>
      intro ih
      dsimp only at ih
      simp only [List.cons_append, List.foldl_append, List.foldl_cons, List.foldl_nil]
      rw [ih]
      rfl

theorem combineTerm_eq (element : List QM31) (z alpha : QM31) (hne : element ≠ []) :
    combineTerm element z alpha = hornerVal alpha element - z := by
  unfold combineTerm
  have := foldl_rev_horner alpha element hne
  revert this
  cases hr : element.reverse with
  | nil => simp at hr; exact absurd hr hne
  | cons v rest => intro h; simp only at h ⊢; rw [h]

/-! ### `public_logup_sum` -/

def GATE_ID : ℕ := 378353459

/-- One public LogUp term: the address constant, the value's four lanes,
the combined element, `inv`. -/
noncomputable def logupEntryG (z alpha gate : ℕ) (addr value : ℕ) (n : ℕ) : Out ℕ :=
  let lanes := unpackFrom ⟨[value], 4⟩ 4 0 (n + 1)
  let hr := hornerG alpha ([gate, n] ++ lanes.res) lanes.next
  ⟨[.const n (QM31.fromBase ((addr : ℕ) : F))] ++ lanes.ops ++ hr.ops ++
    [.sub hr.next hr.res z, .inv (hr.next + 1) hr.next], hr.next + 1, hr.next + 2⟩

/-- The term loop with the running sum. -/
noncomputable def logupLoop (z alpha gate : ℕ) : ℕ → List (ℕ × ℕ) → ℕ → Out ℕ
  | sum, [], n => ⟨[], sum, n⟩
  | sum, (addr, value) :: rest, n =>
    let t := logupEntryG z alpha gate addr value n
    let r := logupLoop z alpha gate t.next rest (t.next + 1)
    ⟨t.ops ++ [.add t.next sum t.res] ++ r.ops, r.res, r.next⟩

/-- `public_logup_sum`: the gate id, the digest words at addresses
`3..11`, then `u` at address 2. -/
noncomputable def publicLogupG (zero z alpha : ℕ) (outs : List ℕ) (uW : ℕ) (n : ℕ) : Out ℕ :=
  let entries := (outs.zipIdx.map fun (x : ℕ × ℕ) => (3 + x.2, x.1)) ++ [(2, uW)]
  let l := logupLoop z alpha n zero entries (n + 1)
  ⟨[.const n gateFelt] ++ l.ops, l.res, l.next⟩

/-- The spec lanes of one entry. -/
def entryLanes (x : QM31) : List QM31 := (List.range 4).map fun c => QM31.fromBase (coord x c)

theorem logupEntryG_sound {ρ : ℕ → QM31} {z alpha gate addr value n : ℕ}
    (h : AllHold ρ (logupEntryG z alpha gate addr value n).ops) :
    combineTerm (ρ gate :: QM31.fromBase ((addr : ℕ) : F) :: entryLanes (ρ value)) (ρ z) (ρ alpha)
        ≠ 0 ∧
    ρ (logupEntryG z alpha gate addr value n).res
      = (combineTerm (ρ gate :: QM31.fromBase ((addr : ℕ) : F) :: entryLanes (ρ value))
          (ρ z) (ρ alpha))⁻¹ := by
  set lanes := unpackFrom ⟨[value], 4⟩ 4 0 (n + 1) with hlanes
  set hr := hornerG alpha ([gate, n] ++ lanes.res) lanes.next with hhr
  rw [show (logupEntryG z alpha gate addr value n).ops =
    [.const n (QM31.fromBase ((addr : ℕ) : F))] ++ lanes.ops ++ hr.ops ++
      [.sub hr.next hr.res z, .inv (hr.next + 1) hr.next] from rfl] at h
  simp only [allHold_append] at h
  obtain ⟨⟨⟨hc, hl⟩, hh⟩, hend⟩ := h
  have hc' : ρ n = QM31.fromBase ((addr : ℕ) : F) := hc _ List.mem_cons_self
  have hs : ρ hr.next = ρ hr.res - ρ z := hend _ List.mem_cons_self
  have hi : ρ hr.next * ρ (hr.next + 1) = QM31.one :=
    hend _ (List.mem_cons_of_mem _ List.mem_cons_self)
  obtain ⟨hll, hlv⟩ := unpackFrom_sound 4 0 (n + 1) hl
  have hll' : lanes.res.length = 4 := hll
  have hlmap : lanes.res.map ρ = entryLanes (ρ value) := by
    refine List.ext_getElem (by simp [hll', entryLanes]) fun c h1 h2 => ?_
    have hc4 : c < 4 := by rw [List.length_map, hll'] at h1; exact h1
    rw [List.getElem_map, ← List.getD_eq_getElem lanes.res 0 (by rw [hll']; exact hc4),
      hlv c hc4]
    simp only [entryLanes, List.getElem_map, List.getElem_range, Nat.zero_add]
    unfold SimdReg.lane
    rw [Nat.div_eq_of_lt hc4, Nat.mod_eq_of_lt hc4]
    rfl
  have hhv := hornerG_sound (alpha := alpha) ([gate, n] ++ lanes.res) lanes.next
    (by simp) hh
  have helem : ([gate, n] ++ lanes.res).map ρ
      = ρ gate :: QM31.fromBase ((addr : ℕ) : F) :: entryLanes (ρ value) := by
    rw [List.map_append, hlmap]
    simp [hc']
  have hct : combineTerm (ρ gate :: QM31.fromBase ((addr : ℕ) : F) :: entryLanes (ρ value))
      (ρ z) (ρ alpha) = ρ hr.next := by
    rw [combineTerm_eq _ _ _ (List.cons_ne_nil _ _), hs, hhv, helem]
  rw [hct]
  have hne : ρ hr.next ≠ 0 := by
    intro h0
    rw [h0, zero_mul] at hi
    exact absurd hi (by decide)
  refine ⟨hne, ?_⟩
  show ρ (hr.next + 1) = (ρ hr.next)⁻¹
  exact (eq_inv_of_mul_eq_one_right hi)

theorem entryLanes_packW (w : Blake2s.Word) :
    entryLanes (packW w) = [QM31.fromBase ((w.toNat % 2 ^ 16 : ℕ) : F),
      QM31.fromBase ((w.toNat / 2 ^ 16 : ℕ) : F), QM31.zero, QM31.zero] := rfl

theorem entryLanes_u :
    entryLanes (QM31.fromM31s 0 0 1 0) = [QM31.zero, QM31.zero, QM31.one, QM31.zero] := rfl

/-- The combined element of one circuit entry. -/
def entryTerm (ρ : ℕ → QM31) (gate z alpha : ℕ) (e : ℕ × ℕ) : QM31 :=
  combineTerm (ρ gate :: QM31.fromBase ((e.1 : ℕ) : F) :: entryLanes (ρ e.2)) (ρ z) (ρ alpha)

theorem logupLoop_sound {ρ : ℕ → QM31} {z alpha gate : ℕ} :
    ∀ (entries : List (ℕ × ℕ)) (sum n : ℕ) (acc : QM31), ρ sum = acc →
      AllHold ρ (logupLoop z alpha gate sum entries n).ops →
      (∀ e ∈ entries, entryTerm ρ gate z alpha e ≠ 0) ∧
      ρ (logupLoop z alpha gate sum entries n).res
        = entries.foldl (fun a e => a + (entryTerm ρ gate z alpha e)⁻¹) acc := by
  intro entries
  induction entries with
  | nil => intro sum n acc hs _; exact ⟨fun _ h => absurd h (by simp), hs⟩
  | cons e rest ih =>
    intro sum n acc hs h
    obtain ⟨addr, value⟩ := e
    set t := logupEntryG z alpha gate addr value n with htdef
    rw [show (logupLoop z alpha gate sum ((addr, value) :: rest) n).ops =
      t.ops ++ [.add t.next sum t.res] ++
        (logupLoop z alpha gate t.next rest (t.next + 1)).ops from rfl,
      allHold_append, allHold_append] at h
    obtain ⟨⟨ht, ha⟩, hr⟩ := h
    obtain ⟨hne, hval⟩ := logupEntryG_sound ht
    have ha' : ρ t.next = ρ sum + ρ t.res := ha _ List.mem_cons_self
    obtain ⟨ihne, ihv⟩ := ih t.next (t.next + 1) (acc + (entryTerm ρ gate z alpha (addr, value))⁻¹)
      (by rw [ha', hs, hval]; rfl) hr
    refine ⟨?_, ?_⟩
    swap
    · show ρ (logupLoop z alpha gate t.next rest (t.next + 1)).res = _
      rw [List.foldl_cons]
      exact ihv
    intro e he
    rcases List.mem_cons.mp he with rfl | he
    · exact hne
    · exact ihne e he

theorem mapM_ok_inv {α : Type} (f : α → QM31) :
    ∀ l : List α, (∀ x ∈ l, f x ≠ 0) →
      (l.mapM fun x => match (f x).inv? with
        | some t => (pure t : Except VError QM31)
        | none => throw VError.divisionByZero) = .ok (l.map fun x => (f x)⁻¹)
  | [], _ => rfl
  | x :: rest, h => by
    rw [List.mapM_cons, inv?_of_ne (h x List.mem_cons_self),
      mapM_ok_inv f rest fun y hy => h y (List.mem_cons_of_mem x hy)]
    rfl

theorem foldl_add_map {α : Type} (g : α → QM31) :
    ∀ (l : List α) (a : QM31),
      (l.map g).foldl (· + ·) a = l.foldl (fun acc x => acc + g x) a
  | [], _ => rfl
  | x :: rest, a => foldl_add_map g rest (a + g x)

theorem specEntries_eq {ρ : ℕ → QM31} {outs : List ℕ} {uW : ℕ}
    (ws : List Blake2s.Word) (hlen : outs.length = ws.length)
    (hout : ∀ i, i < outs.length → ρ (outs.getD i 0) = packW (ws.getD i 0))
    (hu : ρ uW = QM31.fromM31s 0 0 1 0) :
    logupEntries (ws.map BitVec.toNat)
    = ((outs.zipIdx.map fun (x : ℕ × ℕ) => (3 + x.2, x.1)) ++ [(2, uW)]).map
        fun (e : ℕ × ℕ) => (e.1, entryLanes (ρ e.2)) := by
  unfold logupEntries
  rw [List.map_append]
  refine congrArg₂ (· ++ ·) ?_ ?_
  · rw [List.map_map]
    refine List.ext_getElem (by simp [hlen]) fun i h1 h2 => ?_
    have hi : i < outs.length := by simpa using h2
    have hw : i < ws.length := by rw [← hlen]; exact hi
    simp only [List.getElem_map, List.getElem_zipIdx, Function.comp_apply, Nat.zero_add]
    have ho : outs[i] = outs.getD i 0 := by
      rw [List.getD_eq_getElem?_getD, List.getElem?_eq_getElem hi]; rfl
    have hws : ws[i] = ws.getD i 0 := by
      rw [List.getD_eq_getElem?_getD, List.getElem?_eq_getElem hw]; rfl
    rw [ho, hout i hi, entryLanes_packW, hws]
  · simp only [List.map_cons, List.map_nil]
    rw [hu, entryLanes_u]

theorem logupTerm_ok (z α : QM31) (e : ℕ × List QM31)
    (h : combineTerm (gateFelt :: QM31.fromBase ((e.1 : ℕ) : F) :: e.2) z α ≠ 0) :
    logupTerm z α e
      = .ok (combineTerm (gateFelt :: QM31.fromBase ((e.1 : ℕ) : F) :: e.2) z α)⁻¹ := by
  unfold logupTerm
  rw [inv?_of_ne h]
  rfl

/-- **The public LogUp sum.** -/
theorem publicLogupG_sound {ρ : ℕ → QM31} {zero z alpha : ℕ} {outs : List ℕ} {uW n : ℕ}
    (ws : List Blake2s.Word) (hzero : ρ zero = 0) (hlen : outs.length = ws.length)
    (hout : ∀ i, i < outs.length → ρ (outs.getD i 0) = packW (ws.getD i 0))
    (hu : ρ uW = QM31.fromM31s 0 0 1 0)
    (h : AllHold ρ (publicLogupG zero z alpha outs uW n).ops) :
    publicLogupSum (ws.map BitVec.toNat) (ρ z) (ρ alpha)
      = .ok (ρ (publicLogupG zero z alpha outs uW n).res) := by
  set entries := (outs.zipIdx.map fun (x : ℕ × ℕ) => (3 + x.2, x.1)) ++ [(2, uW)]
    with hentries
  rw [show (publicLogupG zero z alpha outs uW n).ops =
    [.const n gateFelt] ++ (logupLoop z alpha n zero entries (n + 1)).ops from rfl,
    allHold_append] at h
  obtain ⟨hg, hl⟩ := h
  have hg' : ρ n = gateFelt := hg _ List.mem_cons_self
  obtain ⟨hne, hval⟩ := logupLoop_sound entries zero (n + 1) 0 hzero hl
  have hterm : ∀ e : ℕ × ℕ, entryTerm ρ n z alpha e = combineTerm
      (gateFelt :: QM31.fromBase ((e.1 : ℕ) : F) :: entryLanes (ρ e.2)) (ρ z) (ρ alpha) :=
    fun e => by unfold entryTerm; rw [hg']
  have hall : ∀ x ∈ entries.map (fun (e : ℕ × ℕ) => (e.1, entryLanes (ρ e.2))),
      logupTerm (ρ z) (ρ alpha) x
        = .ok (combineTerm (gateFelt :: QM31.fromBase ((x.1 : ℕ) : F) :: x.2)
            (ρ z) (ρ alpha))⁻¹ := by
    intro x hx
    refine logupTerm_ok _ _ x ?_
    obtain ⟨e, he, rfl⟩ := List.mem_map.mp hx
    have hnz := hne e he
    rw [hterm] at hnz
    exact hnz
  unfold publicLogupSum
  rw [specEntries_eq ws hlen hout hu, ← hentries, MerkleBatch.mapM_ok' _ _ hall]
  show Except.ok (((entries.map fun (e : ℕ × ℕ) => (e.1, entryLanes (ρ e.2))).map _).foldl
      (· + ·) QM31.zero) = Except.ok (ρ (logupLoop z alpha n zero entries (n + 1)).res)
  rw [hval, List.map_map, foldl_add_map]
  refine congrArg Except.ok (List.foldl_ext _ _ _ fun a e _ => ?_)
  simp only [Function.comp_apply]
  rw [hterm]

/-! ### `validate_logup_sum` -/

def addChain : ℕ → List ℕ → ℕ → Out ℕ
  | acc, [], n => ⟨[], acc, n⟩
  | acc, c :: cs, n =>
    let r := addChain n cs (n + 1)
    ⟨.add n acc c :: r.ops, r.res, r.next⟩

theorem addChain_sound {ρ : ℕ → QM31} :
    ∀ (cs : List ℕ) (acc n : ℕ), AllHold ρ (addChain acc cs n).ops →
      ρ (addChain acc cs n).res = (cs.map ρ).foldl (· + ·) (ρ acc)
  | [], _, _, _ => rfl
  | c :: cs, acc, n, h => by
    rw [show (addChain acc (c :: cs) n).ops = .add n acc c :: (addChain n cs (n + 1)).ops
      from rfl, allHold_cons] at h
    obtain ⟨h1, h2⟩ := h
    simp only [Holds] at h1
    show ρ (addChain n cs (n + 1)).res = _
    rw [addChain_sound cs n (n + 1) h2, h1]
    rfl

theorem foldl_add_zero (l : List QM31) :
    ∀ a : QM31, l.foldl (· + ·) a = a + l.foldl (· + ·) QM31.zero := by
  induction l with
  | nil => intro a; show a = a + 0; ring
  | cons x l ih =>
    intro a
    simp only [List.foldl_cons]
    rw [ih (a + x), ih (QM31.zero + x)]
    show a + x + _ = a + ((0 : QM31) + x + _)
    ring

/-- `validate_logup_sum`: the public sum plus the claimed sums, `eq` zero. -/
def logupSumG (zero pub : ℕ) (claimed : List ℕ) (n : ℕ) : Out Unit :=
  let c := addChain pub claimed n
  ⟨c.ops ++ [.eq c.res zero], (), c.next⟩

theorem logupSumG_sound {ρ : ℕ → QM31} {zero pub n : ℕ} {claimed : List ℕ}
    (hzero : ρ zero = 0) (h : AllHold ρ (logupSumG zero pub claimed n).ops) :
    ρ pub + (claimed.map ρ).foldl (· + ·) QM31.zero = QM31.zero := by
  unfold logupSumG at h
  rw [allHold_append] at h
  obtain ⟨h1, h2⟩ := h
  have he : ρ (addChain pub claimed n).res = ρ zero := h2 _ List.mem_cons_self
  rw [addChain_sound claimed pub n h1, hzero, foldl_add_zero] at he
  exact he

end StwoVerifier.Gadgets