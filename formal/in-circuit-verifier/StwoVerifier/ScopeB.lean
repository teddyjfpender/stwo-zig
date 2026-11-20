/-
**Scope B: the in-circuit `verify` with `CircuitStatement` is sound
for the native statement-level verifier.**

If every gate of `verifyG` holds, the statement wires carry the
statement's preprocessed root and output digest, and the read-off
proof's Blake2s instances are collision-free (on the messages actually
hashed — `NoCollision`), then `circuitAccepts` accepts the read-off
native proof.
-/
import StwoVerifier.ReadOff
import StwoVerifier.SpecAccept
import StwoVerifier.SelectShapes
import StwoVerifier.TreeGlue
import StwoVerifier.Phase5Glue

namespace StwoVerifier.ScopeB

open StwoVerifier StwoVerifier.Gadgets StwoVerifier.Gates StwoVerifier.ReadOff MerkleBatch FriBatch
  Phase5Glue

/-! ### Byte/word glue -/

theorem u8_eq {a b : ℕ} (h : a % 256 = b % 256) : UInt8.ofNat a = UInt8.ofNat b := by
  apply UInt8.toNat_inj.mp
  show a % 2 ^ 8 = b % 2 ^ 8
  exact h

theorem u32Le_mod (x : ℕ) : Channel.u32Le (x % 2 ^ 32) = Channel.u32Le x := by
  unfold Channel.u32Le
  simp only [List.cons.injEq, and_true]
  exact ⟨u8_eq (by omega), u8_eq (by omega), u8_eq (by omega), u8_eq (by omega)⟩

theorem wordsBytes_ofNat : ∀ ns : List ℕ,
    wordsBytes (ns.map (BitVec.ofNat 32)) = ns.flatMap Channel.u32Le
  | [] => rfl
  | w :: ns => by
    have ih := wordsBytes_ofNat ns
    unfold wordsBytes at ih ⊢
    simp only [List.map_cons, List.flatten_cons, List.flatMap_cons, BitVec.toNat_ofNat] at ih ⊢
    rw [u32Le_mod, ih]

theorem packW_ofNat {w : ℕ} (hw : w < 2 ^ 32) :
    packW (BitVec.ofNat 32 w) = QM31.fromM31s ((w % 2 ^ 16 : ℕ) : F) ((w / 2 ^ 16 : ℕ) : F) 0 0 := by
  unfold packW QM31.fromM31s
  rw [BitVec.toNat_ofNat, Nat.mod_eq_of_lt hw]
  rfl

theorem toNat_ofNat_map {ns : List ℕ} (h : ∀ w ∈ ns, w < 2 ^ 32) :
    (ns.map (BitVec.ofNat 32)).map BitVec.toNat = ns := by
  rw [List.map_map]
  conv_rhs => rw [← List.map_id ns]
  refine List.map_congr_left fun w hw => ?_
  simp only [Function.comp_apply, BitVec.toNat_ofNat, id]
  exact Nat.mod_eq_of_lt (h w hw)

theorem range_getD_map {β : Type} (m : ℕ) (f : ℕ → ℕ) (g : ℕ → β) :
    (List.range m).map (fun i => g (((List.range m).map f).getD i 0))
      = ((List.range m).map f).map g := by
  rw [List.map_map]
  refine List.map_congr_left fun i hi => ?_
  simp only [Function.comp_apply]
  rw [List.getD_eq_getElem?_getD, List.getElem?_map, List.getElem?_range (List.mem_range.mp hi)]
  rfl

theorem configWords_map (b : ℕ) (ls : List ℕ) :
    (List.range 3).map (fun i => BitVec.ofNat 32 ((CircuitVerify.configWords b ls).getD i 0))
      = (CircuitVerify.configWords b ls).map (BitVec.ofNat 32) := by
  unfold CircuitVerify.configWords
  exact range_getD_map 3 _ _

theorem wordsBytes_append (a b : List Blake2s.Word) :
    wordsBytes (a ++ b) = wordsBytes a ++ wordsBytes b := by
  simp [wordsBytes]

theorem circuitHash_eq (b : ℕ) (ls pp : List ℕ) :
    Blake2s.blake2s (wordsBytes ((List.range 3).map
      (fun i => BitVec.ofNat 32 ((CircuitVerify.configWords b ls).getD i 0)) ++ pp.map (BitVec.ofNat 32)))
      = CircuitVerify.circuitHash b ls pp := by
  rw [configWords_map, wordsBytes_append, wordsBytes_ofNat, wordsBytes_ofNat]
  unfold CircuitVerify.circuitHash
  rw [List.flatMap_append]

theorem outs_felts {ws : List ℕ} (h : ∀ w ∈ ws, w < 2 ^ 32) :
    (ws.map (BitVec.ofNat 32)).map packW
      = ws.map fun w => QM31.fromM31s ((w % 2 ^ 16 : ℕ) : F) ((w / 2 ^ 16 : ℕ) : F) 0 0 := by
  rw [List.map_map]
  exact List.map_congr_left fun w hw => packW_ofNat (h w hw)

/-! ### Query positions and digits -/

theorem wordBatches_length (s : Channel.St) :
    ∀ k, (Channel.drawWordBatches true k s).1.length = 8 * k := by
  intro k
  induction k generalizing s with
  | zero => rfl
  | succ k ih =>
    show ((Channel.drawU32s true s).1 ++ (Channel.drawWordBatches true k
      (Channel.drawU32s true s).2).1).length = _
    rw [List.length_append, ih]
    simp [Channel.drawU32s, Channel.digestWords]
    ring

theorem drawQueries_getD (L nq : ℕ) (s : Channel.St) {q : ℕ} (hq : q < nq) :
    (Channel.drawQueries true L nq s).1.getD q 0
      = (Channel.drawWordBatches true ((nq + 7) / 8) s).1.getD q 0 % 2 ^ L := by
  have hlen := wordBatches_length s ((nq + 7) / 8)
  unfold Channel.drawQueries
  simp only []
  rw [List.getD_eq_getElem?_getD, List.getElem?_map, List.getElem?_take, if_pos hq,
    List.getElem?_eq_getElem (by omega), List.getD_eq_getElem?_getD,
    List.getElem?_eq_getElem (by omega)]
  rfl

theorem mod_pow_digit (x L t : ℕ) (ht : t < L) : x % 2 ^ L / 2 ^ t % 2 = x / 2 ^ t % 2 := by
  rw [show 2 ^ L = 2 ^ t * 2 ^ (L - t) by rw [← pow_add]; congr 1; omega,
    Nat.mod_mul_right_div_self, Nat.mod_mod_of_dvd]
  exact dvd_pow_self 2 (by omega)

theorem bitNat_val {ρ : ℕ → QM31} {b : SimdReg} {j : ℕ}
    (h : SimdReg.lane ρ b j = 0 ∨ SimdReg.lane ρ b j = 1) :
    bitNat ρ b j = (SimdReg.lane ρ b j).val := by
  unfold bitNat
  rcases h with h | h <;> rw [h]
  · simp
  · rw [if_neg one_ne_zero, BitDecomp.val_one]

/-! ### Tree shapes -/

theorem colLogs_length (shape : Array ℕ) (ls : List ℕ) (h : shape.toList.length ≤ ls.length) :
    ((shape.toList.zip ls).flatMap fun p => List.replicate p.1 p.2).length = shape.toList.sum := by
  rw [List.length_flatMap]
  simp only [List.length_replicate]
  rw [show ((shape.toList.zip ls).map fun p => p.1) = (shape.toList.zip ls).map Prod.fst from rfl,
    List.map_fst_zip h]

theorem traceCols_length {ls : List ℕ} (h : ls.length = 11) :
    (CircuitVerify.traceColumnLogSizes ls).length = CircuitAirData.nTrace := by
  unfold CircuitVerify.traceColumnLogSizes
  rw [colLogs_length _ _ (by rw [h]; decide)]
  decide

theorem interCols_length {ls : List ℕ} (h : ls.length = 11) :
    (CircuitVerify.interColumnLogSizes ls).length = CircuitAirData.nInter := by
  unfold CircuitVerify.interColumnLogSizes
  rw [colLogs_length _ _ (by rw [h]; decide)]
  decide

theorem mem_colLogs {shape : Array ℕ} {ls : List ℕ} {x : ℕ}
    (h : x ∈ (shape.toList.zip ls).flatMap fun p => List.replicate p.1 p.2) : x ∈ ls := by
  obtain ⟨p, hp, hx⟩ := List.mem_flatMap.mp h
  rw [(List.mem_replicate.mp hx).2]
  exact (List.of_mem_zip hp).2

theorem flatten_getD {cols : List (List ℕ)} {nq : ℕ} (hl : ∀ c ∈ cols, c.length = nq) :
    ∀ {c q : ℕ}, c < cols.length → q < nq →
      cols.flatten.getD (c * nq + q) 0 = (cols.getD c []).getD q 0 := by
  induction cols with
  | nil => intro c q hc; simp at hc
  | cons col rest ih =>
    intro c q hc hq
    have hcl := hl col List.mem_cons_self
    rw [List.flatten_cons]
    cases c with
    | zero =>
      rw [Nat.zero_mul, Nat.zero_add, List.getD_eq_getElem?_getD,
        List.getElem?_append_left (by omega), List.getD_cons_zero, ← List.getD_eq_getElem?_getD]
    | succ c =>
      rw [List.getD_eq_getElem?_getD, List.getElem?_append_right (by rw [hcl]; nlinarith), hcl,
        show (c + 1) * nq + q - nq = c * nq + q by rw [Nat.succ_mul]; omega,
        ← List.getD_eq_getElem?_getD, List.getD_cons_succ]
      exact ih (fun c' hc' => hl c' (List.mem_cons_of_mem _ hc')) (by simpa using hc) hq

theorem regWords_getD (ρ : ℕ → QM31) (l : List (List ℕ)) (i : ℕ) :
    (l.map (regWords ρ)).getD i [] = regWords ρ (l.getD i []) :=
  List.getD_map l [] (regWords ρ)

theorem regBytes_getD (ρ : ℕ → QM31) (l : List (List ℕ)) (i : ℕ) :
    (l.map (regBytes ρ)).getD i [] = regBytes ρ (l.getD i []) :=
  List.getD_map l [] (regBytes ρ)

theorem logs_lt {shape : Array ℕ} {ls : List ℕ} (hl : ls.length = 11)
    (hP : ∀ j, j < 11 → ls.getD j 0 < 2 ^ 5) :
    ∀ c, c < ((shape.toList.zip ls).flatMap fun p => List.replicate p.1 p.2).length →
      ((shape.toList.zip ls).flatMap fun p => List.replicate p.1 p.2).getD c 0 < 2 ^ 5 := by
  intro c hc
  rw [List.getD_eq_getElem _ _ hc]
  have hm := mem_colLogs (shape := shape) (List.getElem_mem hc)
  obtain ⟨j, hj, he⟩ := List.getElem_of_mem hm
  rw [← he, ← List.getD_eq_getElem _ 0 hj]
  exact hP j (by omega)

theorem natConsts_getD {xs : List ℕ} {c : ℕ} (hc : c < xs.length) :
    (natConsts xs).getD c 0 = QM31.fromBase ((xs.getD c 0 : ℕ) : F) := by
  unfold natConsts
  rw [List.getD_eq_getElem _ _ (by simpa using hc), List.getElem_map, List.getD_eq_getElem _ _ hc]

/-! ### Spec-side glue -/

theorem foldl_max_le {m : ℕ} : ∀ (l : List ℕ) (z : ℕ), z ≤ m → (∀ x ∈ l, x ≤ m) → l.foldl max z ≤ m
  | [], _, hz, _ => hz
  | x :: rest, z, hz, h => by
    rw [List.foldl_cons]
    exact foldl_max_le rest _ (max_le hz (h x List.mem_cons_self))
      (fun y hy => h y (List.mem_cons_of_mem _ hy))

theorem prepare_id {L : ℕ} (hL : 1 ≤ L) (ps : List ℕ) :
    Pcs.prepareTreePositions ps L (some L) = ps := by
  unfold Pcs.prepareTreePositions
  obtain ⟨M, rfl⟩ : ∃ M, L = M + 1 := ⟨L - 1, by omega⟩
  simp only [lt_irrefl, if_false, Nat.sub_self, Nat.zero_add, pow_one]
  conv_rhs => rw [← List.map_id ps]
  exact List.map_congr_left fun p _ => by simp only [id]; omega

theorem fri_roots (ρ : ℕ → QM31) (S : Stmt) (g : ProofRegs)
    (hlen : g.friRoots.length = S.logTrace) (hL : 1 ≤ S.logTrace) :
    ((rdFri ρ S g).firstLayer :: (rdFri ρ S g).innerLayers).map (·.commitment) = rdFriRoots ρ g := by
  unfold rdFriRoots
  refine List.ext_getElem (by simp [rdFri, hlen]; omega) fun j h1 h2 => ?_
  rw [List.getElem_map, ← List.getD_eq_getElem _ [] (by simpa using h2), regBytes_getD]
  cases j with
  | zero => rfl
  | succ j =>
    simp only [List.getElem_cons_succ]
    have hj : j < S.logTrace + 1 - 2 := by simp [rdFri] at h1; omega
    simp only [rdFri, List.getElem_map, List.getElem_range]
    rfl

/-- The queried values at the unique positions read the raw ones at representatives. -/
def SelRel (u : ℕ) (rep : ℕ → ℕ) (a b : List F) : Prop := ∀ k, k < u → a.getD k 0 = b.getD (rep k) 0

theorem selRel_getD {u : ℕ} {rep : ℕ → ℕ} {l l' : List (List F)} (h : List.Forall₂ (SelRel u rep) l l') :
    ∀ i, SelRel u rep (l.getD i []) (l'.getD i []) := by
  intro i
  by_cases hi : i < l.length
  · exact Phase5Glue.forall2_getD h [] [] hi
  · rw [List.getD_eq_default _ _ (by omega), List.getD_eq_default _ _ (by rw [← h.length_eq]; omega)]
    intro k _
    rfl

theorem queried_sel (ρ : ℕ → QM31) (S : Stmt) (g : ProofRegs) (hrep : ∀ k, k < (rdUniq ρ S g).length →
      rdRep ρ S g k < S.nq) :
    List.Forall₂ (SelRel (rdUniq ρ S g).length (rdRep ρ S g))
      ((List.range 4).map (rdQueried ρ S g)).flatten (Phase5Glue.rdQueriedRaw ρ S g).flatten := by
  have ht : ∀ t, List.Forall₂ (SelRel (rdUniq ρ S g).length (rdRep ρ S g)) (rdQueried ρ S g t)
      ((List.range (treeCols.getD t 0)).map fun c => (List.range S.nq).map fun q => xv ρ g t c q) := by
    intro t
    refine List.forall₂_iff_get.mpr ⟨by simp [rdQueried], fun c h1 h2 => ?_⟩
    intro k hk
    simp only [rdQueried, List.get_eq_getElem, List.getElem_map, List.getElem_range]
    rw [TreeGlue.grm _ _ hk, TreeGlue.grm _ _ (hrep k hk)]
  unfold Phase5Glue.rdQueriedRaw
  rw [show List.range 4 = [0, 1, 2, 3] from rfl]
  simp only [List.map_cons, List.map_nil, List.flatten_cons, List.flatten_nil, List.append_nil]
  exact Phase5Glue.forall2_append (ht 0) (Phase5Glue.forall2_append (ht 1)
    (Phase5Glue.forall2_append (ht 2) (ht 3)))

/-- The collision hypotheses: per-instance Blake2s injectivity on the
read-off proof's Merkle node messages and FRI leaves. -/
structure NoCollision (ρ : ℕ → QM31) (S : Stmt) (g : ProofRegs) : Prop where
  trees : ∀ t, t < 4 → ∀ q ∈ treeMQs ρ S g t, ∀ q' ∈ treeMQs ρ S g t, ∀ k, k < S.logTrace + 1 →
    Blake2s.blake2s (msg q k) = Blake2s.blake2s (msg q' k) → msg q k = msg q' k
  fri : ∀ l, l < S.logTrace → ∀ q ∈ allMQ (fqs0 ρ S g l), ∀ q' ∈ allMQ (fqs0 ρ S g l),
    ∀ k, k < S.logTrace + 1 - l →
      Blake2s.blake2s (msg q k) = Blake2s.blake2s (msg q' k) → msg q k = msg q' k
  leaf : ∀ l, l < S.logTrace → LeafInj (fqs0 ρ S g l)

/-- Statement well-formedness (static facts about the request). -/
structure WF (S : Stmt) : Prop where
  hls : CircuitVerify.componentLogSizes S.layout = some S.logSizes
  hlsl : S.logSizes.length = 11
  hlsP : ∀ j, j < 11 → S.logSizes.getD j 0 < 2 ^ 5
  hlT : 18 ≤ S.logTrace
  hlT29 : S.logTrace ≤ 29
  hpb : S.powBits ≤ 30
  hnq : 0 < S.nq
  hnqP : (S.nq + 7) / 8 < P
  hlay : S.layout.length = CircuitAirData.nPp
  hlayMono : ∀ i j, i < j → j < S.layout.length →
    (S.layout.getD i ("", 0)).2 ≤ (S.layout.getD j ("", 0)).2
  hlayLe : ∀ c ∈ S.layout, c.2 ≤ S.logTrace
  hppPos : ∀ j ∈ CircuitAir.ppPositions S.layout, j < CircuitAirData.nPp
  hpp8 : S.ppRootWords.length = 8
  hppW : ∀ w ∈ S.ppRootWords, w < 2 ^ 32
  hout8 : S.outputDigest.length = 8
  houtW : ∀ w ∈ S.outputDigest, w < 2 ^ 32
  hcdb : 1 ≤ S.logSizes.foldl max 0

set_option maxHeartbeats 64000000 in
/-- **Scope B.** -/
theorem verify_sound (S : Stmt) (hS : WF S) (ρ : ℕ → QM31) (ppRoot outs : List ℕ) (n : ℕ)
    (hpp : RegsWords ρ ppRoot (S.ppRootWords.map (BitVec.ofNat 32)))
    (hout : RegsWords ρ outs (S.outputDigest.map (BitVec.ofNat 32)))
    (h : AllHold ρ (verifyG S.layout S.logSizes S.logTrace S.powBits S.nq ppRoot outs n).ops)
    (hcoll : NoCollision ρ S (guessG S.nq (S.logTrace + 1) (n + 6)).res) :
    CircuitVerify.circuitAccepts true S.config S.layout S.ppRootWords S.outputDigest
      (ρ (guessG S.nq (S.logTrace + 1) (n + 6)).res.salt)
      (nonceNat (ρ (guessG S.nq (S.logTrace + 1) (n + 6)).res.interNonce))
      ((guessG S.nq (S.logTrace + 1) (n + 6)).res.claimed.map ρ)
      (rdCommitments ρ S (guessG S.nq (S.logTrace + 1) (n + 6)).res)
      (rdProof ρ S (guessG S.nq (S.logTrace + 1) (n + 6)).res) = .ok () := by
  unfold verifyG at h
  set K := constsG [0, 1, uQ, QM31.fromBase ((2 ^ bTrace : ℕ) : F), QM31.fromBase ((2 ^ bInter : ℕ) : F), uQ⁻¹] n with hKdef
  rw [allHold_seq] at h
  obtain ⟨hK, h⟩ := h
  beta_reduce at h
  set G := guessG S.nq (S.logTrace + 1) K.next with hGdef
  rw [allHold_seq] at h
  obtain ⟨hG, h⟩ := h
  beta_reduce at h
  set R1 := phase1G (K.res.getD 0 0) (K.res.getD 1 0) (K.res.getD 2 0) S.logSizes S.logTrace (cfgFelts S.powBits S.nq).1 (cfgFelts S.powBits S.nq).2 (CircuitVerify.configWords 1 S.logSizes) G.res.salt ppRoot outs G.res.traceRoot G.res.interNonce G.res.claimed G.res.interRoot G.res.compRoot G.next with hR1def
  rw [allHold_seq] at h
  obtain ⟨hR1, h⟩ := h
  beta_reduce at h
  set R2 := phase2G (K.res.getD 0 0) (K.res.getD 1 0) S.logTrace R1.res.low R1.res.high R1.res.sizeBits R1.res.sizes R1.res.oods R1.res.coeff R1.res.z R1.res.alpha (CircuitAir.ppPositions S.layout) G.res.ppAt G.res.traceAt (interAtOf G.res.comps) G.res.compAt G.res.claimed R1.next with hR2def
  rw [allHold_seq] at h
  obtain ⟨hR2, h⟩ := h
  beta_reduce at h
  set R3 := phase3G (K.res.getD 0 0) (K.res.getD 1 0) (S.logTrace + 1) S.nq S.powBits R2.res.1 R2.res.2 G.res.friRoots [G.res.lastCoef] G.res.powNonce R2.next with hR3def
  rw [allHold_seq] at h
  obtain ⟨hR3, h⟩ := h
  beta_reduce at h
  set SB := Bridge.unpackAllG S.nq (R3.res.bits.take (S.logTrace + 1)) R3.next with hSBdef
  rw [allHold_seq] at h
  obtain ⟨hSB, h⟩ := h
  beta_reduce at h
  set TL := constsG (natConsts (CircuitVerify.traceColumnLogSizes S.logSizes)) SB.next with hTLdef
  rw [allHold_seq] at h
  obtain ⟨hTL, h⟩ := h
  beta_reduce at h
  set IL := constsG (natConsts (CircuitVerify.interColumnLogSizes S.logSizes)) TL.next with hILdef
  rw [allHold_seq] at h
  obtain ⟨hIL, h⟩ := h
  beta_reduce at h
  set T0 := plainTreeG (G.res.cols.getD 0 []).flatten CircuitAirData.nPp S.nq (bitsOfQ SB.res (S.logTrace + 1)) ppRoot (fun q => (G.res.authT.getD 0 []).getD q []) (List.range S.nq) IL.next with hT0def
  rw [allHold_seq] at h
  obtain ⟨hT0, h⟩ := h
  beta_reduce at h
  set T1 := sortedTreeG (K.res.getD 0 0) (K.res.getD 1 0) (K.res.getD 2 0) (K.res.getD 3 0) (K.res.getD 5 0) TL.res bTrace (G.res.cols.getD 1 []).flatten CircuitAirData.nTrace S.nq (bitsOfQ SB.res (S.logTrace + 1)) G.res.traceRoot (fun q => (G.res.authT.getD 1 []).getD q []) T0.next with hT1def
  rw [allHold_seq] at h
  obtain ⟨hT1, h⟩ := h
  beta_reduce at h
  set T2 := sortedTreeG (K.res.getD 0 0) (K.res.getD 1 0) (K.res.getD 2 0) (K.res.getD 4 0) (K.res.getD 5 0) IL.res bInter (G.res.cols.getD 2 []).flatten CircuitAirData.nInter S.nq (bitsOfQ SB.res (S.logTrace + 1)) G.res.interRoot (fun q => (G.res.authT.getD 2 []).getD q []) T1.next with hT2def
  rw [allHold_seq] at h
  obtain ⟨hT2, h⟩ := h
  beta_reduce at h
  set T3 := plainTreeG (G.res.cols.getD 3 []).flatten 8 S.nq (bitsOfQ SB.res (S.logTrace + 1)) G.res.compRoot (fun q => (G.res.authT.getD 3 []).getD q []) (List.range S.nq) T2.next with hT3def
  rw [allHold_seq] at h
  obtain ⟨hT3, h⟩ := h
  beta_reduce at h
  set FI := phase5G (K.res.getD 0 0) (K.res.getD 1 0) (canonicStep S.logTrace) R1.res.sizeBits R1.res.oods R3.res.points S.nq R3.res.oq G.res.ppAt G.res.traceAt G.res.comps G.res.compAt ((List.range 11).map fun j => S.logSizes.getD j 0 + 1) (fun c i => ((allCols G.res).getD c []).getD i 0) T3.next with hFIdef
  rw [allHold_seq] at h
  obtain ⟨hFI, h⟩ := h
  beta_reduce at h
  -- Constants.
  obtain ⟨-, hk⟩ := constsG_sound hK
  have hzero : ρ (K.res.getD 0 0) = 0 := hk 0 (by simp)
  have hone : ρ (K.res.getD 1 0) = 1 := hk 1 (by simp)
  have hu : ρ (K.res.getD 2 0) = uQ := hk 2 (by simp)
  have hsT : ρ (K.res.getD 3 0) = QM31.fromBase ((2 ^ bTrace : ℕ) : F) := hk 3 (by simp)
  have hsI : ρ (K.res.getD 4 0) = QM31.fromBase ((2 ^ bInter : ℕ) : F) := hk 4 (by simp)
  have huinv : ρ (K.res.getD 5 0) = uQ⁻¹ := hk 5 (by simp)
  -- The guessed proof.
  have hKn : K.next = n + 6 := rfl
  have hGF : GuessFacts ρ S.nq (S.logTrace + 1) G.res := guessG_sound hG
  have hg : (guessG S.nq (S.logTrace + 1) (n + 6)).res = G.res := by rw [hGdef, hKn]
  rw [hg] at hcoll ⊢
  -- Phase 1.
  have hp1 := phase1G_sound (S.ppRootWords.map (BitVec.ofNat 32))
    (S.outputDigest.map (BitVec.ofNat 32)) (regWords ρ G.res.traceRoot) (regWords ρ G.res.interRoot)
    (regWords ρ G.res.compRoot) hzero hone hu (by have := hS.hlT29; omega) hS.hlsl
    hpp (by simp [hS.hpp8]) hout (by simp [hS.hout8])
    hGF.traceRoot.1 (by simp [regWords, hGF.traceRoot.2])
    hGF.interRoot.1 (by simp [regWords, hGF.interRoot.2])
    hGF.compRoot.1 (by simp [regWords, hGF.compRoot.2]) hR1
  rw [← hR1def] at hp1
  obtain ⟨hpw1, hdr1, hpub, hsum, hcoef, ⟨tO, hseed, hpt⟩, hch11, hlog, hszl, hszd, hsz, hsbl,
    hsbs, hsb⟩ := hp1
  have hch11' : ChDigest ρ R1.res.low R1.res.high (st11 ρ S G.res).digest := hch11
  -- Log sizes.
  have hlsv : ∀ j, j < 11 → (((S.logSizes.getD j 0 : ℕ) : F)).val = S.logSizes.getD j 0 :=
    fun j hj => ZMod.val_cast_of_lt (lt_trans (hS.hlsP j hj) (by unfold P; norm_num))
  have hsb' : ∀ j, j < 11 → ∀ t, t < S.logTrace + 1 →
      SimdReg.lane ρ (R1.res.sizeBits.getD t dummySimd) j
        = if t = S.logSizes.getD j 0 then 1 else 0 := fun j hj t ht => by
    rw [hsb j hj t ht, hlsv j hj]
  have hsz' : ∀ j, j < 11 → SimdReg.lane ρ R1.res.sizes j = 2 ^ (S.logSizes.getD j 0) :=
    fun j hj => by rw [hsz j hj, hlsv j hj]
  have hlv : ∀ j, j < 11 → S.logSizes.getD j 0 ≤ S.logTrace := fun j hj => by
    have := (hlog j hj).2; rwa [hlsv j hj] at this
  have hOC : OnCircleQ (R1.res.oods.val ρ) := securePoint_onCircle hpt
  -- Phase 2.
  have hp2 := phase2G_sound S.layout S.logSizes (st11 ρ S G.res) hzero hone hch11'
    (mixRoot_len _ _) hS.hlsl (fun j hj => lt_trans (hS.hlsP j hj) (by unfold P; norm_num)) hlv
    (by have := hS.hlT; omega) (by have := hS.hlT29; omega) (by have := hS.hlT; omega)
    hsbl hsbs hsb' hszl hszd hsz' hOC hGF.ppLen
    (by simp [CircuitAir.ppPositions, CircuitAirData.ppIds, CircuitAirData.nPp])
    (fun j hj => by rw [hGF.ppLen]; exact hS.hppPos j hj) rfl hGF.traceLen
    (interAtOf_length hGF.compsLen hGF.compsShape) (interAtOf_kinds hGF.compsLen hGF.compsShape)
    hGF.claimedLen hGF.compLen hR2
  rw [← hR2def] at hp2
  obtain ⟨hru, hch12, v, hext, heval⟩ := hp2
  have hch12' : ChDigest ρ R2.res.1 R2.res.2 (st12 ρ S G.res).digest := by
    unfold st12 rdSampled
    rw [svOf_flatten]
    exact hch12
  -- Phase 3.
  have hfrl : G.res.friRoots.length = (rdFriRoots ρ G.res).length := by
    unfold rdFriRoots; rw [List.length_map]
  have hroots : ∀ i, i < (rdFriRoots ρ G.res).length →
      RootRegs ρ (G.res.friRoots.getD i []) ((rdFriRoots ρ G.res).getD i []) := by
    intro i hi
    have hi' : i < G.res.friRoots.length := by rw [hfrl]; exact hi
    have h8 := hGF.friRoots i (by rw [← hGF.friRootsLen]; exact hi')
    rw [show (rdFriRoots ρ G.res).getD i [] = regBytes ρ (G.res.friRoots.getD i []) from by
      unfold rdFriRoots
      rw [List.getD_eq_getElem?_getD, List.getElem?_map, List.getElem?_eq_getElem hi',
        List.getD_eq_getElem?_getD, List.getElem?_eq_getElem hi']; rfl]
    exact rootRegs_words h8.1 (by rw [regWords, List.length_map]; exact h8.2)
  have hp3 := phase3G_sound (st12 ρ S G.res) (rdFriRoots ρ G.res) hzero hone hch12'
    (chHash_true_length _) rfl hfrl hroots hS.hpb (by have := hS.hlT; omega)
    (by have := hS.hlT29; omega) hS.hnqP hR3
  rw [← hR3def] at hp3
  obtain ⟨hdeep, halph, hpow, hil, hcov, hlane, hbitsn, hpts⟩ := hp3
  have hp3f := phase3G_facts hzero (by have := hS.hlT; omega) (by have := hS.hlT29; omega) hcov hR3
  rw [← hR3def] at hp3f
  obtain ⟨hbl31, hbsh, hptsh, hbool⟩ := hp3f
  -- Raw positions and their digits.
  have hposq : ∀ q, q < S.nq → (rdRaw ρ S G.res).getD q 0
      = (SimdReg.lane ρ R3.res.input q).val % 2 ^ (S.logTrace + 1) := by
    intro q hq
    unfold rdRaw
    rw [drawQueries_getD _ _ _ hq, hlane q hq]
    rfl
  have hposlt : ∀ q, q < S.nq → (rdRaw ρ S G.res).getD q 0 < 2 ^ (S.logTrace + 1) := by
    intro q hq; rw [hposq q hq]; exact Nat.mod_lt _ (by positivity)
  have hdig : ∀ q, q < S.nq → ∀ t, t < S.logTrace + 1 →
      bitNat ρ (R3.res.bits.getD t dummySimd) q = (rdRaw ρ S G.res).getD q 0 / 2 ^ t % 2 := by
    intro q hq t ht
    rw [bitNat_val (hbool q hq t (by have := hS.hlT29; omega)), hposq q hq,
      mod_pow_digit _ _ _ ht, ← hbitsn q hq,
      natOf_digit _ 31 t (by have := hS.hlT29; omega) (fun i hi => hbool q hq i hi)]
  have hrawl : (rdRaw ρ S G.res).length = S.nq := by
    unfold rdRaw Channel.drawQueries
    simp only [List.length_map, List.length_take, wordBatches_length]
    omega
  -- The unpacked bits.
  obtain ⟨hsbl', hsbv⟩ := Bridge.unpackAllG_sound _ _ hSB
  have hsb : ∀ t, t < S.logTrace + 1 → ∀ i, i < S.nq →
      ρ ((SB.res.getD t []).getD i 0)
        = QM31.fromBase (SimdReg.lane ρ (R3.res.bits.getD t dummySimd) i) := by
    intro t ht i hi
    rw [hsbv t (by simp [hbl31]; have := hS.hlT29; omega) i hi, Bridge.getD_take' _ _ ht]
  have hsb01 : ∀ t, t < S.logTrace + 1 → ∀ i, i < S.nq →
      ρ ((SB.res.getD t []).getD i 0) = 0 ∨ ρ ((SB.res.getD t []).getD i 0) = 1 := by
    intro t ht i hi
    rw [hsb t ht i hi]
    exact Bridge.fromBase_bit01 (hbool i hi t (by have := hS.hlT29; omega))
  have hsbq : ∀ t, t < S.logTrace + 1 → ∀ i, i < S.nq →
      qbit (ρ ((SB.res.getD t []).getD i 0)) = (rdRaw ρ S G.res).getD i 0 / 2 ^ t % 2 := by
    intro t ht i hi
    rw [← hdig i hi t ht, hsb t ht i hi]
    unfold qbit bitNat
    rcases hbool i hi t (by have := hS.hlT29; omega) with h0 | h1
    · rw [h0, if_pos rfl, if_pos (show QM31.fromBase 0 = 0 from rfl)]
    · rw [h1, if_neg (fromBase_ne_zero one_ne_zero), if_neg one_ne_zero]
  -- Phase 4: the eval-domain trees.
  have hcolsv : ∀ t, t < 4 → ∀ c, c < treeCols.getD t 0 → ∀ q, q < S.nq →
      ρ (((G.res.cols.getD t []).flatten).getD (c * S.nq + q) 0)
        = QM31.fromBase (xv ρ G.res t c q) := by
    intro t ht c hc q hq
    obtain ⟨hl1, hl2⟩ := hGF.colsLen t ht
    have hall : ∀ col ∈ G.res.cols.getD t [], col.length = S.nq := by
      intro col hcol
      obtain ⟨i, hi, rfl⟩ := List.getElem_of_mem hcol
      rw [← List.getD_eq_getElem _ [] hi]
      exact hl2 i (by rw [← hl1]; exact hi)
    rw [flatten_getD hall (by rw [hl1]; exact hc) hq]
    exact isBase_eq (hGF.cols t ht c hc q hq)
  have hauthv : ∀ t, t < 4 → ∀ q, q < S.nq → ∀ i, i < ((G.res.authT.getD t []).getD q []).length →
      RegsWords ρ (((G.res.authT.getD t []).getD q []).getD i [])
        ((((G.res.authT.getD t []).getD q []).map (regWords ρ)).getD i []) ∧
      ((((G.res.authT.getD t []).getD q []).map (regWords ρ)).getD i []).length = 8 := by
    intro t ht q hq i hi
    have hh := hGF.auth t ht q hq i (by rw [← hGF.authLen t ht q hq]; exact hi)
    rw [regWords_getD]
    exact ⟨hh.1, by rw [regWords, List.length_map]; exact hh.2⟩
  have hbitsv : ∀ q, q < S.nq → ∀ b ∈ bitsOfQ SB.res (S.logTrace + 1) q, ρ b = 0 ∨ ρ b = 1 := by
    intro q hq b hb
    unfold bitsOfQ at hb
    obtain ⟨t, ht, rfl⟩ := List.mem_map.mp hb
    exact hsb01 t (List.mem_range.mp ht) q hq
  have htail : ∀ t, t < 4 → ∀ root : Channel.Bytes, (∀ q, q < S.nq → root = pathRoot
      (Merkle.leafHash ((Merkle.columnOrder (treeLogs S t)).map fun c => xv ρ G.res t c q))
      ((bitsOfQ SB.res (S.logTrace + 1) q).map fun b => qbit (ρ b))
      ((((G.res.authT.getD t []).getD q []).map (regWords ρ)).map wordsBytes)) →
      Paths (treeMQs ρ S G.res t) (S.logTrace + 1) root := by
    intro t ht root hr
    refine TreeGlue.tree_paths hposlt (fun q hq => ?_) (fun q _ => blake2s_length _)
      (fun q hq => by rw [List.length_map]; exact hGF.authLen t ht q hq) (fun q hq k hk => ?_)
      (hcoll.trees t ht)
    · rw [hr q hq]
      have e1 : (bitsOfQ SB.res (S.logTrace + 1) q).map (fun b => qbit (ρ b))
          = (List.range (S.logTrace + 1)).map fun t => (rdRaw ρ S G.res).getD q 0 / 2 ^ t % 2 := by
        unfold bitsOfQ
        rw [List.map_map]
        exact List.map_congr_left fun t' ht' => hsbq t' (List.mem_range.mp ht') q hq
      rw [e1, List.map_map]
      rfl
    · have hk' : k < ((G.res.authT.getD t []).getD q []).length := by
        rw [hGF.authLen t ht q hq]; exact hk
      have hh := hGF.auth t ht q hq k hk
      rw [regBytes_getD, regBytes, wordsBytes_length, regWords, List.length_map, hh.2]
  -- Tree 0: preprocessed (unsorted; nondecreasing layout).
  have hco0 : Merkle.columnOrder (treeLogs S 0) = List.range CircuitAirData.nPp := by
    show Merkle.columnOrder (S.layout.map (·.2 + 1)) = _
    rw [show S.layout.map (·.2 + 1) = (S.layout.map (·.2)).map (· + 1) by rw [List.map_map]; rfl,
      ColumnOrder.columnOrder_shift, ColumnOrder.columnOrder_mono, List.length_map, hS.hlay]
    intro i j hij hj
    rw [List.length_map] at hj
    rw [show (S.layout.map (·.2)).getD i 0 = (S.layout.map (·.2)).getD i (("", 0) : String × ℕ).2
      from rfl, List.getD_map, show (S.layout.map (·.2)).getD j 0
        = (S.layout.map (·.2)).getD j (("", 0) : String × ℕ).2 from rfl, List.getD_map]
    exact hS.hlayMono i j hij hj
  have ht0 := plainTreeG_sound (xv ρ G.res 0)
    (fun q => ((G.res.authT.getD 0 []).getD q []).map (regWords ρ))
    (fun c hc q hq => hcolsv 0 (by norm_num) c hc q hq) hpp (by simp [hS.hpp8])
    (fun q hq => by rw [List.length_map]) (hauthv 0 (by norm_num)) hbitsv (List.range S.nq) _
    (fun q hq => List.mem_range.mp hq) hT0
  have hP0 : Paths (treeMQs ρ S G.res 0) (S.logTrace + 1)
      (wordsBytes (S.ppRootWords.map (BitVec.ofNat 32))) :=
    htail 0 (by norm_num) _ fun q hq => by rw [ht0 q (List.mem_range.mpr hq), hco0]; rfl
  -- Tree 1: trace (sorted).
  have hTLv := constsG_sound hTL
  have htl : (CircuitVerify.traceColumnLogSizes S.logSizes).length = CircuitAirData.nTrace :=
    traceCols_length hS.hlsl
  have ht1 := sortedTreeG_sound (CircuitVerify.traceColumnLogSizes S.logSizes) (xv ρ G.res 1)
    (fun q => ((G.res.authT.getD 1 []).getD q []).map (regWords ρ)) hzero hone hu hsT huinv
    (by decide) (by rw [htl]; decide) (logs_lt hS.hlsl hS.hlsP) htl.symm
    (by rw [hTLv.1, natConsts, List.length_map])
    (fun c hc => by rw [hTLv.2 c (by rw [natConsts, List.length_map]; exact hc), natConsts_getD hc])
    hS.hnq (fun c hc q hq => hcolsv 1 (by norm_num) c hc q hq) hGF.traceRoot.1
    (by rw [regWords, List.length_map]; exact hGF.traceRoot.2) (fun q hq => by rw [List.length_map])
    (hauthv 1 (by norm_num)) hbitsv hT1
  have hP1 : Paths (treeMQs ρ S G.res 1) (S.logTrace + 1) (wordsBytes (regWords ρ G.res.traceRoot)) :=
    htail 1 (by norm_num) _ fun q hq => by
      rw [ht1 q hq]
      show _ = pathRoot (Merkle.leafHash ((Merkle.columnOrder
        ((CircuitVerify.traceColumnLogSizes S.logSizes).map (· + 1))).map _)) _ _
      rw [ColumnOrder.columnOrder_shift]
  -- Tree 2: interaction (sorted).
  have hILv := constsG_sound hIL
  have hil : (CircuitVerify.interColumnLogSizes S.logSizes).length = CircuitAirData.nInter :=
    interCols_length hS.hlsl
  have ht2 := sortedTreeG_sound (CircuitVerify.interColumnLogSizes S.logSizes) (xv ρ G.res 2)
    (fun q => ((G.res.authT.getD 2 []).getD q []).map (regWords ρ)) hzero hone hu hsI huinv
    (by decide) (by rw [hil]; decide) (logs_lt hS.hlsl hS.hlsP) hil.symm
    (by rw [hILv.1, natConsts, List.length_map])
    (fun c hc => by rw [hILv.2 c (by rw [natConsts, List.length_map]; exact hc), natConsts_getD hc])
    hS.hnq (fun c hc q hq => hcolsv 2 (by norm_num) c hc q hq) hGF.interRoot.1
    (by rw [regWords, List.length_map]; exact hGF.interRoot.2) (fun q hq => by rw [List.length_map])
    (hauthv 2 (by norm_num)) hbitsv hT2
  have hP2 : Paths (treeMQs ρ S G.res 2) (S.logTrace + 1) (wordsBytes (regWords ρ G.res.interRoot)) :=
    htail 2 (by norm_num) _ fun q hq => by
      rw [ht2 q hq]
      show _ = pathRoot (Merkle.leafHash ((Merkle.columnOrder
        ((CircuitVerify.interColumnLogSizes S.logSizes).map (· + 1))).map _)) _ _
      rw [ColumnOrder.columnOrder_shift]
  -- Tree 3: composition (unsorted, equal log sizes).
  have hco3 : Merkle.columnOrder (treeLogs S 3) = List.range 8 := by
    show Merkle.columnOrder (List.replicate 8 (S.logTrace + 1)) = _
    rw [ColumnOrder.columnOrder_mono, List.length_replicate]
    intro i j hij hj
    rw [List.length_replicate] at hj
    rw [List.getD_eq_getElem _ _ (by rw [List.length_replicate]; omega), List.getElem_replicate,
      List.getD_eq_getElem _ _ (by rw [List.length_replicate]; exact hj), List.getElem_replicate]
  have ht3 := plainTreeG_sound (xv ρ G.res 3)
    (fun q => ((G.res.authT.getD 3 []).getD q []).map (regWords ρ))
    (fun c hc q hq => hcolsv 3 (by norm_num) c hc q hq) hGF.compRoot.1
    (by rw [regWords, List.length_map]; exact hGF.compRoot.2)
    (fun q hq => by rw [List.length_map]) (hauthv 3 (by norm_num)) hbitsv (List.range S.nq) _
    (fun q hq => List.mem_range.mp hq) hT3
  have hP3 : Paths (treeMQs ρ S G.res 3) (S.logTrace + 1) (wordsBytes (regWords ρ G.res.compRoot)) :=
    htail 3 (by norm_num) _ fun q hq => by rw [ht3 q (List.mem_range.mpr hq), hco3]; rfl
  -- Phase 5: the DEEP answers at the raw positions.
  obtain ⟨batches, hbuild⟩ := hbuild_ok ρ G.res S (R1.res.oods.val ρ) (S.logTrace + 1)
    (ρ R3.res.oq) hGF.ppLen hS.hlay hGF.traceLen hGF.compLen hGF.compsLen hS.hlsl hGF.compsShape
  have hrel := allCols_colRel ρ S G.res hGF
  have hqlen := queriedRaw_length ρ S G.res
  have hsize : (canonicDomain (S.logTrace + 1)).size = 2 ^ (S.logTrace + 1) := by
    show 2 ^ (canonicDomain (S.logTrace + 1)).logSize = _
    rw [Bridge.canonic_logSize (by omega)]
  have hp5 := phase5G_sound S.logTrace (fun j => S.logSizes.getD j 0) (R1.res.oods.val ρ)
    (clsList S) (spList (R1.res.oods.val ρ) S.logTrace) (rdSampled ρ G.res) (rdRaw ρ S G.res)
    (rdQueriedRaw ρ S G.res) batches (treeLogs S 0) (treeLogs S 1) (treeLogs S 3) hzero hone
    (by have := hS.hlT; omega) hS.hlT29 hsbl hsbs hsb' hlv rfl hOC hGF.compsLen rfl hrawl
    (fun pos hp => by
      obtain ⟨i, hi, rfl⟩ := List.getElem_of_mem hp
      rw [hsize, ← List.getD_eq_getElem _ 0 hi]
      exact hposlt i (by rw [← hrawl]; exact hi))
    (fun i hi => by rw [hpts i hi, ← hposq i hi])
    hbuild (htrees_ok ρ G.res S _ hGF.ppLen hS.hlay hGF.traceLen hGF.compLen hGF.compsLen hS.hlsl
      hGF.compsShape)
    (by rw [List.length_map, hGF.ppLen]; show _ ≤ (S.layout.map _).length; rw [List.length_map, hS.hlay])
    (by rw [List.length_map, hGF.traceLen]
        show _ ≤ ((CircuitVerify.traceColumnLogSizes S.logSizes).map _).length
        rw [List.length_map, traceCols_length hS.hlsl])
    (by rw [List.length_map, hGF.compLen]; show _ ≤ (List.replicate 8 _).length
        rw [List.length_replicate])
    (fun col hcol => by
      obtain ⟨tc, htc, hcol⟩ := List.mem_flatten.mp hcol
      obtain ⟨t, -, rfl⟩ := List.mem_map.mp htc
      obtain ⟨c, -, rfl⟩ := List.mem_map.mp hcol
      rw [List.length_map, List.length_range, hrawl])
    (fun pers prev => by
      have hfc : ∀ x ∈ respLayout R1.res.oods prev G.res.ppAt G.res.traceAt
          (interEntries pers G.res.comps ((List.range 11).map fun j => S.logSizes.getD j 0 + 1))
          G.res.compAt, x.2 < (rdQueriedRaw ρ S G.res).flatten.length := by
        intro x hx
        have h1 := respLayout_fc hx
        have h2 := interEntries_sum pers G.res.comps ((List.range 11).map fun j => S.logSizes.getD j 0 + 1)
        rw [comps_sum hGF.compsLen hGF.compsShape] at h2
        rw [hqlen]
        rw [hGF.ppLen, hGF.traceLen, hGF.compLen] at h1
        omega
      refine ⟨fun j hj => ?_, fun j hj i hi => ?_⟩
      · rw [List.getD_eq_getElem _ _ (by rw [List.length_map]; exact hj), List.getElem_map]
        exact hfc _ (List.getElem_mem hj)
      · have hc : (List.map Prod.snd (respLayout R1.res.oods prev G.res.ppAt G.res.traceAt
            (interEntries pers G.res.comps ((List.range 11).map fun j => S.logSizes.getD j 0 + 1))
            G.res.compAt)).getD j 0 < (allCols G.res).length := by
          rw [hrel.length_eq, List.getD_eq_getElem _ _ (by rw [List.length_map]; exact hj),
            List.getElem_map]
          exact hfc _ (List.getElem_mem hj)
        exact (forall2_getD hrel [] [] hc).2.2 i (by rw [← hrawl]; exact hi))
    hFI
  rw [← hFIdef] at hp5
  obtain ⟨hans, him, hidx, hden⟩ := hp5
  have hcolsRaw : ∀ col ∈ (rdQueriedRaw ρ S G.res).flatten, col.length = (rdRaw ρ S G.res).length := by
    intro col hcol
    obtain ⟨tc, htc, hcol⟩ := List.mem_flatten.mp hcol
    obtain ⟨t, -, rfl⟩ := List.mem_map.mp htc
    obtain ⟨c, -, rfl⟩ := List.mem_map.mp hcol
    rw [List.length_map, List.length_range, hrawl]
  have hposRaw : ∀ pos ∈ rdRaw ρ S G.res, pos < (canonicDomain (S.logTrace + 1)).size := by
    intro pos hp
    obtain ⟨i, hi, rfl⟩ := List.getElem_of_mem hp
    rw [hsize, ← List.getD_eq_getElem _ 0 hi]
    exact hposlt i (by rw [← hrawl]; exact hi)
  have hFIlen : FI.res.length = S.nq := by
    have hc := Quotients.friAnswers_ok (clsList S) (spList (R1.res.oods.val ρ) S.logTrace)
      (rdSampled ρ G.res) (ρ R3.res.oq) (rdRaw ρ S G.res) (rdQueriedRaw ρ S G.res) (S.logTrace + 1)
      batches hbuild hcolsRaw him hidx hposRaw (fun b hb pos _ => hden b hb pos)
    rw [hans] at hc
    have := congrArg List.length (Except.ok.inj hc)
    rw [List.length_map, List.length_map, List.length_zipIdx, hrawl] at this
    exact this
  -- Phase 6: the FRI decommitment.
  have hpx : R3.res.points.x.data.length = R3.res.input.data.length := hptsh.dataX
  have hp6 := Bridge.phase6G_sound (fPos ρ S G.res) (fWr ρ G.res) (fSws ρ G.res) hzero hone
    (by have := hS.hlT; omega) (by have := hS.hlT29; omega) (by rw [hbl31]; have := hS.hlT29; omega)
    (fun b hb => by rw [hpx]; exact hbsh b hb) (by rw [hpx]; exact hptsh)
    (fun t ht i hi => hbool i hi t (by have := hS.hlT29; omega))
    (fun t ht i hi => hdig i hi t ht) hposlt
    (fun i hi => by rw [hpts i hi, ← hposq i hi]; rfl) hsb hFIlen
    (fun l hl => ⟨(hGF.friRoots l (by rw [hGF.friRootsLen] at *; omega)).1,
      by rw [fWr, regWords, List.length_map]; exact (hGF.friRoots l (by omega)).2⟩)
    (fun l hl i hi => by rw [fSws, List.length_map])
    (fun l hl i hi k hk => by
      have hh := hGF.friAuth l hl i hi k (by rw [← hGF.friAuthLen l hl i hi]; exact hk)
      rw [fSws, regWords_getD]
      exact ⟨hh.1, by rw [regWords, List.length_map]; exact hh.2⟩)
    h
  obtain ⟨V, hV0, hVL, hVl⟩ := hp6
  /- ## The spec side. -/
  have hlsmem : ∀ l ∈ S.logSizes, l ≤ S.logTrace ∧ l < 2 ^ 5 := by
    intro l hl
    obtain ⟨j, hj, rfl⟩ := List.getElem_of_mem hl
    rw [← List.getD_eq_getElem _ 0 hj]
    rw [hS.hlsl] at hj
    exact ⟨hlv j hj, hS.hlsP j hj⟩
  have hmaxl : S.logSizes.foldl max 0 ≤ S.logTrace :=
    foldl_max_le _ _ (Nat.zero_le _) fun l hl => (hlsmem l hl).1
  have hmaxeq : max ((S.logSizes.foldl max 0) + 1 - 1) (S.logTrace + 1 - 1) = S.logTrace := by
    omega
  -- Statement transcript to the interaction commit.
  have hppB : wordsBytes (S.ppRootWords.map (BitVec.ofNat 32)) = S.ppRootWords.flatMap Channel.u32Le :=
    wordsBytes_ofNat _
  set s0 := Channel.mixFelts true (Channel.mixFelts true Channel.init [ρ G.res.salt])
      [QM31.fromM31s (S.config.powBits : Nat) (S.config.logBlowupFactor : Nat)
        (S.config.nQueries : Nat) (S.config.logLastLayerDegreeBound : Nat),
       QM31.fromM31s (S.config.foldStep : Nat) 0 0 0] with hs0
  set ppB := S.ppRootWords.flatMap Channel.u32Le with hppBdef
  set tr0 : Pcs.Tree := ⟨ppB, (S.layout.map (fun c : String × ℕ => c.2)).map (· + 1), S.logTrace + 1⟩
    with htr0
  have hc0 : Pcs.commit true S.config [] s0 ppB (S.layout.map (fun c : String × ℕ => c.2))
      = .ok ([tr0], Channel.mixRoot true s0 ppB) :=
    SpecGlue.pcsCommit_ok true S.config [] s0 ppB _
      (by
        intro he
        have h1 := congrArg List.length he
        rw [List.length_map, hS.hlay] at h1
        exact absurd h1 (by decide))
      (fun l hl => by
        obtain ⟨c, hc, rfl⟩ := List.mem_map.mp hl
        have := hS.hlayLe c hc
        show c.2 + 1 ≤ S.logTrace + 1
        omega)
  set s5 := Channel.mixFelts true (Channel.mixRoot true (Channel.mixRoot true s0 ppB)
      (CircuitVerify.circuitHash S.config.logBlowupFactor S.logSizes S.ppRootWords))
      (S.outputDigest.map fun w => QM31.fromM31s ((w % 2 ^ 16 : Nat) : F) ((w / 2 ^ 16 : Nat) : F) 0 0)
    with hs5
  have hst6 : st6 ρ S G.res = Channel.mixRoot true s5 (regBytes ρ G.res.traceRoot) := by
    unfold st6 st3
    rw [circuitHash_eq, wordsBytes_ofNat, outs_felts hS.houtW]
    rfl
  set tr1 : Pcs.Tree := ⟨regBytes ρ G.res.traceRoot,
    (CircuitVerify.traceColumnLogSizes S.logSizes).map (· + 1), S.logTrace + 1⟩ with htr1
  have hc1 : Pcs.commit true S.config [tr0] s5 (regBytes ρ G.res.traceRoot)
      (CircuitVerify.traceColumnLogSizes S.logSizes)
      = .ok ([tr0, tr1], Channel.mixRoot true s5 (regBytes ρ G.res.traceRoot)) :=
    SpecGlue.pcsCommit_ok true S.config [tr0] s5 _ _
      (by intro he; have := congrArg List.length he; rw [traceCols_length hS.hlsl] at this
          exact absurd this (by decide))
      (fun l hl => by
        have := (hlsmem l (mem_colLogs hl)).1
        show l + 1 ≤ S.logTrace + 1
        omega)
  set tr2 : Pcs.Tree := ⟨regBytes ρ G.res.interRoot,
    (CircuitVerify.interColumnLogSizes S.logSizes).map (· + 1), S.logTrace + 1⟩ with htr2
  have hc2 : Pcs.commit true S.config [tr0, tr1] (Channel.mixFelts true (st7 ρ S G.res)
      (G.res.claimed.map ρ)) (regBytes ρ G.res.interRoot) (CircuitVerify.interColumnLogSizes S.logSizes)
      = .ok ([tr0, tr1, tr2], st9 ρ S G.res) :=
    SpecGlue.pcsCommit_ok true S.config [tr0, tr1] _ _ _
      (by intro he; have := congrArg List.length he; rw [interCols_length hS.hlsl] at this
          exact absurd this (by decide))
      (fun l hl => by
        have := (hlsmem l (mem_colLogs hl)).1
        show l + 1 ≤ S.logTrace + 1
        omega)
  have hsz : (S.logSizes.any fun l => decide (l ≥ 2 ^ 5 ∨
      S.config.traceLiftingLogSize - S.config.logBlowupFactor < l)) = false := by
    rw [List.any_eq_false]
    intro l hl
    have := hlsmem l hl
    show ¬ decide (l ≥ 2 ^ 5 ∨ S.logTrace + 1 - 1 < l) = true
    simp only [decide_eq_true_eq]
    omega
  have hstep1 := SpecAccept.circuitAccepts_eq true S.config S.layout S.ppRootWords S.outputDigest
    (ρ G.res.salt) (nonceNat (ρ G.res.interNonce)) (G.res.claimed.map ρ) (rdCommitments ρ S G.res)
    (rdProof ρ S G.res) S.logSizes _ _ _ _ _ (st7 ρ S G.res) _ (ρ R1.res.z) (ρ R1.res.alpha)
    (ρ R1.res.pub) hS.hls (by show 1 ≤ S.logTrace + 1; omega) hsz hru hc0
    hc1
    (by rw [← hst6]; exact hpw1) (by rw [← hst6]; exact hdr1)
    (by rw [← toNat_ofNat_map hS.houtW]; exact hpub) hsum hc2
  rw [hstep1]
  set air := CircuitAir.circuitAir S.layout (ρ R1.res.z) (ρ R1.res.alpha) (G.res.claimed.map ρ)
    S.logSizes with hair
  have hmax : max (air.compositionLogDegreeBound - 1)
      (S.config.traceLiftingLogSize - S.config.logBlowupFactor) = S.logTrace := hmaxeq
  set tr3 : Pcs.Tree := ⟨regBytes ρ G.res.compRoot,
    (List.replicate 8 (max (air.compositionLogDegreeBound - 1)
      (S.config.traceLiftingLogSize - S.config.logBlowupFactor))).map (· + 1), S.logTrace + 1⟩ with htr3
  have hc3 : Pcs.commit true S.config [tr0, tr1, tr2] ⟨(st9 ρ S G.res).digest, 1⟩
      (regBytes ρ G.res.compRoot) (List.replicate 8 (max (air.compositionLogDegreeBound - 1)
        (S.config.traceLiftingLogSize - S.config.logBlowupFactor)))
      = .ok ([tr0, tr1, tr2, tr3], st11 ρ S G.res) :=
    SpecGlue.pcsCommit_ok true S.config _ _ _ _ (by simp)
      (fun l hl => by
        rw [(List.mem_replicate.mp hl).2, hmax]
        show S.logTrace + 1 ≤ S.logTrace + 1
        exact le_rfl)
  have hstep2 := SpecAccept.nativeAccepts_eq true S.config air [tr0, tr1, tr2] (st9 ρ S G.res)
    (rdCommitments ρ S G.res) (rdProof ρ S G.res) (ρ R1.res.coeff) ⟨(st9 ρ S G.res).digest, 1⟩
    (regBytes ρ G.res.compRoot) [tr0, tr1, tr2, tr3] (st11 ρ S G.res) tO
    ⟨(st11 ρ S G.res).digest, 1⟩ (R1.res.oods.val ρ) v (by simp) rfl
    (by show 1 < S.logSizes.foldl max 0 + 1; have := hS.hcdb; omega)
    (by show 1 ≤ S.logTrace + 1; omega) hcoef rfl hc3 hseed hpt
    (by rw [hmax]; exact hext) (by rw [hmax]; exact heval)
  rw [hstep2, hmax]
  -- The FRI commit.
  have hfrl : G.res.friRoots.length = S.logTrace := by rw [hGF.friRootsLen]; omega
  have hroots := fri_roots ρ S G.res hfrl (by have := hS.hlT; omega)
  have hal : R3.res.alphas.length = G.res.friRoots.length := by rw [hR3def]; exact phase3G_alphas_length
  have htrl : (rdFriTr ρ S G.res).1.length = S.logTrace := by
    show (friTr _ _).1.length = _
    rw [← halph, List.length_map, hal, hfrl]
  have hfc := SpecGlue.friCommit_ok ⟨(st12 ρ S G.res).digest, 1⟩ S.config.friConfig rfl rfl rfl
    (rdFri ρ S G.res) S.logTrace (by have := hS.hlT; omega) (by simp [rdFri])
    (by rw [hroots]; show (rdFriTr ρ S G.res).1.length = _; rw [htrl]; simp [rdFri]; have := hS.hlT; omega)
    (by simp [rdFri])
  rw [hroots] at hfc
  have huniq : Merkle.sortedUnique (Channel.drawQueries true (canonicDomain (S.logTrace + 1)).logSize
      S.nq (stP ρ S G.res)).1 = rdUniq ρ S G.res := by
    rw [Bridge.canonic_logSize (by omega)]; rfl
  refine SpecAccept.verifyValues_ok true S.config [tr0, tr1, tr2, tr3] _ (rdProof ρ S G.res) _
    (ρ R3.res.oq) ⟨(st12 ρ S G.res).digest, 1⟩ _ _
    ((List.range (rdUniq ρ S G.res).length).map fun k => (FI.res.map ρ).getD (rdRep ρ S G.res k) 0)
    (by simp) rfl rfl hdeep ?_ (by show 1 ≤ S.logTrace + 1; omega) hfc hpow ?_ ?_ ?_
  · -- Shapes.
    have hi2 : ((CircuitAirData.interShape.toList.flatMap fun n =>
        List.replicate (n - 4) [R1.res.oods.val ρ] ++
          List.replicate 4 [CircuitAir.prevPoint (R1.res.oods.val ρ) S.logTrace, R1.res.oods.val ρ])).length
        = CircuitAirData.nInter := by
      rw [List.length_flatMap]
      simp only [List.length_append, List.length_replicate]
      decide
    change Pcs.shapeCheck _ (CircuitAir.maskPoints (R1.res.oods.val ρ) S.logTrace ++
      [List.replicate 8 [R1.res.oods.val ρ]]) = _
    unfold Pcs.shapeCheck
    simp only [CircuitAir.maskPoints, List.cons_append, List.nil_append, List.length_cons, List.length_nil,
      ne_eq, not_true_eq_false, if_false, List.zip_cons_cons, List.zip_nil_left, List.any_cons,
      List.any_nil, Bool.or_false, bind, Except.bind, pure, Except.pure, htr0, htr1, htr2, htr3,
      List.length_map, List.length_replicate, hS.hlay, traceCols_length hS.hlsl,
      interCols_length hS.hlsl, hi2]
    rfl
  · -- Merkle, per tree.
    have hprep : Pcs.prepareTreePositions (Merkle.sortedUnique (Channel.drawQueries true
        (canonicDomain (S.logTrace + 1)).logSize S.nq (stP ρ S G.res)).1) (S.logTrace + 1)
        (if S.logTrace + 1 = 0 then none else some (S.logTrace + 1)) = rdUniq ρ S G.res := by
      rw [if_neg (by omega), prepare_id (by omega), huniq]
    have hver : ∀ t, t < 4 → ∀ root logs, logs = treeLogs S t →
        (treeLogs S t).length = treeCols.getD t 0 →
        Paths (treeMQs ρ S G.res t) (S.logTrace + 1) root →
        Merkle.verify root logs (S.logTrace + 1) (rdUniq ρ S G.res) (rdQueried ρ S G.res t)
          (wits (treeMQs ρ S G.res t) (rdUniq ρ S G.res) 0 (S.logTrace + 1)) = .ok () := by
      intro t ht root logs hlogs hlen hP
      have := TreeGlue.tree_verify (treeLogs S t) (xv ρ G.res t) hrawl hS.hnq hP
      rw [hlen] at this
      rw [hlogs]
      exact this
    have hdec4 : (rdProof ρ S G.res).decommitments = [wits (treeMQs ρ S G.res 0) (rdUniq ρ S G.res) 0
        (S.logTrace + 1), wits (treeMQs ρ S G.res 1) (rdUniq ρ S G.res) 0 (S.logTrace + 1),
        wits (treeMQs ρ S G.res 2) (rdUniq ρ S G.res) 0 (S.logTrace + 1),
        wits (treeMQs ρ S G.res 3) (rdUniq ρ S G.res) 0 (S.logTrace + 1)] := rfl
    have hq4 : (rdProof ρ S G.res).queriedValues = [rdQueried ρ S G.res 0, rdQueried ρ S G.res 1,
        rdQueried ρ S G.res 2, rdQueried ρ S G.res 3] := rfl
    intro x hx
    rw [hdec4, hq4] at hx
    simp only [List.zip_cons_cons, List.zip_nil_left, List.mem_cons, List.not_mem_nil, or_false] at hx
    rcases hx with rfl | rfl | rfl | rfl
    · show Merkle.verify ppB ((S.layout.map (fun c : String × ℕ => c.2)).map (· + 1)) (S.logTrace + 1)
        (Pcs.prepareTreePositions (Merkle.sortedUnique (Channel.drawQueries true
          (canonicDomain (S.logTrace + 1)).logSize S.nq (stP ρ S G.res)).1) (S.logTrace + 1)
          (if S.logTrace + 1 = 0 then none else some (S.logTrace + 1))) _ _ = _
      rw [hprep]
      exact hver 0 (by norm_num) _ _ (by rw [List.map_map]; rfl)
        (by show (S.layout.map _).length = _; rw [List.length_map, hS.hlay]; rfl)
        (by rw [← hppB]; exact hP0)
    · show Merkle.verify (regBytes ρ G.res.traceRoot) _ (S.logTrace + 1)
        (Pcs.prepareTreePositions (Merkle.sortedUnique (Channel.drawQueries true
          (canonicDomain (S.logTrace + 1)).logSize S.nq (stP ρ S G.res)).1) (S.logTrace + 1)
          (if S.logTrace + 1 = 0 then none else some (S.logTrace + 1))) _ _ = _
      rw [hprep]
      exact hver 1 (by norm_num) _ _ rfl
        (by show (List.map _ _).length = _; rw [List.length_map, traceCols_length hS.hlsl]; rfl) hP1
    · show Merkle.verify (regBytes ρ G.res.interRoot) _ (S.logTrace + 1)
        (Pcs.prepareTreePositions (Merkle.sortedUnique (Channel.drawQueries true
          (canonicDomain (S.logTrace + 1)).logSize S.nq (stP ρ S G.res)).1) (S.logTrace + 1)
          (if S.logTrace + 1 = 0 then none else some (S.logTrace + 1))) _ _ = _
      rw [hprep]
      exact hver 2 (by norm_num) _ _ rfl
        (by show (List.map _ _).length = _; rw [List.length_map, interCols_length hS.hlsl]; rfl) hP2
    · show Merkle.verify (regBytes ρ G.res.compRoot) _ (S.logTrace + 1)
        (Pcs.prepareTreePositions (Merkle.sortedUnique (Channel.drawQueries true
          (canonicDomain (S.logTrace + 1)).logSize S.nq (stP ρ S G.res)).1) (S.logTrace + 1)
          (if S.logTrace + 1 = 0 then none else some (S.logTrace + 1))) _ _ = _
      rw [hprep]
      exact hver 3 (by norm_num) _ _ (by
          show (List.replicate 8 (max (air.compositionLogDegreeBound - 1)
            (S.config.traceLiftingLogSize - S.config.logBlowupFactor))).map (· + 1) = _
          rw [hmax, List.map_replicate]; rfl)
        (by show (List.replicate 8 _).length = _; rw [List.length_replicate]; rfl) hP3
  · -- The DEEP answers at the unique positions.
    have hcls : [tr0, tr1, tr2, tr3].map (·.columnLogSizes) = clsList S := by
      show [(S.layout.map (fun c : String × ℕ => c.2)).map (· + 1),
        (CircuitVerify.traceColumnLogSizes S.logSizes).map (· + 1),
        (CircuitVerify.interColumnLogSizes S.logSizes).map (· + 1),
        (List.replicate 8 (max (air.compositionLogDegreeBound - 1)
          (S.config.traceLiftingLogSize - S.config.logBlowupFactor))).map (· + 1)] = _
      rw [hmax, List.map_replicate, List.map_map]
      rfl
    have hrepq : ∀ k, k < (rdUniq ρ S G.res).length →
        rdRep ρ S G.res k < (rdRaw ρ S G.res).length ∧
        (rdRaw ρ S G.res).getD (rdRep ρ S G.res k) 0 = (rdUniq ρ S G.res).getD k 0 :=
      fun k hk => TreeGlue.rep_spec hk
    have hsel := queried_sel ρ S G.res fun k hk => by rw [← hrawl]; exact (hrepq k hk).1
    change Quotients.friAnswers _ (spList (R1.res.oods.val ρ) S.logTrace) (rdSampled ρ G.res)
      (ρ R3.res.oq) (Merkle.sortedUnique (Channel.drawQueries true
        (canonicDomain (S.logTrace + 1)).logSize S.nq (stP ρ S G.res)).1)
      ((List.range 4).map (rdQueried ρ S G.res)) (S.logTrace + 1) = _
    rw [hcls, huniq]
    exact SpecGlue.friAnswers_select (clsList S) _ (rdSampled ρ G.res) (ρ R3.res.oq) (rdRaw ρ S G.res)
      (rdUniq ρ S G.res) (rdQueriedRaw ρ S G.res) _ (S.logTrace + 1) batches (FI.res.map ρ)
      (rdRep ρ S G.res) hbuild him hidx hden hcolsRaw hposRaw hans hsel.length_eq
      (fun col hcol => by
        obtain ⟨tc, htc, hcol⟩ := List.mem_flatten.mp hcol
        obtain ⟨t, -, rfl⟩ := List.mem_map.mp htc
        obtain ⟨c, -, rfl⟩ := List.mem_map.mp hcol
        rw [List.length_map, List.length_range])
      hrepq (fun k hk ci => selRel_getD hsel ci k hk)
  · -- The FRI decommitment.
    have hL1 : S.logTrace + 1 - 1 = S.logTrace := by omega
    have H : Bridge.FriH ρ S.nq (S.logTrace + 1) (fPos ρ S G.res) (fWit G.res) (fSws ρ G.res)
        (fWr ρ G.res) R3.res.alphas G.res.lastCoef (rdUniq ρ S G.res) V := by
      refine ⟨by have := hS.hlT; omega, by have := hS.hlT29; omega, hposlt, fun p => ?_,
        TreeGlue.sortedUnique_lt _, hS.hnq, fun l hl i hi => (hVl l hl i hi).1,
        fun l hl i hi => (hVl l hl i hi).2.1, fun l hl i hi => (hVl l hl i hi).2.2, hVL,
        fun l hl i hi => ?_, fun l hl i hi k hk => ?_,
        fun l hl q hq q' hq' k hk h => hcoll.fri l (by omega) q hq q' hq' k (by omega) h,
        fun l hl => hcoll.leaf l (by omega)⟩
      · unfold rdUniq
        rw [TreeGlue.sortedUnique_mem, List.mem_iff_getElem]
        constructor
        · rintro ⟨i, hi, rfl⟩
          exact ⟨i, by rw [← hrawl]; exact hi, by
            show (rdRaw ρ S G.res).getD i 0 = _; rw [List.getD_eq_getElem _ _ hi]⟩
        · rintro ⟨i, hi, rfl⟩
          exact ⟨i, by rw [hrawl]; exact hi, by
            show _ = (rdRaw ρ S G.res).getD i 0; rw [List.getD_eq_getElem _ _ (by rw [hrawl]; exact hi)]⟩
      · rw [fSws, List.length_map]; exact hGF.friAuthLen l hl i hi
      · have hh := hGF.friAuth l hl i hi k (by rw [fSws, List.length_map] at hk; rw [← hGF.friAuthLen l hl i hi]; exact hk)
        rw [fSws, regWords_getD, regWords, List.length_map]
        exact hh.2
    have hαl : R3.res.alphas.length = S.logTrace := by rw [hal, hfrl]
    have htrα : ∀ i, i < S.logTrace → (rdFriTr ρ S G.res).1.getD i 0 = ρ (R3.res.alphas.getD i 0) := by
      intro i hi
      show (friTr _ _).1.getD i 0 = _
      rw [← halph, List.getD_eq_getElem _ _ (by rw [List.length_map, hαl]; exact hi), List.getElem_map,
        List.getD_eq_getElem _ _ (by rw [hαl]; exact hi)]
    have hdecH := H.decommit ⟨S.config.friConfig, canonicDomain (S.logTrace + 1),
        (rdFriTr ρ S G.res).1.getD 0 0, (rdFri ρ S G.res).firstLayer,
        (List.range (S.logTrace - 1)).map (fun i => (LineDomain.double^[i] ⟨Coset.halfOdds S.logTrace⟩,
          (rdFriTr ρ S G.res).1.getD (i + 1) 0, (rdFri ρ S G.res).innerLayers.getD i SpecGlue.dummyLP)),
        LineDomain.double^[S.logTrace - 1] ⟨Coset.halfOdds S.logTrace⟩, (rdFri ρ S G.res).lastLayerPoly⟩
      rfl (by show (rdFriTr ρ S G.res).1.getD 0 0 = _; exact htrα 0 (by have := hS.hlT; omega)) rfl
      (by
        show (List.range (S.logTrace - 1)).map _ = (List.range (S.logTrace + 1 - 2)).map _
        rw [show S.logTrace + 1 - 2 = S.logTrace - 1 by omega]
        refine List.map_congr_left fun i hi => ?_
        have hi' : i < S.logTrace - 1 := List.mem_range.mp hi
        rw [htrα (i + 1) (by omega)]
        rw [show (rdFri ρ S G.res).innerLayers.getD i SpecGlue.dummyLP
          = (Bridge.friEntry ρ S.nq (S.logTrace + 1) (fPos ρ S G.res) (fWit G.res) (fSws ρ G.res)
              (fWr ρ G.res) [] (rdUniq ρ S G.res) i).2.2 from by
            unfold rdFri; exact TreeGlue.grm _ _ (by omega)]
        rfl)
      rfl
    have hanswers : ((List.range (rdUniq ρ S G.res).length).map fun k =>
        (FI.res.map ρ).getD (rdRep ρ S G.res k) 0)
        = (rdUniq ρ S G.res).map (FriBatch.Cv (Bridge.qsOf ρ S.nq (fPos ρ S G.res) (fWit G.res)
          (fSws ρ G.res) V 0)) := by
      refine List.ext_getElem (by simp) fun k h1 h2 => ?_
      have hk : k < (rdUniq ρ S G.res).length := by simpa using h1
      obtain ⟨hr, he⟩ := TreeGlue.rep_spec hk
      have hrq : rdRep ρ S G.res k < S.nq := by rw [← hrawl]; exact hr
      rw [List.getElem_map, List.getElem_range, List.getElem_map,
        List.getD_eq_getElem _ _ (by rw [List.length_map, hFIlen]; exact hrq), List.getElem_map,
        ← List.getD_eq_getElem FI.res 0 (by rw [hFIlen]; exact hrq), ← hV0 _ hrq,
        ← H.cv0 hrq, ← List.getD_eq_getElem _ 0 hk]
      show FriBatch.Cv _ ((rdRaw ρ S G.res).getD (rdRep ρ S G.res k) 0) = _
      rw [show (rdRaw ρ S G.res).getD (rdRep ρ S G.res k) 0 = (rdUniq ρ S G.res).getD k 0 from he]
    change Fri.decommit _ (Merkle.sortedUnique (Channel.drawQueries true
      (canonicDomain (S.logTrace + 1)).logSize S.nq (stP ρ S G.res)).1) _ = _
    rw [huniq, hanswers]
    exact hdecH

end StwoVerifier.ScopeB
