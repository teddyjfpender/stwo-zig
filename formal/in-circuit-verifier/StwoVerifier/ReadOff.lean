/-
**The read-off native proof.**

From a gate assignment `ρ` and the guessed proof registers `g`, the
native `circuitAccepts` arguments: salt, nonces, claimed sums, the four
commitments, and the PCS proof — sampled values, the per-tree Merkle
witnesses (`MerkleBatch.wits`) and queried values at the unique
positions, the proof of work, and the FRI proof (`fwit`/`wits` per
layer, the last-layer constant). Positions come from the spec
transcript replayed on the read-off values (`rdRaw`), which the scope-B
theorem shows is the circuit's query selection.
-/
import StwoVerifier.VerifyG
import StwoVerifier.PhaseFriSpec
import StwoVerifier.SpecGlue
import StwoVerifier.ColumnOrder

namespace StwoVerifier.ReadOff

open StwoVerifier StwoVerifier.Gadgets StwoVerifier.Gates MerkleBatch FriBatch

/-- A guessed hash's bytes. -/
noncomputable def regBytes (ρ : ℕ → QM31) (regs : List ℕ) : Channel.Bytes :=
  wordsBytes (regWords ρ regs)

/-- An M31 wire's base value. -/
def baseOf (x : QM31) : F := x.c0.a

/-- The static statement and profile. -/
structure Stmt where
  layout : List (String × ℕ)
  logSizes : List ℕ
  ppRootWords : List ℕ
  outputDigest : List ℕ
  logTrace : ℕ
  powBits : ℕ
  nq : ℕ

/-- The pinned profile's PCS config. -/
def Stmt.config (S : Stmt) : Pcs.PcsConfig :=
  ⟨S.powBits, 1, 0, S.nq, 1, S.logTrace + 1, S.logTrace + 1⟩

section
variable (ρ : ℕ → QM31) (S : Stmt) (g : ProofRegs)

/-! ### The replayed transcript -/

/-- After the salt, FRI config and preprocessed root (phase 1's byte
forms; `ScopeB` converts them to the spec's). -/
noncomputable def st3 : Channel.St :=
  Channel.mixRoot true (Channel.mixFelts true (Channel.mixFelts true Channel.init [ρ g.salt])
    [(cfgFelts S.powBits S.nq).1, (cfgFelts S.powBits S.nq).2])
    (wordsBytes (S.ppRootWords.map (BitVec.ofNat 32)))

/-- After the circuit hash, the outputs and the trace root. -/
noncomputable def st6 : Channel.St :=
  Channel.mixRoot true (Channel.mixFelts true (Channel.mixRoot true (st3 ρ S g)
    (Blake2s.blake2s (wordsBytes (((List.range 3).map fun i =>
      BitVec.ofNat 32 ((CircuitVerify.configWords 1 S.logSizes).getD i 0))
      ++ S.ppRootWords.map (BitVec.ofNat 32)))))
    ((S.outputDigest.map (BitVec.ofNat 32)).map packW))
    (wordsBytes (regWords ρ g.traceRoot))

/-- After the interaction proof of work and the two interaction draws. -/
noncomputable def st7 : Channel.St :=
  ⟨(Channel.mixU64 true (st6 ρ S g) (nonceNat (ρ g.interNonce))).digest, 1⟩

/-- After the claimed sums and the interaction root. -/
noncomputable def st9 : Channel.St :=
  Channel.mixRoot true (Channel.mixFelts true (st7 ρ S g) (g.claimed.map ρ))
    (wordsBytes (regWords ρ g.interRoot))

/-- After the composition coefficient draw and the composition root. -/
noncomputable def st11 : Channel.St :=
  Channel.mixRoot true ⟨(st9 ρ S g).digest, 1⟩ (wordsBytes (regWords ρ g.compRoot))

/-- The proof's sampled values. -/
noncomputable def rdSampled : List (List (List QM31)) :=
  svOf ρ g.ppAt g.traceAt (interAtOf g.comps) g.compAt

/-- After the OODS point draw and the sampled-value mix. -/
noncomputable def st12 : Channel.St :=
  Channel.mixFelts true ⟨(st11 ρ S g).digest, 1⟩ (((rdSampled ρ g).map (·.flatten)).flatten)

/-- The FRI roots' bytes. -/
noncomputable def rdFriRoots : List Channel.Bytes := g.friRoots.map (regBytes ρ)

/-- The FRI commit transcript, from the state after the DEEP draw. -/
noncomputable def rdFriTr : List QM31 × Channel.St :=
  friTr ⟨(st12 ρ S g).digest, 1⟩ (rdFriRoots ρ g)

/-- The state the queries are drawn from. -/
noncomputable def stP : Channel.St :=
  Channel.mixU64 true (Channel.mixFelts true (rdFriTr ρ S g).2 [ρ g.lastCoef])
    (nonceNat (ρ g.powNonce))

/-- The raw query positions. -/
noncomputable def rdRaw : List ℕ :=
  (Channel.drawQueries true (S.logTrace + 1) S.nq (stP ρ S g)).1

/-- The unique positions. -/
noncomputable def rdUniq : List ℕ := Merkle.sortedUnique (rdRaw ρ S g)

/-- A representative raw query of unique position `k`. -/
noncomputable def rdRep (k : ℕ) : ℕ := (rdRaw ρ S g).findIdx (· = (rdUniq ρ S g).getD k 0)

/-! ### The trees -/

/-- The spec column log sizes of tree `t` (blowup-extended). -/
def treeLogs (S : Stmt) : ℕ → List ℕ
  | 0 => S.layout.map (·.2 + 1)
  | 1 => (CircuitVerify.traceColumnLogSizes S.logSizes).map (· + 1)
  | 2 => (CircuitVerify.interColumnLogSizes S.logSizes).map (· + 1)
  | _ => List.replicate 8 (S.logTrace + 1)

/-- Raw sample of tree `t`, column `c`, query `q`. -/
noncomputable def xv (t c q : ℕ) : F := baseOf (ρ (((g.cols.getD t []).getD c []).getD q 0))

/-- Tree `t`'s per-query Merkle views. -/
noncomputable def treeMQs (t : ℕ) : List MQ :=
  (List.range S.nq).map fun q =>
    ⟨(rdRaw ρ S g).getD q 0,
     Merkle.leafHash ((Merkle.columnOrder (treeLogs S t)).map fun c => xv ρ g t c q),
     ((g.authT.getD t []).getD q []).map (regBytes ρ)⟩

/-- Tree `t`'s queried values at the unique positions. -/
noncomputable def rdQueried (t : ℕ) : List (List F) :=
  (List.range (treeCols.getD t 0)).map fun c =>
    (List.range (rdUniq ρ S g).length).map fun k => xv ρ g t c (rdRep ρ S g k)

/-! ### FRI -/

noncomputable def fWit (l i : ℕ) : ℕ × ℕ := (g.friWit.getD l []).getD i (0, 0)
noncomputable def fSws (l i : ℕ) : List (List Blake2s.Word) :=
  ((g.friAuth.getD l []).getD i []).map (regWords ρ)
noncomputable def fWr (l : ℕ) : List Blake2s.Word := regWords ρ (g.friRoots.getD l [])
noncomputable def fPos (q : ℕ) : ℕ := (rdRaw ρ S g).getD q 0

/-- Layer 0's raw queries with the fold output zeroed. -/
noncomputable def fqs0 (l : ℕ) : List FQ :=
  Bridge.qsOf ρ S.nq (fPos ρ S g) (fWit g) (fSws ρ g) (fun _ _ => 0) l

/-- The read-off FRI proof. -/
noncomputable def rdFri : Fri.FriProof :=
  ⟨⟨fwit (fqs0 ρ S g 0) (rdUniq ρ S g),
    wits (allMQ (fqs0 ρ S g 0))
      ((par (rdUniq ρ S g)).flatMap fun k => [k * 2, k * 2 + 1]) 0 (S.logTrace + 1),
    regBytes ρ (g.friRoots.getD 0 [])⟩,
   (List.range (S.logTrace + 1 - 2)).map fun l =>
     (Bridge.friEntry ρ S.nq (S.logTrace + 1) (fPos ρ S g) (fWit g) (fSws ρ g) (fWr ρ g) []
       (rdUniq ρ S g) l).2.2,
   [ρ g.lastCoef]⟩

/-! ### The proof -/

/-- The read-off PCS proof. -/
noncomputable def rdProof : Pcs.Proof :=
  ⟨rdSampled ρ g,
   (List.range 4).map fun t => wits (treeMQs ρ S g t) (rdUniq ρ S g) 0 (S.logTrace + 1),
   (List.range 4).map (rdQueried ρ S g),
   nonceNat (ρ g.powNonce),
   rdFri ρ S g⟩

/-- The read-off commitments (the preprocessed one is the statement's). -/
noncomputable def rdCommitments : List Channel.Bytes :=
  [S.ppRootWords.flatMap Channel.u32Le, regBytes ρ g.traceRoot, regBytes ρ g.interRoot,
   regBytes ρ g.compRoot]

end

end StwoVerifier.ReadOff
