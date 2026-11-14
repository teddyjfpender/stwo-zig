/-
**Spec-side assembly**: the top-level acceptance predicates succeed
given their intermediate facts.

`verifyValues_ok`, `nativeAccepts_ok`, `circuitAccepts_ok` unfold the
spec's `Pcs.verifyValues`, `NativeAccepts` and `CircuitVerify.circuitAccepts`
and discharge every check from a named hypothesis (each the exact
sub-computation the spec performs). They are the interface the gadget
walk of the in-circuit `verify` delivers.
-/
import StwoVerifier.CircuitVerify
import StwoVerifier.MerkleBatch

namespace StwoVerifier.SpecAccept

open StwoVerifier

/-- **`verifyValues` succeeds** given each of its steps. -/
theorem verifyValues_ok (m31 : Bool) (config : Pcs.PcsConfig) (trees : List Pcs.Tree)
    (sampledPoints : List (List (List PointQ))) (proof : Pcs.Proof) (s : Channel.St)
    (deep : QM31) (s1 : Channel.St) (fri : Fri.Committed) (s2 : Channel.St)
    (answers : List QM31)
    (hne : trees.isEmpty = false)
    (hdl : proof.decommitments.length = trees.length)
    (hql : proof.queriedValues.length = trees.length)
    (hdraw : Channel.drawSecureFelt m31 (Channel.mixFelts m31 s
      ((proof.sampledValues.map (·.flatten)).flatten)) = some (deep, s1))
    (hshape : Pcs.shapeCheck trees sampledPoints = .ok ())
    (hlift : config.logBlowupFactor ≤ (trees.getLast?.map (·.height)).getD 0)
    (hfri : Fri.commit m31 s1 config.friConfig proof.friProof
      ((trees.getLast?.map (·.height)).getD 0 - config.logBlowupFactor) = .ok (fri, s2))
    (hpow : Channel.verifyPowNonce m31 s2 config.powBits proof.proofOfWork = true)
    (hmerkle : ∀ x ∈ (trees.zip proof.decommitments).zip proof.queriedValues,
      Merkle.verify x.1.1.root x.1.1.columnLogSizes x.1.1.height
        (Pcs.prepareTreePositions (Merkle.sortedUnique (Channel.drawQueries m31
          fri.columnCommitmentDomain.logSize config.nQueries
          (Channel.mixU64 m31 s2 proof.proofOfWork)).1)
          ((trees.getLast?.map (·.height)).getD 0)
          (if x.1.1.height = 0 then none else some x.1.1.height))
        x.2 x.1.2 = .ok ())
    (hans : Quotients.friAnswers (trees.map (·.columnLogSizes)) sampledPoints
      proof.sampledValues deep
      (Merkle.sortedUnique (Channel.drawQueries m31 fri.columnCommitmentDomain.logSize
        config.nQueries (Channel.mixU64 m31 s2 proof.proofOfWork)).1)
      proof.queriedValues ((trees.getLast?.map (·.height)).getD 0) = .ok answers)
    (hdec : Fri.decommit fri (Merkle.sortedUnique (Channel.drawQueries m31
      fri.columnCommitmentDomain.logSize config.nQueries
      (Channel.mixU64 m31 s2 proof.proofOfWork)).1) answers = .ok ()) :
    Pcs.verifyValues m31 config trees sampledPoints proof s = .ok () := by
  unfold Pcs.verifyValues
  simp only [hne, Bool.false_eq_true, if_false, hdl, hql, ne_eq, not_true_eq_false]
  rw [hdraw]
  simp only [pure, Except.pure, bind, Except.bind]
  rw [hshape]
  simp only []
  rw [if_neg (by omega), hfri]
  simp only []
  rw [hpow]
  simp only [Bool.not_true, Bool.false_eq_true, if_false, not_true_eq_false]
  rw [MerkleBatch.mapM_ok' (fun _ => ()) _ hmerkle]
  simp only []
  rw [hans]
  exact hdec

/-- **`NativeAccepts` reduces to `verifyValues`** given its transcript
steps and the composition check. -/
theorem nativeAccepts_eq (m31 : Bool) (config : Pcs.PcsConfig) (air : Air)
    (trees : List Pcs.Tree) (s : Channel.St) (commitments : List Channel.Bytes)
    (proof : Pcs.Proof) (r : QM31) (s1 : Channel.St) (cc : Channel.Bytes)
    (trees' : List Pcs.Tree) (s2 : Channel.St) (seed : QM31) (s3 : Channel.St)
    (pt : PointQ) (v : QM31)
    (htl : 0 < trees.length) (hsplit : air.compositionLogSplit = 1)
    (hcl : 1 < air.compositionLogDegreeBound)
    (hlift : config.logBlowupFactor ≤ config.traceLiftingLogSize)
    (hdr1 : Channel.drawSecureFelt m31 s = some (r, s1))
    (hlast : commitments.getLast? = some cc)
    (hcommit : Pcs.commit m31 config trees s1 cc (List.replicate 8
      (max (air.compositionLogDegreeBound - 1)
        (config.traceLiftingLogSize - config.logBlowupFactor))) = .ok (trees', s2))
    (hdr2 : Channel.drawSecureFelt m31 s2 = some (seed, s3))
    (hpt : securePointFromSeed seed = some pt)
    (hext : extractCompositionOodsEval proof.sampledValues pt
      (max (air.compositionLogDegreeBound - 1)
        (config.traceLiftingLogSize - config.logBlowupFactor) + 1) 1 = some v)
    (heval : air.evalComposition pt proof.sampledValues r
      (max (air.compositionLogDegreeBound - 1)
        (config.traceLiftingLogSize - config.logBlowupFactor)) = .ok v) :
    NativeAccepts m31 config air trees s commitments proof
      = Pcs.verifyValues m31 config trees'
          (air.maskPoints pt (max (air.compositionLogDegreeBound - 1)
            (config.traceLiftingLogSize - config.logBlowupFactor))
            ++ [List.replicate 8 [pt]]) proof s3 := by
  unfold NativeAccepts
  rw [if_neg (by omega), hsplit]
  simp only [compositionColumnCount, show ¬ ((1 : ℕ) = 0 ∨ 1 > 8) by omega, if_false,
    pure, Except.pure, bind, Except.bind]
  rw [if_neg (by omega), if_neg (by omega), hdr1]
  simp only []
  rw [hlast]
  simp only []
  rw [show 2 ^ 1 * 4 = 8 from rfl, hcommit]
  simp only []
  rw [hdr2]
  simp only []
  rw [hpt]
  simp only []
  rw [hext]
  simp only []
  rw [heval]
  simp only [not_true_eq_false, if_false]

open CircuitVerify in
/-- **`circuitAccepts` reduces to `NativeAccepts`** given the statement
checks and transcript steps. -/
theorem circuitAccepts_eq (m31 : Bool) (config : Pcs.PcsConfig)
    (layout : List (String × Nat)) (ppRootWords outputDigest : List Nat)
    (channelSalt : QM31) (interactionPowNonce : Nat) (claimedSums : List QM31)
    (commitments : List Channel.Bytes) (proof : Pcs.Proof)
    (logSizes : List Nat) (t0 t1 t2 : List Pcs.Tree) (s3 s6 s7 s8 : Channel.St)
    (z alpha pub : QM31)
    (hls : componentLogSizes layout = some logSizes)
    (hlift : config.logBlowupFactor ≤ config.traceLiftingLogSize)
    (hsz : (logSizes.any fun l => decide (l ≥ 2 ^ 5 ∨
      config.traceLiftingLogSize - config.logBlowupFactor < l)) = false)
    (hru : relationUsesOk logSizes = true)
    (hc0 : Pcs.commit m31 config []
      (Channel.mixFelts m31 (Channel.mixFelts m31 Channel.init [channelSalt])
        [QM31.fromM31s (config.powBits : Nat) (config.logBlowupFactor : Nat)
          (config.nQueries : Nat) (config.logLastLayerDegreeBound : Nat),
         QM31.fromM31s (config.foldStep : Nat) 0 0 0])
      (ppRootWords.flatMap Channel.u32Le) (layout.map (·.2)) = .ok (t0, s3))
    (hc1 : Pcs.commit m31 config t0
      (Channel.mixFelts m31 (Channel.mixRoot m31 s3
        (circuitHash config.logBlowupFactor logSizes ppRootWords))
        (outputDigest.map fun w =>
          QM31.fromM31s ((w % 2 ^ 16 : Nat) : F) ((w / 2 ^ 16 : Nat) : F) 0 0))
      (commitments.getD 1 []) (traceColumnLogSizes logSizes) = .ok (t1, s6))
    (hpow : Channel.verifyPowNonce m31 s6 20 interactionPowNonce = true)
    (hdraw : Channel.drawSecureFelts m31 2 (Channel.mixU64 m31 s6 interactionPowNonce)
      = some ([z, alpha], s7))
    (hpub : publicLogupSum outputDigest z alpha = .ok pub)
    (hsum : pub + claimedSums.foldl (· + ·) QM31.zero = QM31.zero)
    (hc2 : Pcs.commit m31 config t1 (Channel.mixFelts m31 s7 claimedSums)
      (commitments.getD 2 []) (interColumnLogSizes logSizes) = .ok (t2, s8)) :
    circuitAccepts m31 config layout ppRootWords outputDigest channelSalt
        interactionPowNonce claimedSums commitments proof
      = NativeAccepts m31 config (CircuitAir.circuitAir layout z alpha claimedSums logSizes)
          t2 s8 commitments proof := by
  unfold circuitAccepts
  rw [hls]
  simp only [pure, Except.pure, bind, Except.bind]
  rw [if_neg (by omega), hsz]
  simp only [Bool.false_eq_true, if_false, hru, Bool.not_true, not_true_eq_false]
  rw [hc0]
  simp only []
  rw [hc1]
  simp only []
  rw [hpow]
  simp only [Bool.not_true, Bool.false_eq_true, if_false, not_true_eq_false]
  rw [hdraw]
  simp only []
  rw [show [z, alpha].getD 0 QM31.zero = z from rfl,
    show [z, alpha].getD 1 QM31.zero = alpha from rfl, hpub]
  simp only []
  rw [hsum]
  simp only [not_true_eq_false, if_false]
  rw [hc2]

end StwoVerifier.SpecAccept
