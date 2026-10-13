/-
**The in-circuit `verify` with `CircuitStatement`, composed**
(`verify.zig` `verify`, at the pinned profile: blowup 1, fold step 1,
last-layer bound 0).

`verifyG`: the constants, the guessed proof (`guessG`), then the six
phases in the circuit's order — transcript to the OODS point; relation
uses, OODS mix and composition check; DEEP draw, FRI commit, proof of
work and query selection; the query bits; the four eval-domain
decommitments; the DEEP answers; the FRI decommitment. The statement's
preprocessed root and output digest are input registers.
-/
import StwoVerifier.GuessPhase
import StwoVerifier.PhaseComposition
import StwoVerifier.PhasePcs
import StwoVerifier.PhaseDecommit
import StwoVerifier.PhaseDeep
import StwoVerifier.PhaseFri

namespace StwoVerifier.Gadgets

open StwoVerifier StwoVerifier.Gates

/-- The sort-key index bits of the trace and interaction trees
(`log2(ceil_pow2(n_columns))`). -/
def bTrace : ℕ := 7
def bInter : ℕ := 8

/-- The packed FRI config felts (`mix_fri_config`). -/
def cfgFelts (powBits nq : ℕ) : QM31 × QM31 :=
  (QM31.fromM31s ((powBits : ℕ) : F) ((1 : ℕ) : F) ((nq : ℕ) : F) ((0 : ℕ) : F),
   QM31.fromM31s ((1 : ℕ) : F) 0 0 0)

/-- Query `q`'s scalar bits. -/
def bitsOfQ (sb : List (List ℕ)) (L q : ℕ) : List ℕ :=
  (List.range L).map fun t => (sb.getD t []).getD q 0

/-- All eval-domain sample columns, tree after tree. -/
def allCols (g : ProofRegs) : List (List ℕ) :=
  (g.cols.getD 0 []) ++ (g.cols.getD 1 []) ++ (g.cols.getD 2 []) ++ (g.cols.getD 3 [])

/-- Per-column constants of a list of naturals. -/
def natConsts (xs : List ℕ) : List QM31 := xs.map fun x => QM31.fromBase ((x : ℕ) : F)

/-- **`verify`**. -/
noncomputable def verifyG (layout : List (String × ℕ)) (logSizes : List ℕ)
    (logTrace powBits nq : ℕ) (ppRoot outs : List ℕ) (n : ℕ) : Out Unit :=
  (constsG [0, 1, uQ, QM31.fromBase ((2 ^ bTrace : ℕ) : F), QM31.fromBase ((2 ^ bInter : ℕ) : F),
    uQ⁻¹] n).seq fun k n =>
  (guessG nq (logTrace + 1) n).seq fun g n =>
  (phase1G (k.getD 0 0) (k.getD 1 0) (k.getD 2 0) logSizes logTrace (cfgFelts powBits nq).1
    (cfgFelts powBits nq).2 (CircuitVerify.configWords 1 logSizes) g.salt ppRoot outs
    g.traceRoot g.interNonce g.claimed g.interRoot g.compRoot n).seq fun r1 n =>
  (phase2G (k.getD 0 0) (k.getD 1 0) logTrace r1.low r1.high r1.sizeBits r1.sizes r1.oods
    r1.coeff r1.z r1.alpha (CircuitAir.ppPositions layout) g.ppAt g.traceAt (interAtOf g.comps)
    g.compAt g.claimed n).seq fun r2 n =>
  (phase3G (k.getD 0 0) (k.getD 1 0) (logTrace + 1) nq powBits r2.1 r2.2 g.friRoots [g.lastCoef]
    g.powNonce n).seq fun r3 n =>
  (Bridge.unpackAllG nq (r3.bits.take (logTrace + 1)) n).seq fun sb n =>
  (constsG (natConsts (CircuitVerify.traceColumnLogSizes logSizes)) n).seq fun tl n =>
  (constsG (natConsts (CircuitVerify.interColumnLogSizes logSizes)) n).seq fun il n =>
  (plainTreeG (g.cols.getD 0 []).flatten CircuitAirData.nPp nq (bitsOfQ sb (logTrace + 1)) ppRoot
    (fun q => (g.authT.getD 0 []).getD q []) (List.range nq) n).seq fun _ n =>
  (sortedTreeG (k.getD 0 0) (k.getD 1 0) (k.getD 2 0) (k.getD 3 0) (k.getD 5 0) tl bTrace
    (g.cols.getD 1 []).flatten CircuitAirData.nTrace nq (bitsOfQ sb (logTrace + 1)) g.traceRoot
    (fun q => (g.authT.getD 1 []).getD q []) n).seq fun _ n =>
  (sortedTreeG (k.getD 0 0) (k.getD 1 0) (k.getD 2 0) (k.getD 4 0) (k.getD 5 0) il bInter
    (g.cols.getD 2 []).flatten CircuitAirData.nInter nq (bitsOfQ sb (logTrace + 1)) g.interRoot
    (fun q => (g.authT.getD 2 []).getD q []) n).seq fun _ n =>
  (plainTreeG (g.cols.getD 3 []).flatten 8 nq (bitsOfQ sb (logTrace + 1)) g.compRoot
    (fun q => (g.authT.getD 3 []).getD q []) (List.range nq) n).seq fun _ n =>
  (phase5G (k.getD 0 0) (k.getD 1 0) (canonicStep logTrace) r1.sizeBits r1.oods r3.points nq
    r3.oq g.ppAt g.traceAt g.comps g.compAt
    ((List.range 11).map fun j => logSizes.getD j 0 + 1)
    (fun c i => ((allCols g).getD c []).getD i 0) n).seq fun fi n =>
  Bridge.phase6G (k.getD 0 0) (k.getD 1 0) (logTrace + 1) nq r3.bits r3.points sb fi r3.alphas
    (fun l i => (g.friWit.getD l []).getD i (0, 0)) g.friRoots
    (fun l i => (g.friAuth.getD l []).getD i []) g.lastCoef n

end StwoVerifier.Gadgets
