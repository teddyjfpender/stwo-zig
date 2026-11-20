/-
**Differential checker**: replays the Zig harness's vector file
(`harness/harness.zig`) through the executable Lean spec
(`Pcs.verifyValues` after the commit transcript) and requires accept/reject
to agree with the native verifier on every case.

Usage: `lake exe diffcheck harness/vectors_pow0.json [...]`
-/
import StwoVerifier.Verifier
import Lean.Data.Json

open StwoVerifier
open Lean (Json)

def parseHex (s : String) : Channel.Bytes :=
  let chars := s.toList
  let val (c : Char) : Nat :=
    if c.isDigit then c.toNat - '0'.toNat
    else if 'a' ≤ c ∧ c ≤ 'f' then 10 + c.toNat - 'a'.toNat
    else if 'A' ≤ c ∧ c ≤ 'F' then 10 + c.toNat - 'A'.toNat else 0
  let rec go : List Char → List UInt8
    | hi :: lo :: rest => UInt8.ofNat (16 * val hi + val lo) :: go rest
    | _ => []
  go chars

partial def jNat (j : Json) : Nat :=
  match j.getNat? with | .ok n => n | .error _ => 0

def jArr (j : Json) : Array Json :=
  match j.getArr? with | .ok a => a | .error _ => #[]

def jStr (j : Json) : String :=
  match j.getStr? with | .ok s => s | .error _ => ""

def jField (j : Json) (k : String) : Json :=
  match j.getObjVal? k with | .ok v => v | .error _ => Json.null

def parseQM31 (j : Json) : QM31 :=
  let limbs := (jArr j).map jNat
  QM31.fromM31s (limbs.getD 0 0 : Nat) (limbs.getD 1 0 : Nat)
    (limbs.getD 2 0 : Nat) (limbs.getD 3 0 : Nat)

def parsePoint (j : Json) : PointQ :=
  ⟨parseQM31 (jField j "x"), parseQM31 (jField j "y")⟩

def parseM31 (j : Json) : F := (jNat j : F)

def parse3 {α : Type} (j : Json) (f : Json → α) : List (List (List α)) :=
  ((jArr j).map fun tree =>
    ((jArr tree).map fun col => ((jArr col).map f).toList).toList).toList

def parseLayer (j : Json) : Fri.FriLayerProof :=
  ⟨((jArr (jField j "witness")).map parseQM31).toList,
   ((jArr (jField j "hash_witness")).map (parseHex ∘ jStr)).toList,
   parseHex (jStr (jField j "commitment"))⟩

def parseProof (j : Json) : Pcs.Proof :=
  let fri := jField j "fri"
  { sampledValues := parse3 (jField j "sampled_values") parseQM31
    decommitments :=
      ((jArr (jField j "decommitments")).map fun d =>
        ((jArr d).map (parseHex ∘ jStr)).toList).toList
    queriedValues := parse3 (jField j "queried_values") parseM31
    proofOfWork := jNat (jField j "proof_of_work")
    friProof :=
      ⟨parseLayer (jField fri "first_layer"),
       ((jArr (jField fri "inner_layers")).map parseLayer).toList,
       ((jArr (jField fri "last_layer_poly")).map parseQM31).toList⟩ }

def verdictName : VError → String
  | .invalidStructure => "InvalidStructure"
  | .oodsNotMatching => "OodsNotMatching"
  | .proofOfWork => "ProofOfWork"
  | .shapeMismatch => "ShapeMismatch"
  | .emptySampledSet => "EmptySampledSet"
  | .emptyTrees => "EmptyTrees"
  | .invalidPreprocessedTree => "InvalidPreprocessedTree"
  | .queryPositionOutOfRange => "QueryPositionOutOfRange"
  | .columnIndexOutOfBounds => "ColumnIndexOutOfBounds"
  | .divisionByZero => "DivisionByZero"
  | .degenerateLine => "DegenerateLine"
  | .invalidNumFriLayers => "InvalidNumFriLayers"
  | .firstLayerEvaluationsInvalid => "FirstLayerEvaluationsInvalid"
  | .firstLayerCommitmentInvalid => "FirstLayerCommitmentInvalid"
  | .innerLayerCommitmentInvalid => "InnerLayerCommitmentInvalid"
  | .innerLayerEvaluationsInvalid => "InnerLayerEvaluationsInvalid"
  | .lastLayerDegreeInvalid => "LastLayerDegreeInvalid"
  | .lastLayerEvaluationsInvalid => "LastLayerEvaluationsInvalid"
  | .witnessTooShort => "WitnessTooShort"
  | .witnessTooLong => "WitnessTooLong"
  | .rootMismatch => "RootMismatch"
  | .invalidQueryShape => "InvalidQueryShape"
  | .duplicateQueryMismatch => "DuplicateQueryMismatch"
  | .invalidTreeHeight => "InvalidTreeHeight"
  | .insufficientWitness => "InsufficientWitness"
  | .drawFuelExhausted => "DrawFuelExhausted"

def checkFile (path : String) : IO (Nat × Nat) := do
  let text ← IO.FS.readFile path
  let json ← match Json.parse text with
    | .ok j => pure j | .error e => throw (IO.userError s!"bad json: {e}")
  let profile := jField json "profile"
  let config : Pcs.PcsConfig :=
    { powBits := jNat (jField profile "pow_bits")
      logBlowupFactor := jNat (jField profile "log_blowup")
      logLastLayerDegreeBound := jNat (jField profile "log_last_layer")
      nQueries := jNat (jField profile "n_queries")
      foldStep := jNat (jField profile "fold_step")
      traceLiftingLogSize := jNat (jField profile "trace_lifting_log_size")
      preprocessedLiftingLogSize := jNat (jField profile "preprocessed_lifting_log_size") }
  let m31 := true
  let samplePoints := parse3 (jField json "sample_points") parsePoint
  -- Replay the commit transcript: FRI config mix, then one commit per tree.
  let s0 := Channel.mixFelts m31 Channel.init
    [QM31.fromM31s (config.powBits : Nat) (config.logBlowupFactor : Nat)
      (config.nQueries : Nat) (config.logLastLayerDegreeBound : Nat),
     QM31.fromM31s (config.foldStep : Nat) 0 0 0]
  let treeLogSizes := (jArr (jField json "trees")).toList.map fun treeJson =>
    ((jArr (jField treeJson "log_sizes")).map jNat).toList
  -- The commit transcript uses the roots the *proof* carries, as the Zig
  -- harness does per case (a mutated root changes the transcript).
  let commitAll (roots : List Channel.Bytes) :
      Except VError (List Pcs.Tree × Channel.St) := do
    let mut trees : List Pcs.Tree := []
    let mut s := s0
    for (root, logSizes) in roots.zip treeLogSizes do
      let (trees', s') ← Pcs.commit m31 config trees s root logSizes
      trees := trees'; s := s'
    return (trees, s)
  -- Statement-level files carry a "statement" object: the case then runs
  -- the full `NativeAccepts` with the constant-composition mock Air.
  let statementJson := jField json "statement"
  let air? : Option Air :=
    if statementJson.isNull then none else some
      { compositionLogDegreeBound := jNat (jField statementJson "composition_log_degree_bound")
        compositionLogSplit := jNat (jField statementJson "split")
        maskPoints := fun p _ =>
          let nPre := jNat (jField statementJson "n_preprocessed_columns")
          let indices := ((jArr (jField statementJson "preprocessed_mask_indices")).map jNat).toList
          [(List.range nPre).map fun i => if indices.contains i then [p] else [],
           [[p]]]
        evalComposition := fun _ _ _ _ =>
          .ok (parseQM31 (jField statementJson "composition_value")) }
  let mut agree := 0
  let mut disagree := 0
  for caseJson in jArr (jField json "cases") do
    let label := jStr (jField caseJson "label")
    let native := jStr (jField caseJson "verdict")
    let proof := parseProof (jField caseJson "proof")
    let commitments := ((jArr (jField (jField caseJson "proof") "commitments")).map
      (parseHex ∘ jStr)).toList
    let roots := commitments.take treeLogSizes.length
    let spec := match (do
        let (trees, s) ← commitAll roots
        match air? with
        | some air => NativeAccepts m31 config air trees s commitments proof
        | none => Pcs.verifyValues m31 config trees samplePoints proof s :
          Except VError Unit) with
      | .ok () => "accept"
      | .error e => verdictName e
    let nativeAccepts := native = "accept"
    let specAccepts := spec = "accept"
    if nativeAccepts = specAccepts then
      agree := agree + 1
      IO.println s!"  OK   {label}: native={native} spec={spec}"
    else
      disagree := disagree + 1
      IO.println s!"  FAIL {label}: native={native} spec={spec}"
  return (agree, disagree)

/-- Debug: recompute the spec's intermediates for the baseline case and
print them beside the native capture's, to localize a divergence. -/
def debugFile (path : String) : IO Unit := do
  let text ← IO.FS.readFile path
  let json ← match Json.parse text with
    | .ok j => pure j | .error e => throw (IO.userError s!"bad json: {e}")
  let profile := jField json "profile"
  let config : Pcs.PcsConfig :=
    { powBits := jNat (jField profile "pow_bits")
      logBlowupFactor := jNat (jField profile "log_blowup")
      logLastLayerDegreeBound := jNat (jField profile "log_last_layer")
      nQueries := jNat (jField profile "n_queries")
      foldStep := jNat (jField profile "fold_step")
      traceLiftingLogSize := jNat (jField profile "trace_lifting_log_size")
      preprocessedLiftingLogSize := jNat (jField profile "preprocessed_lifting_log_size") }
  let m31 := true
  let samplePoints := parse3 (jField json "sample_points") parsePoint
  let dbg := jField json "debug"
  let caseJson := (jArr (jField json "cases")).getD 0 Json.null
  let proof := parseProof (jField caseJson "proof")
  let treeLogSizes := (jArr (jField json "trees")).toList.map fun treeJson =>
    ((jArr (jField treeJson "log_sizes")).map jNat).toList
  let roots := ((jArr (jField (jField caseJson "proof") "commitments")).map
    (parseHex ∘ jStr)).toList.take treeLogSizes.length
  let s0 := Channel.mixFelts m31 Channel.init
    [QM31.fromM31s (config.powBits : Nat) (config.logBlowupFactor : Nat)
      (config.nQueries : Nat) (config.logLastLayerDegreeBound : Nat),
     QM31.fromM31s (config.foldStep : Nat) 0 0 0]
  let mut trees : List Pcs.Tree := []
  let mut s := s0
  for (root, logSizes) in roots.zip treeLogSizes do
    match Pcs.commit m31 config trees s root logSizes with
    | .ok (trees', s') => trees := trees'; s := s'
    | .error e => IO.println s!"commit failed {verdictName e}"; return
  -- Replay verifyValues step by step.
  let s1 := Channel.mixFelts m31 s ((proof.sampledValues.map (·.flatten)).flatten)
  let some (deepRandomness, s2) := Channel.drawSecureFelt m31 s1
    | do IO.println "draw failed"; return
  IO.println s!"spec deep_randomness {repr deepRandomness.coords}"
  IO.println s!"zig  deep_randomness {jField dbg "deep_randomness"}"
  let liftingLogSize := (trees.getLast?.map (·.height)).getD 0
  let bound := liftingLogSize - config.logBlowupFactor
  match Fri.commit m31 s2 config.friConfig proof.friProof bound with
  | .error e => IO.println s!"fri commit failed {verdictName e}"
  | .ok (fri, s3) => do
    IO.println s!"spec first alpha {repr fri.firstAlpha.coords}"
    IO.println s!"spec inner alphas {repr (fri.innerLayers.map fun (_, a, _) => a.coords)}"
    IO.println s!"zig  layer alphas {(jArr (jField dbg "fri_layers")).map (fun l => jField l "alpha")}"
    let powOk := Channel.verifyPowNonce m31 s3 config.powBits proof.proofOfWork
    IO.println s!"spec pow ok {powOk}"
    let s4 := Channel.mixU64 m31 s3 proof.proofOfWork
    let (raw, _) := Channel.drawQueries m31 fri.columnCommitmentDomain.logSize config.nQueries s4
    let unique := Merkle.sortedUnique raw
    IO.println s!"spec raw[0:8] {raw.take 8}"
    IO.println s!"zig  raw[0:8] {(jArr (jField dbg "raw_queries")).toList.take 8 |>.map jNat}"
    IO.println s!"spec unique count {unique.length} head {unique.take 8}"
    match Quotients.friAnswers (trees.map (·.columnLogSizes)) samplePoints
        proof.sampledValues deepRandomness unique proof.queriedValues liftingLogSize with
    | .error e => IO.println s!"friAnswers failed {verdictName e}"
    | .ok answers => do
      let rawHead := (jArr (jField dbg "raw_queries")).toList.take 2 |>.map jNat
      for q in rawHead do
        match unique.findIdx? (· = q) with
        | some i => IO.println s!"spec answer at {q}: {repr ((answers.getD i QM31.zero).coords)}"
        | none => IO.println s!"query {q} not in unique?"
      IO.println s!"zig  answers raw[0:2] {(jArr (jField dbg "deep_answers_raw")).toList.take 2}"
      -- First layer rebuild + Merkle.
      match Fri.rebuildSubsets unique answers fri.firstProof.friWitness with
      | .error e => IO.println s!"rebuild failed {verdictName e}"
      | .ok subsets => do
        IO.println s!"spec n subsets {subsets.length} first {(subsets.headD ⟨0, []⟩).start}"
        match Fri.verifyLayerMerkle subsets fri.columnCommitmentDomain.logSize
            fri.firstProof.commitment fri.firstProof.hashWitness with
        | .ok () => IO.println "spec first layer merkle OK"
        | .error e => IO.println s!"spec first layer merkle FAIL {verdictName e}"

def main (args : List String) : IO UInt32 := do
  if args.headD "" = "--debug" then
    for path in args.tail do debugFile path
    return 0
  let mut failures := 0
  for path in args do
    IO.println s!"{path}:"
    let (agree, disagree) ← checkFile path
    IO.println s!"  {agree} agree, {disagree} disagree"
    failures := failures + disagree
  return if failures = 0 then 0 else 1
