/-
**Circuit-statement differential checker** (scope B): replays
`harness/circuitharness.zig`'s vector file through `circuitAccepts`
(the Lean circuit-statement verifier over `circuitAir`) and requires
accept/reject to agree with the shipping acceptance predicate — the
in-circuit verifier built with values — on every case.

The in-circuit verifier rejects by circuit unsatisfiability, without a
spec error code, so the comparison is verdict-level.

Usage: `lake exe circuitcheck harness/circuitvectors.json`
-/
import StwoVerifier.CircuitVerify
import Lean.Data.Json

open StwoVerifier
open Lean (Json)

private def parseHex (s : String) : Channel.Bytes :=
  let chars := s.toList
  let val (c : Char) : Nat :=
    if c.isDigit then c.toNat - '0'.toNat
    else if 'a' ≤ c ∧ c ≤ 'f' then 10 + c.toNat - 'a'.toNat
    else if 'A' ≤ c ∧ c ≤ 'F' then 10 + c.toNat - 'A'.toNat else 0
  let rec go : List Char → List UInt8
    | hi :: lo :: rest => UInt8.ofNat (16 * val hi + val lo) :: go rest
    | _ => []
  go chars

private def jNat (j : Json) : Nat :=
  match j.getNat? with | .ok n => n | .error _ => 0

private def jArr (j : Json) : Array Json :=
  match j.getArr? with | .ok a => a | .error _ => #[]

private def jStr (j : Json) : String :=
  match j.getStr? with | .ok s => s | .error _ => ""

private def jField (j : Json) (k : String) : Json :=
  match j.getObjVal? k with | .ok v => v | .error _ => Json.null

private def jBool (j : Json) : Bool :=
  match j.getBool? with | .ok b => b | .error _ => false

private def parseQM31 (j : Json) : QM31 :=
  let limbs := (jArr j).map jNat
  QM31.fromM31s (limbs.getD 0 0 : Nat) (limbs.getD 1 0 : Nat)
    (limbs.getD 2 0 : Nat) (limbs.getD 3 0 : Nat)

private def parseM31 (j : Json) : F := (jNat j : F)

private def parse3 {α : Type} (j : Json) (f : Json → α) : List (List (List α)) :=
  ((jArr j).map fun tree =>
    ((jArr tree).map fun col => ((jArr col).map f).toList).toList).toList

private def parseLayer (j : Json) : Fri.FriLayerProof :=
  ⟨((jArr (jField j "witness")).map parseQM31).toList,
   ((jArr (jField j "hash_witness")).map (parseHex ∘ jStr)).toList,
   parseHex (jStr (jField j "commitment"))⟩

private def parseProof (j : Json) : Pcs.Proof :=
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

private def verdictName : VError → String
  | .invalidStructure => "InvalidStructure"
  | .oodsNotMatching => "OodsNotMatching"
  | .proofOfWork => "ProofOfWork"
  | .shapeMismatch => "ShapeMismatch"
  | .divisionByZero => "DivisionByZero"
  | .rootMismatch => "RootMismatch"
  | e => s!"VError#{(repr e).pretty}"

def main (args : List String) : IO UInt32 := do
  let path := args.headD "harness/circuitvectors.json"
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
  let statement := jField json "statement"
  let layoutIds := (jArr (jField statement "layout")).toList.map fun c =>
    jStr (jField c "id")
  let mut agree := 0
  let mut disagree := 0
  for caseJson in jArr (jField json "cases") do
    let label := jStr (jField caseJson "label")
    let nativeAccepts := jBool (jField caseJson "accepted")
    let request := jField caseJson "request"
    let layout := layoutIds.zip
      (((jArr (jField request "layout_log_sizes")).map jNat).toList)
    let ppRootWords := ((jArr (jField request "preprocessed_root")).map jNat).toList
    let outputDigest := ((jArr (jField request "output_digest")).map jNat).toList
    let salt := jNat (jField caseJson "channel_salt")
    let nonce := jNat (jField caseJson "interaction_pow_nonce")
    let claimedSums := ((jArr (jField caseJson "claimed_sums")).map parseQM31).toList
    let proof := parseProof (jField caseJson "proof")
    let commitments := ((jArr (jField (jField caseJson "proof") "commitments")).map
      (parseHex ∘ jStr)).toList
    let spec := match CircuitVerify.circuitAccepts m31 config layout ppRootWords
        outputDigest (QM31.fromM31s ((salt : Nat) : F) 0 0 0) nonce claimedSums commitments
        proof with
      | .ok () => "accept"
      | .error e => verdictName e
    let specAccepts := spec = "accept"
    if nativeAccepts = specAccepts then
      agree := agree + 1
      IO.println s!"  OK   {label}: native={if nativeAccepts then "accept" else jStr (jField caseJson "stage")} spec={spec}"
    else
      disagree := disagree + 1
      IO.println s!"  FAIL {label}: native accepted={nativeAccepts} spec={spec}"
  IO.println s!"{agree} agree, {disagree} disagree"
  return if disagree = 0 then 0 else 1
