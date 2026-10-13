/-
**`circuitAccepts`: the circuit-statement verifier** (scope B).

The acceptance predicate of a circuit proof under the pinned profile,
as the in-circuit verifier enforces it (`stark_verifier/verify.zig`
with `CircuitStatement`), stated over the native proof shape:

1. the statement transcript — channel salt, FRI config, preprocessed
   root (tree 0 commit), circuit hash `Blake2s(config words ‖ root)`
   and output digest as `u32` claims, trace root (tree 1 commit), the
   20-bit interaction proof of work, the interaction elements
   `z, alpha`, the public LogUp sum against the claimed sums, claimed
   sums mixed, interaction root (tree 2 commit);
2. the statement-side validity checks — component log sizes within
   5 bits of the trace log, the relation-use bound
   `Σ (⌊2^log/2^16⌋ + 1)·uses < 2^15` per relation;
3. `NativeAccepts` with `circuitAir` — composition draw, composition
   tree, OODS, PCS.

The channel salt is taken as the QM31 the in-circuit verifier mixes (its
wire is an unconstrained guess); the native proofs' integer salts are the
case `(salt, 0, 0, 0)`, which `lake exe circuitcheck` passes.

`harness/circuitharness.zig` proves the R7 fibonacci circuit with the
in-repo prover and records the shipping verdict
(`circuit_cpu.verify.verifyProofBytes`, the verification circuit built
with values) on the proof and a tamper battery; `lake exe circuitcheck`
replays each case through this definition and must agree accept/reject.
-/
import StwoVerifier.CircuitAir

namespace StwoVerifier.CircuitVerify

open CircuitAir

/-- Where each component's log size comes from
(`component_facts.log_size`): a preprocessed column's log size for the
gate components, a fixed table log size for the rest. -/
def logSizeSources : List (String ⊕ Nat) :=
  [ .inl "eq_in0_address", .inl "qm31_ops_in0_address",
    .inl "triple_xor_input_addr_0", .inl "m31_to_u32_input_addr",
    .inl "blake_g_gate_input_addr_a",
    .inr 16, .inr 20, .inr 8, .inr 14, .inr 18, .inr 16 ]

/-- `circuit_component_log_sizes`: the per-component log sizes under a
preprocessed layout. -/
def componentLogSizes (layout : List (String × Nat)) : Option (List Nat) :=
  logSizeSources.mapM fun src => match src with
    | .inl id => (layout.find? (·.1 = id)).map (·.2)
    | .inr l => some l

/-- `RELATION_USES_PER_ROW` per component (`component_facts`). -/
def relationUsesPerRow : List (List (String × Nat)) :=
  [ [("Gate", 2)], [("Gate", 2)],
    [("Gate", 3), ("VerifyBitwiseXor_8", 8)],
    [("Gate", 1), ("RangeCheck_16", 3)],
    [("Gate", 6), ("VerifyBitwiseXor_12", 2), ("VerifyBitwiseXor_4", 2),
     ("VerifyBitwiseXor_7", 2), ("VerifyBitwiseXor_8", 6),
     ("VerifyBitwiseXor_8_B", 2), ("VerifyBitwiseXor_9", 2)],
    [], [], [], [], [], [] ]

/-- `check_relation_uses`: per relation, the shifted use-count bound
`Σ over components (⌊2^log / 2^16⌋ + 1) · uses` fits in `31 − 16` bits. -/
def relationUsesOk (logSizes : List Nat) : Bool :=
  let ids := (relationUsesPerRow.flatMap (·.map (·.1))).eraseDups
  ids.all fun id =>
    let total := ((relationUsesPerRow.zip logSizes).map fun (uses, log) =>
      ((uses.find? (·.1 = id)).map (·.2)).getD 0 * (2 ^ log / 2 ^ 16 + 1)).sum
    total < 2 ^ 15

/-- `config_words`: 12 bytes — the blowup factor, then one byte per
component log size — as three little-endian `u32` words. -/
def configWords (logBlowup : Nat) (logSizes : List Nat) : List Nat :=
  let bytes := logBlowup % 256 :: logSizes.map (· % 256)
  (List.range 3).map fun w =>
    (List.range 4).foldl (fun acc b => acc + bytes.getD (4 * w + b) 0 * 2 ^ (8 * b)) 0

/-- The circuit hash: `Blake2s(LE(config words) ‖ preprocessed root)`. -/
def circuitHash (logBlowup : Nat) (logSizes : List Nat)
    (rootWords : List Nat) : Channel.Bytes :=
  Blake2s.blake2s
    ((configWords logBlowup logSizes ++ rootWords).flatMap Channel.u32Le)

/-- `combine_term`: Horner over the reversed element in `alpha`,
minus `z`. -/
def combineTerm (element : List QM31) (z alpha : QM31) : QM31 :=
  match element.reverse with
  | [] => -z
  | v :: rest => rest.foldl (fun acc e => acc * alpha + e) v - z

/-- The gate relation id as a felt. -/
def gateFelt : QM31 := QM31.fromBase ((378353459 : Nat) : F)

/-- The public LogUp entries: the output digest words at addresses
`3..11`, each as lanes `(lo16, hi16, 0, 0)`, then `u` at address 2. -/
def logupEntries (outputDigest : List Nat) : List (Nat × List QM31) :=
  (outputDigest.zipIdx.map fun (x : Nat × Nat) =>
    (3 + x.2, [QM31.fromBase ((x.1 % 2 ^ 16 : Nat) : F),
               QM31.fromBase ((x.1 / 2 ^ 16 : Nat) : F), QM31.zero, QM31.zero]))
    ++ [(2, [QM31.zero, QM31.zero, QM31.one, QM31.zero])]

/-- One public LogUp term `1 / combine(GATE, address, lanes)`. -/
def logupTerm (z alpha : QM31) (e : Nat × List QM31) : Except VError QM31 :=
  match (combineTerm (gateFelt :: QM31.fromBase ((e.1 : Nat) : F) :: e.2) z alpha).inv? with
  | some t => pure t
  | none => throw .divisionByZero

/-- `public_logup_sum` of the circuit statement: the gate-relation uses
of the output digest words at addresses `3..11` and of `u` at
address 2, each `1 / combine(GATE, address, lanes)`. -/
def publicLogupSum (outputDigest : List Nat) (z alpha : QM31) :
    Except VError QM31 := do
  let terms ← (logupEntries outputDigest).mapM (logupTerm z alpha)
  return terms.foldl (· + ·) QM31.zero

/-- Per-column log sizes of the trace tree (`ComponentList` order). -/
def traceColumnLogSizes (logSizes : List Nat) : List Nat :=
  (CircuitAirData.traceShape.toList.zip logSizes).flatMap fun (n, l) =>
    List.replicate n l

/-- Per-column log sizes of the interaction tree. -/
def interColumnLogSizes (logSizes : List Nat) : List Nat :=
  (CircuitAirData.interShape.toList.zip logSizes).flatMap fun (n, l) =>
    List.replicate n l

/-- **The circuit-statement acceptance predicate**: the statement
transcript and claim checks, then `NativeAccepts` with `circuitAir`. -/
def circuitAccepts (m31 : Bool) (config : Pcs.PcsConfig)
    (layout : List (String × Nat)) (ppRootWords outputDigest : List Nat)
    (channelSalt : QM31) (interactionPowNonce : Nat) (claimedSums : List QM31)
    (commitments : List Channel.Bytes) (proof : Pcs.Proof) :
    Except VError Unit := do
  let some logSizes := componentLogSizes layout | throw .invalidStructure
  if config.traceLiftingLogSize < config.logBlowupFactor then
    throw .invalidStructure
  let logTrace := config.traceLiftingLogSize - config.logBlowupFactor
  -- `validate_and_compute_component_sizes`: 5-bit log sizes, none above
  -- the trace log.
  if logSizes.any fun l => l ≥ 2 ^ 5 ∨ logTrace < l then throw .invalidStructure
  if ¬ relationUsesOk logSizes then throw .invalidStructure
  -- Transcript: salt, FRI config.
  let s := Channel.mixFelts m31 Channel.init [channelSalt]
  let s := Channel.mixFelts m31 s
    [QM31.fromM31s (config.powBits : Nat) (config.logBlowupFactor : Nat)
      (config.nQueries : Nat) (config.logLastLayerDegreeBound : Nat),
     QM31.fromM31s (config.foldStep : Nat) 0 0 0]
  -- Preprocessed tree: the REQUEST's root (the statement guesses it; the
  -- Merkle decommitment later authenticates against it).
  let ppRoot : Channel.Bytes := ppRootWords.flatMap Channel.u32Le
  let (trees, s) ← Pcs.commit m31 config [] s ppRoot (layout.map (·.2))
  -- Claims: the circuit hash as a root mix, then the output values —
  -- each digest word as the felt `(lo16, hi16, 0, 0)` — as one felt mix
  -- (`MC.mixRoot(circuit_hash)`; `channel.mixFelts(output_values)`).
  let s := Channel.mixRoot m31 s
    (circuitHash config.logBlowupFactor logSizes ppRootWords)
  let s := Channel.mixFelts m31 s (outputDigest.map fun w =>
    QM31.fromM31s ((w % 2 ^ 16 : Nat) : F) ((w / 2 ^ 16 : Nat) : F) 0 0)
  -- Trace tree, interaction proof of work, interaction elements.
  let (trees, s) ← Pcs.commit m31 config trees s (commitments.getD 1 [])
    (traceColumnLogSizes logSizes)
  if ¬ Channel.verifyPowNonce m31 s 20 interactionPowNonce then
    throw .proofOfWork
  let s := Channel.mixU64 m31 s interactionPowNonce
  let some (elements, s) := Channel.drawSecureFelts m31 2 s
    | throw .drawFuelExhausted
  let z := elements.getD 0 QM31.zero
  let alpha := elements.getD 1 QM31.zero
  -- `validate_logup_sum`: the public sum plus every claimed sum is zero.
  let pub ← publicLogupSum outputDigest z alpha
  if ¬ (pub + claimedSums.foldl (· + ·) QM31.zero = QM31.zero) then
    throw .invalidStructure
  let s := Channel.mixFelts m31 s claimedSums
  let (trees, s) ← Pcs.commit m31 config trees s (commitments.getD 2 [])
    (interColumnLogSizes logSizes)
  NativeAccepts m31 config (circuitAir layout z alpha claimedSums logSizes)
    trees s commitments proof

end StwoVerifier.CircuitVerify
