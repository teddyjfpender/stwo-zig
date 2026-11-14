# In-circuit STARK verifier formalization

Lean 4 (v4.33.1 + Mathlib) formalization of stwo-zig's verifier, per
`VERIFIER_FORMALIZATION_BRIEF.md` (repo root of the main checkout). Pinned
to stwo-zig commit `4afa09dbf` and the `proving_5a7c5ed` profile:
Blake2sM31 Fiat–Shamir channel, plain Blake2s Merkle, `PcsConfigV2` lifted
trees, FRI with `log_blowup_factor = 1`, `fold_step = 1`,
`log_last_layer_degree_bound = 0`, 70 queries, PoW 26.

## Layout

| Module | Specifies | Zig source |
|---|---|---|
| `StwoVerifier/Basic.lean` | `P = 2³¹ − 1` prime (Lucas–Lehmer) | — |
| `StwoVerifier/Fields.lean` | M31 / CM31 / QM31 coordinate arithmetic | `src/core/fields/*` |
| `StwoVerifier/Blake2s.lean` | Blake2s-256 (RFC 7693), executable, `#guard` vectors | — (copied from starked-bitcoin) |
| `StwoVerifier/Channel.lean` | both Blake2s channels: mixes, draws, PoW, query draw, M31 word reduction | `src/core/channel/blake2s.zig`, `src/core/queries.zig` |
| `StwoVerifier/ChannelVectors.lean` | compile-time `#guard`s against stwo-zig's Rust-oracle-pinned digests, draws, grind nonces | the Zig test suites |
| `StwoVerifier/Circle.lean` | circle group, cosets, circle/line domains, bit reversal, OODS point map, `LinePoly` eval | `src/core/circle.zig`, `src/core/poly/*` |
| `StwoVerifier/Merkle.lean` | lifted Merkle multiproof verifier (plain hasher) | `src/core/vcs_lifted/verifier.zig` |
| `StwoVerifier/Fri.lean` | FRI commit transcript, subset rebuild, layer Merkle, folds, last layer (fold step 1) | `src/core/fri.zig`, `src/core/fri/*` |
| `StwoVerifier/Quotients.lean` | sample batches (periodicity duplicate incl.), line coefficients, `friAnswers` | `src/core/pcs/quotients/*`, `src/core/constraints.zig` |
| `StwoVerifier/Pcs.lean` | `commit` + `verifyValues` (the whole PCS opening verification) | `src/core/pcs/verifier.zig` |
| `StwoVerifier/Verifier.lean` | **`NativeAccepts`**: the statement-level verifier over an abstract `Air` | `src/core/verifier.zig`, `src/core/proof.zig` |
| `DiffCheck.lean` | the differential runner (`lake exe diffcheck`) | — |
| `harness/harness.zig` | proof generator + native-verdict recorder (build cmd in its header) | — |

Everything is an executable `def`; the same functions are the statements the
scope-A/B theorems will be proven against.

## Differential testing (deliverable 1)

`harness/harness.zig` proves a two-tree column batch at the PCS level with
stwo-zig's own CPU prover under the pinned profile, runs the native
`CommitmentSchemeVerifier.verifyValues` on the original proof and on a fixed
battery of 11 mutations plus a seeded 48-case fuzz battery (random
single-site corruptions over every proof surface), and records each verdict.
`lake exe diffcheck <vectors.json>` replays every case through the Lean spec
and requires accept/reject to agree.

Status (2026-10-12):

- **PCS level**: all cases agree across PoW 0 / 8 / 26 vector sets —
  and at PoW 8/26 not only the accept/reject bit: the exact error code
  matches (`vectors_pow{0,8,26}.json`). The PoW-0 sets add structural
  mutations (dropped/duplicated FRI layer, over-long last layer); the
  duplicated-layer case confirms the one documented spec deviation is
  verdict-invisible (the native verifier accepts an extra zero-fold layer
  at commit and rejects in decommit; the spec rejects at commit).
- **Statement level** (`NativeAccepts` end to end, with a one-constraint
  constant-composition mock AIR, proved by the engine's `proveEx` and
  natively verified by `core.verifier.verify`): 60 of 60 cases agree at
  PoW 0, including `OodsNotMatching` paths and the full-query-coverage edge
  case where a PoW-nonce flip at `pow_bits = 0` is *correctly accepted*
  (every leaf is opened, so the verdict is query-independent); all cases
  agree across PoW 0 / 8 / 26 (`statement_pow{0,8,26}.json`).
- The live corpus is 366 cases (two 63-case PoW-0 sets with the
  structural battery, four 60-case sets), re-validated in full after the
  spec's loops were refactored to pure recursions.
- The compile-time `#guard` vectors additionally pin the channel law
  (mixes, draws, Merkle-root absorption, FriConfigV2 transcript, PoW
  accept/reject at Rust Stwo's grind nonces) to upstream bytes.

Regenerate and check:

```sh
# from the worktree root
zig build-exe ... (see harness/harness.zig header) -femit-bin=formal/in-circuit-verifier/harness/harness
./formal/in-circuit-verifier/harness/harness formal/in-circuit-verifier/harness/vectors_pow0.json 0 70 48
cd formal/in-circuit-verifier && lake exe diffcheck harness/vectors_pow0.json
```

## Trust boundary, current

- **Differentially validated**: the channel, the commit transcript, PoW,
  query selection, lifted-tree Merkle verification, DEEP quotients
  (`friAnswers`, incl. the two-sample periodicity duplicate), the full FRI
  verifier at fold step 1, and their composition in `Pcs.verifyValues`.
- **Differentially validated at the statement level** with a mock AIR:
  composition-tree commit, OODS draw, chunk reconstruction, and the OODS
  equality check. The AIR itself stays an abstract `Air` record; scope B
  instantiates it with the circuit AIR.
- **Scope A under way** (`Gates.lean`, `Algebra.lean`, `CircleGadgets.lean`,
  `SimdGadgets.lean`, `BitDecomp.lean`), all standard axioms only
  (`#print axioms` = propext, Classical.choice, Quot.sound):
  - the gate model (`Circuit::check` semantics plus finalization
    constraints) and `CommRing` instances for the concrete CM31/QM31;
  - scalar circle gadgets proven sound: `double_x`, `add_points`,
    `double_point` (with the explicit on-circle hypothesis its `2x² − 1`
    doubling needs), `coset_vanishing_poly`, `denom_inverse`;
  - the SIMD lane layer: lane-wise `sub`/`mul`/`scalar_mul`, `Simd::eq`
    with the partial-wire mask, `assert_bits`, `guess_lsb`;
  - **`extract_bits(·, 31)` + `validate_extract_bits` proven sound**
    (`extractBits31_sound`): if the emitted gates hold, each lane's 31
    output bits are *the* binary digits of the lane's canonical M31 value.
    The canonicity hinges on the `(input·aux − 1)·bits₀ = 0` constraint
    rejecting the all-ones encoding of 0 — the circuit does carry the
    constraint its prover-supplied hints need (open question 1, answered
    for this gadget);
  - **the `select_queries` point construction proven sound**
    (`SelectQueries.lean`, `CircleGroup.lean`): `select`, `add_points_simd`,
    `generator_point_simd`, the conditional-add loop
    (`buildLoop_lane`, via the commutative-monoid structure of the circle
    law and `smul` additivity), and the composed
    `selectQueriesPoint_sound`: per lane, the 31 extracted bits are the
    canonical digits of the drawn value, and the built point is
    `gen^(queryIndex bits L)`, conjugated exactly when bit 0 is set.
  - **the bridge to the spec** (`SelectQueriesBridge.lean`): the circle
    generator is on the circle with order `2³¹` (kernel-checked), `toPoint`
    is additive and sends negated indices to conjugates, and
    `queryIndex_eq_domainPoint` equates the gadget's point with
    `(canonicDomain L).at' (bitReverseIndex pos L)` — the very point the
    differentially-validated `Quotients.friAnswers` evaluates. The exported
    end-to-end statement is **`selectQueries_domainPoint`**: gates hold ⇒
    each lane's built point is the spec's domain point at
    `bitReverseIndex (q.val % 2^L) L` for the lane's drawn word `q` —
    verbatim the native verifier's query-to-point law;
  - **deliverable 3 started** (`OodsGadgets.lean`, `FieldTower.lean`,
    `DeepIdentity.lean`): `from_partial_evals` and
    `extract_expected_composition_eval` proven to compute the spec's
    extension-basis recombination and split-1 chunk reconstruction;
    **CM31 and QM31 proven to be fields** (norm arguments, quadratic
    reciprocity for the non-residue `5`); and the **DEEP term identity**:
    the circuit's `compute_fri_input` per-response quotient — the
    `−2u`-scaled `im`-line form — equals the spec's complex-conjugate
    line-coefficient quotient (`deep_term_eq`: numerator and denominator
    are each `−u` times the spec's, and the factors cancel).
  - **deliverable 4 started** (`FriGadgets.lean`): `fold_coset` at the
    pinned fold step 1 proven to compute the spec's `Fri.foldLinePair` —
    the gate-proven twiddle inverse pins `t = x⁻¹` in the QM31 field, and
    the folded wire is the exact circle-to-line / line fold the verifier
    spec runs;
  - **batched DEEP algebra** (`num_identity_batched`,
    `circuit_num_regroup`, `Quotients.flattenBatches_pushEntry`): the
    circuit's per-point accumulation is the sum of per-response terms,
    `−u` times the spec batch's, and sample grouping never changes the
    sum — the remaining `compute_fri_input` work is emitter plumbing,
    not mathematics;
  - **more FRI-decommit primitives proven** (`SelectByIndex.lean`,
    additions to `SelectQueries.lean`, `OodsGadgets.lean`):
    `select_by_index` (the mux tree picks the bits' binary index) and
    `validate_query_position_in_coset` on top of it; `Simd::inv` lane
    soundness (the twiddle hypothesis `foldCoset1_sound` consumes);
    `sub_points_simd` and the `translate_to_base_point` loop
    (conjugate twin of the query loop); and the OODS corollary
    `extractExpected_matches_spec` tying the gadget to
    `reconstructChunks` at the on-circle OODS point.
- **Remaining**: the channel-draw half of `select_queries`
  (`getQuerySelectionInputFromChannel`; its transcript law is proven in
  starked-bitcoin's `Circuit/Channel.lean` for the same builder), the DEEP
  quotient batching (`compute_fri_input`) and FRI gadgets (deliverable 4),
  scope B/C.

## Deviations from Zig noted while specifying

- `FriVerifier.commit` upstream accepts extra zero-fold inner layers at
  commit time and rejects them later in `decommit`; the spec rejects at
  commit (`invalidNumFriLayers`). Accept/reject agrees; the error site
  differs. No mutation vector currently hits this path.
- `drawBaseFelts`' rejection loop is unbounded in Zig; the spec carries
  fuel 64 (`drawFuelExhausted` is unreachable in practice, and on the M31
  channel the loop never rejects at all).
