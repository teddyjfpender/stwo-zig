# Circuit recursion parity fixtures

Checkpoints of StarkWare's circuit recursion stage at
`https://github.com/starkware-libs/proving` commit
`5a7c5ede4299c91a61df19a07cba4f7502c14230` (the Circuit Recursion Lane of
`conformance/upstream.md`). They are the first rungs of the Zig port's parity
ladder: each fixture is either output of `tools/stwo-circuit-oracle-rs`, which
runs the pinned upstream Rust, or an upstream file copied verbatim.
`provenance.json` binds every file to its bytes, SHA-256, generating command,
the oracle's `Cargo.lock` digest, and the digest of the oracle source (including
the shared `tools/stwo-eval-program-abi` and `tools/stwo-trace-digest` sources); it records nothing
host-specific. `python3 scripts/check_upstream_pins.py` rejects any drift. Regenerate only with
`python3 scripts/generate_circuit_oracle_vectors.py`.

| File | Rung | Content |
|---|---|---|
| `r0/primitives.json` | R0 | channel transcripts, grinds, field operations, hashing, circuit hashes, ChaCha20Rng, felt252 encoding, leaf JSON, base64, FRI folding with fold_step 4 |
| `r2/gadgets.json` | R1, R2 | builder and gadget circuits, before and after `finalize` |
| `r3/components.json` | R3 | all 94 in-circuit evaluators in a fresh `Context` |
| `r3/statement_trace.json` | R3 | per-evaluator, per-harness-stage gate digests with evaluator-relative variables, in 128-gate windows |
| `official/compiled_air_constraints_v1.bin` | R3 | constraints-only projection of the compiled AIR (version 2) |
| `r4/verifier_stages.json` | R4 | the multiverifier over `test_data/circuit_multiverifier/{proof,proof_cairo}.bin`, a gate summary after every verifier stage |
| `r5/finalize.json` | R5 | the `prover_test.rs` circuits after `finalize_constants`, guess finalization, each padding kind and ZK blinding |
| `r6/topology.json` | R6 | both registries' multiverifiers rebuilt (layout, per-column digests, preprocessed root, circuit hash); the canonical_small Cairo preprocessed roots |
| `r7/prove_small.json` | R7 | proofs of the `prover_test.rs` circuits: per-step transcript digests, per-column digests, claimed sums, roots, FRI, nonces |
| `r7/prove_profiles.json` | R7 | `fibonacci` and `blake_g_gate` under the 26-bit circuit FRI config on the internal and root channel profiles, with the `prove_small.json` records |
| `r7/multiverifier_inputs.json` | R7 | the multiverifier circuit `official/circuit_multiverifier/proof.bin` proves: digests of its gate lists and values, the preprocessed root, and the SHA-256 of the 179 MB `STWZCIRC/1` inputs file kept outside the tree |
| `r7/verify/*.json` | R7 | upstream `verify_circuit`'s verdicts on the CircuitSerialize proofs the Zig circuit prover wrote: the digest-output `prove_small` and internal-profile proofs and the multiverifier |
| `official/circuit_air.air_programs_v1.bin` | R7 | the circuit AIR's 11 `FrameworkEval`s recorded into the `STWZEVA/1` evaluation-program bundle |
| `official/compiled_{casm,circuit}_air.sample_evaluations.json` | R3 | upstream `outputs/*/sample_evaluations.json`: the evaluator assignments |
| `official/registries/*.json` | R0, R6 | the checked-in circuit registries: the two canonical_small test registries and the privacy `large_proofs` registry |
| `official/circuit_multiverifier/*.bin` | R4, R7 | upstream `test_data/circuit_multiverifier`: `CircuitSerialize` multiverifier and Cairo-verifier proofs (`LOG_BLOWUP_FACTOR` 3) |
| `official/leaf_prover/expected_output.json` | R8 | the leaf prover's `SerializedLeafProof` golden for `use_all_opcodes_and_builtins` |
| `official/recursive_tree/four_leaves/*` | R9 | the recursive tree's four-leaf goldens: `leaf.json` (`LeafInput`), `root.proof`, `root_outputs.json`, `root_packed.json` |
| `r6/cairo_statement.json` | R6 | `CairoStatement` host facts: constants, leaf `enabled_bits`, ordered preprocessed ids, program limbs and hash, a synthetic `FlatClaim`'s aux data and mix digests, the leaf `ProofConfig` and proof size |
| `official/programs/use_all_opcodes_and_builtins_compiled.json` | R6, R8 | upstream `crates/leaf_prover/tests/data/`: the leaf test program |
| `r10/use_all_opcodes_and_builtins.prover_input.json` | R10c | the leaf prover's test program (`crates/leaf_prover/tests/data`) run and adapted by upstream `prove_leaf.rs` steps 1-2 |
| `r10/all_opcodes.fixed_22.prove_cairo.json` | R10c | `all_opcodes` under `LiftingSizePolicy::Fixed(22)`: every tree, the preprocessed one included, lifted one level above its columns |
| `r10/prove_lifted_example.json` | R10 lift | upstream's wide-Fibonacci prover test with the trace tree lifted 0, 1 and 3 levels: `bincode(StarkProof)` digests |
| `r10/{all_opcodes,all_builtins,use_all_opcodes_and_builtins}.prove_cairo.json` | R10c | leaf-lane Cairo proofs (`prove_cairo::<Blake2sM31MerkleChannel>` under the canonical_small leaf registry's `cairo_prover_params`) of the stwo-cairo 82f2125 `vectors/cairo/official` inputs and the adapted leaf-prover program: proof byte digests and per-stage transcript values |

## Encodings

Checkpoints are pretty JSON with a trailing newline and share an envelope:
`schema` (`stwo-circuit-oracle-checkpoint-v1`), `rung`, `subcommand`,
`authority` (repository and revision), `inputs` (every upstream file read, with
bytes and SHA-256), and `body`.

- M31: canonical `u32`. QM31: `[a, b, c, d]` for `(a + b·i) + (c + d·i)·u`.
- Digests (Blake2s, SHA-256): 64 lowercase hex characters, bytes in order.
- `u64` nonces: `{value (decimal string), hi, lo}`.

## Gate-list contract

A circuit is summarized independently of variable values. For each gate kind,
in `Circuit` field order `add, sub, mul, pointwise_mul, eq, triple_xor,
m31_to_u32, blake_g_gate, permutation, output`:

```text
kind_sha256 = SHA-256("STWO_CIRCUIT_GATE_KIND_V1\0" || kind || 0x00 || count:u64 || SHA-256(records))
```

A record is the gate's variable indices in struct field order, each a
little-endian `u32` (`blake_g_gate`: inputs a, b, c, d, f0, f1, then outputs a,
b, c, d); a permutation record is `len(inputs):u32, inputs.., len(outputs):u32,
outputs..`. Then

```text
gate_list_sha256 = SHA-256("STWO_CIRCUIT_GATE_LIST_V1\0" || n_vars:u64 || kind_sha256 × 10)
values_sha256    = SHA-256("STWO_CIRCUIT_VALUES_V1\0" || count:u64 || each value as 4 × u32)
```

with all integers little-endian. `debug_text_sha256` is the SHA-256 of the
upstream `Debug` rendering (`format!("{circuit:?}")`, one gate per line in
`Circuit::all_gates` order: add, sub, mul, pointwise_mul, eq, blake_g_gate,
triple_xor, m31_to_u32, permutation, output). Small finalized gadget circuits
also carry the full text in `finalized_debug_text` for first-difference
diagnostics.

## R0 notes

- Channel scripts start from `Channel::default()`; every operation records the
  resulting digest. `mix_hash` uses `Blake2sMerkleChannel` on the `blake2s` lane
  and `Blake2sM31MerkleChannel` on the `blake2s_m31` lane.
- Grind channels are `Channel::default()` followed by `mix_u64(seed)`. The nonce
  is the smallest `(hi << 32) | lo` with `lo < 2^20` that verifies, `hi`
  scanned upwards; `minimality_proven` marks cases where the oracle rejected
  every smaller candidate.
- `upstream_expectations` lists every in-tree golden the oracle re-derived and
  asserted, including the `circuit_hash` of all four registry entries.
- `formats.base64` pins `serde_with::base64::Base64` (standard alphabet,
  padded), the encoding of `SerializedLeafProof::proof`; the oracle also
  asserts it against an explicit RFC 4648 encoder.
- `fri` folds a 2^8 circle evaluation (`input[i] = (i + 1, 2i + 3, 3i + 5,
  7i + 11)`, stored bit-reversed over `CanonicCoset::new(8).circle_domain()`)
  with `fold_step = 4` to a single value, with fixed layer alphas: layer 0 is
  `fold_circle_into_line(alpha_0)` then three `fold_line`s with `alpha_0^2`,
  `alpha_0^4`, `alpha_0^8`; layer 1 is four `fold_line`s with `alpha_1`,
  `alpha_1^2`, `alpha_1^4`, `alpha_1^8`. Each fold records `values_sha256` and
  its leading values. `src/frontends/circuit/builder/tests/r0_fri_test.zig` inlines this vector, and
  `scripts/check_upstream_pins.py` requires its inlined digests, alphas, log size
  and last layer to equal this fixture.

## R3 harness

Each evaluator is built exactly as `air_code_gen`'s generated
`test_evaluation_result` builds it, in one fresh `Context`:

1. `TestComponentData::from_values`: a `new_var` per trace column; a `new_var`
   per M31 limb of each interaction QM31, then four `new_var`s for the limbs of
   `last_row_sum` (the `at_prev` of the last four interaction columns); 31
   `new_var`s for the bits of `n_instances = 2^log_height`, LSB first; a
   `new_var` for `n_instances`.
2. `new_var(random_coeff)`, `new_var(z)`, `new_var(alpha)`.
3. `constant(value)` per preprocessed column, in the recorded
   `preprocessed_columns` order (`Seq` is keyed `seq_{log_height}`), then per
   public parameter in the recorded order.
4. `CompositionConstraintAccumulator::new`, then `evaluate`.
5. `new_var(claimed_sum)`, `finalize_logup_in_pairs`, `finalize`.

`circuit` summarizes the context after step 5 (no `Context::finalize`), and
`result` is the accumulator value. Values come from
`official/*.sample_evaluations.json[assignment.key]`; the four hand-written
evaluators that the compiled-AIR samples cannot drive carry synthesized inputs
inline. `expected_result` is set, and asserted, for every generated evaluator;
upstream pins no result for hand-written ones. `memory_id_to_big_{1..15}` reuse
the `memory_id_to_big` assignment.

## Statement trace

`r3/statement_trace.json` localises a gate-list mismatch inside an evaluator.
Each evaluator is rebuilt in topology mode on its `components` inputs. For each
harness stage after the inputs (`evaluate`, `finalize_logup_in_pairs`) and each
gate kind the stage appended to, the gates are recorded with variables relative
to `base` (`n_vars` once the harness inputs exist), each an `i32` in two's
complement:

```text
kind   = SHA-256("STWO_CIRCUIT_STATEMENT_TRACE_V1\0" || kind || 0x00 || count:u64 || records)
window = SHA-256("STWO_CIRCUIT_STATEMENT_TRACE_V1\0" || kind || 0x00 || window:u32 || records of gates [128w, 128w + 128))
```

## R4, R5 and R7 stages

`r4/verifier_stages.json` summarizes (`n_vars`, per-kind counts and digests,
`gate_list_sha256`; no `Debug` text) the whole multiverifier circuit after each
stage of `build_multiverifier_circuit` and, per child, of
`stark_verifier::verify`. Gates are only appended, so each summary is of a
prefix of the final gate lists. The oracle asserts the stage summaries are
identical in value and topology mode, that its stage-by-stage mirror equals the
upstream build (gates and values), that the circuit is satisfied, and that its
preprocessed root is upstream's `MULTIVERIFIER_PREPROCESSED_ROOT`.

`r5/finalize.json` and `r7/prove_small.json` use the six `prover_test.rs`
circuits (fibonacci, permutation, blake, triple_xor, m31_to_u32, blake_g_gate).
R7 proves them with the default `Blake2sM31MerkleChannel` and
`default_circuit_pcs_config`, records the channel digest after each transcript
step of `prove_circuit_with_precompute`, and digests every committed column:

```text
column      = SHA-256(domain || component:u32 || u32:len(label) label || column:u32 || rows:u64 || values:u32..)
accumulator = SHA-256(acc_domain || previous[32] || component:u32 || u32:len(label) label || n:u32 || (column:u32 || rows:u64 || column_digest[32])*)
```

the record layout shared with `tools/stwo-cairo-trace-oracle` through
`tools/stwo-trace-digest`, under the domains
`STWO_CIRCUIT_{PREPROCESSED,BASE,INTERACTION}_COLUMN_V1\0` and
`STWO_CIRCUIT_{PREPROCESSED,BASE,INTERACTION}_ACCUMULATOR_V1\0`, with components
in `ComponentList` order (the preprocessed tree is one component labelled
`preprocessed`). The mirrored proof must equal upstream
`prove_circuit_assignment`'s. The interaction-grind nonces of the fibonacci and
blake_g_gate proofs have `hi > 0`.

## R6 topology

For each registry, the multiverifier is rebuilt as `circuit_params` builds it
(layout from the target sizes, `build_multiverifier_context_from_shared_config`,
`pad_to_targets`) and must reproduce the registry's `preprocessed_root` and
`circuit_hash`. The leaf entries need the Cairo preprocessed root, a constant of
the leaf circuit: `cairo_preprocessed_roots` commits the canonical_small Cairo
preprocessed trace at trace log size 20 and log blowups 1, 2 and 3 (lifting log
sizes 21, 22, 23) under `Blake2sM31MerkleChannel`, each asserted against
`cairo_verifier::verify::get_preprocessed_root`. The registries' leaves use log
blowup 1. Rung R10b (`zig build test-circuit-leaf-cairo-roots`) commits the same
trace through the Cairo lane and compares against these roots.

## Circuit AIR programs

`official/circuit_air.air_programs_v1.bin` is an `STWZEVA/1` bundle (the format
of `vectors/cairo/official/*.air_programs_v1.bin`, read by
`src/frontends/cairo/witness/composition_bundle.zig`) of the 11 circuit AIR
components in `ComponentList` order, recorded by the shared
`tools/stwo-eval-program-abi` recorder at the recursive-tree registry's
multiverifier sizes. Lookup elements and claimed sums are runtime parameters;
`trace_log_size`, `evaluation_log_size`, `denominator_inverses` and
`preprocessed_indices` are instance-specific and retargeted by consumers.

## Projection

`official/compiled_air_constraints_v1.bin` is the version-2 binary grammar
documented in `tools/stwo-circuit-oracle-rs/src/project_air.rs`. It holds every
compiled function whose in-circuit evaluator upstream generates, with lookup
tuples already trimmed by upstream `remove_trailing_zeroes`, the sorted
preprocessed columns and public parameters each function reads, and a SHA-256
per function over its canonical record (strings inline, so independent of the
string-table order; version 1 hashed the indexed record). The header carries the revision, the aggregate digest of
the compiled AIR it was projected from, the evaluator slot order of both AIRs,
the hand-written functions it omits, and the upstream constants
`LARGE_MEMORY_VALUE_ID_BASE`, `MAX_SEQUENCE_LOG_SIZE`, and
`MEMORY_ADDRESS_TO_ID_SPLIT`. The pin checker decodes it with an independent
reader and verifies every record digest.

## R6 leaf statement

`r6/cairo_statement.json` (`cairo-statement`) records, from pinned upstream code
or data only:

- `constants`: `AUX_DATA_FIXED_LEN`, `N_OUTPUTS`, the three relation ids the
  statement uses, the memory constants, and the ten builtin memory-cell sizes
  in `CairoStatement::verify_builtins` order (the first entry is the Pedersen
  segment, whose component name depends on the variant);
- `all_components`: the 83 slot names of `all_components()`;
- `variants`: per `PreProcessedTraceVariant`, the leaf disabled-component list
  parsed from `crates/leaf_prover/src/consts.rs` (`null` where
  `disabled_components` panics), the induced `enabled_bits` and the ordered
  `to_preprocessed_trace().ids()`;
- `program`: `load_program` of the leaf test program, summarized by the SHA-256
  of its flattened limbs as LE `u32`, its first and last felt's 28 limbs, and
  the `claims_to_mix` program hash (Blake2s over the QM31-packed limbs);
- `synthetic_claim`: a `FlatClaim` with all eleven segments present and the
  canonical_small enabled bits, with its `serialize_aux_data`, the three
  `PublicData::pack_into_u32s` vectors, and the channel digest after
  `FlatClaim::mix_into` from a default channel under `Blake2sM31MerkleChannel`
  and `Blake2sMerkleChannel`;
- `leaf_configs`: for each leaf entry of the checked-in canonical_small
  registry, the `ProofConfig` that `leaf_verifier_config` builds (component
  shapes, columns per tree, log trace size, interaction PoW bits) and its
  `ProofInfo::total_bytes`.

## Wire-format goldens

The `circuit_multiverifier`, `leaf_prover`, `recursive_tree` and
`privacy_large_proofs` files are upstream outputs copied verbatim (3.2 MB in
all). The `stwo_circuit_recursion_wire` package
(`src/interop/circuit_recursion`) round-trips every one of them
byte-identically; they stay in the tree because they are the only Rust-made
instances of these formats, and producing them again needs a full leaf and
fold proving run on a large host. Keep them until the ladder's R7-R9 rungs
reproduce them from Zig.

## Leaf-lane Cairo proofs (R10c)

`prove-cairo` verifies each proof with upstream `verify_cairo_ex` before
emitting it. `binary` is the SHA-256 and length of
`bincode(CairoProofForRustVerifier)` (the `Binary` proof format without its
bzip2 wrapper), fixed byte for byte by the protocol. `extended_binary` is
`bincode(CairoProof)` (`ExtendedBinary` without bzip2) with every auxiliary
map written in ascending key order: upstream serializes `hashbrown::HashMap`s,
whose iteration order depends on a per-process random seed, so its own
`ExtendedBinary` bytes are not reproducible; lengths and entries are
upstream's. `stages` holds the configuration, the four commitment roots, both
PoW nonces and digests of every proof field, to localise a divergence.

Under the registry's `AtLeastPreprocessed` policy these small programs never
lift a tree: their fixed 2^20-row tables fill the canonical_small
preprocessed domain, so every height is 21. `all_opcodes.fixed_22` and
`prove_lifted_example` are the fixtures that commit trees above their
columns. The
Zig gate is `zig build test-cairo-leaf-proof`, which also checks the R10b
`get_preprocessed_root` constants of `crates/cairo_verifier/src/verify.rs`.
