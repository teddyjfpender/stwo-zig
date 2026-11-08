# Circuit recursion (leaf wrap + 2-to-1 folds): Rust porting map — 2026-09-29

What StarkWare's circuit recursion stage is, file by file, and what stwo-zig has
to build to reproduce its proofs byte for byte. Source: `starkware-libs/proving`
at `5a7c5ede4299c91a61df19a07cba4f7502c14230` (below, `proving/`), read-only.
Context: [`../README.md`](../README.md) §2 (the stage sits between Cairo leaf
proofs and the Cairo-verified root).

Status markers: **VERIFIED** (read in code, with a path), **INFERRED**
(reasoned from evidence, not traced end to end). Nothing here was measured: no
Rust or Zig prover was run for this map.

## 0. Summary

- The stage is **three binaries and one library stack**, all hand-written
  except the AIR/constraint code. `leaf-prover` wraps one Cairo proof in a
  circuit proof. `stwo_run_and_prove_recursive_tree` folds N wrapped proofs
  2-to-1 until one root proof remains. `circuit-params` produces the registry
  of circuit hashes and padding targets that both of them check against.
  (VERIFIED)
- A "circuit" is a flat QM31 wire list built by a gate-builder DSL
  (`crates/circuits`, `Context<Value>`). The in-circuit STARK verifier
  (`crates/stark_verifier`) *is* that DSL program. **The order of builder
  calls fixes the wire numbering, the preprocessed trace, the circuit hash and
  the proof bytes.** Byte parity therefore needs a call-order-exact port of
  the builder, not a semantic re-implementation. (VERIFIED)
- Every circuit is proven by one fixed 11-component AIR (`crates/circuit_prover`).
  Only the preprocessed columns (addresses and multiplicities) and the witness
  differ between circuits. (VERIFIED)
- `proving/` **vendors** stwo, stwo-cairo and stwo-circuits in-tree; there are
  no git pins. The vendored stwo is `7b211ed` plus a PcsConfig refactor that
  changes the transcript (`pow_bits` moves into `FriConfig`, always 2 config
  felts, split trace/preprocessed lifting heights that are never mixed). The
  vendored Cairo AIR and witness code is byte-identical to `stwo-cairo@82f2125`,
  which is our Cairo-lane pin. (VERIFIED by diff)
- About **66k lines** of Rust are in scope. About **60k lines are generated**
  by `crates/air_code_gen` (`generate-stwo-circuits`) from checked-in
  compiled-AIR JSON. The port should reproduce that generator, not the
  generated output. About **12k lines** are hand-written and must be ported
  in call-order-exact form. (VERIFIED, `wc -l`)
- The first parity milestone requires no proving: reproduce the registry's
  `preprocessed_root` and `circuit_hash` for the leaf verifier and the
  multiverifier. Those values exercise the builder, finalize, padding,
  preprocessing, the lifted Merkle commit and the hash. (INFERRED plan)

## 1. The stage end to end

```
 Cairo program + input
        │  cairo_run_program(all_cairo_stwo, proof_mode) → adapt
        ▼
 prove_cairo::<Blake2sM31MerkleChannel>(registry.cairo_prover_params)     ← Cairo proof (in memory only)
        │  prepare_cairo_proof_for_circuit_verifier → Proof<QM31> + aux M31s
        ▼
 LEAF WRAP  build_and_fill_cairo_verifier_circuit → finalize(false)
            → [add_zk_blinding] → pad_to_targets → PreprocessedCircuit
            → prove_circuit_assignment (Blake2sM31MerkleChannel)
            → assert circuit_hash == registry.leaf_verifiers[t].circuit_hash
        │  SerializedLeafProof JSON {circuit_preprocessed_root, circuit_hash, proof: base64(CircuitSerialize)}
        ▼
 FOLD  (per layer, pairs (0,1),(2,3)…, odd entry carried up unchanged)
        build_multiverifier_circuit::<QM31>([L, R]) → pad_to_targets
        non-root: prove_circuit_assignment (Blake2sM31MerkleChannel) → CircuitSerialize bytes (in memory)
        root (layer of exactly 2, or self-fold when N==1):
              prove_circuit_assignment_with_channel::<Blake2sMerkleChannel>
              → prepare_circuit_proof_for_cairo_verifier → felt252 stream
        ▼
 root.proof (pretty JSON "0x…" felts) · root_outputs.json ([u32;8]) · root_packed.json (PackedNode)
        ▼
 Cairo stwo_circuit_verifier inside the applicative bootloader (out of scope here)
```

### 1.1 Leaf wrap — `crates/leaf_prover/src/prove_leaf.rs::prove_leaf` (VERIFIED)

1. Assert `include_all_preprocessed_columns` and
   `lifting_size_policy == AtLeastPreprocessed` in `registry.cairo_prover_params`.
2. Run the VM (`all_cairo_stwo`, proof mode, `disable_trace_padding`,
   `allow_missing_builtins`), then `adapt`. The output segment must be exactly
   `N_OUTPUTS=2` cells. The low 4 u32 words of each cell form
   `output_hash` (8 words).
3. `prove_cairo::<Blake2sM31MerkleChannel>`. The registry's `channel_hash`
   ("blake2s") is **ignored**; the channel is hard-coded.
4. `trace_log_size = trace_lifting − log_blowup`, after asserting trace lifting
   equals preprocessed lifting. Select `registry.leaf_verifier(trace_log_size)`.
   `zk_blinding_size = n_queries + NON_QUERY_INFO_LEAK(10)` if the entry sets
   `zk_blinding`.
5. `leaf_verifier_config`: the disabled-component list depends on the variant
   (`consts.rs`). Canonical disables the four pedersen `*_window_bits_9`
   components; CanonicalSmall disables the `*_window_bits_18` ones.
   `enabled_bits` follows `all_components` order.
   `ProofConfig::new(…, INTERACTION_POW_BITS=24)`. Program felts become 28
   9-bit M31 limbs each.
6. `prepare_cairo_proof_for_circuit_verifier`, then
   `build_and_fill_cairo_verifier_circuit`. Inside the builder:
   `Context::new(8)`, then `CairoStatement::new`, `proof.guess`, `verify`,
   `finalize(false)`, and `add_zk_blinding` when enabled. After that come
   `pad_to_targets(config.target_sizes())` (`prove_leaf.rs:187`) and
   `PreprocessedCircuit::preprocess_circuit`.
7. `prove_circuit_assignment` with
   `PcsConfig::from_fri_and_trace_size(circuit_fri, trace_log_size)`. Assert the
   circuit hash matches the registry. Convert with
   `prepare_circuit_proof_for_circuit_verifier` and serialize with `CircuitSerialize`.
8. Output `serde_json::to_string_pretty(SerializedLeafProof)`, with no
   trailing newline.

### 1.2 Fold — `crates/stwo_run_and_prove_recursive_tree/src/{lib,fold,canonical,leaf_io,output}.rs` (VERIFIED)

- **Input.** A manifest `{"leaves":[paths]}`. Each file is a `LeafInput`:
  a `SerializedLeafProof` (flattened) plus `output_preimage: Vec<String>`
  (decimal felts). The leaf output digest is recomputed on the host:
  `Blake2Felt252::encode_felts_to_u32s` gives 2 BE words for a felt < 2^63,
  otherwise 8 BE words with bit 31 of the first set. Then Blake2s256 runs over
  the words' LE bytes.
- **CanonicalCircuit::build.**
  1. Take exactly one multiverifier from the registry and compute
     `target_sizes`, then `layout_from_component_sizes`, then `trace_log_size`
     (the max), then `PcsConfig::from_fri_and_trace_size`, then `shared_config`.
  2. Build the NoValue topology from two `empty_proof`s, then pad and preprocess.
  3. Check that the layout matches and that `preprocessed_circuit_hash` equals
     the registry hash.
- **Tree shape.**
  - While `len > 1`: pair adjacent entries and carry an odd last entry. A layer
    is the root when it has exactly 2 entries. For example, 3 leaves give
    `[f(0,1), 2]`, then `f(f01, 2)`.
  - N==1 self-folds `(x, x)` with `is_root=true` and one packed child.
    The docs in `main.rs` and `output.rs` say the leaf is copied through; they
    are stale.
- **reduce.**
  1. Run `build_multiverifier_circuit::<QM31>`, then `pad_to_targets`.
  2. Prove with the M31 channel for a non-root fold, or `Blake2sMerkleChannel`
     for the root.
  3. Build the new entry: `preprocessed_root = commitments[0]`, the circuit
     hash words, `output_digest = claim.output_values.map(unpack_u32)`, and
     `packed = Composite{circuit_hash, subtasks}`.
  4. Internal proofs travel as CircuitSerialize bytes. They are re-deserialized
     on every use and never written to disk.
- **Fold public output.** `blake2s` over the words
  `[circuit_hash_L(8), out_L(8), circuit_hash_R(8), out_R(8)]`, in LE bytes,
  built in-circuit by `circuit_multiverifier/src/verify.rs`.

### 1.3 Circuit proof transcript — `crates/circuit_prover/src/prover.rs` (VERIFIED)

The same order applies to every leaf and fold proof:

1. `mix_felts([QM31(0)])`: `channel_salt`, hard-coded to 0.
2. `fri_config.mix_into`: always 2 felts, `[pow, blowup, n_queries, last_layer]`
   then `[fold_step, 0, 0, 0]`.
3. Commit the preprocessed tree (lifting `preprocessed_lifting_log_size`,
   `store_polynomials_coefficients=true`).
4. `write_trace`, then `circuit_hash = H::hash_u32s_followed_by_digest(config_words, preprocessed_root)`,
   then `MC::mix_hash(circuit_hash)`.
5. `claim.mix_into`: `mix_felts(output_values)`, the 8 digest words as packed
   `(lo16, hi16, 0, 0)` QM31s. Then commit the base trace.
6. `grind(INTERACTION_POW_BITS = 20)` (lowest valid nonce), then `mix_u64(nonce)`,
   then draw `CommonLookupElements` (128 alpha powers).
7. `write_interaction_trace`. Mix the 11 claimed sums in ComponentList order,
   then commit the interaction trace.
8. `prove_ex(components, channel, scheme, include_all_preprocessed_columns=true)`:
   `split_at_mid`, so tree 3 holds 8 composition columns.

### 1.4 Artifacts and formats (VERIFIED unless marked)

| Artifact | Producer | Format |
|---|---|---|
| Registry JSON | `circuit-params --registry` | `to_string_pretty` + `\n`. `CircuitRegistry{cairo_prover_params, circuit_proof_configs: BTreeMap, leaf_verifiers[], multiverifiers[]}` (`circuit_registry/src/schema.rs`). `LogSizes` field order is eq, qm31_ops, **m31_to_u32, triple_xor**, blake_g_gate, which differs from PerComponent order. |
| `SerializedLeafProof` | leaf-prover | pretty JSON. `DigestHex` = 8 × `"{:#010x}"` LE words. `proof` = base64 (standard alphabet, padded) of CircuitSerialize. |
| CircuitSerialize | `circuit_serialize` | Length-free, sized by `ProofConfig`. Field order: salt QM31, 3 roots (32 B, words recombined `hi<<16\|lo`, LE), claimed_sums, preprocessed/trace/interaction at OODS (`at_prev` only for cumsum columns), 8 composition evals, eval-domain samples (M31, 4 B), auth paths, pow_nonce, interaction_pow_nonce, FRI (commitments, last-layer coefs, auth paths, witnesses). Total = `ProofInfo::from_config().total_bytes()`. Deserialize rejects values ≥ P and ignores trailing bytes. |
| `root.proof` | fold binary | `serde_json::to_vec_pretty` of `"0x{:x}"` felts: 2-space indent, lowercase, no zero padding, no trailing newline. The golden `four_leaves/root.proof` is 1.5 MB, about 94.7k felts. Encoding is CairoSerialize of `CairoCircuitProof{claim Vec<QM31>, interaction_pow u64, interaction_claim [QM31;11], stark_proof, channel_salt u32}`. Vecs are length-prefixed and fixed arrays are not. PcsConfig writes only the FriConfig (5 felts). `LinePoly` is followed by `ilog2(len)`. `Option` is encoded Some→0, None→1. Queried values: trees 1 and 2 are stable-sorted by column log size and then transposed; trees 0 and 3 are only transposed. |
| `root_outputs.json` | fold binary | `sonic_rs` compact `[u32;8]`, no newline. |
| `root_packed.json` | fold binary | `serde_json::to_string` of the externally tagged `PackedNode`. `circuit_hash` is a number array and preimages are passed through verbatim as decimal strings. |

## 2. Component inventory

LOC counts non-test source unless noted. "Gen" means generated by
`crates/air_code_gen` (`cargo run --bin air_code_gen -- generate-stwo-circuits
--root-dir <repo>`, then `cargo fmt`). Generated files carry the header
`// This file was created by the AIR team.` (`air_code_gen/src/utils.rs:23`).
The generator backends are `src/circuit/component.rs` (circuit/in-circuit
evaluator, about 455 LOC) and the AIR backend
(`AutogenCodeType::AIR(STWO_CIRCUITS_AIR_CONFIG)`). Its inputs are the
checked-in `outputs/compiled_{casm,circuit}_air/compiled_jsons/**` files
(serialized `CompiledAirFn`, `air_compile/src/compiled_structs.rs`), which are
compiled from the DSL in `crates/airs`.

| Crate / module | Path (under `proving/crates/`) | LOC | Gen? | Role | Depends on |
|---|---|---:|---|---|---|
| circuit IR | `circuits/src/circuit.rs` | 489 | hand | 10 gate kinds (Add, Sub, Mul, PointwiseMul, Eq, TripleXor, M31ToU32, BlakeGGate, Permutation, Output); `Circuit` stores one Vec per kind; `compute_multiplicities` | stwo QM31 |
| builder | `circuits/src/context.rs` | 331 | hand | `Context<Value>`: var 0 = zero, 1 = one, 2 = u, then reserved vars 3..10; `constant` interning (IndexMap); `set_outputs`; `finalize` | indexmap |
| ops + `eval!` | `circuits/src/ops.rs` | 382 | hand | Gate-emitting API. The zero/one shortcuts in `add` and `mul` compare var **indices**. Also `Guess`/`Constant` traits | context |
| IValue | `circuits/src/ivalue.rs` | 212 | hand | QM31 witness mode versus `NoValue` topology mode | blake2 |
| in-circuit Blake2s | `circuits/src/blake.rs` | 426 | hand | `blake2s_u32s` built from 80 G gates per block plus 8 triple_xor; `reduce_hash_value` | `BLAKE_SIGMA` |
| wrappers, simd, extract_bits, utils, stats | `circuits/src/{wrappers,simd,extract_bits,utils,stats}.rs` | 715 | hand | U16/U32/M31 guesses, 4-lane `Simd`, bit decomposition, mux | ops |
| finalize_constants | `circuits/src/finalize_constants.rs` | 381 | hand | Derives every constant from u via a +1 chain, base-256 Horner, broadcast and basis steps. Uses IndexMap `swap_remove`/`retain` semantics | context |
| padding + ZK | `circuit_common/src/finalize.rs` | 267 | hand | `pad_to_targets`/`pad_context` (min 16 rows); `add_zk_blinding` with ChaCha20Rng; `ComponentSizes` | rand_chacha 0.3 |
| preprocessed circuit | `circuit_common/src/preprocessed.rs` | 599 | hand | Address and multiplicity columns, `seq_16`, `bitwise_xor_{4,7,8,9,10}_{0,1,2}`, stable sort by length, `preprocessed_root` | stwo prover |
| component_utils | `circuit_common/src/component_utils.rs` | 40 | hand | `seq_of_component_size` gadget | stark_verifier |
| circuit prover entry | `circuit_prover/src/prover.rs` | 239 | hand | Transcript (§1.3), `prepare_circuit_proof_for_circuit_verifier` | stwo, circuit_verifier |
| circuit hash | `circuit_prover/src/circuit_hash.rs`, `circuit_verifier/src/circuit_hash.rs` | ~200 | hand | `hash_u32s_followed_by_digest(config_words(12 B → 3 LE u32), root)` | stwo `Hasher` |
| witness scheduler | `circuit_prover/src/witness/trace.rs` | 429 | hand | rayon DAG; `extend_polys` in ComponentList order | components |
| witness generators | `circuit_prover/src/witness/components/` | 3,478 | hand (styled after stwo-cairo generated witness) | SIMD base and interaction traces for the 11 components | stwo-cairo prover utils |
| circuit AIR | `circuit_prover/src/circuit_air/components/` (+`subroutines/`) | 2,654 | **gen**, except `eq.rs` and `verify_bitwise_xor_12.rs` | `FrameworkEval` for 11 components plus 14 subroutines | constraint-framework |
| in-circuit STARK verifier | `stark_verifier/src/{verify,channel,merkle,fri,fri_proof,oods,constraint_eval,logup,statement,proof,proof_from_stark_proof,circle,select_queries,sort_queries,order_hash_map}.rs` | ~3,100 (+1.5k tests) | hand | `verify()` runs the full transcript and checks as gates. `proof_from_stark_proof` does the conversion | circuits |
| circuit statement | `circuit_verifier/src/{verify,statement,circuit_claim,circuit_components,circuit_proof,relations,sample_evaluations}.rs` | ~590 | hand | `CircuitStatement`, `all_circuit_components`, relation ids, `lookup_sum` | stark_verifier |
| circuit-AIR evaluators (in-circuit) | `circuit_verifier/src/components/**` | ~3,300 | **gen**, except `eq.rs`, `qm_31_ops.rs`, `verify_bitwise_xor_12.rs` | OODS constraint gates for the 11 components | constraint_eval |
| Cairo AIR evaluators (in-circuit) | `cairo_verifier/src/components/**` | 53,618 (43.0k without inline tests) | **gen**, except `memory_address_to_id.rs`, `memory_id_to_big.rs`, `verify_bitwise_xor_12.rs` (347) | 68 components plus 100 inline subroutines | constraint_eval |
| Cairo component registry | `cairo_verifier/src/all_components.rs` | 371 | **gen** | 83 slots in stwo-cairo claim order (`memory_id_to_big` ×16) | components |
| Cairo statement | `cairo_verifier/src/statement.rs` | 821 | hand | `CairoStatement`: public memory logup, builtins, output limbs, aux data | circuits |
| Cairo verifier entry | `cairo_verifier/src/{verify,privacy,preprocessed_columns,utils}.rs` | 700 | hand | `build_and_fill_…`, `get_preprocessed_root` (hard-coded roots for lifting 21/22/23), `load_program` | statement |
| multiverifier | `circuit_multiverifier/src/verify.rs` | 149 | hand | For each child: guess digest, guess root, `CircuitStatement::new`, `proof.guess`, `verify`. Then a blake preimage over all children | circuit_verifier |
| leaf orchestration | `leaf_prover` | 379 | hand | §1.1 | all of the above |
| fold orchestration | `stwo_run_and_prove_recursive_tree` | 613 | hand | §1.2 | multiverifier, serializers |
| registry | `circuit_registry` | 200 | hand | schema + queries | — |
| wire types | `leaf_proof_format` | 142 | hand | `DigestHex`, `SerializedLeafProof`, `PackedNode` | serde_with |
| binary serde | `circuit_serialize` | 440 | hand | CircuitSerialize (§1.4) | stark_verifier |
| felt serde | `circuit_cairo_serialize` | 260 | hand | root felt stream | cairo-serialize |
| registry generator | `circuit_params` | 529 | hand | shared-target fixpoint; root/hash per trace size | leaf_prover, multiverifier |
| generator | `air_code_gen/{bin,src/circuit,src/utils.rs,src/supported_components.rs}` | ~1,480 | hand | emits the gen rows above | air_compile, airs |
| compiled AIR inputs | `outputs/compiled_casm_air/**` (167 JSON, 34 MB, mostly witness deductions), `outputs/compiled_circuit_air/**` (~440 KB), `sample_evaluations.json` (68 goldens) | — | produced by `air_compile` | single source of truth | — |

The generator skips the components listed in
`air_code_gen/src/supported_components.rs::get_manual_circuit_constraints_components`:
`memory_address_to_id`, `memory_id_to_big`, `qm_31_ops`, `circuit_blake_round`,
`verify_bitwise_xor_12`, `qm_31_into_u_32`, `blake_gate`. That list is why
`qm_31_ops` is hand-written in `circuit_verifier` but generated in
`circuit_prover/circuit_air` (VERIFIED by header grep).

The constraint path of the JSON grammar is small: `Const(M31)`, `Var`,
`State`, `BinaryOp(+,-,*)`, `StaticCall`, `Array`, `ExternalState`,
`PublicParam` and `Enabler`. Across the 167 CASM files there are 481
Constraint, 1,110 Intermediate and 378 LookupTerm steps (VERIFIED by the
cairo-verifier reader).

## 3. Byte-parity contract

### 3.1 Circuit topology (determines the preprocessed root and the circuit hash)

- **Var numbering.**
  - Vars 0, 1 and 2 are zero, one and u = (0,0,1,0). Vars 3..10 are the
    reserved output wires. Everything after that is numbered in call order.
  - `eval!` evaluates the left subtree, then the right subtree, then the op.
    `-(x)` emits `sub(zero, x)` after x. StaticCall arguments are evaluated
    left to right before the call. In a LookupTerm, the tuple felts are
    evaluated before the numerator.
  - (VERIFIED `ops.rs`, `air_code_gen/src/circuit/component.rs`)
- **Index-based peepholes.**
  - `add` returns the other operand when either operand is var 0.
  - `mul` returns zero when either operand is var 0, and returns the other
    operand when either is var 1.
  - `sub` and `pointwise_mul` never elide.
  - Folding by value, or adding any algebraic simplification, changes the gate
    count. (VERIFIED)
- **Constant interning.**
  - Constants go into an `IndexMap<QM31, Var>` in first-use order.
  - `finalize_constants` depends on IndexMap `swap_remove` (the last entry
    moves into the hole) combined with `keys().next()`, and on
    order-preserving `retain`.
  - `m31_base = max(longest run 0..N of requested M31s, 256)`.
  - Zig's `std.ArrayHashMap.swapRemove` has the same semantics; `retain` needs
    an order-preserving compaction. (VERIFIED `finalize_constants.rs`)
- **Gate order per component Vec.**
  1. Builder gates.
  2. `finalize_constants` gates.
  3. Guess finalization, in guess order: M31 → `pointwise_mul(v,1,v)`,
     QM31 → `add(v,0,v)`, U16 → `m31_to_u32(v,v)`.
  4. ZK blinding.
  5. Padding, in the order eq, qm31_ops ((1+1), so each row gets a fresh var),
     triple_xor, m31_to_u32, blake_g_gate.

  (VERIFIED)
- **Guess order.**
  - `impl Guess for Proof` guesses trace_root, interaction_root, composition_root,
    claimed_sums, the OODS values, eval samples, auth paths, pow_nonce,
    interaction_pow_nonce, FRI, and **channel_salt last**.
  - `CircuitStatement` guesses in the order output_digest, preprocessed_root,
    statement, proof.
  - `CairoStatement::new` runs: output-hash guess, `set_outputs`, output limbs,
    aux M31s, then a pack of the log sizes. (VERIFIED)
- **ZK blinding.**
  - Uses `rand_chacha 0.3` `ChaCha20Rng::from_seed(LE bytes of trace_root words)`.
  - Each iteration draws 26 u32 in the order qm31 (12), eq (4), triple_xor (3),
    m31_to_u32 (1), blake_g (6).
  - QM31 and M31 draws are fully reduced mod P; u32 draws are packed without
    reduction.
  - stwo-zig has no ChaCha20 RNG yet. `std.crypto.stream.chacha.ChaCha20With64BitNonce`
    (nonce 0, counter 0) should give the same keystream; this needs a
    known-answer test. (VERIFIED Rust side; INFERRED Zig equivalence)
- **Preprocessed layout.**
  - Columns are pushed in component order: eq, qm31_ops, triple_xor,
    m31_to_u32, blake_g_gate. Then `seq_16`, then
    `bitwise_xor_{4,7,8,9,10}_{0,1,2}` (row r: `r>>n`, `r&mask`, xor). Finally
    a **stable** sort ascending by length.
  - Permutation gates lower to qm31_ops rows at synthetic addresses
    `n_vars + g`, so `n_vars`, including the padding vars, must match exactly.
  - `multiplicities[0]` gains 2 per permutation pair.
  - The blake_g multiplicity is taken from out_a, and the code asserts that it
    equals the multiplicities of b, c and d. (VERIFIED `preprocessed.rs`)
- **Circuit hash.**
  - `config_words` is the 12 bytes `[log_blowup, eq, qm31_ops, triple_xor,
    m_31_to_u_32, blake_g_gate, xor8, xor12, xor4, xor7, xor9, range_check_16]`,
    read as 3 LE u32.
  - `circuit_hash = Blake2s(LE(words) ‖ root)` as a single hash, not
    `H(H(words), root)` (`crates/stwo/src/core/vcs_lifted/hasher.rs:19-21`).
  - The in-circuit version is `blake2s_u32s` over 44 bytes. (VERIFIED)
- **In-circuit channel byte lengths.** These feed the Blake2s `t0` counter:
  draw 37, pow prefix 52, pow nonce 40, `mix_commitment` 64. The FRI config is
  5 u32 packed into 2 QM31. (VERIFIED `stark_verifier/src/channel.rs`, `fri.rs`)
- **Other order-sensitive points in the verifier.**
  - `compute_fri_input` groups OODS responses by `(x.idx, y.idx)` Var identity
    in IndexMap order.
  - `check_relation_uses` packs sums in key-sorted String order.
  - `QuerySorter` stable-sorts on the u-coordinate. Only the first query per
    tree range-checks; later queries use `eq`.
  - `fri_decommit` requires `log_last_layer == 0` and breaks early.
  - The multiverifier deduplicates constants across children. (VERIFIED)
- **Generated component code.** The Zig output must mirror the statement order
  and full parenthesisation of the Rust output. It must strip only trailing
  `Const 0` tuple felts (`remove_trailing_zeroes`). Preprocessed reads come
  before constraint 0, sorted by id. A `Seq` read emits gates (every call
  unpacks again; nothing is cached). The fixed-size check is emitted after
  `accumulate_constraints` and before `finalize_logup_in_pairs`. (VERIFIED)

### 3.2 Circuit proof bytes

- **Transcript.** §1.3, exactly as listed.
- **Channels.**
  - Leaves and internal folds use `Blake2sM31MerkleChannel`: the Fiat-Shamir
    channel is `Blake2sM31Channel`, the Merkle hasher is the **plain**
    `Blake2sMerkleHasher`, and `mix_hash` =
    `update_digest(Blake2sHasherGeneric::<true>::concat_and_hash(digest, hash))`.
  - The root uses `Blake2sMerkleChannel` with the `<false>` variant.
  - (VERIFIED `crates/stwo/src/core/vcs_lifted/blake2_merkle.rs:55-82`)
  - In stwo-zig, `Blake2sM31MerkleChannel.mixRoot` already uses the M31
    `concatAndHash` (`src/core/vcs_lifted/blake2_merkle.zig:238-253`). The Merkle
    hasher must be `Blake2sPlainMerkleHasher`, **not** the domain-prefixed
    `Blake2sM31MerkleHasher` alias (`blake2_merkle.zig:19-25`).
- **Grind.** The smallest valid nonce, with both u32 halves < P. The prefix is
  `H(POW_PREFIX LE, 12 zero bytes, digest, pow_bits LE)`. In the M31 variant,
  the first word is reduced mod P before trailing zeros are counted
  (`crates/stwo/src/prover/backend/simd/grind.rs`). (VERIFIED)
- **AIR layout.**
  - The 11 components are in ComponentList order.
  - Column order within a component follows `next_trace_mask` order.
    Interaction columns follow `add_to_relation` order and are paired by
    `finalize_logup_in_pairs` as (0,1), (2,3), …, with an odd last term alone.
  - The pairing is specific per component. blake_g_gate has 13 interaction
    columns. verify_bitwise_xor_12 has 16 multiplicity columns indexed
    `(ah<<2)+bh`.
  - Relation ids: GATE 378353459, RC16 1008385708, XOR4 45448144,
    XOR7 62225763, XOR8 112558620, XOR8_B 521092554, XOR9 95781001,
    XOR12 648362599.
  - The composition random-coefficient power per constraint is fixed by the
    order of `add_constraint` calls. (VERIFIED)
- **LogUp finalize.** `finalize_last` subtracts `claimed_sum / 2^log_size`, then
  takes an inclusive prefix sum in bit-reversed coset order. Committed values
  are exact field sums, so any algebraically equal fraction per column gives
  the same bytes. (VERIFIED)
- **Parallelism.** It never changes bytes. Atomic multiplicities, batch
  inverse and prefix sums are exact, and grind returns the minimum. Only order
  matters. (VERIFIED)
- **`proof_from_stark_proof`.**
  - Queried values are re-expanded to `aux.unsorted_query_locations` order,
    duplicates included.
  - Eval-domain auth paths are `all_node_values[j][pos^1]`.
  - FRI auth paths are `all_node_values[j − pack_shift][pos^1]` with
    `pos >>= fold_sum + step`.
  - Nonces become `QM31(lo, hi, 0, 0)`.
  - The Zig `ExtendedStarkProof` aux must expose the same data. (VERIFIED)

### 3.3 The Cairo proof inside the leaf

The Cairo proof is never emitted by itself, but its values are the wrap
circuit's witness, and the ZK seed is its `trace_root`. It must equal
`prove_cairo::<Blake2sM31MerkleChannel>` under the registry parameters:

- `include_all_preprocessed_columns=true`, `AtLeastPreprocessed`,
  `opt_n_id_to_big_components=16`, salt 0;
- canonical (production) or canonical_small (tests);
- Cairo FRI `{pow 26, blowup 1, last 0, nq 70, fold 1}`; the test registry uses pow 16;
- `INTERACTION_POW_BITS=24` on the Cairo side.

(VERIFIED `circuit_registry_definitions/production/*.json`, `prover/src/prover.rs`)

### 3.4 How parity will be tested

Heavy Rust runs are not allowed on this host (36 GB, swapping). Every oracle
run below must go to a host that has the memory for it, or use committed goldens.

| Level | Oracle | Needs a Rust run? |
|---|---|---|
| L0 primitives | Blake2s/M31-channel/grind vectors; ChaCha20Rng KAT; `hash_u32s_followed_by_digest`; `circuit_hash.rs` expect-test vectors (incl. `poseidon252_root`); FRI `fold_step=4, last_layer 0` vectors | small oracle tool |
| L1 builder | `circuits/src/finalize_constants_test.rs` and `circuit_common/src/preprocessed_test.rs` `expect!` snapshots. These are Debug-format gate lists, so the Rust `Debug` impls need a port | no (snapshots are in-tree) |
| L2 generated evaluators | `outputs/compiled_casm_air/sample_evaluations.json` (68 per-component QM31 goldens); `*_SAMPLE_EVAL_RESULT` in `circuit_verifier/src/components/sample_evaluations.rs` | no |
| L3 topology | Registry `preprocessed_root` + `circuit_hash`: `leaf_prover/tests/data/circuit_registry_canonical_small.json`, `stwo_run_and_prove_recursive_tree/test_data/circuit_registry.json`; multiverifier 45-column layout in `circuit_multiverifier/src/test_utils.rs`; `cairo_verifier::get_preprocessed_root` (canonical_small 21/22/23) | no |
| L4 circuit proofs | `circuit_prover/src/prover_test.rs` small contexts (fibonacci, permutation, blake, …); `circuit_multiverifier/test_data/*.bin` (182,884 B, LOG_BLOWUP=3) for CircuitSerialize round trips | small proofs: yes, on a large host |
| L5 leaf | `leaf_prover/tests/data/expected_output.json` (Rust `cli_test` compares it byte for byte); prebuilt `proving/target/release/leaf-prover` | yes (heavy) |
| L6 fold | `stwo_run_and_prove_recursive_tree/test_data/goldens/four_leaves/{leaf.json, root.proof, root_outputs.json, root_packed.json}`. These are raw Rust output (the Rust test compares parsed JSON). No prebuilt fold binary exists | goldens only, unless a build is allowed |
| Acceptance | Zig proofs verified by Rust `circuit_verifier` and by the Cairo `stwo_circuit_verifier`; Rust proofs verified by Zig | new `tools/stwo-circuit-oracle-rs` |

Proposed oracle: `tools/stwo-circuit-oracle-rs`. It has its own workspace and
lockfile, pins `proving@5a7c5ed`, and is registered in
`conformance/tooling-surface-v1.json`. It dumps per-stage checkpoints: the gate
list hash, preprocessed column SHA-256s, the root, the circuit hash, the
transcript digest after each §1.3 step, and per-component trace SHA-256s
(the same pattern as `tools/stwo-cairo-trace-oracle`). It also verifies Zig output.
(INFERRED plan)

## 4. Reuse vs new work in stwo-zig

### 4.1 Reusable (VERIFIED paths)

| Need | stwo-zig | Notes |
|---|---|---|
| M31/CM31/QM31, packed, batch inverse | `src/core/fields/` | Add circuit-local `pointwiseMul`, `pointwiseInvOrZero` and `pointwiseLsb`. The u32→M31 conversion must be a **full** reduction. |
| Blake2s, SIGMA | `src/core/crypto/blake2s_backend.zig`, `blake2s_parallel4`/`stream4` | `BLAKE_SIGMA` is duplicated in `src/frontends/cairo/preprocessed/columns.zig`; keep one copy. |
| Blake2s / Blake2s-M31 channel, grind | `src/core/channel/blake2s.zig` (`Blake2sChannelGeneric`, `grind` returns the lowest nonce) | Needs 2.4 vectors at 20/24/26 bits. |
| Lifted Merkle, plain hasher, Merkle channels | `src/core/vcs_lifted/blake2_merkle.zig` (`Blake2sPlainMerkleHasher`, `Blake2sM31MerkleChannel.mixRoot`), `verifier.zig`, `src/prover/vcs_lifted/{prover,streaming_committer,blake2_stream4}.zig` | Add `hashU32s` and `hashU32sFollowedByDigest`. |
| FRI with fold_step > 1, packed leaves | `src/core/fri/{config,folding}.zig`, `src/prover/fri.zig` | Annotated "stark-v". Needs a `fold_step=4` vector from `5a7c5ed`. |
| Prover engine | `src/prover/prove.zig` `proveEx(…, include_all_preprocessed_columns)`, `pcs/scheme.zig` `setStorePolynomialsCoefficients`, `ComponentProverVTable` (`air/component_prover.zig:81`) | Circuit components become ComponentProvers. |
| ExtendedStarkProof aux | `src/core/proof.zig:170`, `pcs/mod.zig:89` (unsorted_query_locations), `vcs_lifted/verifier.zig:35` (all_node_values) | Feeds the `proof_from_stark_proof` port. |
| LogUp semantics | `src/core/constraint_framework/evaluator.zig` `FormalLogupAtRow` | Has Cairo parity already. |
| Constraint codegen / AOT kernels | `src/frontends/cairo/codegen/eval_program.zig`, `src/tools/cairo_composition_cpu_codegen`, `build_support/products/cairo_composition_cpu_aot.zig` | Candidate path for the prover-side composition of the 11 circuit components. |
| Cairo AIR, witness, canonical_small, n_id_to_big=16 | `src/frontends/cairo/` (`preprocessed/variant.zig`, `claim_generator.zig`) | The vendored AIR is byte-identical to `82f2125`. |
| Felt JSON writer, query transpose | `src/frontends/cairo/proof/cairo_serde/{felt_json,queries,pcs}.zig` | `felt_json` matches the serde pretty array. `pcs.zig` rejects lifting ≠ 0, and `queries.zig` is tied to the Cairo composition bundle; both need circuit variants. |
| Blake AIR precedent | `src/examples/blake/*` | Style template for blake_g_gate and the xor tables. |
| Graph-builder engineering | `src/frontends/riscv/recursion/arithmetic_circuit.zig` | Take the patterns only (flat nodes, u32 ids, scoped scratch). Its hash-consing **must not** be used because it reorders gates. Do not import from `riscv/`. |

**Not reusable as generators:**

- `tools/stwo-cairo-air-compiler` records `EvalAtRow` into row bytecode. That
  loses the `eval!` operand order, the index-based peepholes, constant
  interning and the circuit LogUp (`combine_term` Horner). It is still useful
  as a semantic cross-check at random points.
- `src/frontends/cairo/witness/eval_program.zig` evaluates rows on the prover
  side, which is a different job.

### 4.2 Must be written

1. **A protocol-revision profile for `proving@5a7c5ed`** (§5): FriConfig with
   `pow_bits`, a 2-felt mix, split lifting heights, the explicit-height Merkle
   rule, and the new PcsConfig serde shape.
2. **`circuits` builder**: IR, `Context` (comptime Value ∈ {QM31, NoValue}),
   ops, Simd, wrappers, in-circuit Blake, extract_bits, finalize_constants,
   padding, ZK blinding plus ChaCha20, the preprocessed circuit and the circuit hash.
3. **In-circuit STARK verifier**: channel, merkle, fri, oods, constraint_eval
   and logup, select and sort queries, proof, `proof_from_stark_proof`.
4. **Generator**: a port of `air_code_gen/src/circuit/component.rs` plus
   `utils.rs` and `all_components.rs`. It reads the compiled JSONs and emits
   Zig `accumulateConstraints` for:
   - the Cairo components, from `compiled_casm_air`;
   - the circuit-AIR components, from `compiled_circuit_air`;
   - optionally the prover-side AIR and witness for the circuit components.

   Hand-port the manual components: Cairo `memory_address_to_id`,
   `memory_id_to_big`, `verify_bitwise_xor_12`, and circuit `eq`, `qm_31_ops`,
   `verify_bitwise_xor_12`.
5. **Circuit prover**: 11 AIR components, witness generators, the transcript
   preamble and the verifier-proof conversion.
6. **Statements**: `CircuitStatement`, `CairoStatement` and the multiverifier.
7. **Formats**: CircuitSerialize (read and write), the circuit Cairo-serde felt
   stream, the registry loader, `leaf_proof_format`, base64, and `Blake2Felt252` encoding.
8. **Cairo leaf lane**: parameterise `src/frontends/cairo` over the
   MerkleChannel (M31 channel with the plain hasher). It is hard-wired today at
   `prove_trace.zig:42-43`, `witness/resident_types.zig:20` and
   `proving/transcript.zig:9`. Also needed:
   - an `include_all_preprocessed_columns` path; `witness/resident_geometry.zig:94-140`
     currently masks to used columns only;
   - `LiftingSizePolicy`;
   - a ProverParameters loader;
   - Blake2s-M31 PoW on Metal and CUDA, or a CPU fallback.
9. **Orchestration and packaging.** Follow CONTRIBUTING (`frontends → integrations
   → prover → core`) with:
   - `src/frontends/circuit/` (package `stwo_circuit_frontend`: builder, verifier
     circuits, components, witness, formats);
   - `src/integrations/circuit_cpu/` (and later metal and cuda);
   - `src/products/circuit_recursion_cpu/` with a descriptor in
     `build_support/products/` and a Scope in `catalog.zig`;
   - leaf and fold CLIs;
   - a "Circuit Recursion Lane" in `conformance/upstream.md`, checked by
     `scripts/check_upstream_pins.py`.

   (INFERRED layout, following the infra reader and `README.md` conventions)

## 5. Version and pin compatibility

- **Pins.** `proving/` is a monorepo. Every dependency is
  `path = "crates/…"` at version 2.4.0 (`Cargo.toml [workspace.dependencies]`),
  with toolchain `nightly-2026-01-15`. By diff against the local cargo
  checkouts:
  - vendored stwo = `7b211ed` + deltas;
  - vendored stwo-cairo = `82f2125` + deltas;
  - `stwo_cairo_verifier/` (Cairo-lang) has diverged further.

  stwo-zig already pins `proving@5a7c5ed`, but only for `cairo-program-runner-lib`
  (`tools/stwo-cairo-vm-adapter-rs`). (VERIFIED)
- **stwo deltas that affect bytes.** Each changed file is listed with its path,
  relative to `crates/stwo/src/`. (VERIFIED)

  | Change | Where |
  |---|---|
  | `FriConfig{pow_bits, log_blowup_factor, log_last_layer_degree_bound, n_queries, fold_step}`. `mix_into` **always** mixes `[(pow, blowup, nq, last), (fold_step, 0, 0, 0)]` | `core/fri.rs:75` |
  | `PcsConfig{fri_config, trace_lifting_log_size, preprocessed_lifting_log_size}`, with no `mix_into`. `lifting_log_size(tree_idx)` returns the preprocessed size for tree 0 and the trace size otherwise | `core/pcs/mod.rs:43` |
  | The Merkle height is exactly the lifting size (asserted ≥ the max column; asserted == 0 for an empty tree) | `core/vcs_lifted/verifier.rs` |
  | Final lifting uses the trace lifting size and errors if it is below the preprocessed size | `core/verifier.rs` |
  | New `Hasher` trait (`hash_u32s`, `hash_u32s_followed_by_digest`) | `core/vcs_lifted/hasher.rs` |
  | `mix_root` renamed to `mix_hash`, same bytes. Batch inverse, barycentric pooling and blake2s_lifted changes are byte-neutral | — |

- **stwo-zig today.** `src/core/pcs/mod.zig:23` has `PcsConfig{pow_bits, fri_config,
  lifting_log_size: ?u32}`.
  - `mixInto` sends **one** felt when `fold_step == 1 && lifting == null`.
    Otherwise it sends `[(pow, blowup, nq, last), (fold_step, lifting orelse 0, 0, 0)]`.
  - With `lifting_log_size = 0` (non-null) the mixed bytes already equal
    5a7c5ed. The height semantics still differ: Zig derives the height from
    the max column, while 5a7c5ed uses explicit per-tree heights.
  - The Cairo lane's `statement_bootstrap.zig:398-410` mixes
    `lifting orelse 0` into slot 2. That matches only while lifting is 0.
    Expressing `AtLeastPreprocessed` by setting a nonzero lifting would fork
    the transcript.
  - `core/proof_json.zig` emits the 82f2125 JSON shape.

  (VERIFIED)
- **Recommendation.** Add an explicit protocol-revision parameter (comptime) in
  core and prover that selects the config-mix rule, the tree-height rule and
  the proof schema. Leave the Native (`a8fcf4b`) and Cairo (`7b211ed`/`82f2125`)
  lanes unchanged. (INFERRED)
- **Leaf Cairo parameters.**
  - `AtLeastPreprocessed` sets both heights to max(trace domain, preprocessed
    domain). Every shipped registry has trace_log ≥ the preprocessed max:
    canonical 25 vs 25 and canonical_small 20 vs 20. Under that condition it
    gives the same heights as `Auto`, so on the same channel the proof equals
    an Auto proof.
  - A Zig shortcut must hard-fail when trace_log < the preprocessed max.
  - (VERIFIED `prover/src/prover.rs`; INFERRED consequence)
- **Registry configs.**

  | Config | Cairo FRI | Circuit FRI | Trace log sizes | ZK |
  |---|---|---|---|---|
  | production | pow 26, blowup 1, nq 70, fold 1 | pow 26, blowup 1, nq 70, fold 4, last 0 | 25..=29 | no |
  | privacy_large_proofs | same as production | blowup 2, nq 35, fold 4 | — | `add_zk_blinding` |
  | canonical_small (tests) | pow 16 | nq 35, fold 4 | 20 | — |

  canonical_small pads to eq 20, qm31_ops 23, m31_to_u32 21, triple_xor 20,
  blake_g_gate 23. (VERIFIED `circuit_registry_definitions/**`)
- **Gaps.**
  - There are no Blake2s-M31 parity vectors in `vectors/`.
  - 5a7c5ed deleted its canonical preprocessed-root regression tests. Expected
    roots for the M31 channel at AtLeastPreprocessed heights exist only for
    canonical_small 21/22/23 (`cairo_verifier/src/verify.rs::get_preprocessed_root`)
    and in the test registries. For canonical 26..30 no hard-coded value was
    found. (VERIFIED absence by grep; INFERRED completeness)
  - `src/backends/metal/runtime/proof_of_work.zig` shows no Blake2s-M31-output
    grind. CUDA was not inspected. (VERIFIED Metal; CUDA open)

## 6. Performance and memory opportunities

None of these changes bytes, as long as the gate order and the transcript are
preserved. (INFERRED unless noted)

1. **Build the topology once and refill values per proof.** Topology depends
   only on (`CairoVerifierConfig`) or (canonical multiverifier config). Rust
   rebuilds it on every leaf and every fold, twice (a NoValue build, then a
   QM31 build).
   - Record a u32 SoA gate tape once. Store Permutation gates in CSR form.
   - Per proof, run a straight-line value fill over a preallocated `[]QM31`.
   - This removes the peephole checks, constant hashing and gate pushes from
     the hot path.
2. **Cache the preprocessed side** per circuit shape: preprocessed columns,
   twiddles, the committed preprocessed tree and the circuit hash.
   - Rust `fold.rs` calls `prove_circuit_assignment` on every reduce. That
     re-interpolates and re-commits the 2^20 xor12, 2^18 xor9 and 2^16 tables,
     although `prove_circuit_with_precompute` exists for exactly this
     (VERIFIED).
   - The root channel uses the same Merkle hasher, so it can share the tree.
   - The fixed columns (`seq_16`, xor tables) do not depend on the circuit.
3. **Memory layout.**
   - u32 addresses instead of `usize`: a Rust gate is 24 B, a Zig gate 12 B.
   - Emit M31 columns directly instead of `Vec<usize>` → `BaseField` copies.
   - Drop `Stats`, `debug_info` and unused-var tracking in release builds.
   - For scale, qm31_ops and blake_g_gate reach 2^23 rows in the test
     registry, and blake_g_gate has 52 trace columns.
4. **Witness generation.**
   - Replace the per-element `HashMap` lookup `make_input_to_row` (xor8/7/9;
     about 16 lookups per blake_g row) with direct indexing, `row = (a<<n)|b`.
   - Use per-worker multiplicity histograms (at most 2^20 u32) instead of
     contended atomics.
   - Do not materialize `LookupData`; blake_g holds about 26 tuples per row.
     Recompute denominators during the interaction pass instead.
   - Use `@Vector(16,u32)` for the xor, split and rotate math.
5. **Fuse and stream.** Run witness generation, then interpolation, then LDE,
   then Merkle leaf hashing per component, through the existing streaming
   committer and the Metal/CUDA commit. Rust holds evaluations, coefficients
   and LDE for every component at once.
   - Choose barycentric OODS over stored coefficients when memory is tight.
     The bytes are identical.
6. **Value-pass arithmetic.**
   - Batch-invert the `compute_fri_input` denominators, the logup `inv(combine)`
     calls and the twiddle inverses.
   - Hash the independent Merkle paths (4 trees × queries × depth) and the FRI
     layers through the 4-way/SIMD Blake2s, recording the G intermediates in bulk.
7. **Scheduling.**
   - Sibling folds in a layer are independent, and so are leaves.
   - Run them concurrently under a static memory budget. Proof shape is fixed
     by the registry targets, so the budget can be computed in advance.
   - Release each child proof as soon as its parent's witness has been filled.
   - Keep internal fold proofs as structured in-memory data instead of a
     CircuitSerialize round trip; only the root artifacts are observable.
8. **Streaming output and leaf caching.**
   - Stream `root.proof` directly through `felt_json.zig`. Rust materializes
     `Vec<Felt>`, then `Vec<String>`, then pretty bytes.
   - Precompute the Cairo program hash and program limbs once per config.
9. **Generated code without dynamic dispatch.** Replace `Box<dyn CircuitEval>`,
   `Vec<Var>` subroutine returns and the `HashMap<String>` lookups with a
   comptime component table and fixed-size subroutine outputs.

## 7. Risks and open questions

**Risks**

- **R1 (blocking).** The transcript and PCS revision mismatch (§5). Nothing
  reaches byte parity before the 5a7c5ed profile lands.
- **R2 (largest effort).** Call-order-exact porting of about 12k hand-written
  lines, where one reordered `eval!` operand or constant request changes every
  downstream hash. Mitigation: L1/L3 goldens first, plus per-stage gate-list
  hashes from the oracle.
- **R3.** The generator must reproduce `air_code_gen` token structure exactly,
  including parenthesisation, `remove_trailing_zeroes`, sorted preprocessed
  reads and sorted public params. The compiled JSONs must be parsed with order
  preserved (serde `preserve_order`).
- **R4.** Pairing the wrong hasher with the channel. The M31 channel uses the
  plain Merkle hasher, while `mix_hash` uses the M31 `concat_and_hash`. The Zig
  aliases `Blake2sM31MerkleHasher` and `Blake2sPlainM31MerkleHasher` make it
  easy to pick the wrong one.
- **R5.** Grind kernels on device must return the minimal nonce and apply the
  M31 reduction.
- **R6.** Leaf parity requires the Zig Cairo prover to produce the Rust Cairo
  proof exactly on the new lane: M31 channel, include-all preprocessed columns,
  and the new heights.
- **R7.** Test infrastructure is limited by this host. Only `circuit-params` and
  `leaf-prover` release binaries are prebuilt. The fold oracle is the committed
  goldens.

**Open questions**

1. **Scope of "byte-identical".** Is it (a) the circuit proof given an identical
   Cairo proof and registry, or (b) end to end from the same Cairo program? (b)
   requires R6. The recommended staging is (a) first, consuming Rust-produced
   leaf Cairo proofs through the oracle.
2. **Protocol lane.** Should 5a7c5ed become a third protocol lane in core, or
   should the Cairo lane migrate? Migration would change the existing Cairo
   proof JSON shape and re-gate every official vector.
3. **Generator home.** A Zig build step under `src/tools/` (no Python at build
   time) or a `scripts/` Python emitter like `generate_cairo_claim_registry.py`?
   Should the 34 MB of compiled JSON be vendored, or only a constraints-only
   projection with sha256 and the proving revision recorded?
4. **Registry authority.** Should stwo-zig ship a `circuit-params` equivalent,
   or consume the Rust registry JSON as the authority? Reproducing the registry
   is the L3 milestone either way.
5. **ZK leaves.** Are ZK-blinded leaves (`privacy_large_proofs`) in scope? If so,
   a verified ChaCha20Rng KAT is required.
6. **Enable-slot order.** Does stwo-zig's `official_claim_registry` enable-slot
   order match all 83 `all_components` entries? The first 49 were confirmed; the
   rest were not compared.
7. **Leaf topologies.** How many distinct leaf topologies must be cached? There
   is one per (variant, trace_log_size, program), and the disabled components
   fix `enabled_bits`.
8. **Unread details.**
   - `memory_address_to_id`'s initial address expression. The reader saw
     "seq + 1 or similar"; re-read `components/memory_address_to_id.rs` when porting.
   - Whether `CommonLookupElements::draw` in the vendored `relation!` macro
     matches the stwo-zig Cairo relation draw order.
   - Whether stwo-zig's `drawSecureFelt` matches the query-draw semantics of
     `Blake2sChannelGeneric<true>`.
