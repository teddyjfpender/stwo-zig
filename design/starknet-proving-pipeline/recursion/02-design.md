# Circuit recursion in Zig (leaf wrap, 2-to-1 folds, tree driver): design — 2026-09-29

How stwo-zig will reproduce StarkWare's circuit recursion stage
(`proving@5a7c5ed`) with byte-identical proofs, higher speed and lower memory.
Inputs: the porting map [`01-rust-map.md`](01-rust-map.md) and its
completeness critique, three competing proposals, and three judgments of them.
This design takes the **parity-first incremental** proposal as its base (it won
two of the three judgments). It grafts in the **maximum-reuse** prover path
(recorded eval programs with the existing AOT, Metal and CUDA composition) and
the **data-oriented** memory techniques (run-length padding, a coefficient-only
policy, cold/warm/service timing). It resolves every fatal flaw the judges
raised; §11.1 lists how.

**Errata applied 2026-09-29** (each re-checked against the cited source
before editing):

1. **PoW grind rule.** Rust's `SimdBackend` grind
   (`crates/stwo/src/prover/backend/simd/grind.rs`, the same file in stwo
   `7b211ed` and `proving@5a7c5ed`) does not return the smallest nonce over all
   u64. It returns the smallest nonce of the form `(hi << 32) | lo` with
   `lo < 2^20` (`GRIND_LOW_BITS = 20`), searching hi-major. Every "minimum
   nonce" and "ascending" statement is replaced by that rule, for CPU and all
   device kernels (§4.4, §4.6, §6.3, §8.2 R0, §9.2, §10, §11.2). A new §4.7
   states the rule and records a consequence for the existing Cairo lane.
2. **Circuit proofs grind twice.** One grind is the 20-bit interaction grind.
   The other is the FRI grind at `fri_config.pow_bits` = 26 inside `prove_ex`.
   The root grinds on plain `Blake2sChannel` (§4.4, §4.6, §9.1, §9.2, M7,
   M12).
3. **The fold TopologyKey depends only on registry config.** Rust asserts the
   fold `circuit_hash` once, in `CanonicalCircuit::build`, not per proof
   (§3.5, §7.2). Open question 5 is closed.
4. **Leaf R6 is not oracle-free.** It needs the Cairo preprocessed root,
   committed at `trace_log_size + log_blowup` under `Blake2sM31MerkleChannel`.
   It consumes committed Cairo-root fixtures and depends on M4 (§0, §8.2,
   §11.1).
5. **The registry targets and the leaf bucket are restated.**
   - The canonical_small `pad_to_component_log_sizes` equal the privacy
     large_proofs registry, and an upstream test asserts they equal the
     production shared target.
   - Production definitions are checked in.
   - The leaf bucket is the lifted Cairo trace log size, which has a floor of
     25; it is not `log2(n_steps)`.
   - The cost model is marked as based on the test registry.

   See §6.5, §9.1 and §11.3.
6. The scratch-checkout path for `proving/` is replaced by the upstream URL
   and commit.
7. **R10 findings (M10, verified by running the oracle).**
   - `get_preprocessed_root(21 | 22 | 23)` is the canonical_small
     preprocessed trace at **log blowup 1, 2 and 3** (heights
     `20 + log_blowup_factor`, `export_circuit_cairo_verifier_preprocessed_roots`),
     not one blowup-1 tree lifted to three heights. R10b tests it that way.
   - Upstream `ExtendedBinary` bytes are **not reproducible**: the aux
     `hashbrown::HashMap`s serialize in per-process random order. R10c
     compares `bincode(CairoProofForRustVerifier)` exactly and
     `bincode(CairoProof)` with every aux map in ascending key order (the
     M3 reader must accept any order; its writer should emit this one).
   - The 5a7c5ed adapter's `public_memory_addresses` order also varies run
     to run; the proof does not depend on it.
   - Small programs **never lift** under `AtLeastPreprocessed` on
     canonical_small: the fixed 2^20-row tables fill the preprocessed domain,
     so every tree sits at 21. Lifting is covered by
     `LiftingSizePolicy::Fixed(22)` on all_opcodes and by the lifted
     wide-Fibonacci prover test (`vectors/circuit/r10`). Production leaves
     (canonical, preprocessed domain 26) lift every trace tree.
   - Any AIR proved on this revision must take its OODS vanishing domain
     from `max_log_degree_bound` (upstream `FrameworkComponent`), which
     lifting raises above the component's rows.
8. **M10 exit is split (R10d rescoped).** R10d proves SN_PIE_2 (7,706,864
   steps) and then wraps that proof, so it needs the M8 leaf wrap and a big
   host (§8.3). M10 closes locally on R10a–R10c with Cairo-lane vectors
   unchanged except the intended PoW-order change (§4.7). R10d moves to a
   big-host gate that runs after M8, listed in the M8 row of §10.
9. **M6 exit is split (big-host registries rescoped).** M6 closes locally on
   the canonical_small leaf: `circuit-parity-r6-leaf` (circuit CPU
   integration) rebuilds the trace-log-20 leaf verifier of the committed
   leaf-prover registry from the committed Cairo root and matches its
   preprocessed root and circuit hash; R10b pins `get_preprocessed_root`
   21/22/23; the 83 slots are checked against upstream `all_components` and
   `official_claim_registry`. The privacy `large_proofs` leaves (canonical,
   trace log 25–29) and the production registry need canonical Cairo roots
   and circuits beyond this host (§8.3), so they move to a big-host gate
   listed in the M6 row of §10.
10. **M9 closes locally on the canonical_small test registry.**
   - `recursion/{canonical,fold,tree}.zig` live in
     `src/integrations/circuit_cpu/recursion/`, not in the frontend (§2.2):
     a fold proves and reads and writes the recursion wire formats, and the
     frontend may depend on neither. Registry generation is
     `recursion/circuit_params.zig` beside them. The product is
     `stwo-circuit-recursion-cpu`, built from the product catalog
     (`zig build stwo-circuit-recursion-cpu`): `leaf-wrap` (M8),
     `fold-tree` and `circuit-params`, the last two with upstream's flag
     names. `verify` is not in it.
   - R9 is `circuit-parity-r9` (circuit CPU integration): 1, 2, 3, 4 and 5
     copies of the golden leaf, all three root files as raw bytes, against
     the upstream four-leaf goldens and the oracle's new `fold-tree`
     checkpoint (`vectors/circuit/r9/fold_tree.json`), which runs
     upstream's tree library on the same leaves. The release binary wrote
     the same bytes. Per-internal-node CircuitSerialize digests are not
     recorded: upstream emits no internal node, and every internal proof is
     bound by the root bytes. A leaf proof with bytes after its
     CircuitSerialize proof is accepted and the extra bytes ignored, as
     upstream's `deserialize_proof_with_config` on a slice ignores them.
   - Registry generation (`circuit-parity-registry`) reproduces both
     canonical_small test registries byte for byte from their upstream
     definitions; the committed registries equal the release
     `circuit-params --registry` output byte for byte.
   - The per-key committed-tree cache of §7.2 and §9.2 is not built: each
     reduction commits the canonical preprocessed trace again, as upstream
     does. One fold takes 50-65 s and up to 18 GB here against upstream's
     20 s and 22.7 GB; speed and the 8 GB host budget are M11.
   - **R11 as §8.2 defines it (acceptance and tamper) is not an M9 exit.**
     The M9 row first read "R11 green". Its local exit is now R9 plus
     byte-identical registry generation. Acceptance of Zig leaf and root
     proofs by the Rust verifiers is implied: their bytes equal upstream's
     (R8, R9). The tamper half is not built, and neither is Zig
     `verify_native`, which R11 also needs to accept Rust proofs. So R11
     stays open. It is listed in the M9 row as a later gate on the big-host
     lane (§8.3).
11. **Wave D audit fixes (2026-09-30).**
   - **R8b** (`circuit-parity-r8b`, product): the Zig lane proves and wraps
     upstream's leaf simple bootloader running the `simple_output` task
     `[11, 13, 17]` (`test_golden_four_leaves_e2e`'s `leaf_bl_input`) under
     the recursive-tree registry. Root, circuit hash and proof equal
     `four_leaves/leaf.json`; the `LeafInput` assembled from the
     bootloader's preimage dump equals the file byte for byte; four Zig
     leaves fold to the root goldens. This closes the Zig-leaf-into-tree
     chain that R8 (another program and registry) and R9 (a Rust leaf) left
     untested.
   - **R11 runs locally** (`circuit-parity-r11`, circuit CPU integration),
     replacing errata 10's big-host deferral. `verify_circuit` is ported
     (`statements/circuit_verifier.zig`, `integrations/circuit_cpu/verify.zig`,
     product command `verify`). Three proofs (upstream's multiverifier
     `proof.bin`, the Rust golden leaf, a Zig R7 proof) are accepted, and
     rejected after each of eight tamperings, by both the Zig verifier and
     oracle `verify-circuit`, whose verdicts are committed
     (`vectors/circuit/r11/verify/`). Acceptance of the Cairo felt stream by
     the Cairo `stwo_circuit_verifier` stays open.
   - **Wire readers follow upstream's release build**: `Felt::from_dec_str`
     wraps its digit add modulo 2^256 (lambdaworks only `debug_assert`s it),
     and a leaf proof's base64 may omit or shorten its padding
     (`serde_with` `DecodePaddingMode::Indifferent`). R0 pins both.
   - **Intentional deviation, fail closed.** Upstream's `fold.rs` checks the
     multiverifier only with `debug_assert!(context.is_circuit_valid())`;
     its release prover's one hard check is `lookup_sum == 0`. So a leaf
     with a wrong declared preprocessed root or a preimage that does not
     hash to its output can make upstream write root files. The Zig tree
     stops with `MultiverifierRejectedInputs` instead. No valid input
     changes; no invalid input gets a root.
   - **Aggregate steps**: `circuit-parity-local` (every rung within 8 GB:
     R0-R7, registry generation, R10b/R10c, R11) is the product's release
     gate; `circuit-parity-large` runs R8, R8b, R9 and the R7 multiverifier;
     `circuit-parity` runs both (§8.2).
   - **One CairoSerde transport**: `src/interop/felt_json.zig` (injected
     as `interop_felt_json` into the Cairo frontend and the wire package)
     owns the felt JSON text, the `stwo-cairo-serialize` primitives and
     `sort_and_transpose_queried_values`; the Cairo proof's CairoSerde
     encoder and the root proof's felt stream both use them (§2.3).
   - **One proof shape model**: `core.circuit_proof_shape` holds the column
     counts, FRI schedule and `CircuitSerialize` size that the in-circuit
     verifier's `ProofConfig` and the wire package's reader both use.
   - **Multi-size ZK registry, checked once by hand.** A canonical_small
     definition with `min_trace_log_size` 20, `max_trace_log_size` 22,
     `add_zk_blinding: true` and no `pad_to_component_log_sizes` generates
     the same registry bytes from Zig `circuit-params --registry` as from
     upstream's release `circuit-params` (2026-09-30; Zig 6.4 s and 3.3 GB,
     upstream 10.3 s and 8.0 GB, other jobs running). No rung runs it yet:
     upstream builds the registry in `circuit_params/src/main.rs`, not in the
     library the oracle links, so a committed fixture needs a black-box
     binary lane.
   - **Still open after the audit fixes** (tracked, not closed here):
     the `ExtendedBinary` Cairo proof reader and `leaf-wrap --cairo-proof`
     (§2.3, §7.4; a Rust-made Cairo proof cannot be wrapped yet; R10c pins
     the Zig Cairo proofs to upstream `prove_cairo` byte for byte, so the
     leaf lane's input is equivalent for the fixtures it covers); the
     `--checkpoints` records and `scripts/circuit_checkpoint_diff.py` of
     §1.3 (a divergence in R8/R8b/R9 still has to be bisected by hand);
     the big-host gates (production and privacy registries, R8 gate 2 on
     the mainnet leaf, R10d); the Cairo `stwo_circuit_verifier` half of R11;
     trees of distinct leaves (N = 7, mixed preimages); an automated ZK
     multi-size registry rung; and memory (M11: 11-18 GB peaks against the
     8 GB guidance).

Rust paths are relative to the root of
[`starkware-libs/proving`](https://github.com/starkware-libs/proving) at commit
`5a7c5ede4299c91a61df19a07cba4f7502c14230` (`proving@5a7c5ed`). The stwo
`7b211ed` paths refer to the stwo revision the Cairo lane pins
(`conformance/upstream.md`). Zig paths are relative to the repo root.

Markers: **VERIFIED** (read in code or data, path given) and **INFERRED**
(reasoned, not traced end to end). Nothing was built, proven or benchmarked for
this document. The only data read beyond source code was the
`execution_resources.json` inside each PIE zip (§6.5).

---

## 0. Decisions in one screen

1. **New frontend package `src/frontends/circuit` (`stwo_circuit_frontend`).**
   It holds a call-order-exact port of `crates/circuits`, `circuit_common`,
   `stark_verifier`, `circuit_verifier`, `cairo_verifier` (the statement) and
   `circuit_multiverifier`. There is one builder, `Context(comptime Value)`
   over `QM31 | NoValue`, as in Rust. **The value-mode Context is the
   production value path.** A topology tape is an optional optimisation (M13),
   allowed only after the fold goldens pass and only behind an audit.
2. **Wire formats go in `src/interop/circuit_recursion`**, next to the
   existing `proof_wire`, `postcard` and `atomic_file`. They do not live in the
   frontend.
3. **In-circuit evaluators (about 56k generated Rust lines) are interpreted,
   not generated.** A pinned Rust oracle deserialises the compiled-AIR JSON
   with upstream `air_compile::compiled_structs` and writes a compact
   constraints-only projection. A Zig interpreter repeats
   `air_code_gen/src/circuit/component.rs`'s walk through the builder.
4. **The prover-side circuit AIR (11 components) is recorded, not ported.** The
   Rust `circuit_air` FrameworkEvals are recorded into the existing
   `air_programs_v1` eval-program ABI. The existing
   `src/tools/cairo_composition_cpu_codegen`, `cairo_metal_codegen` and
   `cairo_cuda_eval_aot` then serve the circuit AIR. The recorder runs in the
   oracle's own `proving@5a7c5ed` workspace. It never shares source by
   `#[path]` with the `82f2125` compiler, and it is gated by an ABI
   byte-compare.
5. **Core gains an explicit protocol revision `proving_5a7c5ed`.** It covers
   `FriConfig` with `pow_bits`, a config mix that is always 2 felts, and
   explicit per-tree lifting heights. The Native and Cairo lanes keep their
   current bytes.
6. **Recursion work does not wait for the Zig Cairo prover.** Stage A consumes
   Rust-produced Cairo proofs (ExtendedBinary, dumped by the oracle). Stage B,
   where the Zig Cairo prover runs on the `Blake2sM31MerkleChannel` lane, is a
   parallel track.
7. **A 12-rung parity ladder, R0–R11.** Each rung is a `zig build` step backed
   by committed fixtures. Four rungs prove nothing: R1 builder snapshots, R3
   per-component gate-list hashes, R5 finalize sub-stages and R6 registry root
   and circuit hash. Only R1 can start before the oracle exists. The leaf part
   of R6 needs the Cairo preprocessed root as a committed fixture and depends
   on M4. The fold part depends on M5 (§8.2).
8. **Performance comes after the ladder is green.** It changes representation,
   residency and scheduling only, never order. The main levers are
   LDE/Merkle/FRI streaming and GPU residency, not the builder (§9.1).

---

## 1. Goals, non-goals, and the byte-parity contract

### 1.1 Goals

- Zig implementations of `leaf-prover` (steps 4–8: wrap a Cairo proof),
  `stwo_run_and_prove_recursive_tree` (fold N wrapped leaves to a root) and
  `circuit-params` (the registry). Each must produce the same bytes as the Rust
  binary for the same inputs.
- CPU SIMD first, then Metal, then CUDA. Every device path is byte-equal to the
  CPU scalar reference.
- Lower wall time and lower peak RSS than the Rust release binaries on the same
  host, measured with the CONTRIBUTING acceptance template (§9).

### 1.2 Non-goals (this design)

- A new recursion protocol, a new circuit AIR, or any deviation from Rust
  semantics, even an "equivalent" one.
- Hash-consing or algebraic simplification in the builder. These are
  explicitly banned (§3.3). `src/frontends/riscv/recursion` is used as a
  pattern source only and never imported: its hash-consing would renumber
  wires.
- The Cairo `stwo_circuit_verifier` program itself. The root felt stream is
  consumed by existing Cairo tooling.
- ZK leaves (`privacy_large_proofs`) are supported by the builder, but they are
  not a release gate until the ChaCha20 KAT passes (R0) and a privacy fixture
  exists.

### 1.3 The byte-parity contract

For identical inputs (registry JSON, Cairo proof or prover input, leaf
manifest), the following must be **byte-identical** to Rust `proving@5a7c5ed`
built with the same toolchain:

| Artifact | Rust producer | Compared as |
|---|---|---|
| Registry JSON (`to_string_pretty` + `\n`) | `circuit-params` | raw bytes |
| Per-circuit `preprocessed_root`, `circuit_hash` | `circuit_common`, `circuit_prover` | 32 B digests |
| Circuit proof (`CircuitSerialize`) for every internal node | `circuit_serialize` | raw bytes |
| `SerializedLeafProof` pretty JSON, no trailing newline | `leaf_prover` | raw bytes |
| `root.proof`, `root_outputs.json`, `root_packed.json` | `stwo_run_and_prove_recursive_tree` | raw bytes. This is stricter than Rust's own test, which compares parsed JSON. |
| Cairo leaf proof (Stage B only, ExtendedBinary) | `leaf_prover` steps 1–3 | raw bytes |

"Measured how": every artifact has a named checkpoint record
(`{stage, sha256, count, n_vars, per_kind_counts}`). The oracle and the Zig
products both emit these records behind `--checkpoints out.jsonl`, and
`scripts/circuit_checkpoint_diff.py` diffs the two files. The script only
compares program outputs and never reimplements semantics. A rung passes only
on exact equality. There is no tolerance and no "equivalent up to ordering".

Accepted but not sufficient: the Rust `circuit_verifier` accepting a Zig proof
(R11). A verifying proof with different bytes is a parity failure.

---

## 2. Module and directory layout

This follows CONTRIBUTING §Repository architecture (frontends → integrations →
prover → core) and §Module and directory design: `mod.zig` is a map, files are
250–650 lines, and every package has a `package.contract.json`.

### 2.1 Core (protocol laws only; additive)

- `src/core/protocol_revision.zig` (new). It defines
  `pub const Revision = enum { stwo_7b211ed, proving_5a7c5ed }` and three
  comptime rules:
  - `configMix(rev)`: under 5a7c5ed it always mixes 2 felts,
    `[(pow, blowup, nq, last), (fold_step, 0, 0, 0)]`;
  - `treeHeight(rev, tree, cfg, max_col)`: under 5a7c5ed tree 0 uses the
    preprocessed lifting height and every other tree uses the trace lifting
    height, with `height ≥ max_col` asserted; an empty tree is valid only
    when its configured height is already 0 (upstream asserts
    `lifting_log_size == 0`, it does not substitute 0), else an error;
  - `finalLiftingCheck`.
- `src/core/pcs/config_v2.zig` (new) with `PcsConfigV2 { fri: FriConfigV2
  {pow_bits, log_blowup, log_last_layer, n_queries, fold_step},
  trace_lifting_log_size, preprocessed_lifting_log_size }`. The existing
  `PcsConfig` (`src/core/pcs/mod.zig:23`) and its `mixInto`
  (`src/core/pcs/mod.zig:34`) are untouched.
- `src/core/vcs_lifted/blake2_merkle.zig`: add `hashU32s` and
  `hashU32sFollowedByDigest`. Each is a single Blake2s over LE(words)‖root
  (`crates/stwo/src/core/vcs_lifted/hasher.rs:19-21`).
- `src/core/crypto/chacha20_rng.zig` (new): rand_chacha 0.3 `ChaCha20Rng`
  (`from_seed`, `next_u32`, and rand_core `BlockRng` buffering and index
  semantics).
- `src/core/fields/qm31_pointwise.zig` (new): `pointwiseMul`,
  `pointwiseInvOrZero`, `pointwiseLsb`, and a fully reducing u32→M31.
- Shared primitives move down one layer. This is a preparatory milestone (M1)
  that resolves the frontend-to-frontend dependency:
  - `BLAKE_SIGMA` moves to `src/core/crypto/blake_sigma.zig` (done in M1b).
    It was copied in the Cairo Blake deductions
    (`src/frontends/cairo/witness/deductions/blake.zig`, read by
    `preprocessed/columns.zig`) and in `core/crypto/blake2s_terminal_parallel.zig`;
    both now use the core table.
  - The pure `seq` and `bitwise_xor_{n}_{k}` column formulas move to
    `src/core/preprocessed_tables.zig` (done in M1b). The Cairo frontend's
    `preprocessed/columns.zig` delegates to them, so its bytes are unchanged.

### 2.2 Frontend `src/frontends/circuit/` (package `stwo_circuit_frontend`)

Dependencies: `stwo_core`, `stwo_prover_engine`, `stwo_backend_contracts`,
`stwo_prover_api`. **There is no dependency on `stwo_cairo_frontend`**, and the
contract enforces that. The Cairo facts the circuit side needs are the 83-slot
`all_components` order, the relation ids, and the preprocessed column ids for
the Cairo AIR. They come from the projection (§5.4). A test-only root
(`conformance/circuit_cairo_slot_order_test_root.zig`) imports both packages and
asserts equality with `src/frontends/cairo/air/official_claim_registry.zig`.
The fold binary therefore never links Cairo witness machinery. The design also
stays clear of the uncommitted edits in `template_binding.zig` and
`witness/eval_program.zig` (git status `M`).

```
src/frontends/circuit/
  README.md  mod.zig  build.zig  build.zig.zon  package.contract.json
  builder/                     # port of crates/circuits, call-order exact
    circuit.zig                # per-kind SoA gate vectors, u32 vars, CSR permutation, pad runs
    context.zig                # Context(Value): vars 0/1/2, reserve, constants, guesses, set_outputs
    ivalue.zig                 # QM31 | NoValue surface (pointwise ops, pack/unpack, sort_by_u)
    ops.zig                    # add/sub/mul/pointwise_mul/eq/guess/constant: index-only peepholes
    wrappers.zig simd.zig extract_bits.zig blake.zig
    finalize_constants.zig     # swapRemove / keys()[0] / retainOrdered
    debug_format.zig           # Rust Debug text of gate lists (tests, oracle diffs)
  common/                      # port of crates/circuit_common
    finalize.zig               # pad_to_targets, pad_context, ComponentSizes
    zk_blinding.zig
    preprocessed.zig           # address + multiplicity columns, permutation lowering at n_vars+g
    circuit_hash.zig
  stark_verifier/              # one Zig file per Rust file of crates/stark_verifier
    channel.zig merkle.zig fri.zig fri_proof.zig oods.zig constraint_eval.zig logup.zig
    statement.zig proof.zig proof_guess.zig circle.zig select_queries.zig
    sort_queries.zig order_map.zig verify.zig
  air_eval/                    # replaces the generated in-circuit evaluators
    projection.zig             # reader for vectors/circuit/official/compiled_air_constraints_v1.bin
    interpreter.zig            # component.rs emission order, generic over Value
    subroutines.zig
    manual/                    # cairo: memory_address_to_id, memory_id_to_big, verify_bitwise_xor_12
                               # circuit: eq, qm_31_ops, verify_bitwise_xor_12
    cairo_components.zig       # 83-slot table, read from the projection header
    circuit_components.zig     # 11-slot table in ComponentList order
  statements/
    circuit_statement.zig      # guess order: output_digest, preprocessed_root, statement, proof
    cairo_statement.zig        # CairoStatement::new order, serialize_aux_data, program limbs
    cairo_public_data.zig      # PublicData::mix_into + FlatClaim::mix_into (host side, tests)
    multiverifier.zig
  air/                         # prover-side 11-component AIR bound to recorded eval programs
    component_list.zig         # order, relation ids, interaction pairing, column layout
    components.zig             # ComponentProverVTable over air_programs bundle
  witness/
    gather.zig                 # generic vectorized gather: eq, qm31_ops, triple_xor, m31_to_u32
    blake_g_gate.zig           # the one hand-written gate witness (@Vector(16,u32))
    tables.zig                 # range_check_16, xor_{4,7,8,8_b,9,12}; per-worker histograms
    interaction.zig            # denominators recomputed; finalize_last
    scheduler.zig
  proving/
    channel_profile.zig        # CircuitChannelProfile {internal, root}, the only two instances
    prove.zig                  # the one transcript sequencer (§4.4)
    to_verifier_proof.zig      # proof_from_stark_proof / prepare_circuit_proof_for_circuit_verifier
    verify_native.zig          # Zig verifier of circuit proofs (local defence, R11)
  recursion/
    leaf_wrap.zig  fold.zig  tree.zig  canonical.zig
    topology_key.zig  topology_cache.zig
```

### 2.3 Interop `src/interop/circuit_recursion/` (versioned wire formats)

- `circuit_serialize.zig`: read and write. Values ≥ P are rejected and trailing
  bytes are ignored, as in Rust.
- `cairo_serialize.zig`: the felt primitives of `crates/cairo-serialize`
  (package `stwo-cairo-serialize`, `serialize.rs`, about 400 lines). They cover:
  - `FriConfig`, and `PcsConfig` with the lifting fields dropped;
  - the `CommitmentSchemeProof` field order;
  - `MerkleDecommitmentLifted`, of which only `hash_witness` is serialized;
  - `LinePoly` + ilog2;
  - `Option` with Some = 0;
  - length-prefixed slices;
  - `Blake2sHash` as 8 LE u32.
- `circuit_felt_stream.zig`: the root `CairoCircuitProof` stream, including
  `sort_and_transpose_queried_values` (`cairo-air/src/utils.rs:220`). Trees 1
  and 2 are stable-sorted by log size and then transposed; trees 0 and 3 are
  only transposed.
- `felt_json.zig`: streaming pretty `0x…` felt JSON. The former
  `src/frontends/cairo/proof/cairo_serde/felt_json.zig` moved in M1b to
  `src/interop/felt_json.zig`, one level above this directory: Zig rejects a
  file that belongs to two modules, so the writer is its own single-file
  module (`interop_felt_json`, injected into the Cairo frontend like the RISC-V
  frontend's `interop_postcard`) that this package imports rather than owns.
  Cairo re-exports it as `proof.cairo_serde.felt_json`; the move is
  byte-neutral. As built (errata 11), the same injected module also holds
  the `stwo-cairo-serialize` primitives (`FeltWriter`, `FeltReader`) and
  `sortAndTransposeQueriedValues`: the wire package's `cairo_serialize` is
  that module, and the Cairo frontend's `cairo_serde/pcs.zig` and
  `queries.zig` encode on it, so the primitives and the query layout have
  one definition (CairoSerde bytes of `all_opcodes` and `all_builtins`
  unchanged).
- `registry.zig`: `CircuitRegistry` and `LogSizes`, parsed into typed values
  and written in Rust struct order (config map keys in byte order) as pretty
  output + `\n`.
- `leaf_proof_json.zig` (`SerializedLeafProof`, `DigestHex` `{:#010x}`, std
  base64 standard padded), `packed_node.zig`, `blake2_felt252.zig`.
- `cairo_proof_binary.zig`: the ExtendedBinary `CairoProof<H>` reader
  (`cairo-air/src/utils.rs:117,146`), the inverse of the Cairo
  `proof/binary/writer.zig`, including the `ExtendedStarkProof` aux fields.

**As built (M3).** The package is `stwo_circuit_recursion_wire`
(`src/interop/circuit_recursion/README.md`). It adds `json_text.zig`, the
serde_json pretty and compact text surface the JSON formats share. The
`ProofConfig` of `circuit_serialize.zig` takes the per-component column counts
as data, so the package holds no circuit AIR facts. Where Rust is lenient in a
way that would break a byte-identical round trip, decoding fails closed and
says so at the decoder (for example an M31 at or above P in the felt stream,
which Rust's `BaseField::from` reduces). `cairo_proof_binary.zig` is not yet
built; the ExtendedBinary round-trip criterion of M3 remains open.

### 2.4 Integration, product, build, tools

- `src/integrations/circuit_cpu/` (`mod.zig`, `prove.zig`, `caches.zig`). It
  binds the frontend to the cpu_scalar/SIMD backends and the AOT composition
  kernels, and owns the topology and preprocessed caches. It contains no
  protocol logic. `circuit_metal/` and `circuit_cuda/` follow later.
- `src/products/circuit_recursion_cpu/{main,app,identity,capabilities}.zig`,
  modelled on `src/products/cairo_cpu`. Subcommands (§7.4): `leaf-wrap`,
  `fold-tree`, `circuit-params`, `verify`.
- `build_support/products/circuit_recursion_cpu.zig` and a `circuit_cpu` Scope in
  `build_support/products/catalog.zig`.
- `build_support/products/cairo_composition_cpu_aot.zig` is generalised to
  take a bundle list and a kernel count, so it is not copied. The circuit AIR
  becomes one more bundle.
- `tools/stwo-circuit-oracle-rs/` is its own Cargo workspace and lockfile,
  pinned to `proving@5a7c5ed` with toolchain `nightly-2026-01-15`. It is
  registered in `conformance/tooling-surface-v1.json`. It depends on a new
  pin-free crate `tools/stwo-eval-program-abi/`, which is extracted from
  `tools/stwo-cairo-air-compiler` (`program.rs`, `encoding.rs`, `bundle.rs`)
  and contains only data types and encoding, with no stwo dependency. Each pin
  keeps its own thin `EvalAtRow` recorder.
- `conformance/upstream.md` gains a "Circuit Recursion Lane" entry that names
  `proving@5a7c5ed`, the vendored stwo `7b211ed` plus its deltas, and
  stwo-cairo `82f2125`. `scripts/check_upstream_pins.py` is extended to check
  it.
- Fixtures go under `vectors/circuit/`: `official/` (projection, air_programs
  bundle and provenance), `registries/`, `r0/`…`r10/` and `goldens/`. Each has
  a `*.provenance.json` in the `witness_programs_v1` style: proving commit,
  sha256 of every source, oracle git hash, host and date.

Naming: the package is `stwo_circuit_frontend` and the Zig namespace is
`circuit`. Rust names keep their stems (`blake_g_gate`, `qm31_ops`,
`CircuitStatement`), so a grep across both trees lands on the counterpart.

---

## 3. Circuit representation and builder

The rule: mirror Rust semantics and change only the representation.

### 3.1 Vars and gates

- `Var = packed struct { idx: u32 }`. Var 0 is zero, var 1 is one, and var 2 is
  u = (0,0,1,0). Vars `3..3+n_reserved` are output wires: 8 for the leaf, set
  by `Context::new(8)`. Everything after that is numbered in call order. The
  builder asserts `n_vars < 2^31` so that addresses fit M31 columns.
- `Circuit` has one `std.ArrayListUnmanaged` SoA per gate kind, in the per-kind
  order of `crates/circuits/src/circuit.rs`:
  - Add, Sub, Mul and PointwiseMul are `{in0, in1, out}`, 12 B each against
    Rust's 24 B of usize;
  - Eq, TripleXor, M31ToU32 and Output;
  - Permutation in CSR form (`offsets`, `inputs`, `outputs`).
- BlakeGGate is `{a, b, c, d, f0, f1, out_base}`, 28 B against 80 B.
  **VERIFIED:** the four outputs are always four consecutive `ctx.new_var` calls
  with nothing in between (`crates/circuits/src/blake.rs:407-410`). The builder
  asserts `out_{b,c,d} == out_base+{1,2,3}` in debug and audit builds, so a
  future upstream change fails loudly.
- **Padding is stored as run descriptors**
  `{kind, count, first_fresh_var, pattern}`, never as rows. They expand lazily
  into preprocessed columns and witness rows. `n_vars` still counts every
  padding var, because permutation lowering uses the addresses `n_vars + g`.
  At the 2^23 targets, most qm31_ops and blake_g rows are padding (INFERRED
  from the canonical_small targets).

### 3.2 Context

- `Context(comptime Value: type)` with `Value ∈ {QM31, NoValue}`. `NoValue` is
  a zero-sized type that implements the same IValue surface (`ivalue.rs`), so
  topology mode and value mode run the same code, as in Rust.
- `Stats`, `debug_info` and the unused-var sets exist only when
  `builtin.mode == .Debug` or `-Dcircuit-audit` is set, and they never affect
  numbering. Tests keep `unused_vars` on because it is a correctness check.
  Under audit, `assert_eq_on_eval` becomes an eager eq check in QM31 mode.
- Each build takes one arena over the product's tracked allocator. The gate
  vectors are pre-reserved from the registry targets. Going over a target is a
  hard error, as Rust's `pad_to_targets` assert is.

### 3.3 Call-order rules (each has an R1–R5 test)

- **Peepholes are index-only** (`crates/circuits/src/ops.rs:106-118`,
  VERIFIED):
  - `add` returns the other operand if either operand is var 0;
  - `mul` returns var 0 if either operand is var 0, and the other operand if
    either is var 1;
  - `sub` and `pointwise_mul` never elide.
  There is no value folding and no hash-consing. A lint
  (`scripts/lint_circuit_frontend.py`, run by `zig build lint`) bans
  `std.sort.pdq`/`std.mem.sort` (unstable), `AutoHashMap` iteration and
  `HashMap.keyIterator` inside `src/frontends/circuit`.
- **Constants** live in `std.AutoArrayHashMapUnmanaged(QM31, Var)` in
  first-use order. `Context.constant` still interns after `finalize_constants`
  (`context.rs:161`, VERIFIED), because `finalize_constants` works on its own
  local IndexMaps (`finalize_constants.rs:50`).
- **`finalize_constants`** is ported verbatim:
  - the m31/qm31 split;
  - `m31_base = max(longest run, 256)`, the +1 chain and the base-B Horner;
  - broadcast and the i/u/iu basis;
  - IndexMap `swap_remove` is Zig's `swapRemove` (the last entry moves into the
    hole), and `keys().next()` is `keys()[0]`;
  - `retain` is `retainOrdered`, an order-preserving compaction followed by a
    reindex. It gets a unit test against `finalize_constants_test.rs`.
- **Guesses**: `guessed_vars` holds a `union(enum){m31, qm31, u16}` in guess
  order. Finalization emits `pointwise_mul(v,1,v)`, `add(v,0,v)` and
  `m31_to_u32(v,v)` in that order. Every proof and statement type has **one**
  `fn guess(self, ctx: anytype)` traversal, shared by the builder, the
  flattener and any future tape. No second copy of the order exists.
- **eval! order** (interpreter, §5.4) evaluates left subtree, then right
  subtree, then the op. `-(x)` is `sub(zero, x)` emitted after x. StaticCall
  arguments are evaluated left to right. In a LookupTerm, the tuple felts come
  before the numerator, with trailing `Const 0` felts stripped
  (`remove_trailing_zeroes`).
- **Post-finalize order**, as appends: builder gates → `finalize_constants` →
  guess finalization → `add_zk_blinding` → `pad_to_targets` (eq, qm31_ops,
  triple_xor, m31_to_u32, blake_g_gate). Padding and ZK use the **real Context
  API**, so post-finalize constants take the Rust path without special cases.
  This covers `U32Wrapper::const_u32(ctx, 0)` in `pad_triple_xor` and
  `pad_blake_g_gate`, and `pack_u32`/`new_var` in the ZK helpers. ZK draws 26
  u32 per iteration in the order qm31(12), eq(4), triple_xor(3), m31_to_u32(1),
  blake_g(6), from ChaCha20Rng seeded with the LE words of the child trace
  root. R5 pins `n_vars` and per-kind counts after every sub-stage.
- **Fold wire order**: the multiverifier shares one Context across its children
  in the Rust child order (L, then R), so constants are deduplicated across
  children. The Blake preimage is built last (`circuit_multiverifier/src/verify.rs`).

### 3.4 Preprocessing and circuit hash

- `common/preprocessed.zig` emits address columns and multiplicity columns
  directly as M31; Rust goes through `Vec<usize>` first. Multiplicity rules:
  `multiplicities[0] += 2` per permutation pair, and the blake_g multiplicity
  is taken from `out_a` and asserted equal for b, c and d. Permutations lower to
  qm31_ops rows at `n_vars + g`. Columns are stable-sorted by length.
- The fixed tables (`seq_16`, `bitwise_xor_{4,7,8,9,10}_{0,1,2}`) come from
  `src/core/preprocessed_tables.zig` (§2.1), not from a copy.
- `circuit_hash = hashU32sFollowedByDigest(config_words, preprocessed_root)`,
  where `config_words` are 12 B read as 3 LE u32
  (`circuit_prover/src/circuit_hash.rs`). R0 checks the in-tree `expect!`
  vectors, including `poseidon252_root`.

### 3.5 Topology identity

`TopologyKey` is the blake2s digest of:

- the revision and the circuit kind (leaf or fold);
- the registry config name, the FriConfig, and the target `ComponentSizes`;
- for a leaf:
  - the variant (Canonical or CanonicalSmall) and `enabled_bits`;
  - `trace_log_size` and the zk flag;
  - the **Cairo preprocessed root value** (interned constants, `statement.rs:644`);
  - the sha256 of the program felts and the **program hash** (`statement.rs:513`);
- for a fold: nothing else. The fold topology depends only on the registry
  config, namely the shared `target_sizes` and the circuit `FriConfig`
  (VERIFIED). It does not depend on any child's circuit hash, for three
  reasons:
  - `CanonicalCircuit::build` derives the `SharedConfig` from
    `layout_from_component_sizes(target_sizes)` and the circuit FRI config
    alone (`stwo_run_and_prove_recursive_tree/src/canonical.rs:45-105`);
  - each child's `preprocessed_root` and `output_digest` are **guessed**, not
    interned as constants;
  - each child's `circuit_hash` is computed in-circuit by `CircuitStatement`
    (`circuit_multiverifier/src/verify.rs:66-109`).

The value-dependent `finalize_constants` gate count is a function of the
constant set, and so of the key. Per key, the integration caches: the circuit
hash, the preprocessed columns (with pad runs), the committed preprocessed tree
with its coefficients, and the `ProofConfig`/`ProofInfo` sizes.

A stale key cannot produce a proof:

- **Leaves.** Rust checks `circuit_hash` against the registry on every leaf
  proof (`leaf_prover/src/prove_leaf.rs:227-233`), and Zig does the same.
- **Folds.** Rust checks it **once**, in `CanonicalCircuit::build` (step 4,
  `canonical.rs:79-95`), before any reduce. Zig does the same when it builds
  a fold key's cache entry. The fold key has no per-child fields, so the
  per-reduce proofs can reuse that one check.

---

## 4. Circuit AIR prover

### 4.1 Components (fixed)

There are 11 components, in `ComponentList` order
(`circuit_prover/src/circuit_air/circuit_components.rs`, 177 hand-written
lines): eq, qm31_ops, triple_xor, m31_to_u32, blake_g_gate,
verify_bitwise_xor_{8,8_b,4,7,9,12} and range_check_16. Only the preprocessed
columns and the witness change between circuits.

Relation ids:

| Relation | Id |
|---|---|
| GATE | 378353459 |
| RC16 | 1008385708 |
| XOR4 | 45448144 |
| XOR7 | 62225763 |
| XOR8 | 112558620 |
| XOR8_B | 521092554 |
| XOR9 | 95781001 |
| XOR12 | 648362599 |

Interaction and lookup layout:

- interaction columns pair as (0,1), (2,3), …, and an odd last column stands
  alone;
- blake_g_gate has 13 interaction columns;
- verify_bitwise_xor_12 has 16 multiplicity columns, indexed `(ah<<2)+bh`;
- lookups draw from `CommonLookupElements` (128 powers).

### 4.2 Constraint code: recorded, not ported or generated

The oracle's `air-programs` subcommand runs each Rust `circuit_air`
FrameworkEval through a `proving@5a7c5ed` EvalAtRow recorder. That covers the
generated evaluators (about 2,471 lines) and the hand-written `eq` and
`verify_bitwise_xor_12`. The output is
`vectors/circuit/official/circuit_air.air_programs_v1.bin`, using the
pin-free ABI crate (§2.4). On the prover side, bytes depend only on:

- the `add_constraint` order, which sets the random-coefficient powers;
- the mask and column order (`next_trace_mask` order);
- the `add_to_relation` order and `finalize_logup_in_pairs` pairing;
- the values themselves.

Recording keeps all four. Operand order inside an expression does not change
the committed field values. It matters only inside the in-circuit builder,
which is why the in-circuit side is interpreted (§5.4) and not recorded.

The Zig side reuses:

- `src/frontends/cairo/codegen/eval_program.zig`-style validation, moved into
  core or the prover engine if the circuit package needs it;
- `src/prover/air/component_programs.zig`;
- `ComponentProverVTable` (`src/prover/air/component_prover.zig:81`);
- the generalised CPU AOT C step, and later `cairo_metal_codegen` and
  `cairo_cuda_eval_aot` over the same bundle.

Gates:

- **ABI byte-compare.** The `82f2125` compiler and the `5a7c5ed` oracle encode
  one shared fixture program, and the two byte strings must match.
- **Relation-descriptor gate.** For circuit relations
  (`CommonLookupElements`, 128 powers), a per-component interaction-column
  sha256 is checked in R7 before any Cairo `interaction_trace.zig` descriptor
  is reused.
- **Composition cross-check.** Random-point evaluations of the recorded
  composition are compared against the oracle's direct evaluation.

### 4.3 Witness

The port reproduces `circuit_prover/src/witness/components/*` (3,478 lines) by
column order, not by structure:

- **Gather.** eq, qm31_ops, triple_xor and m31_to_u32 share one vectorized
  gather, `col[r] = values[addr_col[r]]`, over the preprocessed address columns
  (already M31).
- **blake_g_gate** (52 base columns) is the only hand-written gate witness. It
  does xor limbs and rotations on `@Vector(16,u32)`.
- **Table multiplicities** use direct indexing `row = (a<<n)|b` into per-worker
  u32 histograms (at most 2^20 entries), merged by exact integer sum. This
  replaces Rust's `make_input_to_row` HashMaps (about 16 lookups per blake_g
  row) and its contended `AtomicMultiplicityColumn`.
- **Interaction.** `LookupData` is never materialised. Denominators are
  recomputed in the interaction pass and batch-inverted per tile, which is
  exact. `finalize_last` subtracts `claimed_sum / 2^log_size`, then takes an
  inclusive prefix sum in bit-reversed coset order; it reuses the existing
  `FormalLogupAtRow`.
- Column order in each tree is fixed by `component_list.zig`, whatever order the
  scheduler finishes in.

### 4.4 Transcript, commitment, PCS, channel

`proving/prove.zig` is the only place that sequences channel operations. It
follows map §1.3 exactly:

1. `mix_felts([0])` (salt).
2. `FriConfigV2.mixInto` (2 felts).
3. Commit the preprocessed tree at `preprocessed_lifting_log_size`, with
   `store_polynomials_coefficients = true`. `commit_tree` itself runs
   `mix_hash(preprocessed_root)` (stwo `prover/pcs/mod.rs:105`).
4. `circuit_hash = hashU32sFollowedByDigest(config_words, root)`, then
   `mix_hash(circuit_hash)`. This is a second mix, and both are kept.
5. `claim.mix_into`: the 8 output-digest words packed as (lo16, hi16, 0, 0).
   Then commit the base trace.
6. The **interaction grind**: `INTERACTION_POW_BITS = 20`
   (`circuit_verifier/src/statement.rs:37`, `circuit_prover/src/prover.rs:160`).
   It uses the §4.7 grind rule and asserts both u32 halves < P. Then
   `mix_u64`, then draw `CommonLookupElements`.
7. Mix the 11 claimed sums in ComponentList order, then commit the interaction
   trace.
8. `proveEx(..., include_all_preprocessed_columns = true)`. `split_at_mid`
   gives 8 composition columns in tree 3; FRI uses `fold_step = 4`, packed
   leaves and `log_last_layer = 0`, with tree heights from
   `Revision.proving_5a7c5ed`. Inside it comes the **FRI grind** at
   `fri_config.pow_bits` (stwo `prover/pcs/mod.rs:256`), which is 26 in every
   circuit FriConfig in the checked-in registries and definitions (VERIFIED).
   It uses the same §4.7 rule. So a circuit proof has two grinds, at 20 and at
   26 bits. The 26-bit grind dominates grind time: its expected cost is about
   2^26 hashes, against about 2^20 for the interaction grind.

`CircuitChannelProfile` (`proving/channel_profile.zig`) has exactly two comptime
instances:

- `.internal` (leaves and internal folds): `Blake2sM31Channel` plus
  `Blake2sM31MerkleChannel.mixRoot`, which uses M31 `concatAndHash`
  (`src/core/vcs_lifted/blake2_merkle.zig:238-253`);
- `.root`: `Blake2sChannel` plus `Blake2sMerkleChannel`
  (`stwo_run_and_prove_recursive_tree/src/fold.rs:144`, VERIFIED). Both root
  grinds therefore run on the **plain** `Blake2sChannel`
  (`Blake2sChannelGeneric<false>`): word 0 is not reduced mod P before
  trailing zeros are counted. The internal profile's grinds reduce it.

Both use `Blake2sPlainMerkleHasher`. **VERIFIED:** in Rust both
`Blake2sMerkleChannel` and `Blake2sM31MerkleChannel` set `type H =
Blake2sMerkleHasher = Blake2sHasherGeneric<false>`
(`crates/stwo/src/core/vcs_lifted/blake2_merkle.rs:9,54,75`). So **one cached
preprocessed tree serves both the internal and the root channel**. The
domain-prefixed `Blake2sM31MerkleHasher` alias
(`src/core/vcs_lifted/blake2_merkle.zig:20`) cannot be named inside the
profile.

### 4.5 Converting a circuit proof for the in-circuit verifier

`to_verifier_proof.zig` ports `proof_from_stark_proof` and
`prepare_circuit_proof_for_circuit_verifier`:

- queried values are re-expanded to `aux.unsorted_query_locations` order,
  duplicates included;
- eval auth paths are `all_node_values[j][pos^1]`;
- FRI auth paths are `all_node_values[j − pack_shift][pos^1]`;
- nonces become `QM31(lo, hi, 0, 0)`.

Its inputs are the existing `ExtendedStarkProof` aux
(`src/core/proof.zig:170`, `src/core/pcs/mod.zig:89`,
`src/core/vcs_lifted/verifier.zig:35`). Internal folds pass the structured
proof in memory; a CircuitSerialize round trip is only a test.

### 4.6 Backend plan

1. **CPU scalar reference.** It is the parity oracle for every other backend.
2. **CPU SIMD.** Packed M31/QM31 from `src/backends/cpu_*`, 4-way Blake2s
   (`blake2s_parallel4`, `stream4`), `src/prover/vcs_lifted/streaming_committer.zig`,
   and the AOT C composition.
3. **Metal, then CUDA** (after R9). They reuse the resident LDE, Merkle and FRI
   kernels and the generated composition from the same bundle. New work:
   - **grind kernels that implement the §4.7 rule**, in two variants:
     Blake2s-M31, which reduces word 0 mod P before counting zeros, for the
     internal profile; and plain Blake2s for the root. Each variant serves
     both the 20-bit interaction grind and the 26-bit FRI grind.
     `src/backends/metal/runtime/proof_of_work.zig` has no M31 variant, and
     its search order must be re-checked against §4.7 before it is reused;
   - gather and blake_g witness kernels.

   A device lacking any capability **fails closed**; there is no silent CPU
   fallback. A device grind must return exactly the nonce the §4.7 CPU
   reference returns. Blocks are dispatched in ascending `hi`, and the lowest
   successful `hi` wins, as in Rust's `parallel_grind`. On every proof, the
   host checks that the nonce passes and that `lo < 2^20`. Equality with the
   reference is proven by the R0 grind vectors and the R7–R9 device runs,
   not by re-grinding on every proof.

### 4.7 Grind rule (parity-critical)

**VERIFIED** in `crates/stwo/src/prover/backend/simd/grind.rs`, which is
identical in stwo `7b211ed` and `proving@5a7c5ed`. Rust's `SimdBackend` grind
(the backend both the Cairo and the circuit provers use) returns:

> the smallest `nonce = (hi << 32) | lo` with `0 ≤ lo < 2^20`
> (`GRIND_LOW_BITS = 20`) and `trailing_zeros(word0) ≥ pow_bits`, where
> `hi = 0, 1, 2, …` is searched hi-major and each `hi` block scans
> `lo ∈ [0, 2^20)` in ascending order.

The parallel version (`parallel_grind`) hands out whole `hi` blocks and keeps
the smallest successful `hi`, so its result is deterministic and the same as
the sequential one. For the M31 channel, word 0 is reduced mod P before
trailing zeros are counted. The result asserts both u32 halves < P.

This is **not** "the smallest nonce over all u64". The two rules agree only
when some `lo < 2^20` succeeds with `hi = 0`. The chance of that is
`1 − (1 − 2^-b)^(2^20)`:

| Grind bits | Rules agree | Rules differ |
|---:|---:|---:|
| 16 | ≈ 100% | ≈ 0 |
| 20 | ≈ 63% | ≈ 37% |
| 24 | ≈ 6% | ≈ 94% |
| 26 | ≈ 1.5% | ≈ 98% |

When no `lo` succeeds in block 0, Rust's nonce is at least 2^32. The
all-u64 minimum then lies in `[2^20, 2^32)`.

Zig obligations:

- One CPU reference, `grindHiLo(channel, pow_bits)`, serves every lane that
  targets Rust byte parity. Device kernels search the same `(hi, lo)` blocks.
- R0 pins vectors at 16, 20, 24 and 26 bits for both the M31 and the plain
  channel. It includes seeds, chosen by the oracle, at **20 and 26 bits where
  the answer has `hi > 0`**. Those are the cases where the two rules
  disagree.

**Consequence for the existing Cairo lane (VERIFIED by reading, not by
running).** `src/prover/pcs/proof_of_work.zig` (`grind`, and its pool and
backend paths) and `src/core/channel/blake2s.zig` (`grind`) return the
smallest nonce over all u64. So stwo-zig's current Cairo proofs are valid,
and the official verifier accepts them, because it accepts any nonce that
passes. They are **not** byte-identical to Rust at the PoW nonces: the 24-bit
interaction nonce differs about 94% of the time and the 26-bit FRI nonce about
98% of the time. Each nonce is mixed into the channel, so every later draw and
proof field differs as well. Low-bit test configurations (the 16-bit
canonical_small Cairo config) agree with Rust almost always, so parity
fixtures at those settings cannot expose the difference.

Switching the existing Cairo lane to the §4.7 order changes existing Cairo
proof bytes and vectors. That is a **separate decision for the user** and is
not part of this design. The circuit lane and the M10 Stage B lane
(`Revision.proving_5a7c5ed`) use §4.7 from the start, because byte parity with
`leaf-prover` requires it. Until the user decides, the Native and Cairo lanes
keep their current grind.

---

## 5. In-circuit verifiers

### 5.1 `stark_verifier` (3,500 non-test Rust lines)

The port is one file per Rust file, with the Rust function order kept inside
each file. Guess order, in `proof_guess.zig`:

1. `trace_root`, `interaction_root`, `composition_root`;
2. `claimed_sums`, OODS, eval samples, auth paths;
3. `pow_nonce`, `interaction_pow_nonce`;
4. FRI;
5. `channel_salt`.

Verify order:

- channel replay (the draw byte lengths 37/52/40/64 fed to t0);
- `select_queries`, then `sort_queries` (QuerySorter is stable on u, and only
  the first query per tree range-checks);
- Merkle;
- OODS and `compute_fri_input` (IndexMap grouping by `(x.idx, y.idx)`);
- `check_relation_uses` (keys sorted in String order);
- the FRI decommit.

### 5.2 `circuit_verifier` and the multiverifier

- `CircuitStatement` guess order: output_digest, preprocessed_root, statement,
  proof. The 11 in-circuit circuit-AIR evaluators come from the interpreter
  (§5.4). `sample_evaluations` and `*_SAMPLE_EVAL_RESULT` are checked in R3.
- The multiverifier runs `verify` for each child, then the Blake preimage.
  `CanonicalCircuit::build` (`canonical.rs:45`) checks are ported in
  `recursion/canonical.zig`.

### 5.3 `cairo_verifier` statement

`CairoStatement::new` is ported in its original order:

- **aux data** (`serialize_aux_data`, `statement.rs` ~193): public memory ids,
  then program ids, then `AUX_DATA_FIXED_LEN + program_len + n_components`.
  The order is pinned by an oracle dump of the aux M31 vector, not guessed.
- **program data**: program felts become 28 nine-bit limbs via `split_f252`.
  The program hash is computed once per TopologyKey.
- **constants**: `LARGE_MEMORY_VALUE_ID_BASE`, `MEMORY_ADDRESS_TO_ID_SPLIT`,
  `PreProcessedColumn`/`Seq`/`MAX_SEQUENCE_LOG_SIZE` come from the projection
  header, not from the Cairo frontend.
- **enabled_bits** follow the 83-slot `all_components` order
  (`memory_id_to_big` ×16). Disabled components per variant:
  - Canonical: `pedersen_builtin_narrow_windows` plus the three
    `*_window_bits_9`;
  - CanonicalSmall: `pedersen_builtin` plus the three `*_window_bits_18`.

  All 83 slots are cross-checked against `official_claim_registry`; map §6
  had confirmed only 49.

### 5.4 Evaluators: projection plus interpreter

**Projection.** The oracle's `project-air` subcommand deserialises
`outputs/compiled_{casm,circuit}_air/compiled_jsons/**` with upstream
`air_compile::compiled_structs`, so key order is Rust's own serde and no Zig
JSON parser is involved. It keeps only the constraint path:

- node kinds: Constraint, Intermediate, LookupTerm, Const, Var, State,
  BinaryOp, UnaryOp, StaticCall, Array, ExternalState, PublicParam, Enabler;
- the metadata the generator reads: column names and order, preprocessed ids,
  sorted public params, relations, the subroutine table, the manual-component
  list, and the placement of the fixed-size check.

`remove_trailing_zeroes` is applied during export and asserted against the Rust
function. The export fails if a manual component appears in the bundle. The
output is `compiled_air_constraints_v1.bin` (INFERRED about 1–2 MB instead of
34 MB), with a header, a per-component sha256 and a provenance record. The Zig
build reads the committed file, and `zig build circuit-air-projection-check`
verifies its provenance sha256 values. Products never invoke Cargo.

**Interpreter.** `air_eval/interpreter.zig` (target about 1–1.5k lines) is
generic over `Value` and transliterates `air_code_gen/src/circuit/component.rs`
(about 455 lines), plus `eval_air_fn_constraints` (456) and `air_common` (164).
Its walk, in order:

1. unpack the inputs: limbs, enabler, states;
2. read the preprocessed/ExternalState columns, sorted by id. A function
   body that reads `Seq` calls `seq_of_component_size` once, at its top, and
   binds the result (`air_code_gen/src/circuit/component.rs:160-170`); every
   StaticCall subroutine body that reads `Seq` repeats the call, re-emitting
   its gates, with no caching across bodies (corrected in M4: an earlier draft
   said "on every read");
3. read the PublicParams, sorted;
4. walk the steps (Intermediate, Constraint, LookupTerm) with the eval! order
   of §3.3. StaticCall subroutines return a fixed-size slice from a bump
   scratch;
5. run the fixed-size eq check after `accumulate_constraints` and before
   `finalize_logup_in_pairs`.

Six components are hand-written, as in Rust's manual list: Cairo
`memory_address_to_id`, `memory_id_to_big` and `verify_bitwise_xor_12` (347
lines), and circuit `eq`, `qm_31_ops` and `verify_bitwise_xor_12`.

**Localising divergence.** The oracle's `statement-trace` runs each Rust
generated evaluator in NoValue mode with a recording hook. It prints the
ordered op list with var-relative ids. The Zig interpreter prints the same
list, so a mismatch names the exact eval! statement. Sample evaluations alone
are not enough, because a reordered gate list can still have equal values;
this is why R3 compares gate-list hashes.

Rejected alternatives:

- (a) Generating about 56k lines of Zig. That adds an emitted-text parity
  surface and costs compile time.
- (b) Using the existing EvalAtRow recorder for the **in-circuit** side. It
  loses operand order, index peepholes and constant interning.
- (c) A Zig port of air_code_gen's Rust-text emitter. It would be a second
  implementation of the same logic.

---

## 6. Leaf Cairo lane

### 6.1 What the leaf Cairo proof must be

The leaf Cairo proof is `prove_cairo::<Blake2sM31MerkleChannel>` run under the
registry's `cairo_prover_params`:

- variant canonical (production) or canonical_small (tests);
- `include_all_preprocessed_columns = true`;
- AtLeastPreprocessed lifting;
- `opt_n_id_to_big_components = 16`, salt 0;
- FRI `{pow 26, blowup 1, last 0, nq 70, fold 1}` (test registry: pow 16);
- `INTERACTION_POW_BITS = 24`.

### 6.2 Stage A (interim; unblocks R8 and R9)

- The oracle's `dump-leaf-cairo-proof` runs the `leaf-prover` code path, steps
  1–3 (`prove_leaf.rs`), on a large host. It writes the ExtendedBinary
  `CairoProof<H>` next to its `SerializedLeafProof`.
- `src/interop/circuit_recursion/cairo_proof_binary.zig` reads it. Gate:
  read → write round-trips byte-identically on
  `test_data/test_prove_verify_*/proof.bin` and
  `test_data/all_opcode_components/proof.bin`.
- The Zig leaf wrap consumes the proof. R8 parity is stated as "given an
  identical Cairo proof".

### 6.3 Stage B (the Zig Cairo prover on the M31 lane; R10; parallel track)

All changes are comptime-parameterised, and the existing Cairo-lane vectors are
the regression gate.

1. **MerkleChannel parameter.** A comptime `MerkleChannel` replaces the
   hard-wired channel at `src/frontends/cairo/prove_trace.zig:42-43`,
   `witness/resident_types.zig:20` and `proving/transcript.zig:9`. The new
   instance uses `Blake2sM31Channel`, `Blake2sPlainMerkleHasher`, and M31
   `concatAndHash` for `mix_hash`.
2. **`Revision.proving_5a7c5ed`.** `statement_bootstrap.zig:398-410` stops
   mixing `lifting orelse 0` on this lane only, and switches to the 2-felt V2
   mix with explicit heights.
3. **`LiftingSizePolicy.at_least_preprocessed`.** Both heights become
   `max(trace domain, preprocessed max)`, and the lane fails closed on any
   other policy. **This matters for our workloads.** If the largest Cairo
   component of a PIE has fewer than 2^25 rows, its trace domain is below the
   canonical preprocessed max (`MAX_SEQUENCE_LOG_SIZE = 25`). Its trace-tree
   heights are then lifted above their own max column. This is likely for
   every mainnet and SN PIE (§6.5). The oracle emits a transcript checkpoint
   after each commit, so this is verified, not assumed.
4. **`include_all_preprocessed_columns`.** `witness/resident_geometry.zig:94-140`
   stops masking to the used columns on this lane.
5. **Public-data mix** (`cairo-air/src/air.rs:143-160`, `flat_claims.rs`):
   - output and program claims are hashed with `MC::H` via `update_leaf`
     (plain Blake2s). This already exists: `statement/public_data.zig` uses
     `Blake2sPlainMerkleHasher`, with `updateLeaf` at :271;
   - only the final `MC::mix_hash` changes, to M31 `concat_and_hash`;
   - `FlatClaim::mix_into` mixes the enable-bit count, the bits, the log sizes
     and the program length as packed felts.
6. **Grinds.** On this lane only, the CPU Blake2s-M31 grinds at 24 bits
   (interaction) and 26 bits (FRI) use the §4.7 `(hi, lo < 2^20)` rule. The
   existing Cairo lane keeps its all-u64-minimum grind unless the user
   decides otherwise (§4.7). Device kernels come in M12. Until they exist,
   the device products report an explicit CPU grind stage.
7. **Parameters.** A `ProverParameters` loader for
   `registry.cairo_prover_params`; `channel_hash` is ignored, as in Rust.

The handoff to the wrap is in memory: `ExtendedStarkProof` is passed without
serialization, and the Cairo trace is dropped before the wrap starts.

### 6.4 Ordering

`leaf-wrap` accepts an in-process Zig Cairo proof only after R10c passes. Until
then it accepts ExtendedBinary input only.

### 6.5 Workload sizing (the user's question, VERIFIED)

`n_steps` below is read directly from `execution_resources.json` inside each
zip on 2026-09-29. No code was executed.

| PIE | path | n_steps | n_memory_holes |
|---|---|---:|---:|
| SN_PIE_1 | `~/Downloads/SN_PIE_1.zip` | **14,645,112** | 1,025,855 |
| SN_PIE_2 | `~/Downloads/SN_PIE_2` (zip, no extension) | **7,706,864** | 799,597 |
| SN_PIE_3 | `~/Downloads/SN_PIE_3` (zip, no extension) | **14,075,019** | 1,222,424 |
| SN_PIE_4 | `~/Downloads/SN_PIE_4` (zip, no extension) | **14,058,247** | 1,231,693 |
| mainnet leaf 15627902-15627904 | `block-data/mainnet/pies/leaves/` | **1,224,007** | 225,048 |
| mainnet leaf 15627905-15627907 | same | **785,807** | 174,804 |
| mainnet leaf 15627902-15627907 | same | **1,580,295** | 253,031 |
| aggregator agg-15627902-15627907 | `block-data/mainnet/pies/aggregator/` | **17,325** | 17 |
| aggregator 15627902-15627907 (x2 pipeline) | `block-data/mainnet/pipeline/15627902-15627907_x2/` | **18,816** | 20 |
| sepolia target10m | `~/Downloads/sepolia_near_step_target_pies_10m_to_60m/pies/` | **12,450,281** | 693,876 |
| sepolia target20m | same | **22,212,985** | 777,826 |
| sepolia target30m | same | **32,719,374** | 967,232 |
| sepolia target40m | same | **39,580,612** | 1,184,165 |
| sepolia target50m_v2 | same | **49,746,014** | 1,392,187 |
| sepolia target60m | same | **60,111,972** | 1,595,128 |

`design/starknet-proving-pipeline/README.md` §5 rounds SN_PIE_2 to "7.7M". The
mainnet leaf `15630654-15630683` has no zip yet.

**How the bucket is chosen (VERIFIED in code).** The leaf bucket is not
`log2(n_steps)`. It is the **lifted Cairo trace log size**:

- `prove_leaf.rs:138-150` reads it as
  `pcs_config.trace_lifting_log_size − log_blowup`.
- Under `AtLeastPreprocessed` (`crates/prover/src/prover.rs:131-150`), that
  lifting size is `max(max per-component log size, preprocessed max) +
  log_blowup`.
- For the canonical variant, the preprocessed max is `MAX_SEQUENCE_LOG_SIZE`
  = 25 (`crates/common/src/preprocessed_columns/preprocessed_trace.rs:20`).

So the bucket is `max(25, largest component's log row count)`. The floor is
25, and the production definitions accept 25..29
(`circuit_registry_definitions/production/definition.json`). A single
component's row count, not the total step count, decides whether a PIE leaves
the floor. The steps are split across the 83 component slots, and
`memory_id_to_big` is split across 16 components of at most 2^25 rows each.

Consequence (INFERRED; per-component sizes were not read):

- Every mainnet and SN PIE is at most 14.6M steps (< 2^24). No single
  component can plausibly reach 2^25 rows, so all of them almost certainly
  land in the **trace_log 25** floor bucket.
- For Sepolia 20M–60M, the bucket depends on the largest component. Even
  60M steps may stay at 25 if no single component exceeds 2^25 rows. This
  cannot be read off `n_steps`.
- For current mainnet and SN work, **one leaf topology plus one fold
  topology** likely covers everything, so the topology cache default is 2
  entries. The fold topology depends only on the registry config (§3.5).

---

## 7. Orchestration

### 7.1 Leaf wrap (`recursion/leaf_wrap.zig`)

This covers `prove_leaf.rs` steps 4–8. The input is the Cairo
`ExtendedStarkProof`, plus the claim, the interaction claim and the public
data.

1. Look up the `TopologyKey`.
2. Build `Context(QM31).new(8)`: the statement, then `proof.guess`, then
   verify, finalize, zk and pad.
3. Assert the registry `circuit_hash`.
4. Prove with the `.internal` channel profile.
5. Emit `SerializedLeafProof`.

The cached preprocessed tree is reused whenever the key hits.

**As built (M8).**

- The orchestration lives in the circuit CPU integration,
  `src/integrations/circuit_cpu/recursion/{leaf_wrap,topology_key,topology_cache}.zig`,
  next to M9's fold. It needs the circuit prover and the Cairo frontend's
  statement inputs, which the frontend package may not import (§2.2).
- The input is the Cairo lane's in-memory proof (§6.4; R10c passes), not an
  ExtendedBinary file: `cairo_proof_binary.zig` is still unbuilt (§2.3).
- The cache holds the preprocessed circuit, its root and its circuit hash,
  not a committed tree; the prover commits the preprocessed tree per proof
  until M11. A new entry is published only after its proof passes the
  registry check.
- The leaf key also binds the Cairo proof's FRI config: the in-circuit
  verifier's `ProofConfig`, and so the topology, depends on it.
- R8 gate 1 is green: `circuit-parity-r8` reproduces `expected_output.json`
  byte for byte.
- R8 gate 2 ran Zig-only here on the smallest mainnet leaf,
  `15627905-15627907`, run by the leaf bootloader
  (`leaf_simple_bootloader_compiled.json`) and adapted by the upstream
  adapter (`adapt-program --program-input`). It lands in the trace_log 25
  bucket, and its circuit hash and preprocessed root equal the leaf entry
  of a canonical registry that upstream `circuit-params` built for trace
  logs 25-26. The byte comparison with release `leaf-prover`, and R10d,
  stay big-host gates: upstream `leaf-prover` needs more than this host's
  36 GB on a canonical leaf.

### 7.2 Fold and tree (`recursion/{fold,tree,canonical}.zig`)

- `CanonicalCircuit` is built once per process. Rust builds the topology in
  NoValue once in `CanonicalCircuit::build` and then again in QM31 per reduce
  (`fold.rs:135`). Zig builds the QM31 Context once per reduce and takes the
  topology-derived artifacts from the cache.
- The multiverifier `circuit_hash` is checked against the registry **once**,
  when the fold key's cache entry is built. This mirrors
  `CanonicalCircuit::build` step 4 (`canonical.rs:79-95`). It is not checked
  again per reduce, because the fold key has no per-child inputs (§3.5).
- **Correction to the proposals (VERIFIED):** Rust already caches the
  multiverifier *preprocessed columns* (`canonical.preprocessed_multiverifier`,
  `base_column_pool`). What it redoes on every reduce is the twiddle
  precompute, the interpolation and the Merkle commit of the preprocessed tree
  (`circuit_prover/src/prover.rs:50-95`, `prove_circuit_assignment_with_channel`).
  Zig caches the committed tree and its coefficients per key and shares them
  between `.internal` and `.root` (§4.4).
- Tree shape: layers pair leaves left to right, an odd last entry carries up,
  N == 1 self-folds, and the last reduce is `is_root`. The root uses the
  `.root` profile. The root artifacts are `root.proof` (a felt stream, streamed
  through `felt_json.zig`), `root_outputs.json` and `root_packed.json`.
- Internal proofs stay structured in memory. A child is released as soon as the
  parent's Context has guessed it.

### 7.3 Registry

`circuit-params` reproduces the fixpoint over trace_log sizes and writes the
registry byte-identically (pretty + `\n`). The loader keeps field order and
feeds TopologyKeys and budgets.

### 7.4 CLIs (`src/products/circuit_recursion_cpu`)

- `leaf-wrap --registry R --cairo-proof P.bin [--checkpoints F] -o leaf.json`
  (as built, M8: `leaf-wrap --registry R --program P.json --prover-input
  I.json --output leaf.json`; see §7.1)
- `fold-tree --registry R --manifest leaves.json -o DIR`. The manifest format
  `{"leaves":[...]}` and the outputs match `stwo_run_and_prove_recursive_tree`.
- `circuit-params --definition D -o registry.json`
- `verify --registry R <circuit-proof>` (Zig native verifier)

All commands take `--memory-budget` (§9.3) and `--checkpoints`.

**As built (M8, M9).** One catalog product, `stwo-circuit-recursion-cpu`,
with three commands. `leaf-wrap` is as in §7.1. `fold-tree` takes
`stwo_run_and_prove_recursive_tree`'s flags (`--program_input`,
`--proof_path`, `--program_output`, `--packed_output_path`,
`--circuit_registry_json`). `circuit-params` takes
`--definition D --registry [--output-path P]`. The circuit AIR data is
embedded and authenticated. `verify`, `--memory-budget` and `--checkpoints`
are not built (errata 10).

---

## 8. Parity test ladder

### 8.1 Oracle and fixtures

`tools/stwo-circuit-oracle-rs` subcommands:

- `primitives`, `gadgets`, `components`, `statement-trace`;
- `verifier-stages`, `finalize`, `topology`;
- `project-air`, `air-programs`;
- `prove-small`, `dump-leaf-cairo-proof`, `leaf`, `fold`, `verify`.

The prebuilt binaries in `proving/target/release` (`leaf-prover`,
`circuit-params`, `stwo_run_and_prove_recursive_tree`, `stwo-run-and-prove`)
are black-box oracles for R6, R8 and R9 until the oracle covers them.

In-tree Rust goldens used:

- `leaf_prover/tests/data/{circuit_registry_canonical_small.json, expected_output.json, use_all_opcodes_and_builtins}`;
- `stwo_run_and_prove_recursive_tree/test_data/circuit_registry.json`;
- `goldens/four_leaves/{leaf.json, leaf_preimage.json, root.proof, root_outputs.json, root_packed.json}`;
- `test_data/circuit_multiverifier/{proof,proof_cairo,backward_compatibility_cairo_proof}.bin`;
- `outputs/compiled_casm_air/sample_evaluations.json` (68 goldens).

### 8.2 Rungs

Each rung is a `zig build circuit-parity-rN` step. The aggregate step is
`zig build circuit-parity`. Oracle dependency: "none" means in-tree data only.

| Rung | Content | Compared | Oracle |
|---|---|---|---|
| **R0 primitives** | ChaCha20Rng KAT (first 64 u32 × 3 seeds); `hashU32s*` + `circuit_hash.rs` expect vectors incl. `poseidon252_root`; Blake2s-M31 channel draw/mix/`mix_hash`, `<true>` and `<false>`; FriConfigV2 2-felt mix; FRI fold_step 4 with last_layer 0; `Blake2Felt252.encode_felts_to_u32s`; base64; `DigestHex`. Grind per §4.7 at 16/20/24/26 bits on the M31 and plain channels, including oracle-chosen seeds at 20 and 26 bits whose answer has `hi > 0` | vectors | `primitives` (small, local OK) |
| **R1 builder** | `circuits/src/*_test.rs`, `finalize_constants_test.rs`, `circuit_common/src/preprocessed_test.rs` `expect!` snapshots; IndexMap swapRemove/retain; QM31 vs NoValue identical gate lists | Debug text | none |
| **R2 gadgets** | `blake2s_u32s` at 0/4/44/64/65/128 B, `extract_bits`, Simd ops, U16/U32/M31 wrappers, mux, `sort_by_u_coordinate`/Permutation, `reduce_hash_value` | gate-list + values sha256, n_vars | `gadgets` |
| **R3 evaluators** | all 83 Cairo slots + 11 circuit evaluators in a fresh Context; slot order; 68 `sample_evaluations` + `*_SAMPLE_EVAL_RESULT` | gate-list sha256 per kind, values sha256, statement trace | `components`, `statement-trace` |
| **R4 verifier stages** | on `circuit_multiverifier/proof.bin` (182,884 B, LOG_BLOWUP 3): prefix hash + n_vars after each stage of §5.1 and the multiverifier preimage | prefix sha256 | `verifier-stages` |
| **R5 finalize** | after finalize_constants, guess finalization, ZK (privacy config), each padding kind | n_vars, per-kind counts, sha256 | `finalize` |
| **R6 topology** | Fold: per-column sha256 of preprocessed columns, `preprocessed_root` and `circuit_hash` of the multiverifier (+45-column layout, `circuit_multiverifier/src/test_utils.rs`). Leaf: the same for the canonical_small leaf (trace_log 20), built with the **Cairo preprocessed root** as a constant. That root is committed at `trace_log_size + log_blowup` under `Blake2sM31MerkleChannel` (`circuit_params/src/lib.rs:74-85`) and consumed as a committed fixture, together with `get_preprocessed_root` canonical_small 21/22/23. Production/privacy registries | digests, registry bytes | fold: none for test configs. Leaf: Cairo-root fixtures from the oracle `topology` subcommand (canonical_small, local OK) until R10b produces them in Zig. Production: `circuit-params` binary (big host) |
| **R7 circuit proofs** | `circuit_prover/src/prover_test.rs` contexts (fibonacci, permutation, blake, …): transcript digest after each of the 8 steps, per-component base and interaction column sha256, claimed sums, all roots, FRI layer roots, CircuitSerialize bytes, `ProofInfo::total_bytes()` == length; three `.bin` round trips; ABI byte-compare (§4.2) | bytes | `prove-small`, `air-programs` |
| **R8 leaf wrap** | Stage A: oracle-dumped Cairo proof of `use_all_opcodes_and_builtins` → `expected_output.json` bytes. Then a production-bucket leaf, mainnet `15627902-15627907` (1,580,295 steps, trace_log 25), against release `leaf-prover` | raw bytes | `dump-leaf-cairo-proof` (big host) |
| **R8b leaf into tree** | the leaf simple bootloader's `simple_output` `[11, 13, 17]` execution (adapted by the oracle) → Zig Cairo proof → Zig wrap under the recursive-tree registry == `four_leaves/leaf.json`; four Zig leaves → root goldens (errata 11) | raw bytes | `adapt-program` |
| **R9 fold tree** | `four_leaves` goldens as raw bytes; N = 1, 2, 3, 5 shapes from the release fold binary; per-internal-node CircuitSerialize sha256 | raw bytes | release binary (big host) |
| **R10 Zig Cairo leaf** | R10a M31 channel/grind vectors; R10b canonical_small preprocessed roots at log blowup 1/2/3 (heights 21/22/23, errata 7); R10c `use_all_opcodes_and_builtins`, `all_opcodes`, `all_builtins` Binary bytes and canonical ExtendedBinary bytes (errata 7); R10d SN_PIE_2 (7,706,864 steps) → Zig Cairo proof → Zig wrap == release `leaf-prover` | raw bytes | `dump-leaf-cairo-proof` (big host) |
| **R11 acceptance, tamper** | Rust `circuit_verifier` accepts Zig leaf/fold proofs; Zig `verify_native` accepts Rust proofs; root felt stream accepted by Cairo `stwo_circuit_verifier`; flip each of output digest, preprocessed root, circuit hash, claimed sum, nonce, salt, one FRI witness → both verifiers reject for the intended reason. Built locally (errata 11): Zig `verify_circuit` and oracle `verify-circuit` on upstream's multiverifier proof, the golden leaf and a Zig R7 proof, untouched and with eight tamperings; the Cairo-verifier half is open | accept/reject | `verify-circuit` |

The judges asked that R1 and R6 not wait on the oracle. **Only R1 meets
that.** It needs only in-tree `expect!` snapshots, so it starts alongside M0.

R6 cannot start alongside M0:

- **Leaf.** The leaf circuit interns the Cairo preprocessed root as a
  constant (`cairo_verifier/src/statement.rs:644`). Its constant set, and so
  its `finalize_constants` gates, preprocessed columns and `circuit_hash`,
  depend on that root's value. (`circuit_params`'s `DUMMY_PREPROCESSED_ROOT`
  is valid only for component *sizes*.) The root is a Merkle commitment of
  the whole Cairo preprocessed trace at `trace_log_size + log_blowup`. So leaf
  R6 consumes committed Cairo-root fixtures and needs the Cairo verifier
  evaluators to build the circuit: it depends on **M4** (via M6).
- **Fold.** Fold R6 depends on M5.

### 8.3 Running under the 36 GB constraint (this host is in swap)

- **Local (this host):**
  - R0–R6 run here. They build circuits but prove nothing. The largest is the
    canonical_small leaf topology in NoValue mode (INFERRED at a few GB with
    u32 gates and pad runs).
  - R7 small contexts run here.
  - R9 is a byte check of committed goldens, marked as a labelled large test.
- **Local procedure:**
  1. Check swap and AC power first (memory notes).
  2. Run each rung as a single process under `/usr/bin/time -l`.
  3. The step aborts if its peak RSS exceeds its declared budget
     (`--memory-budget`, default 8 GiB for R0–R7).
  4. Use `zig build -j1` for the parity steps.
  5. Never run a Rust prover or oracle here.
- **Big host:**
  - every oracle `prove-small`, `leaf`, `fold` and `dump-leaf-cairo-proof`
    run;
  - the production and privacy `circuit-params` runs;
  - R8 production, R10d and all benchmarks.

  Outputs are committed under `vectors/circuit/rN/` with provenance. Blobs over
  the CONTRIBUTING large-fixture limit go to a documented external store with
  sha256 values in-tree.
- **CI:**
  - R0–R7 run everywhere;
  - R8 and R9 replay committed fixtures;
  - R10 and R11 run on the big-host lane.

  Every performance PR runs `circuit-parity` up to the highest rung its code
  touches. The heavy oracle re-runs only on an upgrade, per
  `conformance/upstream.md` §Upgrade Policy.

---

## 9. Performance and memory plan

Every number below is a hypothesis until measured with the CONTRIBUTING
acceptance template. That template requires:

- the same host, on AC power;
- every measured proof verified by Rust, with byte-equal outputs;
- cold (topology build), warm (cached topology) and service (sustained N-leaf
  tree) timings reported separately, each with peak RSS.

A cross-backend verify ratio far from 1x is treated as a measurement fault.

### 9.1 Cost model (write it before optimising)

**Status: based on the test registry and unmeasured.** The shapes below come
from the canonical_small `pad_to_component_log_sizes`: eq 20, qm31_ops 23,
m31_to_u32 21, triple_xor 20, blake_g_gate 23. This is not a guess about
production. Those values equal the `component_log_sizes` of the committed
privacy registry (`crates/privacy_circuit_verify/large_proofs_circuit_registry.json`,
leaves 25..29). The upstream test
`test_cairo_verifier_consts_match_production_registry`
(`crates/circuit_params/tests/cairo_consts_test.rs:239-266`) asserts that they
equal the production shared target. It also asserts that canonical_small's
circuit FRI config equals production's: pow 26, blowup 1, 70 queries,
fold_step 4. The privacy config differs, with blowup 2 and 35 queries. That
test was not run here.

Everything in this section is a test-registry projection until M7 measures
it on production-shaped circuits: the column counts, the cell totals and the
time split. Production cannot be regenerated on this host (§8.3).

**Base trace size** (INFERRED, canonical_small targets = asserted production
target):

| Component | Columns × rows | M31 cells |
|---|---|---:|
| blake_g_gate | 52 × 2^23 | ≈ 436M |
| qm31_ops | 12 × 2^23 | ≈ 101M |
| triple_xor, m31_to_u32, eq | smaller | the rest |
| **Total** | | **≈ 570M (≈ 2.3 GB of evaluations)** |

The interaction trace roughly doubles this.

**Where the time goes** (INFERRED). Time is dominated by interpolation and
LDE, Merkle Blake2s, quotients and FRI over those columns. A rough split is
witness 15%, LDE 30%, Merkle 35% and composition/FRI 20%. The builder is a
minority share.

Grinding is a separate line item. Every circuit proof runs a 20-bit
interaction grind and a **26-bit FRI grind**: about 2^26 expected Blake2s
compressions, all on the critical path. The root grinds on the plain
`Blake2sChannel`, and every other proof grinds on the M31 channel. M7 reports
grind time separately.

**The first measurement of M7** is the builder's share of leaf and fold wall
time. That number decides whether M13 (the tape) is worth doing at all.

### 9.2 Wins, ordered by expected value per unit of parity risk

1. **Per-key cache.** The committed preprocessed tree, its coefficients and
   the circuit hash are cached per key. The fixed tables are committed once per
   process, and one tree serves both the internal and the root channel. This
   removes Rust's per-reduce twiddle precompute, interpolation and commit
   (§7.2). No byte risk; R9 guards it.
2. **Witness.**
   - Generic gather witnesses.
   - Direct-index xor lookups instead of about 16 HashMap lookups per blake_g
     row.
   - Per-worker histograms instead of atomics.
   - No `LookupData`; batch inversion per tile.
   - `@Vector(16,u32)` blake_g.
   - Target: witness at least 3x faster than Rust.
3. **Composition.** The existing tuned AOT C kernels, generated from the
   recorded bundle.
4. **Streaming.** Per component, witness → interpolate → LDE → Merkle leaf
   hashing through `streaming_committer.zig` and `blake2_stream4`. Column tiles
   stay in L2 between stages.
5. **Builder.**
   - u32 SoA gates, the blake_g `out_base` form and pad runs.
   - Arena allocation pre-sized from the targets; audit-only bookkeeping.
   - Merkle and FRI in-circuit Blake hashing on 4-way SIMD.
   - Batch inverses in `compute_fri_input` and logup.
6. **Scheduling.** Leaves and sibling folds are independent. Run K reduces
   concurrently, with K derived from the static budget (§9.3), and never
   oversubscribe the worker pools or GPU queues. Stream `root.proof` directly
   instead of going `Vec<Felt>` → `Vec<String>` → bytes.
7. **GPU (M12).** Resident circuit prover, and grind kernels for the §4.7
   `(hi, lo < 2^20)` rule. For circuits these are M31 kernels for leaves and
   internal folds and plain Blake2s for the root, each at 20 bits
   (interaction) and 26 bits (FRI). For the Stage B Cairo lane they are M31
   kernels at 24 and 26 bits. Plus gather and blake_g kernels. The 26-bit
   grinds are the reason for the grind kernels.
8. **Optional tape (M13).** Merged only if the §9.1 measurement shows the
   builder above 10% of proof time.

### 9.3 Memory

- **Static budget.** `StaticBudget.fromRegistry(config)` computes the exact
  peak of build, witness, commit and FRI from the targets before any work
  starts. The shape is fixed per registry. Work that exceeds the configured
  budget is rejected with a report and is never swapped into. This uses
  `host_budget_allocator.zig` and `file_backed_allocator.zig`.
- **Builder.**
  - Gates are 12 B (28 B for blake_g) against Rust's 24 B (80 B), and padding
    is O(1) per run.
  - The QM31 value vector (16 B/var) lives in a per-proof arena. It is freed
    right after the base-trace gathers, since everything later needs only
    columns.
- **Two trace-residency policies with identical bytes.** R7–R9 are asserted
  under both.
  - (a) *resident*: keep coefficients and LDE, and drop evaluations after
    interpolation.
  - (b) *low-memory*: keep coefficients for **all** trees (preprocessed, trace,
    interaction, composition), because quotients and FRI need them. The LDE is
    recomputed per tile for quotients and decommitment through the existing
    `coefficient_storage`, `pcs_quotient_tiles` and barycentric code. Merkle
    keeps its upper layers, and the queried leaves and paths for the 70 queries
    are recomputed from tiles.

  This fixes the maximum-reuse proposal's plan, which kept coefficients only for
  the preprocessed tree and so could not produce a proof.
- **Cache.** A byte-bounded LRU with observable hit, miss and eviction counts
  (default 2 keys, §6.5). Entries are published transactionally, so a failed
  proof leaves no entry.
- **Tree.** At most one in-flight layer per slot, and at most two children
  plus one parent live per fold slot. Children are freed once they have been
  guessed into the parent's Context.
- **Leaf.** The Cairo trace is dropped before the wrap. The about 300 MB
  ProverInput stays in the worker and never goes to disk (README §5).

### 9.4 Targets (hypotheses)

- CPU SIMD, same host as Rust:
  - leaf wrap ≥ 2x faster;
  - warm fold ≥ 2.5x faster;
  - peak RSS ≤ 0.5x (resident) and ≤ 0.25x (low-memory).
- Metal and CUDA: 5–10x over Rust CPU.
- H100: a fold under 1 s. StarkWare quotes a leaf wrap of about 3 s on a
  laptop.
- A 160-leaf tree's recursion stage in under 10 GPU-minutes.

---

## 10. Milestones

Each milestone runs in its own worktree, owned by one agent. Each ends at a
named rung and touches the files listed. "Deps" are hard prerequisites; the
work can be started earlier against committed fixtures.

| M | Name | Scope (files) | Exit criteria | Deps | Est. |
|---|---|---|---|---|---|
| **M0** | Oracle, lane pin, in-tree fixtures | `tools/stwo-circuit-oracle-rs` (primitives, gadgets, components, statement-trace, verifier-stages, finalize, topology, project-air, air-programs); `tools/stwo-eval-program-abi`; `conformance/upstream.md`, `tooling-surface-v1.json`, `scripts/check_upstream_pins.py`; `vectors/circuit/` layout; import of in-tree goldens | Oracle builds from its lockfile on the big host; R0–R6 checkpoint JSONs (including §4.7 grind vectors with `hi > 0` and the canonical_small Cairo preprocessed-root fixtures for leaf R6) and the projection and air_programs bundle committed with provenance; `zig build upstream-pins` green; ABI byte-compare green | — | 2 wk |
| **M1** | Core revision and shared primitives | `src/core/protocol_revision.zig`, `pcs/config_v2.zig`, explicit heights in `vcs_lifted` (verifier and prover), `hashU32s*`, `chacha20_rng.zig`, `qm31_pointwise.zig`; move `BLAKE_SIGMA`, seq/xor formulas and `felt_json.zig` down with re-exports; `channel_profile.zig` | R0 green; every existing Native and Cairo vector byte-identical (`zig build vectors`, interop, prove-checkpoints) | — (parallel to M0) | 1.5 wk |
| **M2** | Builder | `src/frontends/circuit/builder/*`, package skeleton, contract, lint | R1 text-identical (starts without oracle); R2 matches oracle; QM31 ≡ NoValue gate lists | M1 | 2.5 wk |
| **M3** | Interop formats | `src/interop/circuit_recursion/*` | three multiverifier `.bin` round-trip; `four_leaves/root.proof` parse → re-emit byte-identical; registry re-emit byte-identical; Cairo ExtendedBinary round trip on all `test_data` proofs | M1 | 1.5 wk |
| **M4** | Projection reader and interpreter | `air_eval/*`, the 6 manual components, component tables, slot-order test root | R3 green: all 83 + 11 evaluator gate-list and value hashes, statement traces, 68 sample evaluations | M0 (projection), M2 | 3 wk |
| **M5** | In-circuit verifier and fold topology | `stark_verifier/*`, `statements/{circuit_statement,multiverifier}.zig`, `common/*` | R4 and R5 green; R6 fold registry root and hash plus 45-column layout | M2, M3, M4 | 4 wk |
| **M6** | Cairo statement and leaf topology | `statements/cairo_statement.zig`, `cairo_public_data.zig`, variants, enabled_bits | R6 leaf, from committed Cairo-root fixtures (M0): canonical_small trace_log 20, `get_preprocessed_root` 21/22/23; all 83 slots confirmed; then, on the big host, production and privacy registries against big-host fixtures (errata 9) | M0 (Cairo-root fixtures), M4, M5 | 3 wk |
| **M7** | Circuit prover (scalar and SIMD CPU) | `air/*`, `witness/*`, `proving/*`, generalised composition AOT step, `src/integrations/circuit_cpu` | R7 green, including interaction-column hashes; both grinds (20-bit interaction, 26-bit FRI) per §4.7 on the `.internal` (M31) and `.root` (plain) profiles; multiverifier `proof.bin` reproduced exactly; Rust verifier accepts Zig proofs; builder-share and grind-time measurements recorded | M0 (bundle), M1, M3, M5 | 4–5 wk |
| **M8** | Leaf wrap (Stage A) | `recursion/leaf_wrap.zig`, `topology_key.zig`, `topology_cache.zig`, product `leaf-wrap` | R8 both gates (expected_output.json; mainnet 1,580,295-step bucket-25 leaf); then, on the big host, R10d (Zig Cairo proof of SN_PIE_2 wrapped by Zig == release `leaf-prover`, errata 8) | M6, M7 (R10d also M10) | 1.5 wk |
| **M9** | Fold tree and root | `recursion/{fold,tree,canonical}.zig`, product `fold-tree`, `circuit-params` | R9 raw bytes on four_leaves and N = 1, 2, 3, 5 (Rust-produced leaf fixtures, test registry); registry generation byte-identical for the test definitions (errata 10). Parity-complete for Stage A. Then, as a later gate on the big-host lane, R11 acceptance/tamper (§8.2), which needs Zig `verify_native` (errata 10) | M7, M8 | 2 wk |
| **M10** | Zig Cairo leaf lane (Stage B) | `src/frontends/cairo` channel/revision parameterisation, include-all, AtLeastPreprocessed, public-data mix, params loader, CPU M31 grind | R10a–R10c; Cairo-lane vectors unchanged except the §4.7 PoW order (R10d is a big-host gate after M8, errata 8) | M1 (parallel to M2–M9) | 4–6 wk |
| **M11** | CPU performance | caches, streaming commit, low-memory policy, scheduler, static budget | ladder still green after every change; the §9.4 CPU targets measured, pass or fail reported honestly | M9 | 3–4 wk |
| **M12** | Metal, then CUDA | `src/integrations/circuit_{metal,cuda}`, §4.7 grind kernels (M31 and plain Blake2s; 20 and 26 bits, plus 24 for Stage B), gather and blake_g kernels | R7–R9 on device byte-equal to CPU scalar; fail-closed capability checks | M11 | 4–6 wk |
| **M13** | (optional) topology tape | record the NoValue build per key as an op stream; fill values from the shared `guess` traversal | only if builder share > 10%. Merge gates: two different proofs per key give identical tape digests; tape values equal value-mode Context values on every R8/R9 fixture; `-Dcircuit-audit` re-runs value mode | M9, M11 | 2 wk |

Critical path: M1 → M2 → M4 → M5 → M7 → M8 → M9, about 19 weeks. M0 runs
alongside M1–M2. M3 and M10 run off the critical path.

---

## 11. Risks, mitigations, open questions

### 11.1 Judges' fatal flaws, and how this design resolves them

| Flaw | Resolution |
|---|---|
| Tape as the production value path (performance-first and maximum-reuse proposals) | Value-mode Context is production; the tape is M13, gated on measurement and audit (§10) |
| Prover-side codegen or projection lowering adds a second emitter (all three proposals) | Record the Rust FrameworkEvals into `air_programs_v1` (§4.2) |
| `#[path]` sharing across two pins | Pin-free ABI crate, a per-pin recorder, and an ABI byte-compare gate (§2.4, §4.2) |
| Cairo interaction descriptors reused without a gate | Per-component interaction-column sha256 in R7 |
| Frontend→frontend edge vs. duplicated formulas | Move the shared formulas and `felt_json` down (core, interop); no `stwo_cairo_frontend` dependency; slot-order check in a test-only root (§2.2) |
| blake_g `out_base` unverified | VERIFIED at `blake.rs:407-410`, plus a debug/audit assert (§3.1) |
| One preprocessed tree for both root and internal channels unverified | VERIFIED same `H` (§4.4) |
| Memory plan without trace coefficients | Low-memory policy keeps coefficients for all trees (§9.3) |
| Oracle blocks all Zig work | R1 needs no oracle; M1 and M2 start in parallel with M0. R6 needs no *proving*, but leaf R6 needs committed Cairo-root fixtures and M4, and fold R6 needs M5 (§8.2) |
| Unmeasured speedups | Framed as hypotheses; builder-share measured in M7 (§9.1) |

### 11.2 Risks

1. **Transcript and PCS revision mismatch (blocking).** Mitigation: M1 first,
   with comptime revision instances; the existing vectors are the gate.
2. **Call-order drift in about 17.8k hand-written lines.** Mitigation:
   - a file-per-Rust-file port;
   - R2–R5 prefix hashes with first-differing-gate Debug diffs;
   - statement traces;
   - a single `guess` traversal.
3. **Interpreter semantics.** The risk points are `remove_trailing_zeroes`,
   sorted reads, Seq re-unpacking, fixed-size-check placement and StaticCall
   argument order. Mitigation: R3 per-evaluator gate hashes over all 94
   evaluators before any full circuit exists.
4. **Post-finalize constants and the value-dependent finalize count.**
   Mitigation: the real Context API, R5 sub-stage counts, and the key includes
   the Cairo root and program hash.
5. **Stale topology cache.** Mitigation: a content-addressed key and a
   mandatory registry `circuit_hash` assert.
6. **Hasher and channel mispairing.** Mitigation: `CircuitChannelProfile` and
   R0 vectors for both instances.
7. **Grind order.** A nonce chosen by any rule other than §4.7 verifies but
   breaks parity. The all-u64 minimum is such a rule, and it is what the
   stwo-zig grinds return today. It differs from Rust in about 98% of 26-bit
   grinds. Mitigation: one §4.7 CPU reference; device kernels searching the
   same `(hi, lo)` blocks; R0 at every bit count, including `hi > 0` seeds. The
   existing Cairo lane's divergence is recorded in §4.7, and changing it is a
   user decision.
8. **AtLeastPreprocessed lifting for small leaves.** All our PIEs are below
   the preprocessed max, so heights are lifted. Mitigation: explicit heights
   and oracle transcript checkpoints after each commit (R10).
9. **ChaCha20Rng block buffering.** Mitigation: an R0 KAT before any ZK work.
10. **ExtendedBinary decoding.** Mitigation: the round-trip gate before the
    wrap consumes a proof.
11. **Oracle and host limits.** Mitigation: heavy runs on a big host,
    fixtures with provenance, and the prebuilt release binaries as interim
    oracles.
12. **Upstream drift.** `proving/` vendors its dependencies without git pins,
    and 5a7c5ed deleted the canonical preprocessed-root tests. Mitigation: one
    monorepo pin, and upgrades follow the upstream.md Upgrade Policy with full
    fixture regeneration.
13. **Performance PRs that reorder work.** Mitigation: only exact, order-free
    reductions; the ladder is mandatory in CI; no silent fallback.
14. **In-flight local edits** (`template_binding.zig`, `witness/eval_program.zig`).
    Mitigation: this design never imports them. M10's Cairo changes are
    additive and rebase onto that work after it lands.

### 11.3 Open questions

1. What exactly is the leaf's trace_log bucket for SN_PIE_1 (14.6M steps)?
   It is `max(25, largest component's log row count)` (§6.5), and §6.5 infers
   the floor of 25. This can be confirmed cheaply from the per-component
   `claim.log_sizes()` of a Cairo witness run. A full `leaf-prover` run on the
   big host also confirms it.
2. Is the eval-program ABI truly pin-independent, or do `82f2125` and
   `5a7c5ed` EvalAtRow differ in `finalize_logup_in_pairs` or
   `add_to_relation` batching? M0's byte-compare answers this. If they differ,
   the circuit bundle gets its own ABI version.
3. **Partly closed.** The production and privacy registry *definitions* are
   checked in (`circuit_registry_definitions/{production,privacy_large_proofs}`;
   `definition.json` has `min_trace_log_size` 25 and `max_trace_log_size` 29).
   The committed privacy registry's targets are {eq 20, qm31_ops 23,
   m31_to_u32 21, triple_xor 20, blake_g_gate 23}. They equal the
   canonical_small `pad_to_component_log_sizes`, and an upstream test asserts
   those equal the production shared target (§9.1). What remains open:
   - a **production registry JSON** (with leaf/multiverifier roots and
     circuit hashes) is not checked in. Generating it needs `circuit-params`
     on the production definition, which is a big-host run (>36 GB). It must
     not be run on this host;
   - memory budgets and the cost model stay test-registry based until they
     are measured on production-shaped circuits (M7/M11).
4. Does the `four_leaves` golden depend on the ZK path? Leaf ZK is off in
   production (`add_zk_blinding = false`). Confirm by reading
   `goldens/four_leaves` provenance before R9.
5. **Closed (VERIFIED).** The multiverifier child `ProofConfig` is fully
   determined by the registry. `CanonicalCircuit::build` derives the
   `SharedConfig` (PCS config, `ProofConfig` and preprocessed layout) from the
   registry's target sizes and circuit `FriConfig` alone
   (`canonical.rs:45-105`). Children contribute only guessed values
   (`verify.rs:66-109`). The fold TopologyKey is therefore registry config
   only (§3.5).
6. Should the root `felt_json` writer stream to an atomic file
   (`src/interop/atomic_file.zig`) or to stdout-compatible output? This is a
   product decision and does not affect bytes.
