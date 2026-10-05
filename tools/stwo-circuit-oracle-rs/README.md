# Stwo Circuit Recursion Oracle

This isolated development tool runs StarkWare's circuit recursion crates from
`https://github.com/starkware-libs/proving` at
`5a7c5ede4299c91a61df19a07cba4f7502c14230` and emits the checkpoints the Zig
port's parity ladder compares against (design:
`design/starknet-proving-pipeline/recursion/02-design.md` §8). Released Zig
products never build, invoke, or distribute it.

Every subcommand but `fold-tree` runs in seconds. Most only build circuits or hash data;
`prove-small` and `prove-profiles` prove small circuits, `prove-cairo` proves a small Cairo
program (about 2 GB for the committed all_opcodes and all_builtins fixtures;
larger programs belong on a big host), and `topology` and `verifier-stages`
build multi-million-gate circuits and commit preprocessed traces. Measured peak
resident memory on the 36 GB development host: `topology` 7.1 GB,
`verifier-stages` 3.9 GB, `prove-small` 2.9 GB, the rest under 100 MB. Run the
heavy ones under the host's heavy-command wrapper; `topology` is close to an
8 GB per-process budget, so do not run it beside another multi-GB process.
`fold-tree` proves fifteen 2^23-row multiverifiers with upstream's recursive
tree (6 minutes and 22.7 GB peak on an Apple M4 Max): run it alone, on the
recursive-tree test registry only.

| Subcommand | Rung | Content |
|---|---|---|
| `primitives` | R0 | Blake2s and Blake2s-M31 channel transcripts (mix orders, `mix_hash`, `FriConfig::mix_into`); minimum-nonce grinds at 16/20/24/26 bits, including `hi > 0` nonces; M31 and QM31 operations; `hash_u32s*`, `reduce_to_m31`, host and in-circuit circuit hashes; the ChaCha20Rng KAT; felt252 word encoding; leaf wire JSON; base64; FRI folding with `fold_step = 4` |
| `gadgets` | R1, R2 | Builder circuits (context, peepholes, constants, wrappers) and gadgets (Blake2s at 0/4/44/64/65/128 bytes, `extract_bits`, Simd, mux, `sort_by_u` permutation, `reduce_hash_value`, circuit hash) before and after `finalize` |
| `components` | R3 | All 83 Cairo slots and 11 circuit components, each built in a fresh `Context` through the upstream test harness |
| `statement-trace` | R3 | The same evaluators in topology mode, gate digests per harness stage and kind with evaluator-relative variables, in 128-gate windows |
| `project-air` | R3 | The constraints-only projection of the compiled AIR read by the Zig interpreter |
| `verifier-stages` | R4 | The multiverifier over `test_data/circuit_multiverifier/{proof,proof_cairo}.bin`, summarized after every stage of `build_multiverifier_circuit` and `stark_verifier::verify` |
| `finalize` | R5 | The `prover_test.rs` circuits after `finalize_constants`, guess finalization, each padding kind, and ZK blinding |
| `topology` | R6 | Both checked-in registries' multiverifiers rebuilt (layout, per-column digests, preprocessed root, circuit hash); the canonical_small Cairo preprocessed roots at log blowups 1-3 |
| `fold-tree` | R9 | Upstream `stwo_run_and_prove_recursive_tree` over 1, 2, 3, 4 and 5 copies of `test_data/goldens/four_leaves/leaf.json` under the recursive-tree test registry; the four-leaf tree must equal the committed goldens byte for byte, and each tree's `root_outputs.json` and `root_packed.json` are recorded verbatim, its `root.proof` by length and SHA-256, with its layer and reduction counts |
| `prove-small` | R7 | Proofs of the `prover_test.rs` circuits, mirrored step by step: transcript digests, per-column digests, claimed sums, roots, FRI layer roots, nonces |
| `prove-profiles` | R7 | `fibonacci` and `blake_g_gate` under the circuit FRI config (26 PoW bits, blowup 1, 70 queries, fold step 4) on both channel profiles (`Blake2sM31MerkleChannel`, `Blake2sMerkleChannel`), with the `prove-small` records and the verdict of upstream's native `stwo_verify` on each proof: both grinds in `SimdBackend` order, most nonces with `hi > 0` |
| `multiverifier-inputs` | R7 | The multiverifier `test_data/circuit_multiverifier/proof.bin` proves (two copies of `proof_cairo.bin`, padded to the privacy targets), written as the circuit prover's inputs (`--inputs-output`, `STWZCIRC/1`: gate lists and value table, 179 MB, outside the tree); the checkpoint pins that file, the circuit digests, the preprocessed root and `proof.bin` |
| `verify-circuit` | R7 | Upstream `verify_circuit` on CircuitSerialize bytes (`--proof`) under a request (`--request`: PCS config, preprocessed layout, preprocessed root, output digest); the verdict is a result, and a rejection is recorded, not raised |
| `cairo-statement` | R6 | `CairoStatement` host facts: constants, leaf `enabled_bits`, ordered preprocessed ids, the leaf test program's limbs and hash, a synthetic `FlatClaim`'s aux data and mix digests on both channels, and the leaf `ProofConfig` and proof size |
| `air-programs` | R7 | The circuit AIR's 11 `FrameworkEval`s recorded into the `STWZEVA/1` bundle with the shared recorder of `tools/stwo-eval-program-abi` |
| `prove-lifted-example` | R10 lift | Upstream's wide-Fibonacci prover test (`crates/examples`) with the trace tree committed 0, 1 and 3 levels above its columns, verified; `bincode(StarkProof)` digests and per-stage values |
| `adapt-program` | R10c, R8 | The leaf prover's Cairo VM run and adapter (`prove_leaf.rs` steps 1-2) on a compiled program from the `proving` checkout, with its optional `--program-input` (`leaf-prover --program_input`, for example the leaf bootloader's task list), emitted as `ProverInput` JSON; `--public-output PATH` also records the ordered output-builtin felts without rereading the large adapted input |
| `validate-applicative-input` | handoff | Parse a staged circuit-applicative bootloader input with the pinned Rust runner type; load its aggregator PIE and Cairo 1 verifier task and count packed leaves. This validates the input shape, not the Cairo applicative proof. |
| `prove-cairo` | R10c | `prove_cairo::<Blake2sM31MerkleChannel>` of an adapted `ProverInput` under a registry's `cairo_prover_params` (the leaf prover's Cairo proof; `--lifting-size-policy` overrides the policy), verified with `verify_cairo_ex`; proof byte digests and per-stage values, and optionally the canonical `ExtendedBinary` payload (`--proof-output`) |

`verify_cairo_cuda_json PROOF.json --receipt VERDICT.json` verifies a pinned
Rust-profile Cairo proof and writes a machine-readable receipt containing the
raw JSON and canonical binary proof digests, 70/26 security settings, program
commitment, and public output. The receipt is published only after
`verify_cairo_ex::<Blake2sM31MerkleChannel>` accepts the proof. The same binary
continues to accept its previous optional expected canonical binary digest.

```sh
cd tools/stwo-circuit-oracle-rs
cargo run --release --locked -- primitives --output /tmp/primitives.json
cargo run --release --locked -- components \
  --proving-root ~/.cargo/git/checkouts/proving-<hash>/5a7c5ed \
  --output /tmp/components.json
```

Run Cargo from this directory so `rust-toolchain.toml` selects
`nightly-2026-01-15`. `components`, `statement-trace`, `project-air`,
`verifier-stages`, `topology`, `cairo-statement` and `fold-tree` read data files from a `proving` checkout and
refuse any checkout whose inputs differ from the pinned revision's
(`src/upstream.rs` and each subcommand's pinned aggregate digest). `prove-small`
takes `--memory-budget BYTES` (default 4 GiB) and refuses a circuit whose
estimated prover peak exceeds it; the multiverifier `proof.bin` circuit (trace
log size 21, log blowup 3) is far over that budget. The oracle does not prove it:
`multiverifier-inputs` writes its inputs, and the Zig circuit prover must
reproduce the committed `proof.bin` from them (1 s, 4.1 GB peak for the
oracle). `verify-circuit` checks proofs written by the Zig prover
(`STWO_CIRCUIT_R7_EMIT_DIR`); `scripts/generate_circuit_oracle_vectors.py
--zig-emit-dir DIR` regenerates the committed verdicts from such a directory
and otherwise keeps them.

The oracle compiles in `../stwo-eval-program-abi/src/lib.rs` with `#[path]`: the
evaluation-program recorder and bundle encoder it shares with
`tools/stwo-cairo-air-compiler`. At the start of `air-programs` (and of every
compiler run) both tools encode the same fixture program and require the bytes
committed in `abi_fixture.rs`, across their two Stwo pins. It likewise compiles in
`../stwo-trace-digest/src/lib.rs`, the per-column and chained per-component
trace digests it shares with `tools/stwo-cairo-trace-oracle` (`src/columns.rs`
only adds the circuit domains). Outputs are written atomically and never replace
an existing file. The committed fixtures are regenerated only through
`python3 scripts/generate_circuit_oracle_vectors.py`, which locates the checkout
Cargo resolved and records provenance; `vectors/circuit/README.md` describes the
fixtures and their contracts.

## Self-checks

The oracle aborts instead of emitting a checkpoint when:

- a re-derived upstream golden differs: the `hasher_test.rs` vectors, the
  `circuit_hash_test.rs` golden, the `poseidon252_root` expectation, and the
  `circuit_hash` of all four checked-in registry entries recomputed from their
  `preprocessed_root`;
- a grind nonce fails `verify_pow_nonce`, or, up to 20 bits, a smaller candidate
  of the `(hi, lo < 2^20)` form also verifies;
- a builder circuit differs between `QM31` and `NoValue` builds, is unsatisfied
  after `finalize`, or yields a variable other than exactly once;
- a gadget output differs from the host computation (Blake2s, `reduce_to_m31`);
- a generated evaluator's result differs from its sample evaluation, or its
  topology-mode build differs from its value-mode build;
- a mirrored upstream function (`stark_verifier::verify` and
  `build_multiverifier_circuit` in R4, `prove_circuit_with_precompute` in R7)
  differs from the upstream call, or a rebuilt registry multiverifier, the
  multiverifier test circuit, a `prover_test.rs` circuit or a canonical_small
  Cairo root differs from its upstream constant;
- a recorded component fails the semantic differential, a proof-dependent
  constant cannot be classified, or the ABI fixture bytes drift.

## Pins

The manifest has no path dependencies, patches or replacements. Every upstream
crate is a git dependency on the pinned revision, and `Cargo.lock` was seeded
from the upstream workspace lock, so every registry package has the version and
checksum `proving@5a7c5ed` itself locks. `scripts/check_upstream_pins.py`
validates the manifest, lock, toolchain, source constants, and the committed
fixtures against the Circuit Recursion Lane of `conformance/upstream.md`.
