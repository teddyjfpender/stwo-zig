# Stwo Circuit Recursion Oracle

This isolated development tool runs StarkWare's circuit recursion crates from
`https://github.com/starkware-libs/proving` at
`5a7c5ede4299c91a61df19a07cba4f7502c14230` and emits the checkpoints the Zig
port's parity ladder compares against (design:
`design/starknet-proving-pipeline/recursion/02-design.md` §8). Released Zig
products never build, invoke, or distribute it.

Every subcommand runs in seconds. Most only build circuits or hash data;
`prove-small` proves six small circuits, and `topology` and `verifier-stages`
build multi-million-gate circuits and commit preprocessed traces. Measured peak
resident memory on the 36 GB development host: `topology` 6.7 GB,
`verifier-stages` 3.9 GB, `prove-small` 2.9 GB, the rest under 100 MB. Run the
heavy three under the host's heavy-command wrapper.

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
| `prove-small` | R7 | Proofs of the `prover_test.rs` circuits, mirrored step by step: transcript digests, per-column digests, claimed sums, roots, FRI layer roots, nonces |
| `cairo-statement` | R6 | `CairoStatement` host facts: constants, leaf `enabled_bits`, ordered preprocessed ids, the leaf test program's limbs and hash, a synthetic `FlatClaim`'s aux data and mix digests on both channels, and the leaf `ProofConfig` and proof size |
| `air-programs` | R7 | The circuit AIR's 11 `FrameworkEval`s recorded into the `STWZEVA/1` bundle with the shared recorder of `tools/stwo-eval-program-abi` |

```sh
cd tools/stwo-circuit-oracle-rs
cargo run --release --locked -- primitives --output /tmp/primitives.json
cargo run --release --locked -- components \
  --proving-root ~/.cargo/git/checkouts/proving-<hash>/5a7c5ed \
  --output /tmp/components.json
```

Run Cargo from this directory so `rust-toolchain.toml` selects
`nightly-2026-01-15`. `components`, `statement-trace`, `project-air`,
`verifier-stages`, `topology` and `cairo-statement` read data files from a `proving` checkout and
refuse any checkout whose inputs differ from the pinned revision's
(`src/upstream.rs` and each subcommand's pinned aggregate digest). `prove-small`
takes `--memory-budget BYTES` (default 4 GiB) and refuses a circuit whose
estimated prover peak exceeds it; the multiverifier `proof.bin` circuit (trace
log size 21, log blowup 3) is far over that budget and is therefore covered by
`verifier-stages` only.

The oracle compiles in `../stwo-eval-program-abi/src/lib.rs` with `#[path]`: the
evaluation-program recorder and bundle encoder it shares with
`tools/stwo-cairo-air-compiler`. At the start of `air-programs` (and of every
compiler run) both tools encode the same fixture program and require the bytes
committed in `abi_fixture.rs`, across their two Stwo pins. Outputs are written atomically and never replace
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
