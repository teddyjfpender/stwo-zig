# Stwo Circuit Recursion Oracle

This isolated development tool runs StarkWare's circuit recursion crates from
`https://github.com/starkware-libs/proving` at
`5a7c5ede4299c91a61df19a07cba4f7502c14230` and emits the checkpoints the Zig
port's parity ladder compares against (design:
`design/starknet-proving-pipeline/recursion/02-design.md` §8). Released Zig
products never build, invoke, or distribute it.

Every subcommand except `adapt-program` and `prove-cairo` only builds circuits or hashes data and runs
on a laptop in seconds with a few tens of megabytes of memory. `prove-cairo`
proves a small Cairo program (a few seconds and about 2 GB for the committed
all_opcodes and all_builtins fixtures); larger programs belong on a big host.

| Subcommand | Rung | Content |
|---|---|---|
| `primitives` | R0 | Blake2s and Blake2s-M31 channel transcripts (mix orders, `mix_hash`, `FriConfig::mix_into`); minimum-nonce grinds at 16/20/24/26 bits, including `hi > 0` nonces; M31 and QM31 operations; `hash_u32s*`, `reduce_to_m31`, host and in-circuit circuit hashes; the ChaCha20Rng KAT; felt252 word encoding; leaf wire JSON |
| `gadgets` | R1, R2 | Builder circuits (context, peepholes, constants, wrappers) and gadgets (Blake2s at 0/4/44/64/65/128 bytes, `extract_bits`, Simd, mux, `sort_by_u` permutation, `reduce_hash_value`, circuit hash) before and after `finalize` |
| `components` | R3 | All 83 Cairo slots and 11 circuit components, each built in a fresh `Context` through the upstream test harness |
| `project-air` | R3 | The constraints-only projection of the compiled AIR read by the Zig interpreter |
| `prove-lifted-example` | R10 lift | Upstream's wide-Fibonacci prover test (`crates/examples`) with the trace tree committed 0, 1 and 3 levels above its columns, verified; `bincode(StarkProof)` digests and per-stage values |
| `adapt-program` | R10c | The leaf prover's Cairo VM run and adapter (`prove_leaf.rs` steps 1-2) on a compiled program from the `proving` checkout, emitted as `ProverInput` JSON |
| `prove-cairo` | R10c | `prove_cairo::<Blake2sM31MerkleChannel>` of an adapted `ProverInput` under a registry's `cairo_prover_params` (the leaf prover's Cairo proof; `--lifting-size-policy` overrides the policy), verified with `verify_cairo_ex`; proof byte digests and per-stage values, and optionally the canonical `ExtendedBinary` payload (`--proof-output`) |

```sh
cd tools/stwo-circuit-oracle-rs
cargo run --release --locked -- primitives --output /tmp/primitives.json
cargo run --release --locked -- components \
  --proving-root ~/.cargo/git/checkouts/proving-<hash>/5a7c5ed \
  --output /tmp/components.json
```

Run Cargo from this directory so `rust-toolchain.toml` selects
`nightly-2026-01-15`. `components` and `project-air` read the compiled AIR from a
`proving` checkout and refuse any checkout whose inputs differ from the pinned
revision's (`src/upstream.rs`). Outputs are written atomically and never replace
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
  topology-mode build differs from its value-mode build.

## Pins

The manifest has no path dependencies, patches or replacements. Every upstream
crate is a git dependency on the pinned revision, and `Cargo.lock` was seeded
from the upstream workspace lock, so every registry package has the version and
checksum `proving@5a7c5ed` itself locks. `scripts/check_upstream_pins.py`
validates the manifest, lock, toolchain, source constants, and the committed
fixtures against the Circuit Recursion Lane of `conformance/upstream.md`.
