# `stwo-circuit-recursion-cpu`

The circuit recursion stage of StarkWare's proving pipeline
([starkware-libs/proving](https://github.com/starkware-libs/proving) at
commit `5a7c5ede4299c91a61df19a07cba4f7502c14230`) on the CPU, design §7.4
of the [recursion design](../../../design/starknet-proving-pipeline/recursion/02-design.md).
Its output files are byte-compatible with upstream's binaries.

| Property | Value |
| :--- | :--- |
| Binary | `stwo-circuit-recursion-cpu` |
| Backend | CPU (scalar and SIMD), no fallback |
| Build | `zig build stwo-circuit-recursion-cpu -Doptimize=ReleaseFast -j2` (product catalog, parity-gated) |
| Commands | `leaf-wrap`, `fold-tree`, `fold-stage`, `fold-stage-campaign`, `fold-stage-root`, `circuit-params`, `verify` |
| Upstream counterparts | `leaf-prover` (`crates/leaf_prover`), `stwo_run_and_prove_recursive_tree`, `circuit-params --registry` (`crates/circuit_params`), `verify_circuit` (`crates/circuit_verifier`, no upstream binary) |
| Release gates | `test-circuit-recursion-cpu-product`, `circuit-parity-local` |
| Embedded data | the circuit AIR projection (`vectors/circuit/official/compiled_air_constraints_v1.bin`) and evaluation programs (`circuit_air.air_programs_v1.bin`), SHA-256-checked at run time |

## `leaf-wrap`

```sh
zig build stwo-circuit-recursion-cpu -Doptimize=ReleaseFast -j2
zig-out/bin/stwo-circuit-recursion-cpu leaf-wrap \
  --registry vectors/circuit/official/registries/leaf_prover_canonical_small.json \
  --program vectors/circuit/official/programs/use_all_opcodes_and_builtins_compiled.json \
  --prover-input vectors/circuit/r10/use_all_opcodes_and_builtins.prover_input.json \
  --output leaf.json
```

It runs upstream `prove_leaf` from step 3 on:

1. the leaf Cairo proof, `prove_cairo::<Blake2sM31MerkleChannel>` under the
   registry's `cairo_prover_params` (the Cairo CPU integration's
   `proveLeafCairo`, pinned to upstream by rung R10c);
2. the wrap (`stwo_circuit_cpu_integration.recursion.leaf_wrap`): the
   registry's leaf verifier circuit over that proof, padded to the
   registry's target and proved on the internal channel profile;
3. the `SerializedLeafProof` file, written as `leaf-prover` writes it
   (`serde_json::to_string_pretty`, no trailing newline).

Differences from `leaf-prover`, none of which changes the output bytes:

- The Zig lane has no Cairo VM. It starts from the execution the VM and the
  upstream adapter produce, as `ProverInput` JSON
  (`stwo-circuit-oracle adapt-program`), where `leaf-prover` runs steps 1-2
  itself from `--program_input`. The contract is two steps: run the adapter
  (`adapt-program --program P --program-input I`), then `leaf-wrap`.
  `--program` is still required: its felts are the program the leaf
  circuit interns (`program_felts`). Upstream's `--circuit_registry_json`
  and `--output_path` are accepted for `--registry` and `--output`.
- `--assets` (default `.`) names the repository root that holds the Cairo
  lane's committed witness and AIR bundles under `vectors/cairo/`. The
  circuit AIR data is embedded.
- `--compact-min-log <n|off>` (default 18) keeps only coefficients of the
  circuit proof's columns of at least 2^n rows once they are hashed.
  `--profile` prints the circuit prover's stage times.

## `fold-tree`

```sh
zig-out/bin/stwo-circuit-recursion-cpu fold-tree \
  --program_input leaves.json --circuit_registry_json registry.json \
  --proof_path root.proof --program_output root_outputs.json \
  --packed_output_path root_packed.json
```

`stwo_run_and_prove_recursive_tree` with its flags (`--flag value` or
`--flag=value`): the manifest `{"leaves": [...]}` names `LeafInput` files in
fold order; the three outputs are the root's Cairo-verifier felt stream, its
output digest and its packed-output tree, byte for byte as upstream writes
them (rung R9, `circuit-parity-r9` in the circuit CPU integration).

The tree fails closed where upstream's release build does not. Upstream's
`fold.rs` checks the multiverifier circuit only with
`debug_assert!(context.is_circuit_valid())`, compiled out in release; its
prover's one hard check is `lookup_sum == 0`. So a leaf with, for example, a
wrong declared `circuit_preprocessed_root` or a preimage that does not hash
to its output can make upstream write root files, while `fold-tree` stops
with `MultiverifierRejectedInputs`. This is intentional (design errata 11):
no valid input changes, and no invalid one gets a root.

## Bounded fold stages

`fold-stage` proves a nonterminal subtree with the internal circuit profile
and writes one checkpoint. `fold-stage-root` consumes leaf inputs, checkpoints,
or both and writes the ordinary three root files. Their manifest is
`{"entries":[{"kind":"leaf","path":"..."},{"kind":"checkpoint","path":"..."}]}`
in left-to-right order. A checkpoint carries the exact serialized internal
proof, canonical preprocessed root, output digest, and packed subtree. On load,
the proof is decoded under the canonical circuit config; the preprocessed root
and circuit hash must match that circuit. A terminal root proof cannot be fed
back as an internal checkpoint.

```sh
stwo-circuit-recursion-cpu fold-stage --manifest left.json \
  --registry registry.json --checkpoint left.checkpoint.json
stwo-circuit-recursion-cpu fold-stage-root --manifest final.json \
  --registry registry.json --proof root.proof \
  --outputs root_outputs.json --packed-output root_packed.json
```

`fold-stage-campaign --jobs jobs.json --registry registry.json` proves up to
256 independent **nonterminal** stages in one process. `jobs.json` is an array
of `{"manifest":"left.json","checkpoint":"left.checkpoint.json"}` entries.
The authenticated AIR, canonical circuit, and backend session are built once;
each job receives its own input arena and checkpoint file. The command fails
the whole campaign if any stage fails, so the caller publishes outputs only
after successful exit. The service uses this for independent subtrees at one
level and still runs the single final root with `fold-stage-root`.

Stage chunks should cover power-of-two spans in the original sequence; an
unpaired tail is carried unchanged. This preserves the one-shot tree's pairing
and makes every independent subtree schedulable on a different worker. On
Metal, both a four-leaf split into two checkpoints and a five-leaf tree with an
odd carried leaf produced all three root files byte for byte identical to
`fold-tree`. The proving service records the corresponding receipts. A direct
Metal two-stage campaign produced the same two checkpoint SHA-256 digests as
the separate commands: `1428a8ec…` and `6a9c8d3d…`.

## `verify`

```sh
zig-out/bin/stwo-circuit-recursion-cpu verify --proof proof.bin --request request.json
```

Upstream `verify_circuit` (`crates/circuit_verifier/src/verify.rs`) on a
`CircuitSerialize` proof: the request names the verified circuit's
`PcsConfig`, preprocessed column log sizes (commitment order), preprocessed
root and claimed output digest, in the format of
`stwo-circuit-oracle verify-circuit --request`. The proof is decoded under
`circuit_verifier_proof_config`, the verification circuit is built with
values, and the proof is accepted exactly when that circuit is satisfied.
It prints `accepted: output digest <hex>` and exits 0, or
`rejected at <stage>: <reason>` and exits 3. Rung R11
(`circuit-parity-r11`) holds it to upstream's verdicts.

## `circuit-params`

```sh
zig-out/bin/stwo-circuit-recursion-cpu circuit-params \
  --definition circuit_registry_definitions/canonical_small/definition.json \
  --registry --output-path registry.json
```

`circuit-params --registry`: the definition's paths resolve against the
working directory, as upstream's do. Only the registry output is ported, not
upstream's human-readable sizes report (`--registry` is required). Without
`--output-path` the registry goes to standard output.

Registry generation is setup for a fixed configuration, not work repeated for
each proof. The production registry for upstream `proving@5a7c5ed` is committed
at `vectors/circuit/official/registries/production.json`; pass this file to
`leaf-wrap` or `fold-tree` directly. On an M5 Max, generating that registry
from the upstream production definition took 50.18 s and 43.4 GB peak RSS in
Zig (Rust: 54.22 s and 49.4 GB). The two 4,028-byte outputs matched byte for
byte. A proof run reads the committed registry and does not regenerate it.

`fold-tree` uses one reduction at a time by default. Set
`STWO_CIRCUIT_FOLD_JOBS=2` to prove independent sibling pairs concurrently
when memory permits. On this M5 Max, four identical test leaves took 21.34 s
and 13.8 GB peak RSS with one job, or 18.42 s and 25.2 GB with two; the three
root files were byte-identical. The earlier SIMD composition path took
22.98 s and 20.44 s respectively on the same fixture. Native CPU composition
is enabled by default in these measurements. The measured memory trade-off
keeps one fold job as the default.

## Test

```sh
zig build test-circuit-recursion-cpu-product -Doptimize=ReleaseFast -j2
zig build circuit-parity-local -j2      # the release gate: every rung within 8 GB
zig build circuit-parity-large -j2      # R8, R8b, R9 (11-18 GB peaks)
zig build circuit-parity -j2            # both, local first
zig build circuit-parity-r8 -Doptimize=ReleaseFast -j2
zig build circuit-parity-r8b -Doptimize=ReleaseFast -j2
```

`test-circuit-recursion-cpu-product` runs the command-line and
embedded-asset tests, `--help` on the installed binary and the product
closure gate.

The parity lanes run each rung of design §8.2 as its own `zig build`, one
after another. `circuit-parity-local`: the wire vectors (R0), the frontend
rungs (R0 FRI, R1-R5, R4, R6 fold), R4 values, R6 leaf, R7, registry
generation, R10b/R10c (`test-cairo-leaf-proof`) and R11.
`circuit-parity-large`: R8, R8b, R9 and, when
`STWO_CIRCUIT_MULTIVERIFIER_INPUTS` names its inputs, the R7 multiverifier.

`circuit-parity-r8b` (labelled large) is the end-to-end chain: the Zig lane
proves and wraps upstream's leaf simple bootloader running the
`simple_output` task `[11, 13, 17]` under the recursive-tree registry, the
leaf must equal `four_leaves/leaf.json` (root, circuit hash and proof, then
the whole `LeafInput` assembled from the bootloader's preimage dump), and
four copies of the Zig leaf must fold to `root.proof`, `root_outputs.json`
and `root_packed.json` byte for byte. It took 278 s and 15.8 GB maximum RSS
on 2026-09-30 (AC power, other agents running; indicative only).

`circuit-parity-r8` (labelled large: a 2^23-row circuit proof, about 11 GB
and 1-2 minutes) wraps `use_all_opcodes_and_builtins` and requires the file
to equal `vectors/circuit/official/leaf_prover/expected_output.json`, the
golden upstream's `cli_test.rs` pins. Upstream's release `leaf-prover`
reproduced that golden on this host on 2026-09-30.

## Measurements

Apple M4 Max, AC power, `ReleaseFast`, compact storage from log 18, with
other agents' jobs running and 8-14 GB of swap in use (an upper band, not a
benchmark):

| Leaf | Bucket | Cairo proof | Wrap | Wall | Max RSS | Peak footprint |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: |
| `use_all_opcodes_and_builtins` (canonical_small) | 20 | 1.6-2.7 s | 36-44 s | 43-60 s | 11-17.5 GB | 17.5-22 GB |
| mainnet `15627905-15627907` (leaf bootloader over the PIE; canonical) | 25 | 75.2 s | 39.0 s | 114.4 s | 18.5 GB | 28.1 GB |

The mainnet row used a canonical registry built by upstream `circuit-params`
for trace logs 25-26; the Zig wrap's circuit hash and preprocessed root
equal its leaf entry. Upstream `leaf-prover` was not run on that leaf (it
needs more than this host's 36 GB). On the canonical_small leaf upstream
`leaf-prover` takes 30.4 s, 12.6 GB maximum RSS and 25.4 GB peak footprint
on the same host.
