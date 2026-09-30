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
| Commands | `leaf-wrap` |
| Upstream counterpart | `leaf-prover` (`crates/leaf_prover`) |

## `leaf-wrap`

```sh
zig build install --build-file src/products/circuit_recursion_cpu/build.zig -Doptimize=ReleaseFast -j2
src/products/circuit_recursion_cpu/zig-out/bin/stwo-circuit-recursion-cpu leaf-wrap \
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
  itself. `--program` is still required: its felts are the program the leaf
  circuit interns (`program_felts`).
- `--assets` names the repository root that holds the committed artifacts
  (`vectors/circuit/official/compiled_air_constraints_v1.bin`,
  `circuit_air.air_programs_v1.bin` and the Cairo lane's witness and AIR
  bundles).
- `--compact-min-log <n|off>` (default 18) keeps only coefficients of the
  circuit proof's columns of at least 2^n rows once they are hashed.
  `--profile` prints the circuit prover's stage times.

## Test

```sh
zig build test --build-file src/products/circuit_recursion_cpu/build.zig -Doptimize=ReleaseFast -j2
zig build circuit-parity-r8 --build-file src/products/circuit_recursion_cpu/build.zig -Doptimize=ReleaseFast -j2
```

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
