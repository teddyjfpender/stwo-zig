# Cairo / RISC-V CSP comparison contract

[`comparison-manifest-v1.json`](comparison-manifest-v1.json) is the authority
for apples-to-apples cross-frontend function benchmarks. It deliberately
separates a useful implementation lead from an exact workload match.

A row becomes `exact_runnable` only after it has all of the following:

- the same logical function and variant as the RISC-V row;
- the exact authenticated logical input, independently of frontend framing;
- a pinned Cairo executable and arguments;
- a reproducible, digest-pinned ProverInput and exact VM-step count;
- a public-statement projection binding the program, input, and canonical
  output; and
- a separately verified proof whose output equals the pinned expected value.

The v1 validators intentionally reject every `exact_runnable` promotion even
when those files are present. The current official-verifier receipt does not
expose a verifier-accepted public-statement digest, so v1 cannot
cryptographically prove that the program, ProverInput, logical input, output,
protocol, proof, and receipt all describe one statement. Admitting a runnable
row therefore requires a schema upgrade with that linkage, not a status edit.

The PR 171 zkVM SHA2/SHA3 fixtures remain valuable whole-pipeline benchmarks.
Their pinned Cairo-0 programs call `finalize_sha256` / `finalize_keccak`, so they
are the constrained adaptation base for exact SHA-256 and Keccak rows. They
cannot be used unchanged because they synthesize data from an iteration count
and publish no digest.

[`fixture-provenance-v1.json`](fixture-provenance-v1.json) records the exact
adaptations now prepared in [`sources/`](sources/):

- SHA-256 embeds the normalized 2 KiB payload as 512 consecutive big-endian
  `u32` words, retains `finalize_sha256`, and publishes all eight digest words;
- Keccak-256 embeds the same payload as 256 consecutive little-endian `u64`
  words, retains `finalize_keccak`, and publishes the low then high `u128`
  digest limbs.

Neither source reads `program_input`. The compiled program therefore binds the
message constants, while the output builtin binds the digest through Cairo
public output. Both are still `source_ready_compilation_pending`: source review
does not substitute for an authenticated compiled program, derived
ProverInput/VM-step pin, proof, public statement, or independent verifier
receipt.

The modern Cairo corelib SHA-256 and Keccak APIs are semantic source references
only. They delegate to host-executed Starknet syscalls whose semantics the
current AIR does not constrain. A wrapper that returns the right digest would
therefore not be proof-sound evidence of the hash computation. The corelib
Poseidon and ECDSA APIs are also near-matches: they use classic Poseidon over
`felt252` and the STARK curve, respectively, while the current RISC-V rows use
Poseidon2-M31 and secp256k1.

`riscv.input_sha256` authenticates the complete RISC-V fixture file, including
its frontend framing. `logical_input.logical_input_sha256` authenticates the
normalized logical input. For the SHA-256 row that second digest intentionally
equals the expected SHA-256 output; this is a consequence of the workload, not
a reused or missing pin.

Validate and inspect the current plan without building a prover:

```sh
python3 autoresearch/benchmarks/cairo_csp_comparison.py
python3 autoresearch/benchmarks/cairo_csp_comparison.py --json
python3 scripts/cairo_csp_fixtures.py
zig build cairo-csp-fixtures
```

The build step validates source and provenance. Once a fixture is marked
`compiled_ready_derivation_pending`, the same step derives its ProverInput
through the pinned VM adapter into a `.candidate.prover_input.json` review
artifact. Derivation does not authenticate or promote that artifact, and the
step never overwrites an `exact_runnable` fixture. It does not compile Cairo or
prove implicitly.

Automation that intends to run comparison timings must use a strict runnable
gate. Both forms currently fail by design rather than timing a source-only or
near-match row:

```sh
python3 autoresearch/benchmarks/cairo_csp_comparison.py --require-runnable
python3 scripts/cairo_csp_fixtures.py --require-runnable
zig build cairo-csp-runnable
```

The exact compiler authority is `cairo-lang==0.14.0.1`,
`cairo-compile --proof_mode`; the PyPI source distribution size and SHA-256 are
pinned in fixture provenance. On this host the compiler is not yet provisioned.
A Python 3.12 `pipx`/venv installation is the available native route, but its
full dependency resolution must be captured before compiled artifacts are
admitted.

Compilation and fixture derivation are excluded from timed samples. Once rows
are runnable, their timing scope is VM execution plus witness/ProverInput
construction plus proof generation, matching the RISC-V CSP definition;
verification is reported separately.
