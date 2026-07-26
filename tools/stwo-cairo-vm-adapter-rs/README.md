# Official Cairo VM Execution Adapter

This isolated sidecar executes compiled Cairo programs with Cairo VM `3.2.0`
under the `all_cairo_stwo` proof layout and converts the resulting runner state
through the pinned official `stwo-cairo-adapter`.

It is an execution dependency, not a proof oracle. Zig owns witness generation,
proof generation, and in-process verification. The separately isolated
`stwo-cairo-official-verifier` remains the final correctness oracle for every
published proof.

```sh
cargo run --manifest-path tools/stwo-cairo-vm-adapter-rs/Cargo.toml -- \
  run \
  --program /absolute/path/compiled.json \
  --program-type json \
  --prover-input-out /absolute/path/prover-input.json
```

The output path must not exist. Public-memory addresses are sorted before
serialization so equivalent VM executions have one stable adapter document.
Executable-format Cairo programs are not yet released and fail closed.
