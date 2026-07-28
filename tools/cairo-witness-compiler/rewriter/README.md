# Cairo Witness Rewriter

This standalone development tool converts official Stwo-Cairo's generated
`write_trace_simd` component writers into backend-neutral per-row
`WitnessEval` programs. It performs a finite, auditable source transformation:
unsupported syntax is reported as a skipped component and is never lowered
approximately.

The tool is part of the source-to-artifact witness compiler. Released Zig
products consume the authenticated binary program bundle and do not invoke
Rust, Cargo, Git, or this rewriter while proving.

```sh
cargo run --release --locked -- \
  --census /path/to/stwo-cairo/stwo_cairo_prover/crates/prover/src/witness/components
```

Use `--emit-dir <directory>` to stage transformed full-file copies without
changing the authenticated upstream checkout. `--in-place` and `--check`
exist for isolated compiler-overlay development only.

The generated marker retains its historical `witness_genericize` spelling.
That string is part of the deterministic artifact format and must not be
renamed without an explicit format migration.
