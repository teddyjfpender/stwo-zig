# Official Cairo AIR Compiler

This build-time tool lowers the complete typed `FrameworkEval` tree from the
pinned official Stwo-Cairo source into stwo-zig's backend-neutral evaluation
program ABI. Rust is a source and correctness oracle only; released Zig
products consume authenticated artifacts and never invoke Cargo while proving.

The official Stwo framework keeps the evaluator inside `FrameworkComponent`
private. `generate.py` therefore:

1. authenticates the exact Stwo revision and Git tree;
2. exports that immutable tree into the ignored repository `target/` cache;
3. applies one exact-context `evaluator()` accessor patch;
4. runs the locked compiler with the official nightly toolchain; and
5. refuses to replace an existing output artifact.

```sh
python3 tools/stwo-cairo-air-compiler/generate.py \
  --stwo-source /path/to/stwo-at-7b211edd \
  --proof vectors/cairo/official/all_opcodes_blake2s.proof.bz2 \
  --output /tmp/all-opcodes-air.bin
```

For every component, two independent lookup/claimed-sum probes identify
proof-dependent extension constants. The compiler converts those constants to
typed runtime parameters, rejects ambiguous or unclassified values, then binds
the original values back and requires byte-identical program reconstruction
before emitting a bundle.
