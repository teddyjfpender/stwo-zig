# Cairo Witness Compiler

This directory owns the development-time compiler that turns a pinned official
Stwo-Cairo witness implementation into deterministic, backend-neutral programs
consumed by the Zig Cairo frontend.

It is deliberately outside every released product dependency closure:

```text
authenticated official source
            |
            v
        rewriter/            finite Rust-AST lowering
            |
            v
    isolated source overlay  generic evaluator + recorder
            |
            v
  witness_programs_v1.bin    parsed and authenticated by Zig
```

`rewriter/` is the first repository-owned phase. It parses generated component
writers with `syn`, accepts only known shapes and operations, and reports every
unsupported construct. It never edits the authenticated checkout during normal
artifact generation. Its `--emit-dir` output is staged into a disposable
overlay.

The remaining compiler phases must live beside it:

- a backend-neutral evaluator instruction model;
- deterministic component recording and bundle serialization;
- an orchestrator that verifies the official source revision and clean tree;
- provenance generation that binds the source, compiler closure, toolchain,
  component census, and artifact digest;
- reproduction and mutation gates for every released program bundle.

The compiler is not part of proof generation. `stwo-cairo-cpu` and
`stwo-cairo-metal` read only authenticated artifacts already present in the
repository. They must never shell out to Cargo, Git, Rust tools, or an upstream
source checkout.

## Current Checkpoint

At official Stwo-Cairo revision
`82f21252a68ec006d73e299f5bf1ce6d4db0ee78`, the rewriter scans 67 component
files, finds 64 generated writers, emits 27 exactly, identifies two requiring
known evaluator extensions, and rejects 38 with explicit reasons. Its census
and all emitted files are byte-identical to the migration transformer recorded
by `vectors/cairo/official/witness_programs_v1.provenance.json`.

This establishes rewriter ownership, not release completion. The binary bundle
remains non-release evidence until this directory owns the entire compiler
closure, all official witness writers are covered, every input edge is bound,
and the resulting SIMD and Metal proofs pass the official verifier.
