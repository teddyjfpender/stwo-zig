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

`rewriter/` parses generated component
writers with `syn`, accepts only known shapes and operations, and reports every
unsupported construct. It never edits the authenticated checkout during normal
artifact generation. Its `--emit-dir` output is staged into a disposable
overlay.

The rest of the owned compiler closure lives beside it:

- `support/` contains the backend-neutral evaluator, SSA instruction model,
  deterministic recorder, and bundle exporter installed into the isolated
  official-source overlay;
- `orchestrator.py` verifies the official revision, tree, and clean checkout,
  creates the overlay from `git archive`, runs the rewriter and official Rust
  compiler, validates the complete bundle, and publishes outputs without
  replacement;
- `generate.py` is the small command-line boundary;
- `tests/` covers compiler identities, registry patch admission, immutable
  publication, and the checked-in bundle contract.

Generate a new artifact and deterministic receipt with:

```sh
python3 tools/cairo-witness-compiler/generate.py \
  --source /path/to/clean/stwo-cairo \
  --output /path/to/new/witness_programs_v1.bin \
  --receipt /path/to/new/compiler-receipt.json
```

The first run populates `tools/cairo-witness-compiler/target/`, which is ignored
by Git. Later runs use a process lock, a stable official-overlay path, and
content-derived mtimes so Cargo can reuse the exact compiler closure. A change
to the official tree, orchestrator, rewriter, or support sources changes that
identity and forces the staged prover crate to rebuild once; identical-closure
runs retain Cargo's warm path.

The compiler is not part of proof generation. `stwo-cairo-cpu` and
`stwo-cairo-metal` read only authenticated artifacts already present in the
repository. They must never shell out to Cargo, Git, Rust tools, or an upstream
source checkout.

## Current Checkpoint

At official Stwo-Cairo revision
`82f21252a68ec006d73e299f5bf1ce6d4db0ee78`, the rewriter scans 67 component
files, finds 64 generated writers, emits 61 exactly with no census-only sites
inside that supported cohort, and rejects seven with explicit reasons. The emitted
artifact and its compiler closure are authenticated by
`vectors/cairo/official/witness_programs_v1.provenance.json`.

This establishes compiler ownership, not product release completion. The
binary bundle remains non-release evidence until all official witness writers
are covered, every input edge is bound, and the resulting SIMD and Metal
proofs pass the official verifier.
