# Decomposition plan for baselined legacy findings

Repository-local plan required by the source-conformance ratchet: every
baseline exception names this file, and an exception may only shrink. The
full historical narrative lives in the `stwo-zig-og-docs` archive; this file
is the operative ledger.

## Rules

- A new finding fails CI immediately; the baseline never grows.
- Removing debt removes its baseline entry in the same commit.
- `--update-baseline` runs are reviewed: the diff must only shrink.

## Remaining owners and next extractions

| Owner | Next extraction |
| --- | --- |
| `.github/workflows/ci.yml` | extract the protected build-architecture session, host producers, and verifier into a separately reviewed reusable workflow once GitHub's called-workflow identity is explicitly admitted by the receipt protocol |
| `src/tools/metal_arena_plan/main.zig` | the active owner now has a responsible directory behind a 7-line Zig 0.15 package-root facade; split its retained 4,887-line orchestration by admission, schedule construction, proving, verification, and reporting without changing Metal semantics |
| `src/backends/metal/runtime.zig` | continue the runtime decomposition into `src/backends/metal/runtime/` owners |
| `src/backends/metal/runtime.m` | split the Objective-C bridge by admission, resources, encoding, and lifecycle |
| `src/integrations/cairo_metal/arena_binding.zig` | phase facade split per the archived arena-binding plan (Cairo work resumes with stwo-cairo) |
| Cairo-deferred trees (`src/frontends/cairo/`, `src/tests/cairo/`, tooling) | untouched until the stwo-cairo effort restarts; entries stay frozen |
| Rust support crates over the size ceiling | reduce when the pinned oracle next changes; never edited casually |
| `src/frontends/riscv/prover.zig` | split statement and column planning from backend-neutral proof orchestration; concrete CPU selection now lives in `src/integrations/riscv_cpu/` |
| RISC-V oversized trace sources (`air/trace_columns.zig`, `infra_trace.zig`, `runner/trace.zig`) | decompose during the active Stark-V adapter completion; shrink each baseline entry with its extraction |
| `src/tools/riscv/bench/main.zig`, `src/tools/riscv/trace/main.zig` | active owners now sit below `src/tools/riscv/` behind 5-line Zig 0.15 package-root facades; split their retained benchmark and trace orchestration before removing the temporary deferred-policy prefixes |
| `src/tools/riscv/metal_bench/main.zig` | the Metal benchmark owner now sits below `src/tools/riscv/` behind a 5-line Zig 0.15 package-root facade; remove the facade with the other RISC-V tool facades when named imports replace the compatibility module root |
| `src/cairo_cuda.zig`, `src/stwo_native_cpu.zig`, `src/stwo_native_metal.zig`, `src/stwo_riscv_cpu.zig`, `src/stwo_aggregate_cpu.zig`, `src/stwo_aggregate_metal.zig` | retain these small declarative package-root maps while Zig 0.15 relative imports require an `src/` module root; they expose imports only, construct no executable, install, test, or backend selection, and must disappear when every child is a named module |
