# Typed session retirement cleanup

The canonical execution session now handles ECALL/EBREAK directly after typed
retirement dispatch. Removed unreachable ordinary load/store witness bookkeeping
and the production dependency on the legacy executor. Host memory writes still
record their transitions and host instruction trace/register bookkeeping remains
unchanged. Removed the unused `runner.execute_mod` public export; the fail-closed
old executor remains available only to existing direct tests and source audits.

The typed dispatch table now checks every decoded opcode at compile time:
ordinary opcodes require a typed authority, while ECALL/EBREAK remain host-only.
An import guard prevents the legacy executor returning to the session closure
and checks its public export remains absent. The static graph includes test-support
imports; this guard does not claim that every lexically reachable source is
production-instantiated.

Validation:
- `zig build test-execution-session --build-file src/frontends/riscv/build.zig -Doptimize=ReleaseSafe -j1 --summary all`: 31 tests passed; compile six seconds,
  execution 639 ms. Covers existing host and continuation tests plus EBREAK.
- Product closure and typed proposal isolation: 44 tests passed.
- Test inventory: two tests passed.
- Formatting and diff whitespace checks passed.
- Conformance reported 107 size findings, including this batch pushing the closure
  test file one line over its ceiling. Removed that extra blank line (850 lines);
  the other 106 findings remain. No baseline update.

No complete-proof rebuild was performed. Final frozen-source CPU/Metal/AOT and
1/2/4/8 qualification remains outstanding, as does Linux artifact-store runtime
qualification. This is scoped frontend cleanup, not completion of the broader goal.
