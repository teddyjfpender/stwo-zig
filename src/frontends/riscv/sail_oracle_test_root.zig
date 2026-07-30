//! Test root for the two `runner/sail_oracle.zig` self-checks.
//!
//! `zig test` collects tests only from the files of its ROOT module, and only
//! from those the compiler actually analyses — an unreferenced file-scope
//! `pub const x = @import("...")` is analysed lazily, i.e. never, which is
//! why `runner/mod.zig`'s long-standing `pub const sail_oracle` did not make
//! them run. Every RISC-V product test step roots at `src/tests.zig` and
//! reaches this package as a module *dependency*, and dependency modules
//! contribute no tests at all, so the oracle self-check and the forged-trace
//! rejection ran in no build step until 2026-07-29.
//!
//! This file exists so a test artifact can root here. It cannot root at
//! `runner/sail_oracle.zig` directly: that would make `runner/` the module
//! path and every `../isa`, `../air`, `../host` import in the runner subtree
//! an "import of file outside module path". It deliberately does not root at
//! `mod.zig` either — that is the package's own test root and additionally
//! pulls the opcode-coverage, AIR-extract and semantic-eval suites, which is
//! a scope decision this file does not make. No pinned test filter is
//! involved anywhere, so there is no literal that could silently stop
//! matching and empty the step.
//!
//! Consumed by `build_support/products/riscv_sail_oracle_tests.zig`
//! (`zig build test-riscv-sail-oracle`). `mod.zig` names
//! `runner/sail_oracle.zig` separately, which is what makes the package's own
//! `zig build test` cover it too.

test {
    _ = @import("runner/sail_oracle.zig");
}
