//! The build home for the two `sail_oracle.zig` self-tests.
//!
//! Measured 2026-07-29 on this branch: those two tests — the oracle
//! self-check and the forged-trace rejection — executed in NO build step.
//! `zig test` collects tests only from the files of its ROOT module, and
//! every existing RISC-V test step roots at `src/tests.zig`, which reaches
//! `sail_oracle.zig` through the `stwo_riscv_frontend` *module* dependency.
//! Dependency modules contribute no tests, so
//! `-Driscv-test-filter="runner agrees with pinned Sail"` matched no name in
//! `test-riscv-release-exhaustive` and `EmptySelectionGuard` failed the build.
//! A check that never runs is indistinguishable from a check that passed,
//! which is the exact failure mode `sail_oracle.zig` exists to refuse.
//!
//! The fix is a test artifact rooted at `src/frontends/riscv/
//! sail_oracle_test_root.zig`, a two-line file whose `test` block names
//! `runner/sail_oracle.zig`, which makes those tests root-module tests and
//! collects them unconditionally. Rooting at `sail_oracle.zig` itself does
//! not compile: it would make `runner/` the module path and every `../isa`,
//! `../air`, `../host` import in the runner subtree an "import of file
//! outside module path" (measured, 14 errors). Two consequences are
//! deliberate:
//!
//!  - **No pinned `filters`.** Narrowing the binary to literally two tests
//!    would take a pinned filter, and `EmptySelectionGuard` guards only the
//!    command-line flag, never pinned literals — a step that needed one would
//!    reinstall this very defect somewhere new. So the step runs whatever the
//!    root collects: 254 tests as measured on 2026-07-29, 252 passing and the
//!    two Sail tests skipping visibly. The extra 252 are the runner, ISA and
//!    AIR-program files those two tests analyse; they come along because Zig
//!    collects tests from every root-module file it analyses, and they cost
//!    ~0.3 s. That is collateral coverage, not the step's contract.
//!  - **Its own top-level step rather than a dependency of
//!    `test-riscv-release-exhaustive`.** `-Driscv-test-filter` REPLACES a
//!    step's filters and takes a single value, so folding this artifact into
//!    the exhaustive step would make the pinned Sail job's
//!    `-Driscv-test-filter="malicious prover"` invocation fail this
//!    artifact's selection guard.
//!
//! Rooting at the dedicated file rather than at the package root
//! (`src/frontends/riscv/mod.zig`) keeps the collected set to what the two
//! Sail tests actually reach. The package root is the right home for the
//! package's own `zig build test` — it now names `runner/sail_oracle.zig` in
//! its aggregation block — but using it here would additionally pull the
//! opcode-coverage, AIR-extract and semantic-eval suites (317 tests total),
//! none of which this fix is about.
//!
//! Both tests spawn `scripts/riscv_sail_oracle.py`. Without the pinned Sail
//! workspace each spawn takes the visible-skip path in ~0.08 s (measured),
//! so the step is affordable in the PR-blocking `test-riscv-cpu-product`
//! lane, which is what makes a compile break in these tests a PR failure
//! rather than a surprise inside the scope-gated Sail job. They only do more
//! than skip in `.github/workflows/riscv-sail-differential.yml`, the one job
//! with a verified pinned oracle, which runs this step with
//! `STWO_ZIG_REQUIRE_SAIL_ORACLE=1`.

const std = @import("std");
const graph = @import("../graph/modules.zig");
const test_filter = @import("riscv_test_filter.zig");

pub const STEP_NAME = "test-riscv-sail-oracle";
pub const DESCRIPTION =
    "Run the sail_oracle self-check and forged-trace rejection against the pinned Sail oracle";

const ROOT_SOURCE_FILE = "src/frontends/riscv/sail_oracle_test_root.zig";

/// Declares `test-riscv-sail-oracle` and returns the step to depend on, so a
/// caller can also fold it into a broader product test step.
pub fn add(
    b: *std.Build,
    test_product: graph.Product,
    protocol: graph.ProtocolModules,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) *std.Build.Step {
    const root = graph.create(b, .{
        // The owner derives this through riscv_shared_shell.roleProduct, so
        // every RISC-V CPU test artifact shares one identity construction.
        .product = test_product,
        .root_source_file = ROOT_SOURCE_FILE,
        .target = target,
        .optimize = optimize,
    });
    protocol.addImports(root);
    const tests = b.addTest(.{
        .root_module = root,
        .filters = test_filter.apply(b, &.{}),
    });
    const run = test_filter.addRun(b, tests);
    b.step(STEP_NAME, DESCRIPTION).dependOn(run);
    return run;
}
