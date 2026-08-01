//! Command-line focus for the RISC-V test steps: `-Driscv-test-filter=<text>`.
//!
//! The exhaustive gate is tens of minutes of end-to-end proving, and in its
//! default `-Doptimize=Debug` a profile of it is dominated by Blake2s Merkle
//! commitment. Focusing it used to mean hand-editing the `TestRoot` literals in
//! `riscv_cpu.zig`, which is how a temporary `.filters = &.{"malicious prover"}`
//! once reached `addExhaustiveTests` and quietly reduced the whole adversarial
//! gate to a handful of tests while still reporting green. A command-line
//! filter removes the reason to edit that file at all.
//!
//! Fast local loop, about two orders of magnitude off the full Debug gate:
//!
//!     zig build test-riscv-release-exhaustive \
//!         -Driscv-test-filter="malicious prover" -Doptimize=ReleaseSafe
//!
//! `-Doptimize=ReleaseSafe` keeps every safety check (bounds, overflow) and
//! only drops the debug-mode slowdown, so it is a legitimate iteration
//! configuration. Gates still run what CI pins.
//!
//! Two properties worth knowing before trusting a filtered run:
//!
//!  - The flag REPLACES a step's pinned filters rather than adding to them.
//!    `filters` is an OR, so appending would broaden a scoped step instead of
//!    narrowing it, which is the opposite of what a focus flag should do. A
//!    step run under this flag is whatever the caller asked for, not the step's
//!    advertised scope.
//!  - A filter that matches nothing is a build FAILURE, not a green run. The
//!    compiler applies `filters` when it compiles the test binary, dropping
//!    every named test the text misses. An unmatched filter therefore leaves a
//!    binary holding nothing but the anonymous `test { _ = @import(...) }`
//!    aggregation blocks — those declare no name, so no filter ever excludes
//!    them — which run in milliseconds and exit 0. That is the same silent-green
//!    shape the flag exists to prevent, so every filtered run carries
//!    `EmptySelectionGuard`: it reads the test-name table the build runner
//!    already collects over the test runner's IPC channel and fails the build
//!    unless some executed test name contains the filter text. The guard is
//!    attached only when `-Driscv-test-filter` is supplied; an unfiltered gate
//!    run keeps exactly the steps, caching and runtime it had before.
//!
//! The guard covers the flag, not the pinned literals: a step whose own
//! `TestRoot.filters` stopped matching still reports green. Those literals are
//! reviewed source, and guarding them would put a new failure mode in the
//! unfiltered gate path.
//!
//! ## The same shape without a filter
//!
//! A test binary that compiled almost nothing exits 0 in milliseconds, exactly
//! like the unmatched-filter case, and nothing about the build output tells them
//! apart. That is not hypothetical here: every test under `src/frontends/riscv`
//! -- the largest test body in the repository -- was absent from every product
//! gate, and 142 of them were absent from the frontend package's own `test` step
//! too, for as long as both existed. So a `Suite` may also declare the fewest
//! tests its artifact must contain, and the same guard fails the build when the
//! binary comes up short.

const std = @import("std");

/// The filter set for one test step: the caller's `-Driscv-test-filter` when
/// present, otherwise whatever the step pinned for itself.
pub fn apply(b: *std.Build, pinned: []const []const u8) []const []const u8 {
    const requested = read(b) orelse return pinned;
    return b.allocator.dupe([]const u8, &.{requested}) catch @panic("out of memory");
}

/// One test artifact a RISC-V step runs, plus what the step guarantees about it.
pub const Suite = struct {
    tests: *std.Build.Step.Compile,
    /// Fewest named tests this artifact must contain in an unfiltered run; zero
    /// declines the floor.
    ///
    /// A floor exists because a test binary that compiled almost nothing is
    /// indistinguishable from one that ran everything: both exit 0 in
    /// milliseconds. `src/frontends/riscv/**` spent its whole life in that
    /// state, so the count is asserted rather than assumed.
    minimum: usize = 0,
};

/// Run one RISC-V test artifact and return the step to depend on.
pub fn addRun(b: *std.Build, tests: *std.Build.Step.Compile) *std.Build.Step {
    return addSuites(b, &.{.{ .tests = tests }});
}

/// Run every suite of one step and return the single step to depend on.
///
/// Guarding *per step* rather than per artifact is load-bearing once a step runs
/// more than one: `-Driscv-test-filter` is satisfied by a match in any suite of
/// the step, and demanding one per artifact would fail a correct focus run
/// simply because the other artifact holds no test of that name.
pub fn addSuites(b: *std.Build, suites: []const Suite) *std.Build.Step {
    const runs = b.allocator.alloc(*std.Build.Step.Run, suites.len) catch
        @panic("out of memory");
    // Retained, not borrowed: callers pass an anonymous array literal, whose
    // storage is the caller's frame and is gone by the time the guard runs. The
    // first draft read that memory and demanded 12297829382473034410 tests.
    const retained = b.allocator.dupe(Suite, suites) catch @panic("out of memory");
    const filter = read(b);
    var guarded = filter != null;
    for (suites, runs) |suite, *run| {
        run.* = b.addRunArtifact(suite.tests);
        // Production ReleaseFast proving avoids re-evaluating the direct AIR
        // before commitment. RISC-V test/CI runs deliberately restore that
        // diagnostic pass so malformed generated witnesses keep their exact
        // early-rejection coverage in every optimization mode.
        run.*.setEnvironmentVariable(
            "STWO_ZIG_RISCV_AUDIT_OPCODE_WITNESS",
            "1",
        );
        if (suite.minimum != 0) guarded = true;
    }
    // Both duties read the run's test-name table, which only the invocation that
    // actually executed the binary populates: a cache hit leaves it null and
    // would fail closed on every repeat of a *correct* run. Marking the runs
    // side-effecting keeps them out of the run cache so the table is always
    // real. Executing a suite that is already compiled costs its runtime only,
    // and a step that asserts nothing keeps the run cache it had before.
    if (guarded) {
        for (runs) |run| run.has_side_effects = true;
    }

    const guard = b.allocator.create(SelectionGuard) catch @panic("out of memory");
    guard.* = .{
        .step = std.Build.Step.init(.{
            .id = .custom,
            .name = "riscv test suite guard",
            .owner = b,
            .makeFn = SelectionGuard.make,
        }),
        .suites = retained,
        .runs = runs,
        .filter = filter,
    };
    for (runs) |run| guard.step.dependOn(&run.step);
    return &guard.step;
}

/// Turns "the filter matched nothing" and "the binary lost its tests" from a
/// zero exit into named failures.
const SelectionGuard = struct {
    step: std.Build.Step,
    suites: []const Suite,
    runs: []const *std.Build.Step.Run,
    filter: ?[]const u8,

    fn make(step: *std.Build.Step, _: std.Build.Step.MakeOptions) anyerror!void {
        const guard: *SelectionGuard = @fieldParentPtr("step", step);
        if (guard.filter) |filter| return guard.checkSelection(step, filter);
        for (guard.suites, guard.runs) |suite, run| {
            if (suite.minimum == 0) continue;
            const metadata = run.cached_test_metadata orelse return step.fail(
                "{s}: the run reported no test names, so its test count could not be verified",
                .{run.producer.?.name},
            );
            if (metadata.names.len >= suite.minimum) continue;
            return step.fail(
                \\{s} compiled {d} tests; this step requires at least {d}.
                \\  A test binary that compiled almost nothing still exits 0, so the count is
                \\  the only thing that distinguishes "ran the suite" from "ran an empty shell".
                \\  Either the module's test aggregation dropped files, or the floor in
                \\  build_support/products/ is stale and should be moved deliberately.
            , .{ run.producer.?.name, metadata.names.len, suite.minimum });
        }
    }

    fn checkSelection(guard: *SelectionGuard, step: *std.Build.Step, filter: []const u8) !void {
        var reported = false;
        // Same substring rule the compiler used to decide what to compile in,
        // over the same fully qualified names, so a match here means the filter
        // selected something and not just the always-present anonymous blocks.
        for (guard.runs) |run| {
            const metadata = run.cached_test_metadata orelse continue;
            reported = true;
            for (0..metadata.names.len) |index| {
                const name = metadata.testName(@intCast(index));
                if (std.mem.indexOf(u8, name, filter) != null) return;
            }
        }
        if (!reported) return step.fail(
            "-Driscv-test-filter='{s}': no run reported test names, so the selection could not be verified",
            .{filter},
        );
        return step.fail(
            \\-Driscv-test-filter='{s}' matched no test name in any suite of this step.
            \\  The compiler dropped every named test, leaving only unnamed aggregation
            \\  blocks, so the suite exits 0 without proving anything. Correct the filter
            \\  text, or drop the flag to run the step's own pinned scope.
        , .{filter});
    }
};

/// `std.Build.option` panics if the same option name is declared twice and
/// every test step routes through `apply`, so the flag is read once and the
/// answer reused. Build-graph construction is single-threaded, which is what
/// makes this safe.
var state: union(enum) { unread, known: ?[]const u8 } = .unread;

fn read(b: *std.Build) ?[]const u8 {
    switch (state) {
        .unread => {
            const value = b.option(
                []const u8,
                "riscv-test-filter",
                "Run RISC-V tests whose names contain this text",
            );
            state = .{ .known = value };
            return value;
        },
        .known => |value| return value,
    }
}
