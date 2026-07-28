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

const std = @import("std");

/// The filter set for one test step: the caller's `-Driscv-test-filter` when
/// present, otherwise whatever the step pinned for itself.
pub fn apply(b: *std.Build, pinned: []const []const u8) []const []const u8 {
    const requested = read(b) orelse return pinned;
    return b.allocator.dupe([]const u8, &.{requested}) catch @panic("out of memory");
}

/// Run one RISC-V test artifact and return the step to depend on. Unfiltered,
/// that is the plain run, unchanged. Under `-Driscv-test-filter` it is a guard
/// that fails the build when the filter selected no test.
pub fn addRun(b: *std.Build, tests: *std.Build.Step.Compile) *std.Build.Step {
    const run = b.addRunArtifact(tests);
    const requested = read(b) orelse return &run.step;

    // The guard reads the run's test-name table, which only the invocation that
    // actually executed the binary populates: a cache hit leaves it null and
    // would fail closed on every repeat of a *correct* filter. Marking the run
    // side-effecting keeps it out of the run cache so the table is always real.
    // Re-executing is what a focus run wants anyway; gate runs never get here.
    run.has_side_effects = true;

    const guard = b.allocator.create(EmptySelectionGuard) catch @panic("out of memory");
    guard.* = .{
        .step = std.Build.Step.init(.{
            .id = .custom,
            .name = "riscv-test-filter selection guard",
            .owner = b,
            .makeFn = EmptySelectionGuard.make,
        }),
        .run = run,
        .filter = requested,
    };
    guard.step.dependOn(&run.step);
    return &guard.step;
}

/// Turns "the filter matched nothing" from a zero exit into a named failure.
const EmptySelectionGuard = struct {
    step: std.Build.Step,
    run: *std.Build.Step.Run,
    filter: []const u8,

    fn make(step: *std.Build.Step, _: std.Build.Step.MakeOptions) anyerror!void {
        const guard: *EmptySelectionGuard = @fieldParentPtr("step", step);
        // Same substring rule the compiler used to decide what to compile in,
        // over the same fully qualified names, so a match here means the filter
        // selected something and not just the always-present anonymous blocks.
        if (guard.run.cached_test_metadata) |metadata| {
            for (0..metadata.names.len) |index| {
                const name = metadata.testName(@intCast(index));
                if (std.mem.indexOf(u8, name, guard.filter) != null) return;
            }
            return step.fail(
                \\-Driscv-test-filter='{s}' matched no test name.
                \\  The compiler dropped every named test, leaving only unnamed aggregation
                \\  blocks, so the suite exits 0 without proving anything. Correct the filter
                \\  text, or drop the flag to run the step's own pinned scope.
            , .{guard.filter});
        }
        return step.fail(
            "-Driscv-test-filter='{s}': the run reported no test names, so the selection could not be verified",
            .{guard.filter},
        );
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
