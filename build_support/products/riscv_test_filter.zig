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
//!  - **A filter that matches nothing exits 0.** The test runner reports
//!    success for an empty selection, so a typo is indistinguishable from a
//!    passing suite — verified: `-Driscv-test-filter=zzz-no-such-test` returns
//!    0. Read the runtime, not just the exit code, and never let this flag
//!    stand in for a gate. That is the same silent-green shape the flag exists
//!    to prevent, moved rather than removed; enforcing a non-empty selection
//!    would need a run wrapper that counts executed tests.

const std = @import("std");

/// The filter set for one test step: the caller's `-Driscv-test-filter` when
/// present, otherwise whatever the step pinned for itself.
pub fn apply(b: *std.Build, pinned: []const []const u8) []const []const u8 {
    const requested = read(b) orelse return pinned;
    return b.allocator.dupe([]const u8, &.{requested}) catch @panic("out of memory");
}

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
