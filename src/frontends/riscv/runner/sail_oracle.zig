//! Test-only bridge to the pinned Sail oracle (`scripts/riscv_sail_oracle.py`).
//!
//! Hands a guest ELF and the runner's canonical retirement trace to the
//! oracle process, which replays the retired instruction words through the
//! pinned Sail model over RVFI-DII and compares every architectural
//! retirement field (pc, instruction, rd, rd_value, next_pc, memory effect).
//!
//! The verdict contract is the load-bearing part. `unavailable` means the
//! pinned Sail binary cannot be consulted on this host and must surface as a
//! *visible skip* naming what was not checked; `divergent` and
//! `protocol_error` must fail the test. Conflating absence with disagreement
//! is how a dead oracle starts to read as coverage, which is worse than no
//! check at all.

const std = @import("std");
const trace_mod = @import("trace.zig");
const cpu_mod = @import("cpu.zig");
const trace_dump = @import("trace_dump.zig");

const ORACLE_SCRIPT_RELATIVE = "scripts/riscv_sail_oracle.py";

/// Exit-code contract shared with `scripts/riscv_sail_oracle.py`:
/// 0 EQUIVALENT, 1 DIVERGENT, 2 ERROR, 3 UNAVAILABLE.
pub const Verdict = enum {
    /// Sail retired the identical sequence on every compared field.
    equivalent,
    /// Sail was consulted and contradicts the trace: a soundness signal.
    divergent,
    /// The pinned Sail binary cannot be consulted on this host.
    unavailable,
    /// The harness or the RVFI-DII transport is broken. Never a skip: a
    /// broken harness that skipped would be indistinguishable from coverage.
    protocol_error,
};

pub const Outcome = struct {
    verdict: Verdict,
    /// The oracle's JSON report (its stdout), or its stderr when stdout is
    /// empty, or a synthesized reason when the process could not start.
    /// Caller-owned.
    report: []u8,

    pub fn deinit(self: *Outcome, allocator: std.mem.Allocator) void {
        allocator.free(self.report);
        self.* = undefined;
    }
};

/// Ask the pinned Sail model whether it agrees with one runner execution.
/// Serializes the trace exactly as `riscv-trace-dump` would, so the oracle
/// sees the same canonical artefact in-process tests and CLI runs produce.
pub fn checkTrace(
    allocator: std.mem.Allocator,
    elf_bytes: []const u8,
    exec_trace: *const trace_mod.Trace,
    final_cpu: cpu_mod.Cpu,
) !Outcome {
    var json_buf: std.ArrayList(u8) = .{};
    defer json_buf.deinit(allocator);
    try trace_dump.writeTraceJson(json_buf.writer(allocator), exec_trace, final_cpu);
    return checkTraceJson(allocator, elf_bytes, json_buf.items);
}

/// Lower-level entry taking an already-serialized canonical trace, so a
/// mutation test can corrupt the artefact and prove the oracle says no.
pub fn checkTraceJson(
    allocator: std.mem.Allocator,
    elf_bytes: []const u8,
    trace_json: []const u8,
) !Outcome {
    const script = try findOracleScript(allocator);
    defer allocator.free(script);

    var scratch = std.testing.tmpDir(.{});
    defer scratch.cleanup();
    try scratch.dir.writeFile(.{ .sub_path = "guest.elf", .data = elf_bytes });
    try scratch.dir.writeFile(.{ .sub_path = "trace.json", .data = trace_json });
    const elf_path = try scratch.dir.realpathAlloc(allocator, "guest.elf");
    defer allocator.free(elf_path);
    const trace_path = try scratch.dir.realpathAlloc(allocator, "trace.json");
    defer allocator.free(trace_path);

    const run = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &.{ "python3", script, "check", "--elf", elf_path, "--trace", trace_path },
        .max_output_bytes = 1 << 20,
    }) catch |err| switch (err) {
        // No python3 is the same class of absence as no Sail binary: the
        // oracle cannot be consulted, and the caller must skip visibly.
        error.FileNotFound => return .{
            .verdict = .unavailable,
            .report = try allocator.dupe(u8, "python3 not found on PATH; Sail oracle not consulted"),
        },
        else => return err,
    };
    errdefer allocator.free(run.stdout);
    defer allocator.free(run.stderr);

    const verdict: Verdict = switch (run.term) {
        .Exited => |code| switch (code) {
            0 => .equivalent,
            1 => .divergent,
            3 => .unavailable,
            else => .protocol_error,
        },
        else => .protocol_error,
    };
    if (run.stdout.len != 0) return .{ .verdict = verdict, .report = run.stdout };
    const report = try allocator.dupe(u8, run.stderr);
    allocator.free(run.stdout);
    return .{ .verdict = verdict, .report = report };
}

/// The consumer-facing seam: pass on agreement, skip VISIBLY when the pinned
/// oracle is absent, and fail loudly on disagreement or harness breakage.
pub fn requireAgreement(
    allocator: std.mem.Allocator,
    elf_bytes: []const u8,
    exec_trace: *const trace_mod.Trace,
    final_cpu: cpu_mod.Cpu,
) !void {
    var outcome = try checkTrace(allocator, elf_bytes, exec_trace, final_cpu);
    defer outcome.deinit(allocator);
    switch (outcome.verdict) {
        .equivalent => {},
        .unavailable => {
            std.debug.print(
                "SKIP: pinned Sail oracle unavailable; runner-vs-Sail agreement " ++
                    "was NOT checked for this guest.\n{s}\n",
                .{outcome.report},
            );
            return error.SkipZigTest;
        },
        .divergent => {
            std.debug.print(
                "Pinned Sail DISAGREES with the runner's retirement trace:\n{s}\n",
                .{outcome.report},
            );
            return error.SailDisagreesWithRunner;
        },
        .protocol_error => {
            std.debug.print(
                "Sail oracle harness failure (this is not a skip):\n{s}\n",
                .{outcome.report},
            );
            return error.SailOracleProtocolFailure;
        },
    }
}

/// Locate the oracle script by a bounded upward walk from the cwd: test
/// binaries run either at the repository root (`zig test`) or inside a cache
/// directory beneath it (`zig build`). A missing script is a harness error,
/// never an oracle absence, so it must not be classified as `unavailable`.
fn findOracleScript(allocator: std.mem.Allocator) ![]u8 {
    var cwd_buf: [std.fs.max_path_bytes]u8 = undefined;
    var dir: []const u8 = try std.process.getCwd(&cwd_buf);
    var depth: usize = 0;
    while (depth < 16) : (depth += 1) {
        const candidate = try std.fs.path.join(allocator, &.{ dir, ORACLE_SCRIPT_RELATIVE });
        if (std.fs.accessAbsolute(candidate, .{})) |_| {
            return candidate;
        } else |_| {
            allocator.free(candidate);
        }
        dir = std.fs.path.dirname(dir) orelse return error.OracleScriptNotFound;
    }
    return error.OracleScriptNotFound;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const runner = @import("mod.zig");

test "sail_oracle: runner agrees with pinned Sail on a small guest (skips visibly when Sail absent; ~0.3s when present)" {
    const alloc = std.testing.allocator;
    const elf = trace_dump.buildTestElf(4, .{
        0x00A00093, // ADDI x1, x0, 10
        0x01400113, // ADDI x2, x0, 20
        0x002081B3, // ADD  x3, x1, x2
        0x00000073, // ECALL (host event, not a retirement in the trace)
    });
    var result = try runner.run(alloc, &elf, 1000);
    defer result.deinit();
    try requireAgreement(alloc, &elf, &result.execution_trace, result.cpu_final);
}

test "sail_oracle: a forged integer write is DIVERGENT, never a pass or a skip (~0.3s when present)" {
    const alloc = std.testing.allocator;
    const elf = trace_dump.buildTestElf(4, .{
        0x00A00093, // ADDI x1, x0, 10
        0x01400113, // ADDI x2, x0, 20
        0x002081B3, // ADD  x3, x1, x2 = 30
        0x00000073, // ECALL
    });
    var result = try runner.run(alloc, &elf, 1000);
    defer result.deinit();

    var honest: std.ArrayList(u8) = .{};
    defer honest.deinit(alloc);
    try trace_dump.writeTraceJson(honest.writer(alloc), &result.execution_trace, result.cpu_final);

    // Claim ADD retired 31 instead of 30. `writeTraceJson` output is
    // deterministic, so the textual field is a stable mutation point.
    const forged = try std.mem.replaceOwned(u8, alloc, honest.items, "\"rd_value\":30", "\"rd_value\":31");
    defer alloc.free(forged);
    try std.testing.expect(!std.mem.eql(u8, honest.items, forged));

    var outcome = try checkTraceJson(alloc, &elf, forged);
    defer outcome.deinit(alloc);
    switch (outcome.verdict) {
        .divergent => {},
        .unavailable => {
            std.debug.print(
                "SKIP: pinned Sail oracle unavailable; the forged-trace rejection " ++
                    "was NOT checked.\n{s}\n",
                .{outcome.report},
            );
            return error.SkipZigTest;
        },
        else => {
            std.debug.print("expected DIVERGENT, got: {s}\n", .{outcome.report});
            return error.ForgedTraceNotRejected;
        },
    }
}
