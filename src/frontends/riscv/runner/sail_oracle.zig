//! Test-only bridge to the pinned Sail oracle (`scripts/riscv_sail_oracle.py`).
//!
//! Hands a guest ELF and the runner's canonical retirement trace to the
//! oracle process, which replays the retired instruction words through the
//! pinned Sail model over RVFI-DII and compares every architectural
//! retirement field (pc, instruction, rd, rd_value, next_pc, memory effect).
//!
//! The verdict contract is the load-bearing part. `unavailable` means the
//! pinned Sail binary cannot be consulted on this host and by default must
//! surface as a *visible skip* naming what was not checked; `divergent` and
//! `protocol_error` must fail the test. Conflating absence with disagreement
//! is how a dead oracle starts to read as coverage, which is worse than no
//! check at all.
//!
//! A gate may nonetheless refuse to accept absence. Setting
//! `STWO_ZIG_REQUIRE_SAIL_ORACLE` makes every `unavailable` verdict return
//! `error.SailOracleUnavailable` after printing the same not-checked report.
//! Absence is still absence: that error names the missing oracle and stays
//! distinct from `error.SailDisagreesWithRunner`, so a job that demands the
//! oracle goes red for the provisioning failure it actually has and never
//! borrows the language of a soundness signal. Unset, nothing changes, since
//! on a host with no pinned Sail a hard failure would be noise rather than
//! evidence.

const std = @import("std");
const trace_mod = @import("trace.zig");
const cpu_mod = @import("cpu.zig");
const trace_dump = @import("trace_dump.zig");

const ORACLE_SCRIPT_RELATIVE = "scripts/riscv_sail_oracle.py";

/// Must match `INITIAL_MEMORY_SCHEMA` in `scripts/riscv_sail_oracle.py`; a
/// drift is a loud ERROR verdict, never a silently unseeded comparison.
const INITIAL_MEMORY_SCHEMA = "stwo-riscv-initial-memory-v1";

/// One word of the memory image the runner started from. RVFI-DII injects
/// instruction words without loading the ELF, so Sail's memory begins zeroed
/// and a guest that loads runner-initialized memory (a public-input region,
/// ELF data) can only be compared after that image is seeded into Sail.
///
/// The image must come from the guest's *definition* — its ELF and declared
/// input — never from the trace's own read claims, which would make every
/// load self-fulfilling and reduce Sail to an echo of the candidate.
pub const MemoryWord = struct {
    address: u32,
    value: u32,
};

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

/// Opt-in gate switch: when set, an `unavailable` verdict is a failure.
///
/// An environment variable rather than a build option on purpose — every
/// consumer of this module is a plain `zig test` binary, so a CI job that has
/// provisioned the pinned oracle can require it without any build plumbing,
/// and a job that has not provisioned it keeps today's behaviour by doing
/// nothing.
pub const REQUIRE_AVAILABLE_ENV = "STWO_ZIG_REQUIRE_SAIL_ORACLE";

/// The two errors an `unavailable` verdict can produce. Neither is
/// `error.SailDisagreesWithRunner`: absence never speaks as disagreement.
pub const UnavailableError = error{ SkipZigTest, SailOracleUnavailable };

/// What an `unavailable` verdict means to this process.
pub const AbsencePolicy = enum {
    /// Default. Absence is a visible skip naming what went unchecked.
    skip,
    /// A gate required the oracle, so absence is a named failure.
    fail,

    /// Read `REQUIRE_AVAILABLE_ENV` from a raw value, `null` when unset.
    ///
    /// Unset, empty, `0`, `false`, `no`, and `off` (any case, surrounding
    /// whitespace ignored) keep the default skip. Every other value requires
    /// the oracle: this is a gate switch, so a value we do not recognise must
    /// fail closed rather than quietly disarm the gate a job asked for.
    pub fn fromEnvValue(raw: ?[]const u8) AbsencePolicy {
        const value = std.mem.trim(u8, raw orelse return .skip, " \t\r\n");
        if (value.len == 0) return .skip;
        for ([_][]const u8{ "0", "false", "no", "off" }) |disabled| {
            if (std.ascii.eqlIgnoreCase(value, disabled)) return .skip;
        }
        return .fail;
    }

    /// The error a call site returns once it has printed its report.
    pub fn err(self: AbsencePolicy) UnavailableError {
        return switch (self) {
            .skip => error.SkipZigTest,
            .fail => error.SailOracleUnavailable,
        };
    }
};

/// `REQUIRE_AVAILABLE_ENV` as this process sees it.
pub fn absencePolicy(allocator: std.mem.Allocator) AbsencePolicy {
    const raw = std.process.getEnvVarOwned(allocator, REQUIRE_AVAILABLE_ENV) catch |err| switch (err) {
        error.EnvironmentVariableNotFound => return .skip,
        // Fail closed: an environment we could not read is not a reason to
        // stop requiring an oracle a job explicitly asked for.
        else => return .fail,
    };
    defer allocator.free(raw);
    return AbsencePolicy.fromEnvValue(raw);
}

/// The single seam every `unavailable` verdict goes through.
///
/// `unchecked` names what did NOT happen ("the forged-trace rejection"), and
/// is printed either way: a required run must say exactly as much about the
/// gap as a skipping one, because the report is the only record of what the
/// oracle would have covered. Always returns an error.
pub fn reportUnavailable(
    allocator: std.mem.Allocator,
    unchecked: []const u8,
    report: []const u8,
) UnavailableError!void {
    const policy = absencePolicy(allocator);
    switch (policy) {
        .skip => std.debug.print(
            "SKIP: pinned Sail oracle unavailable; {s} was NOT checked.\n{s}\n",
            .{ unchecked, report },
        ),
        // Name the error in the log too: the Zig test runner prints captured
        // stderr rather than the error name, and a reader of a red CI job
        // must be able to tell this apart from a Sail disagreement.
        .fail => std.debug.print(
            "FAIL (error.SailOracleUnavailable, NOT a disagreement): pinned Sail " ++
                "oracle unavailable while " ++ REQUIRE_AVAILABLE_ENV ++
                " requires it; {s} was NOT checked.\n{s}\n",
            .{ unchecked, report },
        ),
    }
    return policy.err();
}

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
    initial_memory: []const MemoryWord,
) !Outcome {
    var json_buf: std.ArrayList(u8) = .{};
    defer json_buf.deinit(allocator);
    try trace_dump.writeTraceJson(json_buf.writer(allocator), exec_trace, final_cpu);
    return checkTraceJson(allocator, elf_bytes, json_buf.items, initial_memory);
}

/// Lower-level entry taking an already-serialized canonical trace, so a
/// mutation test can corrupt the artefact and prove the oracle says no.
pub fn checkTraceJson(
    allocator: std.mem.Allocator,
    elf_bytes: []const u8,
    trace_json: []const u8,
    initial_memory: []const MemoryWord,
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

    var argv: std.ArrayList([]const u8) = .{};
    defer argv.deinit(allocator);
    try argv.appendSlice(
        allocator,
        &.{ "python3", script, "check", "--elf", elf_path, "--trace", trace_path },
    );
    var memory_path: ?[]u8 = null;
    defer if (memory_path) |path| allocator.free(path);
    if (initial_memory.len != 0) {
        var memory_buf: std.ArrayList(u8) = .{};
        defer memory_buf.deinit(allocator);
        try writeMemoryJson(memory_buf.writer(allocator), initial_memory);
        try scratch.dir.writeFile(.{ .sub_path = "memory.json", .data = memory_buf.items });
        memory_path = try scratch.dir.realpathAlloc(allocator, "memory.json");
        try argv.appendSlice(allocator, &.{ "--memory", memory_path.? });
    }

    const run = std.process.Child.run(.{
        .allocator = allocator,
        .argv = argv.items,
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
/// oracle is absent (or fail with `error.SailOracleUnavailable` when
/// `REQUIRE_AVAILABLE_ENV` demands it), and fail loudly on disagreement or
/// harness breakage.
///
/// `guest_label` names the guest in every notice, because a skip that does
/// not say *what* went unchecked reads as coverage from the summary line.
pub fn requireAgreement(
    allocator: std.mem.Allocator,
    guest_label: []const u8,
    elf_bytes: []const u8,
    exec_trace: *const trace_mod.Trace,
    final_cpu: cpu_mod.Cpu,
    initial_memory: []const MemoryWord,
) !void {
    var outcome = try checkTrace(allocator, elf_bytes, exec_trace, final_cpu, initial_memory);
    defer outcome.deinit(allocator);
    switch (outcome.verdict) {
        .equivalent => {},
        .unavailable => {
            const unchecked = try std.fmt.allocPrint(
                allocator,
                "runner-vs-Sail agreement for guest '{s}'",
                .{guest_label},
            );
            defer allocator.free(unchecked);
            return reportUnavailable(allocator, unchecked, outcome.report);
        },
        .divergent => {
            std.debug.print(
                "Pinned Sail DISAGREES with the runner's retirement trace " ++
                    "for guest '{s}':\n{s}\n",
                .{ guest_label, outcome.report },
            );
            return error.SailDisagreesWithRunner;
        },
        .protocol_error => {
            std.debug.print(
                "Sail oracle harness failure for guest '{s}' (this is not a skip):\n{s}\n",
                .{ guest_label, outcome.report },
            );
            return error.SailOracleProtocolFailure;
        },
    }
}

/// Canonical serialization of an initial-memory image for `--memory`.
fn writeMemoryJson(writer: anytype, words: []const MemoryWord) !void {
    try writer.writeAll("{\"schema\":\"" ++ INITIAL_MEMORY_SCHEMA ++ "\",\"words\":[");
    for (words, 0..) |word, index| {
        if (index != 0) try writer.writeByte(',');
        try writer.print("{{\"address\":{d},\"value\":{d}}}", .{ word.address, word.value });
    }
    try writer.writeAll("]}");
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

// Where the two tests below run, and why it took a dedicated step.
//
// Until 2026-07-29 they ran in NO build step. `zig test` collects tests only
// from the files of its ROOT module; every RISC-V step roots at
// `src/tests.zig` and reaches this file through the `stwo_riscv_frontend`
// module dependency, and dependency modules contribute no tests. Measured:
// `zig build test-riscv-release-exhaustive
// -Driscv-test-filter="runner agrees with pinned Sail"` failed
// `EmptySelectionGuard` with "matched no test name". They are exactly the
// self-check ("does the oracle answer at all?") and the disagreement check
// ("is a forged trace really DIVERGENT?"), so the absence was this module's
// own failure mode turned on itself: a check nobody runs reads as coverage,
// and worse than a skip, because a skip at least prints.
//
// Two collections now name this file, both by root-module membership:
//
//  - `zig build test-riscv-sail-oracle` (also a dependency of
//    `test-riscv-cpu-product`) roots a test artifact directly here — see
//    `build_support/products/riscv_sail_oracle_tests.zig`. Renaming either
//    test cannot empty it: the binary carries no pinned filter to drift.
//    `.github/workflows/riscv-sail-differential.yml` runs that step with
//    `STWO_ZIG_REQUIRE_SAIL_ORACLE=1`, which is the only place on earth
//    these two tests meet a real oracle instead of skipping.
//  - The package's own `zig build test` (`src/frontends/riscv/build.zig`)
//    reaches them because `src/frontends/riscv/mod.zig` now names this file
//    inside a `test` block. The file-scope `pub const sail_oracle =
//    @import("sail_oracle.zig")` that `runner/mod.zig` has always had is not
//    enough: nothing referenced it, so it was never analysed.
//
// The `AbsencePolicy` coverage additionally lives in
// `src/tests/riscv/unit_test.zig`, which every exhaustive step collects.

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
    try requireAgreement(
        alloc,
        "sail_oracle ADDI/ADD self-test",
        &elf,
        &result.execution_trace,
        result.cpu_final,
        &.{},
    );
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

    var outcome = try checkTraceJson(alloc, &elf, forged, &.{});
    defer outcome.deinit(alloc);
    switch (outcome.verdict) {
        .divergent => {},
        .unavailable => return reportUnavailable(
            alloc,
            "the forged-trace rejection",
            outcome.report,
        ),
        else => {
            std.debug.print("expected DIVERGENT, got: {s}\n", .{outcome.report});
            return error.ForgedTraceNotRejected;
        },
    }
}

test "E-018 staged typed LUI retirement agrees with pinned Sail (skips visibly when Sail absent)" {
    const typed_lui = @import("../air/lang/typed_lui.zig");
    const typed_lui_authority = @import("../air/lang/typed_lui_authority.zig");
    const alloc = std.testing.allocator;
    const words = [_]u32{
        0x1234_50b7, // LUI x1,  0x12345
        0x8000_0fb7, // LUI x31, 0x80000
        0xffff_f037, // LUI x0,  0xfffff (architecturally discarded)
        0x0000_0073, // ECALL (host event, not a retirement in the trace)
    };
    const elf = trace_dump.buildTestElf(words.len, words);

    var definition = try typed_lui.build(alloc, .generated);
    defer definition.deinit();
    const binding = typed_lui_authority.Binding.canonical(&definition);
    const authority = try typed_lui_authority.Authority.init(&definition, &binding);

    var cpu = runner.Cpu.init(0x0001_0000, runner.elf_loader.DEFAULT_STACK_POINTER);
    var exec_trace = runner.trace.Trace.init(alloc);
    defer exec_trace.deinit();
    exec_trace.initial_pc = cpu.pc;
    var tracker = runner.state_chain.StateChainTracker.init(alloc);
    defer tracker.deinit();

    for (words[0..3], 0..) |word, index| {
        try runner.lui_retirement.retireAtomic(
            &authority,
            &cpu,
            &exec_trace,
            &tracker,
            try runner.DecodedInst.decode(word),
            word,
            @intCast(index + 1),
        );
    }
    exec_trace.final_pc = cpu.pc;

    try requireAgreement(
        alloc,
        "E-018 staged typed LUI authority",
        &elf,
        &exec_trace,
        cpu,
        &.{},
    );
}

test "E-019 staged typed FENCE retirement agrees with pinned Sail (skips visibly when Sail absent)" {
    const typed_fence = @import("../air/lang/typed_fence.zig");
    const typed_fence_authority = @import("../air/lang/typed_fence_authority.zig");
    const alloc = std.testing.allocator;
    const words = [_]u32{
        0x0000_000f, // canonical FENCE
        0xffff_8f8f, // imm=-1, reserved rs1=x31, rd=x31
        0x8a53_038f, // negative imm, reserved rs1=x6, rd=x7
        0x0008_828f, // imm=0, reserved rs1=x17, rd=x5
        0x0000_0073, // ECALL (host event, not a retirement in the trace)
    };
    const elf = trace_dump.buildTestElf(words.len, words);

    var definition = try typed_fence.build(alloc, .generated);
    defer definition.deinit();
    const binding = try typed_fence_authority.Binding.canonical(&definition);
    const authority = try typed_fence_authority.Authority.init(&definition, &binding);

    var cpu = runner.Cpu.init(0x0001_0000, runner.elf_loader.DEFAULT_STACK_POINTER);
    var exec_trace = runner.trace.Trace.init(alloc);
    defer exec_trace.deinit();
    exec_trace.initial_pc = cpu.pc;
    var tracker = runner.state_chain.StateChainTracker.init(alloc);
    defer tracker.deinit();

    for (words[0..4], 0..) |word, index| {
        try runner.fence_retirement.retireAtomic(
            &authority,
            &cpu,
            &exec_trace,
            &tracker,
            try runner.DecodedInst.decode(word),
            word,
            @intCast(index + 1),
        );
    }
    exec_trace.final_pc = cpu.pc;

    try requireAgreement(
        alloc,
        "E-019 staged typed FENCE authority",
        &elf,
        &exec_trace,
        cpu,
        &.{},
    );
}

test "E-020 staged typed BASE_ALU_IMM retirement agrees with pinned Sail (skips visibly when Sail absent)" {
    const typed_addi = @import("../air/lang/typed_addi.zig");
    const typed_authority = @import("../air/lang/typed_base_alu_imm_authority.zig");
    const alloc = std.testing.allocator;
    const words = [_]u32{
        0x8000_0093, // ADDI x1, x0, -2048
        0x7ff0_c113, // XORI x2, x1, 2047
        0xfff1_6193, // ORI  x3, x2, -1
        0x8001_f213, // ANDI x4, x3, -2048
        0x0012_8293, // ADDI x5, x5, 1 (source/destination alias)
        0xfff0_0013, // ADDI x0, x0, -1 (discarded destination)
        0x0000_0073, // ECALL (host event, not a retirement in the trace)
    };
    const elf = trace_dump.buildTestElf(words.len, words);

    var definition = try typed_addi.build(alloc, .generated);
    defer definition.deinit();
    const binding = try typed_authority.Binding.canonical(&definition);
    const authority = try typed_authority.Authority.init(&definition, &binding);

    var cpu = runner.Cpu.init(0x0001_0000, runner.elf_loader.DEFAULT_STACK_POINTER);
    var exec_trace = runner.trace.Trace.init(alloc);
    defer exec_trace.deinit();
    exec_trace.initial_pc = cpu.pc;
    var tracker = runner.state_chain.StateChainTracker.init(alloc);
    defer tracker.deinit();

    for (words[0..6], 0..) |word, index| {
        try runner.base_alu_imm_retirement.retireAtomic(
            &authority,
            &cpu,
            &exec_trace,
            &tracker,
            try runner.DecodedInst.decode(word),
            word,
            @intCast(index + 1),
        );
    }
    exec_trace.final_pc = cpu.pc;

    try requireAgreement(
        alloc,
        "E-020 staged typed BASE_ALU_IMM authority",
        &elf,
        &exec_trace,
        cpu,
        &.{},
    );
}

test "E-020 staged typed BASE_ALU_REG retirement agrees with pinned Sail (skips visibly when Sail absent)" {
    const typed_base_alu_reg = @import("../air/lang/typed_base_alu_reg.zig");
    const typed_authority = @import("../air/lang/typed_base_alu_reg_authority.zig");
    const alloc = std.testing.allocator;
    const words = [_]u32{
        0x02a0_0113, // ADDI x2, x0, 42 (synchronize runner/Sail initial x2)
        0x0001_00b3, // ADD x1, x2, x0
        0x4020_81b3, // SUB x3, x1, x2
        0x0020_c233, // XOR x4, x1, x2
        0x0000_e2b3, // OR  x5, x1, x0
        0x0020_f333, // AND x6, x1, x2
        0x0073_83b3, // ADD x7, x7, x7 (rd == rs1 == rs2)
        0x0020_8033, // ADD x0, x1, x2 (architecturally discarded)
        0x0000_0073, // ECALL (host event, not a retirement in the trace)
    };
    const elf = trace_dump.buildTestElf(words.len, words);

    var definition = try typed_base_alu_reg.build(alloc, .generated);
    defer definition.deinit();
    const binding = try typed_authority.Binding.canonical(&definition);
    const authority = try typed_authority.Authority.init(&definition, &binding);

    var cpu = runner.Cpu.init(
        0x0001_0000,
        runner.elf_loader.DEFAULT_STACK_POINTER,
    );
    var exec_trace = runner.trace.Trace.init(alloc);
    defer exec_trace.deinit();
    exec_trace.initial_pc = cpu.pc;
    var tracker = runner.state_chain.StateChainTracker.init(alloc);
    defer tracker.deinit();

    try runner.base_alu_imm_retirement.retireAtomic(
        &runner.base_alu_imm_retirement.PINNED_AUTHORITY,
        &cpu,
        &exec_trace,
        &tracker,
        try runner.DecodedInst.decode(words[0]),
        words[0],
        1,
    );
    for (words[1..8], 0..) |word, index| {
        try runner.base_alu_reg_retirement.retireAtomic(
            &authority,
            &cpu,
            &exec_trace,
            &tracker,
            try runner.DecodedInst.decode(word),
            word,
            @intCast(index + 2),
        );
    }
    exec_trace.final_pc = cpu.pc;

    try requireAgreement(
        alloc,
        "E-020 staged typed BASE_ALU_REG authority",
        &elf,
        &exec_trace,
        cpu,
        &.{},
    );
}

test "typed AUIPC retirement agrees with pinned Sail (skips visibly when Sail absent)" {
    const typed_auipc = @import("../air/lang/typed_auipc.zig");
    const typed_authority = @import("../air/lang/typed_auipc_authority.zig");
    const alloc = std.testing.allocator;
    const words = [_]u32{
        0x0000_0097, // AUIPC x1, 0
        0x7fff_f117, // AUIPC x2, 0x7ffff000
        0x8000_0f97, // AUIPC x31, 0x80000000
        0xffff_f017, // AUIPC x0, 0xfffff000 (discarded destination)
        0x0000_0073, // ECALL (host event, not a retirement in the trace)
    };
    const elf = trace_dump.buildTestElf(words.len, words);

    var definition = try typed_auipc.build(alloc, .generated);
    defer definition.deinit();
    const binding = try typed_authority.Binding.canonical(&definition);
    const authority = try typed_authority.Authority.init(&definition, &binding);

    var cpu = runner.Cpu.init(
        0x0001_0000,
        runner.elf_loader.DEFAULT_STACK_POINTER,
    );
    var exec_trace = runner.trace.Trace.init(alloc);
    defer exec_trace.deinit();
    exec_trace.initial_pc = cpu.pc;
    var tracker = runner.state_chain.StateChainTracker.init(alloc);
    defer tracker.deinit();

    for (words[0..4], 0..) |word, index| {
        try runner.auipc_retirement.retireAtomic(
            &authority,
            &cpu,
            &exec_trace,
            &tracker,
            try runner.DecodedInst.decode(word),
            word,
            @intCast(index + 1),
        );
    }
    exec_trace.final_pc = cpu.pc;

    try requireAgreement(
        alloc,
        "typed AUIPC authority",
        &elf,
        &exec_trace,
        cpu,
        &.{},
    );
}
