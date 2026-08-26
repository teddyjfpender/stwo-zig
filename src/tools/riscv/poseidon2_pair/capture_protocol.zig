//! Closed command/report protocol for one fresh C-013 CPU proof child.
//!
//! This is capture infrastructure, not a promotion receipt.  It makes arm,
//! security, phase, shape, corpus identity, and sample order explicit so a
//! later orchestrator cannot reinterpret an emitted attempt.

const std = @import("std");
const corpus = @import("corpus.zig");
const report_types = @import("capture_report_types.zig");

pub const schema = "stwo.c013.poseidon2-cpu-proof-child.v3";
pub const resource_scope =
    "verified-arm:execution+proof+encoding+independent-verification";
pub const capture_schedule_sha256 =
    "20153896cdcc903d6784499fba267f0ff5c8e532573b9b415b28121352775dd4";

pub const Arm = enum {
    software,
    precompile,
};

pub const Security = enum {
    functional,
    secure,
};

pub const Phase = enum {
    diagnostic,
    calibration,
    warmup,
    measured,

    pub fn requiresPins(self: Phase) bool {
        return self != .diagnostic;
    }
};

pub const Shape = enum {
    core_only,
    balanced_core_and_poseidon2,
    poseidon2_dominant,

    /// Exact portable Poseidon2 permutations executed in addition to the one
    /// compared software/precompile operation for every corpus state.
    pub fn backgroundPermutationsPerCall(self: Shape) usize {
        return switch (self) {
            .core_only => 15,
            .balanced_core_and_poseidon2 => 1,
            .poseidon2_dominant => 0,
        };
    }
};

pub const Options = struct {
    arm: Arm,
    security: Security,
    phase: Phase,
    shape: Shape,
    elf_path: []const u8,
    calls: usize,
    sample_index: usize,
    max_steps: ?usize,
    expected_schedule_sha256: ?[32]u8,
    expected_input_sha256: ?[32]u8,
    expected_output_sha256: ?[32]u8,
    expected_elf_sha256: ?[32]u8,
    expected_executable_sha256: ?[32]u8,

    pub fn validate(self: Options) !void {
        if (self.elf_path.len == 0) return error.MissingElf;
        if (self.calls > corpus.maximum_calls) return error.CallCountOutOfRange;
        if (self.max_steps != null and self.max_steps.? == 0)
            return error.InvalidMaxSteps;
        if (self.phase == .calibration) return error.InvalidChildPhase;
        if (self.phase.requiresPins() and self.security != .secure)
            return error.InsecureCapture;
        if (self.phase.requiresPins() and
            (self.expected_schedule_sha256 == null or
                self.expected_input_sha256 == null or
                self.expected_output_sha256 == null or
                self.expected_elf_sha256 == null or
                self.expected_executable_sha256 == null))
        {
            return error.MissingCaptureDigestPin;
        }
        if (self.expected_schedule_sha256) |actual| {
            const expected = parseDigest(capture_schedule_sha256) catch
                unreachable;
            if (!std.mem.eql(u8, &actual, &expected))
                return error.CaptureScheduleMismatch;
        }
    }
};

pub fn parseOptions(args: []const []const u8) !Options {
    var arm: ?Arm = null;
    var security: ?Security = null;
    var phase: ?Phase = null;
    var shape: ?Shape = null;
    var elf_path: ?[]const u8 = null;
    var calls: ?usize = null;
    var sample_index: ?usize = null;
    var max_steps: ?usize = null;
    var expected_schedule: ?[32]u8 = null;
    var expected_input: ?[32]u8 = null;
    var expected_output: ?[32]u8 = null;
    var expected_elf: ?[32]u8 = null;
    var expected_executable: ?[32]u8 = null;
    var index: usize = 1;
    while (index < args.len) : (index += 1) {
        const argument = args[index];
        if (std.mem.eql(u8, argument, "--help") or
            std.mem.eql(u8, argument, "-h"))
        {
            return error.HelpRequested;
        } else if (std.mem.eql(u8, argument, "--arm")) {
            if (arm != null) return error.DuplicateArgument;
            arm = try parseEnum(Arm, try next(args, &index));
        } else if (std.mem.eql(u8, argument, "--security")) {
            if (security != null) return error.DuplicateArgument;
            security = try parseEnum(Security, try next(args, &index));
        } else if (std.mem.eql(u8, argument, "--phase")) {
            if (phase != null) return error.DuplicateArgument;
            phase = try parseEnum(Phase, try next(args, &index));
        } else if (std.mem.eql(u8, argument, "--shape")) {
            if (shape != null) return error.DuplicateArgument;
            shape = try parseEnum(Shape, try next(args, &index));
        } else if (std.mem.eql(u8, argument, "--elf")) {
            if (elf_path != null) return error.DuplicateArgument;
            elf_path = try next(args, &index);
        } else if (std.mem.eql(u8, argument, "--calls")) {
            if (calls != null) return error.DuplicateArgument;
            calls = try std.fmt.parseInt(usize, try next(args, &index), 10);
        } else if (std.mem.eql(u8, argument, "--sample-index")) {
            if (sample_index != null) return error.DuplicateArgument;
            sample_index = try std.fmt.parseInt(
                usize,
                try next(args, &index),
                10,
            );
        } else if (std.mem.eql(u8, argument, "--max-steps")) {
            if (max_steps != null) return error.DuplicateArgument;
            max_steps = try std.fmt.parseInt(usize, try next(args, &index), 10);
        } else if (std.mem.eql(u8, argument, "--schedule-sha256")) {
            if (expected_schedule != null) return error.DuplicateArgument;
            expected_schedule = try parseDigest(try next(args, &index));
        } else if (std.mem.eql(u8, argument, "--expected-input-sha256")) {
            if (expected_input != null) return error.DuplicateArgument;
            expected_input = try parseDigest(try next(args, &index));
        } else if (std.mem.eql(u8, argument, "--expected-output-sha256")) {
            if (expected_output != null) return error.DuplicateArgument;
            expected_output = try parseDigest(try next(args, &index));
        } else if (std.mem.eql(u8, argument, "--expected-elf-sha256")) {
            if (expected_elf != null) return error.DuplicateArgument;
            expected_elf = try parseDigest(try next(args, &index));
        } else if (std.mem.eql(u8, argument, "--expected-executable-sha256")) {
            if (expected_executable != null) return error.DuplicateArgument;
            expected_executable = try parseDigest(try next(args, &index));
        } else return error.UnknownArgument;
    }
    const result = Options{
        .arm = arm orelse return error.MissingArm,
        .security = security orelse return error.MissingSecurity,
        .phase = phase orelse return error.MissingPhase,
        .shape = shape orelse return error.MissingShape,
        .elf_path = elf_path orelse return error.MissingElf,
        .calls = calls orelse return error.MissingCallCount,
        .sample_index = sample_index orelse return error.MissingSampleIndex,
        .max_steps = max_steps,
        .expected_schedule_sha256 = expected_schedule,
        .expected_input_sha256 = expected_input,
        .expected_output_sha256 = expected_output,
        .expected_elf_sha256 = expected_elf,
        .expected_executable_sha256 = expected_executable,
    };
    try result.validate();
    return result;
}

fn next(args: []const []const u8, index: *usize) ![]const u8 {
    if (index.* + 1 >= args.len) return error.MissingArgumentValue;
    index.* += 1;
    return args[index.*];
}

fn parseEnum(comptime T: type, text: []const u8) !T {
    inline for (std.meta.tags(T)) |value| {
        if (std.mem.eql(u8, text, @tagName(value))) return value;
    }
    return error.InvalidEnumValue;
}

fn parseDigest(text: []const u8) ![32]u8 {
    if (text.len != 64) return error.InvalidDigest;
    var result: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, text) catch return error.InvalidDigest;
    return result;
}

pub const AttemptMetrics = report_types.AttemptMetrics;
pub const Pcs = report_types.Pcs;
pub const Resources = report_types.Resources;

pub const Report = struct {
    schema: []const u8,
    status: []const u8,
    arm: []const u8,
    security: []const u8,
    phase: []const u8,
    shape: []const u8,
    background_permutations_per_call: usize,
    schedule_sha256: ?[]const u8,
    calls: usize,
    sample_index: usize,
    max_steps: usize,
    input_bytes: usize,
    output_bytes: usize,
    extension_calls: usize,
    input_sha256: []const u8,
    output_sha256: []const u8,
    elf_sha256: []const u8,
    executable_sha256: []const u8,
    proof_sha256: []const u8,
    implementation_commit: []const u8,
    implementation_tree: ?[]const u8,
    implementation_dirty: bool,
    dirty_content_sha256: ?[]const u8,
    pcs: Pcs,
    metrics: AttemptMetrics,
    resources: Resources,

    pub fn validate(self: Report) !void {
        if (!std.mem.eql(u8, self.schema, schema) or
            !std.mem.eql(u8, self.status, "verified"))
        {
            return error.InvalidReportEnvelope;
        }
        const arm = try parseEnum(Arm, self.arm);
        const security = try parseEnum(Security, self.security);
        const phase = try parseEnum(Phase, self.phase);
        const shape = try parseEnum(Shape, self.shape);
        if (self.calls > corpus.maximum_calls or self.max_steps == 0)
            return error.InvalidReportGeometry;
        const expected_input = try std.math.add(
            usize,
            @sizeOf(u32),
            try std.math.mul(usize, self.calls, corpus.lanes * @sizeOf(u32)),
        );
        const expected_output = try std.math.mul(
            usize,
            self.calls,
            corpus.lanes * @sizeOf(u32),
        );
        if (self.background_permutations_per_call !=
            shape.backgroundPermutationsPerCall() or
            self.input_bytes != expected_input or
            self.output_bytes != expected_output or
            self.extension_calls != if (arm == .precompile) self.calls else 0)
        {
            return error.InvalidReportGeometry;
        }
        if (phase.requiresPins()) {
            if (security != .secure or self.implementation_dirty or
                self.implementation_tree == null or
                self.dirty_content_sha256 != null)
            {
                return error.InvalidCaptureIdentity;
            }
            const schedule_digest = self.schedule_sha256 orelse
                return error.InvalidReportIdentity;
            if (!std.mem.eql(u8, schedule_digest, capture_schedule_sha256))
                return error.InvalidReportIdentity;
        } else if (self.schedule_sha256 != null) {
            return error.InvalidReportIdentity;
        }
        const execution_and_proving = try std.math.add(
            u64,
            self.metrics.execution_ns,
            self.metrics.proving_ns,
        );
        const verified = try std.math.add(
            u64,
            execution_and_proving,
            self.metrics.verification_ns,
        );
        if (verified == 0 or verified != self.metrics.verified_request_ns or
            self.metrics.proof_wire_bytes == 0)
        {
            return error.InvalidReportTiming;
        }
        inline for (.{
            self.input_sha256,
            self.output_sha256,
            self.elf_sha256,
            self.executable_sha256,
            self.proof_sha256,
        }) |digest| if (digest.len != 64) return error.InvalidReportDigest;
        if (self.implementation_commit.len != 40 or
            (self.implementation_tree != null and
                self.implementation_tree.?.len != 40) or
            self.implementation_dirty != (self.dirty_content_sha256 != null))
        {
            return error.InvalidReportIdentity;
        }
    }
};
