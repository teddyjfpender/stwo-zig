//! Closed command/report contract for the C-013 A/A admission child.
//!
//! Calibration deliberately uses the ordinary `multi_shard_addi` guest, not
//! either Poseidon2 arm. Both labels execute one identical ELF through the
//! same base-RV32IM proof path; the labels exist only to expose launch-order
//! bias before any M6 candidate sample is admitted.

const std = @import("std");
const capture = @import("capture_protocol.zig");
const report_types = @import("capture_report_types.zig");

pub const schema = "stwo.c013.aa-proof-child.v2";
pub const workload = "multi_shard_addi";
pub const default_max_steps: usize = 262_144;

pub const Label = enum { a, a_control };
pub const Phase = enum { diagnostic, calibration };

pub const Options = struct {
    label: Label,
    security: capture.Security,
    phase: Phase,
    elf_path: []const u8,
    sample_index: usize,
    max_steps: ?usize,
    expected_schedule_sha256: ?[32]u8,
    expected_elf_sha256: ?[32]u8,
    expected_executable_sha256: ?[32]u8,

    pub fn validate(self: Options) !void {
        if (self.elf_path.len == 0) return error.MissingElf;
        if (self.max_steps != null and self.max_steps.? == 0)
            return error.InvalidMaxSteps;
        if (self.phase == .calibration) {
            if (self.security != .secure) return error.InsecureCalibration;
            if (self.expected_schedule_sha256 == null or
                self.expected_elf_sha256 == null or
                self.expected_executable_sha256 == null)
            {
                return error.MissingCaptureDigestPin;
            }
            const expected = parseDigest(capture.capture_schedule_sha256) catch
                unreachable;
            if (!std.mem.eql(
                u8,
                &self.expected_schedule_sha256.?,
                &expected,
            )) return error.CaptureScheduleMismatch;
        } else if (self.expected_schedule_sha256 != null) {
            return error.DiagnosticSchedulePin;
        }
    }
};

pub fn parseOptions(args: []const []const u8) !Options {
    var label: ?Label = null;
    var security: ?capture.Security = null;
    var phase: ?Phase = null;
    var elf_path: ?[]const u8 = null;
    var sample_index: ?usize = null;
    var max_steps: ?usize = null;
    var schedule_digest: ?[32]u8 = null;
    var elf_digest: ?[32]u8 = null;
    var executable_digest: ?[32]u8 = null;
    var index: usize = 1;
    while (index < args.len) : (index += 1) {
        const argument = args[index];
        if (std.mem.eql(u8, argument, "--help") or
            std.mem.eql(u8, argument, "-h"))
        {
            return error.HelpRequested;
        } else if (std.mem.eql(u8, argument, "--label")) {
            if (label != null) return error.DuplicateArgument;
            label = try parseEnum(Label, try next(args, &index));
        } else if (std.mem.eql(u8, argument, "--security")) {
            if (security != null) return error.DuplicateArgument;
            security = try parseEnum(capture.Security, try next(args, &index));
        } else if (std.mem.eql(u8, argument, "--phase")) {
            if (phase != null) return error.DuplicateArgument;
            phase = try parseEnum(Phase, try next(args, &index));
        } else if (std.mem.eql(u8, argument, "--elf")) {
            if (elf_path != null) return error.DuplicateArgument;
            elf_path = try next(args, &index);
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
            if (schedule_digest != null) return error.DuplicateArgument;
            schedule_digest = try parseDigest(try next(args, &index));
        } else if (std.mem.eql(u8, argument, "--expected-elf-sha256")) {
            if (elf_digest != null) return error.DuplicateArgument;
            elf_digest = try parseDigest(try next(args, &index));
        } else if (std.mem.eql(u8, argument, "--expected-executable-sha256")) {
            if (executable_digest != null) return error.DuplicateArgument;
            executable_digest = try parseDigest(try next(args, &index));
        } else return error.UnknownArgument;
    }
    const options = Options{
        .label = label orelse return error.MissingLabel,
        .security = security orelse return error.MissingSecurity,
        .phase = phase orelse return error.MissingPhase,
        .elf_path = elf_path orelse return error.MissingElf,
        .sample_index = sample_index orelse return error.MissingSampleIndex,
        .max_steps = max_steps,
        .expected_schedule_sha256 = schedule_digest,
        .expected_elf_sha256 = elf_digest,
        .expected_executable_sha256 = executable_digest,
    };
    try options.validate();
    return options;
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

pub const Report = struct {
    schema: []const u8,
    status: []const u8,
    label: []const u8,
    security: []const u8,
    phase: []const u8,
    workload: []const u8,
    schedule_sha256: ?[]const u8,
    sample_index: usize,
    max_steps: usize,
    input_bytes: usize,
    output_bytes: usize,
    input_sha256: []const u8,
    output_sha256: []const u8,
    elf_sha256: []const u8,
    executable_sha256: []const u8,
    proof_sha256: []const u8,
    implementation_commit: []const u8,
    implementation_tree: ?[]const u8,
    implementation_dirty: bool,
    dirty_content_sha256: ?[]const u8,
    pcs: report_types.Pcs,
    metrics: report_types.AttemptMetrics,
    resources: report_types.Resources,

    pub fn validate(self: Report) !void {
        if (!std.mem.eql(u8, self.schema, schema) or
            !std.mem.eql(u8, self.status, "verified") or
            !std.mem.eql(u8, self.workload, workload))
        {
            return error.InvalidReportEnvelope;
        }
        _ = try parseEnum(Label, self.label);
        const security = try parseEnum(capture.Security, self.security);
        const phase = try parseEnum(Phase, self.phase);
        if (self.max_steps == 0 or self.input_bytes != 0 or
            self.output_bytes != 0)
        {
            return error.InvalidReportGeometry;
        }
        if (phase == .calibration) {
            if (security != .secure or self.implementation_dirty or
                self.implementation_tree == null or
                self.dirty_content_sha256 != null)
            {
                return error.InvalidCalibrationIdentity;
            }
            const digest = self.schedule_sha256 orelse
                return error.InvalidReportIdentity;
            if (!std.mem.eql(u8, digest, capture.capture_schedule_sha256))
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
