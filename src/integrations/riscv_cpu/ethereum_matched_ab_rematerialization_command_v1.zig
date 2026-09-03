//! Typed CLI for the capture-only matched A/B rematerialization transaction.

const std = @import("std");

const artifact_io = @import("ethereum_precompile_artifact_io.zig");
const authority =
    @import("ethereum_matched_ab_rematerialization_authority_v1.zig");
const controller =
    @import("ethereum_matched_ab_rematerialization_controller_v1.zig");

pub const command_name = "ethereum-matched-ab-rematerialize-capture-v1";
pub const minimum_hard_cap_seconds: u64 = 600;
pub const maximum_hard_cap_seconds: u64 = 3_600;

pub fn run(allocator: std.mem.Allocator, arguments: []const []const u8) !void {
    var options = try Options.parseAndResolve(allocator, arguments);
    defer options.deinit(allocator);
    try controller.captureBoth(allocator, options.captureOptions());
}

const Options = struct {
    baseline_elf: []u8,
    candidate_admission_receipt: []u8,
    candidate_elf: []u8,
    expected_output: []u8,
    historical_baseline_materialization: []u8,
    input: []u8,
    output_root: []u8,
    power_source: []const u8,
    candidate_hard_cap_ns: u64,

    fn captureOptions(self: Options) controller.Options {
        return .{
            .baseline_elf = self.baseline_elf,
            .candidate_admission_receipt = self.candidate_admission_receipt,
            .candidate_elf = self.candidate_elf,
            .expected_output = self.expected_output,
            .historical_baseline_materialization = self.historical_baseline_materialization,
            .input = self.input,
            .output_root = self.output_root,
            .power_source = self.power_source,
            .candidate_hard_cap_ns = self.candidate_hard_cap_ns,
        };
    }

    fn parseAndResolve(
        allocator: std.mem.Allocator,
        arguments: []const []const u8,
    ) !Options {
        if (arguments.len != 20) return error.InvalidArguments;
        var baseline_elf: ?[]const u8 = null;
        var candidate_receipt: ?[]const u8 = null;
        var candidate_elf: ?[]const u8 = null;
        var expected_output: ?[]const u8 = null;
        var historical: ?[]const u8 = null;
        var input: ?[]const u8 = null;
        var output_root: ?[]const u8 = null;
        var power_source: ?[]const u8 = null;
        var segment_step_budget: ?usize = null;
        var hard_cap_seconds: ?u64 = null;
        var cursor: usize = 0;
        while (cursor < arguments.len) : (cursor += 2) {
            const name = arguments[cursor];
            const value = arguments[cursor + 1];
            if (value.len == 0) return error.InvalidArguments;
            if (std.mem.eql(u8, name, "--baseline-elf")) {
                try set(&baseline_elf, value);
            } else if (std.mem.eql(u8, name, "--candidate-receipt")) {
                try set(&candidate_receipt, value);
            } else if (std.mem.eql(u8, name, "--candidate-elf")) {
                try set(&candidate_elf, value);
            } else if (std.mem.eql(u8, name, "--expected-output")) {
                try set(&expected_output, value);
            } else if (std.mem.eql(
                u8,
                name,
                "--historical-baseline-materialization",
            )) {
                try set(&historical, value);
            } else if (std.mem.eql(u8, name, "--input")) {
                try set(&input, value);
            } else if (std.mem.eql(u8, name, "--output-root")) {
                try set(&output_root, value);
            } else if (std.mem.eql(u8, name, "--power-source")) {
                try set(&power_source, value);
            } else if (std.mem.eql(u8, name, "--segment-step-budget")) {
                if (segment_step_budget != null)
                    return error.DuplicateArgument;
                segment_step_budget = std.fmt.parseUnsigned(
                    usize,
                    value,
                    10,
                ) catch return error.InvalidArguments;
            } else if (std.mem.eql(u8, name, "--hard-cap-seconds")) {
                if (hard_cap_seconds != null) return error.DuplicateArgument;
                hard_cap_seconds = std.fmt.parseUnsigned(
                    u64,
                    value,
                    10,
                ) catch return error.InvalidArguments;
            } else return error.InvalidArguments;
        }
        if ((segment_step_budget orelse return error.InvalidArguments) !=
            authority.segment_step_budget)
        {
            return error.InvalidArguments;
        }
        const power = power_source orelse return error.InvalidArguments;
        if (!std.mem.eql(u8, power, "ac") and
            !std.mem.eql(u8, power, "battery"))
        {
            return error.InvalidArguments;
        }
        const seconds = hard_cap_seconds orelse return error.InvalidArguments;
        if (seconds < minimum_hard_cap_seconds or
            seconds > maximum_hard_cap_seconds)
        {
            return error.InvalidArguments;
        }
        const hard_cap_ns = std.math.mul(
            u64,
            seconds,
            std.time.ns_per_s,
        ) catch return error.InvalidArguments;

        var paths: [7][]u8 = undefined;
        var initialized: usize = 0;
        errdefer for (paths[0..initialized]) |path| allocator.free(path);
        inline for (.{
            baseline_elf,
            candidate_receipt,
            candidate_elf,
            expected_output,
            historical,
            input,
            output_root,
        }, 0..) |optional, index| {
            paths[index] = try artifact_io.resolveAbsolute(
                allocator,
                optional orelse return error.InvalidArguments,
            );
            initialized += 1;
        }
        for (paths, 0..) |left, left_index|
            for (paths[0..left_index]) |right|
                if (std.mem.eql(u8, left, right)) return error.DuplicatePath;
        return .{
            .baseline_elf = paths[0],
            .candidate_admission_receipt = paths[1],
            .candidate_elf = paths[2],
            .expected_output = paths[3],
            .historical_baseline_materialization = paths[4],
            .input = paths[5],
            .output_root = paths[6],
            .power_source = power,
            .candidate_hard_cap_ns = hard_cap_ns,
        };
    }

    fn deinit(self: *Options, allocator: std.mem.Allocator) void {
        inline for (.{
            self.baseline_elf,
            self.candidate_admission_receipt,
            self.candidate_elf,
            self.expected_output,
            self.historical_baseline_materialization,
            self.input,
            self.output_root,
        }) |path| allocator.free(path);
        self.* = undefined;
    }
};

fn set(slot: *?[]const u8, value: []const u8) !void {
    if (slot.* != null) return error.DuplicateArgument;
    slot.* = value;
}

test "matched rematerialization CLI pins 2^20 and permits battery" {
    const arguments = [_][]const u8{
        "--baseline-elf",                        "/tmp/baseline.elf",
        "--candidate-receipt",                   "/tmp/candidate.json",
        "--candidate-elf",                       "/tmp/candidate.elf",
        "--expected-output",                     "/tmp/output.bin",
        "--historical-baseline-materialization", "/tmp/historical.json",
        "--input",                               "/tmp/input.bin",
        "--output-root",                         "/tmp/rematerialized",
        "--power-source",                        "battery",
        "--segment-step-budget",                 "1048576",
        "--hard-cap-seconds",                    "600",
    };
    var parsed = try Options.parseAndResolve(std.testing.allocator, &arguments);
    defer parsed.deinit(std.testing.allocator);
    try std.testing.expectEqual(
        @as(u64, 600 * std.time.ns_per_s),
        parsed.candidate_hard_cap_ns,
    );
    try std.testing.expectEqualStrings("battery", parsed.power_source);

    var wrong_budget = arguments;
    wrong_budget[17] = "2097152";
    try std.testing.expectError(
        error.InvalidArguments,
        Options.parseAndResolve(std.testing.allocator, &wrong_budget),
    );
}
