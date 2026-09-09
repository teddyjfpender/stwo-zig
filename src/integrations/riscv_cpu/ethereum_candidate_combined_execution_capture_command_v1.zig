//! Typed CLI for the real execution-only combined candidate capture.

const std = @import("std");

const artifact_io = @import("ethereum_precompile_artifact_io.zig");
const bridge = @import("ethereum_candidate_combined_execution_capture_v1.zig");

pub const command_name = "ethereum-candidate-combined-execution-capture-v1";
pub const fixed_segment_step_budget: usize = 4_194_304;
pub const minimum_hard_cap_seconds: u64 = 600;
pub const maximum_hard_cap_seconds: u64 = 3_600;

pub fn run(allocator: std.mem.Allocator, arguments: []const []const u8) !void {
    var options = try Options.parseAndResolve(allocator, arguments);
    defer options.deinit(allocator);
    return bridge.capture(allocator, options.capture());
}

const Options = struct {
    receipt_path: []u8,
    elf_path: []u8,
    input_path: []u8,
    expected_output_path: []u8,
    output_root: []u8,
    power_source: []const u8,
    segment_step_budget: usize,
    hard_cap_ns: u64,

    fn capture(self: Options) bridge.CaptureOptions {
        return .{
            .receipt_path = self.receipt_path,
            .elf_path = self.elf_path,
            .input_path = self.input_path,
            .expected_output_path = self.expected_output_path,
            .output_root = self.output_root,
            .power_source = self.power_source,
            .segment_step_budget = self.segment_step_budget,
            .hard_cap_ns = self.hard_cap_ns,
        };
    }

    fn parseAndResolve(
        allocator: std.mem.Allocator,
        arguments: []const []const u8,
    ) !Options {
        if (arguments.len != 16) return error.InvalidArguments;
        var receipt_path: ?[]const u8 = null;
        var elf_path: ?[]const u8 = null;
        var input_path: ?[]const u8 = null;
        var expected_output_path: ?[]const u8 = null;
        var output_root: ?[]const u8 = null;
        var power_source: ?[]const u8 = null;
        var segment_step_budget: ?usize = null;
        var hard_cap_seconds: ?u64 = null;
        var cursor: usize = 0;
        while (cursor < arguments.len) : (cursor += 2) {
            const name = arguments[cursor];
            const value = arguments[cursor + 1];
            if (value.len == 0) return error.InvalidArguments;
            if (std.mem.eql(u8, name, "--receipt")) {
                if (receipt_path != null) return error.DuplicateArgument;
                receipt_path = value;
            } else if (std.mem.eql(u8, name, "--elf")) {
                if (elf_path != null) return error.DuplicateArgument;
                elf_path = value;
            } else if (std.mem.eql(u8, name, "--input")) {
                if (input_path != null) return error.DuplicateArgument;
                input_path = value;
            } else if (std.mem.eql(u8, name, "--expected-output")) {
                if (expected_output_path != null)
                    return error.DuplicateArgument;
                expected_output_path = value;
            } else if (std.mem.eql(u8, name, "--output-root")) {
                if (output_root != null) return error.DuplicateArgument;
                output_root = value;
            } else if (std.mem.eql(u8, name, "--power-source")) {
                if (power_source != null) return error.DuplicateArgument;
                if (!std.mem.eql(u8, value, "ac") and
                    !std.mem.eql(u8, value, "battery"))
                {
                    return error.InvalidArguments;
                }
                power_source = value;
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
        const budget = segment_step_budget orelse return error.InvalidArguments;
        if (budget != fixed_segment_step_budget) return error.InvalidArguments;
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

        const resolved_receipt = try artifact_io.resolveAbsolute(
            allocator,
            receipt_path orelse return error.InvalidArguments,
        );
        errdefer allocator.free(resolved_receipt);
        const resolved_elf = try artifact_io.resolveAbsolute(
            allocator,
            elf_path orelse return error.InvalidArguments,
        );
        errdefer allocator.free(resolved_elf);
        const resolved_input = try artifact_io.resolveAbsolute(
            allocator,
            input_path orelse return error.InvalidArguments,
        );
        errdefer allocator.free(resolved_input);
        const resolved_expected = try artifact_io.resolveAbsolute(
            allocator,
            expected_output_path orelse return error.InvalidArguments,
        );
        errdefer allocator.free(resolved_expected);
        const resolved_output = try artifact_io.resolveAbsolute(
            allocator,
            output_root orelse return error.InvalidArguments,
        );
        errdefer allocator.free(resolved_output);
        const all_paths = [_][]const u8{
            resolved_receipt,
            resolved_elf,
            resolved_input,
            resolved_expected,
            resolved_output,
        };
        for (all_paths, 0..) |left, left_index|
            for (all_paths[0..left_index]) |right|
                if (std.mem.eql(u8, left, right)) return error.DuplicatePath;
        return .{
            .receipt_path = resolved_receipt,
            .elf_path = resolved_elf,
            .input_path = resolved_input,
            .expected_output_path = resolved_expected,
            .output_root = resolved_output,
            .power_source = power_source orelse return error.InvalidArguments,
            .segment_step_budget = budget,
            .hard_cap_ns = hard_cap_ns,
        };
    }

    fn deinit(self: *Options, allocator: std.mem.Allocator) void {
        allocator.free(self.receipt_path);
        allocator.free(self.elf_path);
        allocator.free(self.input_path);
        allocator.free(self.expected_output_path);
        allocator.free(self.output_root);
        self.* = undefined;
    }
};

test "candidate execution CLI pins real segment authority and power source" {
    const allocator = std.testing.allocator;
    const arguments = [_][]const u8{
        "--receipt",             "/tmp/receipt.json",
        "--elf",                 "/tmp/candidate.elf",
        "--input",               "/tmp/input.bin",
        "--expected-output",     "/tmp/output.bin",
        "--output-root",         "/tmp/capture",
        "--segment-step-budget", "4194304",
        "--hard-cap-seconds",    "900",
        "--power-source",        "battery",
    };
    var parsed = try Options.parseAndResolve(allocator, &arguments);
    defer parsed.deinit(allocator);
    try std.testing.expectEqual(
        fixed_segment_step_budget,
        parsed.segment_step_budget,
    );
    try std.testing.expectEqualStrings("battery", parsed.power_source);
    try std.testing.expectEqual(
        @as(u64, 900 * std.time.ns_per_s),
        parsed.hard_cap_ns,
    );
}

test "combined candidate checker framing requires exactly one trailing LF" {
    const allocator = std.testing.allocator;
    const canonical = "{\"schema\":\"candidate\"}";
    const retained = try std.fmt.allocPrint(allocator, "{s}\n", .{canonical});
    defer allocator.free(retained);
    try bridge.validateCanonicalReceiptFraming(canonical, retained);
    try std.testing.expectError(
        error.NonCanonicalCombinedCandidateReceipt,
        bridge.validateCanonicalReceiptFraming(canonical, canonical),
    );
    const crlf = try std.fmt.allocPrint(allocator, "{s}\r\n", .{canonical});
    defer allocator.free(crlf);
    try std.testing.expectError(
        error.NonCanonicalCombinedCandidateReceipt,
        bridge.validateCanonicalReceiptFraming(canonical, crlf),
    );
    const double_lf = try std.fmt.allocPrint(allocator, "{s}\n\n", .{canonical});
    defer allocator.free(double_lf);
    try std.testing.expectError(
        error.NonCanonicalCombinedCandidateReceipt,
        bridge.validateCanonicalReceiptFraming(canonical, double_lf),
    );
    const drifted = try allocator.dupe(u8, retained);
    defer allocator.free(drifted);
    drifted[1] ^= 1;
    try std.testing.expectError(
        error.NonCanonicalCombinedCandidateReceipt,
        bridge.validateCanonicalReceiptFraming(canonical, drifted),
    );
}
