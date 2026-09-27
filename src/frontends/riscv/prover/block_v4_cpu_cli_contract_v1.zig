//! Canonical block-v4 CPU CLI input contract and read-only preflight.
//! Producing a bundle or returning complete-block authority is intentionally
//! outside this module; those require staged recursion and fresh verification.
const std = @import("std");
const runner = @import("block_v4_cpu_runner_source.zig");
const manifest_mod = @import("block_v4_cpu_trusted_manifest_v1.zig");
const trusted_mod = @import("block_v4_cpu_multi_segment_assembly.zig");
const parent = @import("../recursion/blake3_execution_parent_protocol.zig");

pub const argument_usage = "ELF INPUT ORACLE MAX_SEGMENT_CYCLES SCHEDULE_JSON TRUSTED_MANIFEST_JSON TRUSTED_MANIFEST_SHA256 OUTPUT_DIR";

pub const Arguments = struct {
    elf_path: []const u8,
    input_path: []const u8,
    oracle_path: []const u8,
    max_segment_cycles: u32,
    schedule_path: []const u8,
    manifest_path: []const u8,
    manifest_sha256: [32]u8,
    output_dir: []const u8,

    /// `args` are the eight tokens following a future v4 CLI subcommand.
    /// The SHA-256 pin must be supplied by caller policy, separately from
    /// the manifest file and any proof bundle.
    pub fn parse(args: []const []const u8) !Arguments {
        if (args.len != 8) return error.InvalidBlockV4CliArguments;
        const max_segment_cycles = std.fmt.parseInt(u32, args[3], 10) catch
            return error.InvalidBlockV4SegmentBudget;
        if (max_segment_cycles == 0 or max_segment_cycles > 1 << 22)
            return error.InvalidBlockV4SegmentBudget;
        for ([_]usize{ 0, 1, 2, 4, 5, 7 }) |index|
            if (args[index].len == 0) return error.InvalidBlockV4CliArguments;
        return .{
            .elf_path = args[0],
            .input_path = args[1],
            .oracle_path = args[2],
            .max_segment_cycles = max_segment_cycles,
            .schedule_path = args[4],
            .manifest_path = args[5],
            .manifest_sha256 = try manifest_mod.parseSha256Hex(args[6]),
            .output_dir = args[7],
        };
    }
};

pub const Preflight = struct {
    manifest: manifest_mod.Owned,
    source: runner.Source,
    output_dir: []u8,

    pub fn deinit(self: *Preflight, a: std.mem.Allocator) void {
        self.source.deinit();
        self.manifest.deinit();
        a.free(self.output_dir);
        self.* = undefined;
    }

    pub fn trusted(self: *const Preflight) trusted_mod.Trusted {
        return self.manifest.trusted();
    }
};

/// Reads only caller-selected files and runs the strict source preflight. No
/// output directory or proof artifact is created. Future production dispatch
/// may pass the owned Source to `streaming.withProduced` after its full bundle
/// and complete receiver path is wired.
pub fn load(a: std.mem.Allocator, dir: std.fs.Dir, args: Arguments) !Preflight {
    var manifest = try manifest_mod.read(a, dir, args.manifest_path, args.manifest_sha256);
    errdefer manifest.deinit();
    const elf = try readBounded(a, dir, args.elf_path, 32 * 1024 * 1024);
    defer a.free(elf);
    const input = try readBounded(a, dir, args.input_path, 64 * 1024 * 1024);
    defer a.free(input);
    const oracle = try readBounded(a, dir, args.oracle_path, 1024 * 1024);
    defer a.free(oracle);
    const schedule = try readBounded(a, dir, args.schedule_path, 1024 * 1024);
    defer a.free(schedule);
    try manifest.admitInputs(elf, input, oracle, schedule);
    var source = try runner.Source.initWithSchedule(a, elf, input, oracle, args.max_segment_cycles, parent.Profile.csp_q70_pow26.config(), manifest.sourcePins(), schedule);
    errdefer source.deinit();
    if (!std.meta.eql(source.job, manifest.trusted().job))
        return error.UntrustedBlockV4CliJob;
    return .{
        .manifest = manifest,
        .source = source,
        .output_dir = try a.dupe(u8, args.output_dir),
    };
}

fn readBounded(a: std.mem.Allocator, dir: std.fs.Dir, path: []const u8, max: usize) ![]u8 {
    var file = try dir.openFile(path, .{});
    defer file.close();
    return file.readToEndAlloc(a, max);
}

test "block-v4 CLI contract requires exact schedule and out-of-band manifest pin" {
    const digest = [_]u8{'0'} ** 64;
    const tokens = [_][]const u8{ "guest.elf", "input.bin", "output.bin", "4194304", "schedule.json", "trusted.json", &digest, "bundle-dir" };
    const parsed = try Arguments.parse(&tokens);
    try std.testing.expectEqual(@as(u32, 1 << 22), parsed.max_segment_cycles);
    try std.testing.expectEqual(@as([32]u8, @splat(0)), parsed.manifest_sha256);
    try std.testing.expectError(error.InvalidBlockV4CliArguments, Arguments.parse(tokens[0..7]));
    var missing_schedule = tokens;
    missing_schedule[4] = "";
    try std.testing.expectError(error.InvalidBlockV4CliArguments, Arguments.parse(&missing_schedule));
    var wrong_budget = tokens;
    wrong_budget[3] = "4194305";
    try std.testing.expectError(error.InvalidBlockV4SegmentBudget, Arguments.parse(&wrong_budget));
    var wrong_digest = tokens;
    wrong_digest[6] = "from-bundle";
    try std.testing.expectError(error.InvalidTrustedManifestDigest, Arguments.parse(&wrong_digest));
}
