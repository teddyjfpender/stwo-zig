//! Execution-only entry point: no prover or backend ownership is imported.
const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const model = @import("recursive_segment_v2_memory_workload_test_support.zig");
const workload = @import("recursive_segment_v2_two_segment_test_support.zig");

pub fn main() !void {
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .init;
    defer std.debug.assert(gpa.deinit() == .ok);
    const allocator = gpa.allocator();
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    if (args.len == 1) return workload.checkSegmentLadder(allocator);
    if (args.len != 6 or !std.mem.eql(u8, args[1], "--export-segment-inputs"))
        return error.ExpectedExportSegmentInputsCountAddressesSeedNewDirectory;
    const count = try std.fmt.parseInt(usize, args[2], 10);
    const addresses = try std.fmt.parseInt(usize, args[3], 10);
    const seed = try std.fmt.parseInt(u32, args[4], 0);
    switch (count) {
        inline 2, 4, 8 => |n| try exportInputs(n, allocator, addresses, seed, args[5]),
        else => return error.InvalidSegmentCount,
    }
}

fn exportInputs(comptime count: usize, allocator: std.mem.Allocator, addresses: usize, seed: u32, output: []const u8) !void {
    var segments = try model.materialize(count, allocator, addresses, seed);
    defer for (&segments) |*segment| segment.deinit();
    var results: [count]*const frontend.runner.SegmentResult = undefined;
    for (&segments, 0..) |*segment, index| results[index] = &segment.base;
    try workload.validateSegments(count, results, addresses, seed);
    const statements = try workload.fixtureStatementsForSegments(count, allocator, results);
    const session = frontend.recursion.poseidon2_channel.hashBytes("recursive-v2-session", 0x5632_504f);
    const admitted = try workload.admitSegments(count, results, session, statements);
    try std.fs.cwd().makeDir(output);
    var directory = try std.fs.cwd().openDir(output, .{});
    defer directory.close();
    for (admitted.sources, 0..) |source, index| {
        const words = try allocator.alloc(@import("stwo_core").fields.m31.M31, try source.canonicalWordCount());
        defer allocator.free(words);
        _ = try source.encodeCanonical(words);
        const values = try allocator.alloc(u32, words.len);
        defer allocator.free(values);
        for (words, values) |word, *value| value.* = word.toU32();
        const bytes = try std.json.Stringify.valueAlloc(allocator, values, .{});
        defer allocator.free(bytes);
        var name_buffer: [48]u8 = undefined;
        const name = try std.fmt.bufPrint(&name_buffer, "child-{d}-expected-wire.json", .{index});
        var file = try directory.createFile(name, .{ .exclusive = true });
        defer file.close();
        try file.writeAll(bytes);
    }
    std.debug.print("SEGMENT_V2_EXPECTED_INPUTS segments={d} addresses={d} seed={d} retired={d} proofs_created=0 directory={s}\n", .{ count, addresses, seed, admitted.folded.body.executed.cycle_count, output });
}
