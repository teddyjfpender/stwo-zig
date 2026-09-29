const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const M31 = core.fields.m31.M31;
const fold = @import("../runtime/native_coefficient_fold.zig").fold;
const shared = @import("../shared_runtime.zig");
const telemetry = @import("../telemetry.zig");
const a = std.testing.allocator;
const Job = struct { source: []const M31, coordinates: [4][]M31, coefficients: [4]M31 };

fn planes(owner: []M31) [4][]M31 {
    const rows = owner.len / 4;
    var result: [4][]M31 = undefined;
    inline for (0..4) |coord| result[coord] = owner[coord * rows ..][0..rows];
    return result;
}

fn accumulate(expected: [4][]M31, job: Job) void {
    inline for (0..4) |coord| for (job.source, expected[coord][0..job.source.len]) |value, *target| {
        target.* = target.add(value.mul(job.coefficients[coord]));
    };
}

test "metal: native coefficient fold joins bounded adjacent sources and zero extends both output placements" {
    try shared.initialize(a, .source_jit);
    defer shared.shutdown() catch @panic("coefficient fold leaked runtime custody");
    const rows = 4096;
    const count = 300;
    const alignment = comptime std.mem.Alignment.fromByteUnits(std.heap.page_size_max);
    const coefficients = try a.alignedAlloc(M31, alignment, count * 16);
    defer a.free(coefficients);
    for (coefficients, 0..) |*value, i| value.* = M31.fromCanonical(@intCast((i * 919 + 0x7fffff00) % 0x7fffffff));
    const aligned_output = try a.alignedAlloc(M31, alignment, rows * 4);
    defer a.free(aligned_output);
    const unaligned_owner = try a.alignedAlloc(M31, alignment, rows * 4 + 1);
    defer a.free(unaligned_owner);
    const outputs = [_][]M31{ aligned_output, unaligned_owner[1..] };
    var jobs: [count]Job = undefined;
    const expected = try a.alloc(M31, rows * 4);
    defer a.free(expected);
    for (outputs) |output| {
        @memset(expected, M31.zero());
        @memset(output, M31.fromCanonical(123));
        for (&jobs, 0..) |*job, i| {
            job.* = .{
                .source = coefficients[i * 16 ..][0..16],
                .coordinates = planes(output),
                .coefficients = .{ M31.fromCanonical(@intCast(i + 1)), M31.zero(), M31.fromCanonical(0x7ffffffe), M31.fromCanonical(13) },
            };
            accumulate(planes(expected), job.*);
        }
        const before = telemetry.capture(std.mem.zeroes(@import("../runtime.zig").PipelineCacheStats)).counters;
        try fold(a, &jobs);
        const after = telemetry.capture(std.mem.zeroes(@import("../runtime.zig").PipelineCacheStats)).counters;
        try std.testing.expectEqual(@as(u64, 2), after.metal_coefficient_fold_dispatches - before.metal_coefficient_fold_dispatches);
        try std.testing.expectEqualSlices(M31, expected, output);
        // GPU reduction must never mutate retained source coefficients.
        for (coefficients, 0..) |value, i| try std.testing.expectEqual(@as(u32, @intCast((i * 919 + 0x7fffff00) % 0x7fffffff)), value.v);
    }
}

test "metal: native coefficient fold separates interleaved groups and fragmented mixed length sources" {
    try shared.initialize(a, .source_jit);
    defer shared.shutdown() catch @panic("coefficient fold leaked runtime custody");
    var sources: [11][]M31 = undefined;
    var made: usize = 0;
    defer for (sources[0..made]) |source| a.free(source);
    var output: [2][256 * 4]M31 = undefined;
    var expected = [_][256 * 4]M31{ [_]M31{M31.zero()} ** (256 * 4), [_]M31{M31.zero()} ** (256 * 4) };
    var jobs: [11]Job = undefined;
    for (&jobs, &sources, 0..) |*job, *source, i| {
        source.* = try a.alloc(M31, 7 + i * 17);
        made += 1;
        for (source.*, 0..) |*value, row| value.* = M31.fromCanonical(@intCast(row * 789 + i * 41));
        const group = i % 2;
        job.* = .{ .source = source.*, .coordinates = planes(&output[group]), .coefficients = .{ M31.one(), M31.fromCanonical(17), M31.fromCanonical(41), M31.fromCanonical(0x7ffffffe) } };
        accumulate(planes(&expected[group]), job.*);
    }
    try fold(a, &jobs);
    for (&expected, &output) |*want, *got| try std.testing.expectEqualSlices(M31, want, got);
}

fn failureCase(allocator: std.mem.Allocator, jobs: []Job) !void {
    try fold(allocator, jobs);
}

test "metal: native coefficient fold releases rejected device admissions and all host allocation failures" {
    try shared.initialize(a, .source_jit);
    defer shared.shutdown() catch @panic("coefficient fold leaked runtime custody");
    var output: [256 * 4]M31 = undefined;
    const source = [_]M31{M31.fromCanonical(17)} ** 16;
    var jobs = [_]Job{.{ .source = &source, .coordinates = planes(&output), .coefficients = .{ M31.one(), M31.one(), M31.one(), M31.one() } }};
    for ([_]usize{ 512, 65536 }) |limit| {
        const budget = try prover.host_budget_allocator.SharedHostBudget.create(a, limit);
        defer budget.destroy();
        if (limit == 512) try std.testing.expectError(error.OutOfMemory, fold(budget.allocator(), &jobs)) else try fold(budget.allocator(), &jobs);
        try std.testing.expectEqual(@as(usize, 0), budget.snapshot().external_live_bytes);
    }
    try std.testing.checkAllAllocationFailures(a, failureCase, .{jobs[0..]});
    jobs[0].coordinates[1] = jobs[0].coordinates[2];
    try std.testing.expectError(error.InvalidCoefficientFold, fold(a, &jobs));
}
