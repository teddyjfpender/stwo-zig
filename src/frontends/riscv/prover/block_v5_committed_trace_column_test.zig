const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const M = core.fields.m31.M31;
const poly = engine.poly.circle.poly;
const canonic = core.poly.circle.canonic;
const Recover = @import("block_v5_committed_trace_column_v1.zig");

test "block-v5 selected recovery shares one transform with exact column and degree parity" {
    const a = std.testing.allocator;
    var batch = try Recover.Batch.init(a, 7);
    defer batch.deinit();
    const shared = batch.owned.twiddles.ptr;
    const minimum = batch.minimum.?.twiddles.ptr;
    try std.testing.expectEqual(@as(usize, 8), std.mem.sliceAsBytes(batch.minimum.?.twiddles).len + std.mem.sliceAsBytes(batch.minimum.?.itwiddles).len);
    for ([_]u32{ 1, 3, 5, 1 }) |trace_log| {
        const coefficients = try a.alloc(M, @as(usize, 1) << @intCast(trace_log));
        defer a.free(coefficients);
        for (coefficients, 0..) |*value, i| value.* = M.fromCanonical(@intCast(17 + 3 * i));
        const polynomial = try poly.CircleCoefficients.initBorrowed(coefficients);
        const reference = try polynomial.evaluate(a, canonic.CanonicCoset.new(trace_log).circleDomain());
        defer a.free(reference.values);
        for ([_]u32{ trace_log, trace_log + 2 }) |committed_log| {
            const committed = try polynomial.evaluate(a, canonic.CanonicCoset.new(committed_log).circleDomain());
            defer a.free(committed.values);
            for ([_]bool{ false, true }) |retained| {
                const recovered = try batch.recover(.{ .log_size = committed_log, .values = if (retained) &.{} else committed.values, .coefficient_values = if (retained) coefficients else null }, trace_log);
                defer a.free(recovered.values);
                try std.testing.expectEqualSlices(M, reference.values, recovered.values);
                try std.testing.expectEqual(trace_log, recovered.log_size);
                try std.testing.expect(batch.owned.twiddles.ptr == shared);
                try std.testing.expect(batch.minimum.?.twiddles.ptr == minimum);
            }
        }
    }
    // A valid committed LDE with a nonzero coefficient above the admitted
    // trace bound must fail both retained and reconstructed coefficient paths.
    var high: [32]M = @splat(M.zero());
    high[8] = M.one();
    const polynomial = try poly.CircleCoefficients.initBorrowed(&high);
    const committed = try polynomial.evaluate(a, canonic.CanonicCoset.new(5).circleDomain());
    defer a.free(committed.values);
    for ([_]bool{ false, true }) |retained|
        try std.testing.expectError(error.InvalidV5CommittedTraceDegree, batch.recover(.{ .log_size = 5, .values = if (retained) &.{} else committed.values, .coefficient_values = if (retained) &high else null }, 3));
    var low_high: [8]M = @splat(M.zero());
    low_high[2] = M.one();
    const low_polynomial = try poly.CircleCoefficients.initBorrowed(&low_high);
    const low_committed = try low_polynomial.evaluate(a, canonic.CanonicCoset.new(3).circleDomain());
    defer a.free(low_committed.values);
    for ([_]bool{ false, true }) |retained|
        try std.testing.expectError(error.InvalidV5CommittedTraceDegree, batch.recover(.{ .log_size = 3, .values = if (retained) &.{} else low_committed.values, .coefficient_values = if (retained) &low_high else null }, 1));
    try std.testing.expect(batch.owned.twiddles.ptr == shared);
}
