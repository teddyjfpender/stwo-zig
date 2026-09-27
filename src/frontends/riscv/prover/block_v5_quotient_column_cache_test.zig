const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const M = core.fields.m31.M31;
const poly = engine.poly.circle.poly;
const canonical = core.poly.circle.canonic;
const Shared = @import("block_v5_quotient_column_cache_v1.zig");

test "block-v5 quotient cache preserves exact domains degree checks and bounded fallback" {
    const a = std.testing.allocator;
    var coefficients: [8]M = undefined;
    for (&coefficients, 0..) |*value, index| value.* = M.fromCanonical(@intCast(19 + 7 * index));
    const polynomial = try poly.CircleCoefficients.initBorrowed(&coefficients);
    const source = try polynomial.evaluate(a, canonical.CanonicCoset.new(4).circleDomain());
    defer a.free(source.values);
    const original = try a.dupe(M, source.values);
    defer a.free(original);
    const reference = try polynomial.evaluate(a, canonical.CanonicCoset.new(5).circleDomain());
    defer a.free(reference.values);
    var twiddles = try engine.poly.twiddles.precomputeM31(a, canonical.CanonicCoset.new(5).circleDomain().half_coset);
    defer engine.poly.twiddles.deinitM31(a, &twiddles);
    const transform = engine.poly.twiddles.TwiddleTree([]const M).init(twiddles.root_coset, twiddles.twiddles, twiddles.itwiddles);
    for ([_]Shared.Policy{ .retained, .packed_word, .lookup }) |policy| {
        var cache = try Shared.Cache.initBounded(a, 128, 8);
        defer cache.deinit();
        const column: engine.air.component_prover.Poly = .{ .log_size = 4, .values = source.values, .coefficients = if (policy == .retained) polynomial else null };
        const first = (try cache.get(policy, column, 3, 5, transform)).?;
        const second = (try cache.get(policy, column, 3, 5, transform)).?;
        try std.testing.expectEqualSlices(M, reference.values, first);
        try std.testing.expect(first.ptr == second.ptr);
        try std.testing.expectEqual(@as(usize, 1), cache.recovered_columns);
        try std.testing.expectEqual(@as(usize, 1), cache.reused_columns);
        try std.testing.expectEqual(@as(usize, 128), cache.reserved_bytes);
        const distinct: engine.air.component_prover.Poly = .{ .log_size = 4, .values = original, .coefficients = column.coefficients };
        try std.testing.expect(try cache.get(policy, distinct, 3, 5, transform) == null);
        try std.testing.expect((try cache.get(policy, column, 3, 5, transform)).?.ptr == first.ptr);
    }
    try std.testing.expectEqualSlices(M, original, source.values);
    var high: [16]M = @splat(M.zero());
    high[8] = M.one();
    const high_poly = try poly.CircleCoefficients.initBorrowed(&high);
    const high_source = try high_poly.evaluate(a, canonical.CanonicCoset.new(4).circleDomain());
    defer a.free(high_source.values);
    for ([_]Shared.Policy{ .packed_word, .lookup }) |policy| {
        var cache = try Shared.Cache.initBounded(a, 256, 8);
        defer cache.deinit();
        const column: engine.air.component_prover.Poly = .{ .log_size = 4, .values = high_source.values };
        const expected = if (policy == .packed_word) error.InvalidProofShape else error.InvalidV5LookupRequestSourceDegree;
        try std.testing.expectError(expected, cache.get(policy, column, 3, 5, transform));
        try std.testing.expectError(expected, cache.get(policy, column, 3, 5, transform));
        try std.testing.expectEqual(@as(usize, 0), cache.reserved_bytes);
        try std.testing.expectEqual(@as(usize, 0), cache.recovered_columns);
        // A wider independently admitted degree is a distinct cache key.
        const admitted = (try cache.get(policy, column, 4, 5, transform)).?;
        const high_reference = try high_poly.evaluate(a, canonical.CanonicCoset.new(5).circleDomain());
        defer a.free(high_reference.values);
        try std.testing.expectEqualSlices(M, high_reference.values, admitted);
    }
}

test "block-v5 quotient cache shares immutable recovery across concurrent slots" {
    const a = std.testing.allocator;
    var coefficients: [32]M = @splat(M.one());
    const polynomial = try poly.CircleCoefficients.initBorrowed(&coefficients);
    const source = try polynomial.evaluate(a, canonical.CanonicCoset.new(6).circleDomain());
    defer a.free(source.values);
    var twiddles = try engine.poly.twiddles.precomputeM31(a, canonical.CanonicCoset.new(7).circleDomain().half_coset);
    defer engine.poly.twiddles.deinitM31(a, &twiddles);
    const transform = engine.poly.twiddles.TwiddleTree([]const M).init(twiddles.root_coset, twiddles.twiddles, twiddles.itwiddles);
    var cache = try Shared.Cache.initBounded(a, 1024, 4);
    defer cache.deinit();
    const Job = struct {
        cache: *Shared.Cache,
        column: engine.air.component_prover.Poly,
        twiddles: engine.poly.twiddles.TwiddleTree([]const M),
        result: ?[]const M = null,
        failure: ?anyerror = null,
        fn run(self: *@This()) void {
            self.result = self.cache.get(.packed_word, self.column, 5, 7, self.twiddles) catch |failure| {
                self.failure = failure;
                return;
            };
        }
    };
    var jobs: [6]Job = undefined;
    var threads: [6]std.Thread = undefined;
    var spawned: usize = 0;
    errdefer for (threads[0..spawned]) |thread| thread.join();
    for (&jobs, &threads) |*job, *thread| {
        job.* = .{ .cache = &cache, .column = .{ .log_size = 6, .values = source.values }, .twiddles = transform };
        thread.* = try std.Thread.spawn(.{}, Job.run, .{job});
        spawned += 1;
    }
    for (threads) |thread| thread.join();
    spawned = 0;
    for (jobs) |job| {
        try std.testing.expect(job.failure == null);
        try std.testing.expect(job.result.?.ptr == jobs[0].result.?.ptr);
    }
    try std.testing.expectEqual(@as(usize, 1), cache.recovered_columns);
    try std.testing.expectEqual(@as(usize, 5), cache.reused_columns);
}
