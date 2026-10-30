const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const M = core.fields.m31.M31;
const poly = engine.poly.circle.poly;
const canonical = core.poly.circle.canonic;
const Shared = @import("../block_v7_shared_quotient_cache_v1.zig");

test "v7 proof scoped cache separates policies and rejects weaker degree and malformed columns" {
    const a = std.testing.allocator;
    var coefficients: [8]M = undefined;
    for (&coefficients, 0..) |*cell, i| cell.* = M.fromCanonical(@intCast(19 + 7 * i));
    const polynomial = try poly.CircleCoefficients.initBorrowed(&coefficients);
    const source = try polynomial.evaluate(a, canonical.CanonicCoset.new(4).circleDomain());
    defer a.free(source.values);
    const reference = try polynomial.evaluate(a, canonical.CanonicCoset.new(5).circleDomain());
    defer a.free(reference.values);
    var twiddles = try engine.poly.twiddles.precomputeM31(a, canonical.CanonicCoset.new(5).circleDomain().half_coset);
    defer engine.poly.twiddles.deinitM31(a, &twiddles);
    const transform = engine.poly.twiddles.TwiddleTree([]const M).init(twiddles.root_coset, twiddles.twiddles, twiddles.itwiddles);
    const owner = (try Shared.Owner.create(a, 512)).?;
    defer owner.destroy();
    const column: engine.air.component_prover.Poly = .{ .log_size = 4, .values = source.values };
    var lookup = (try owner.cache.get(.lookup, column, 3, 5, transform)).?;
    defer lookup.release();
    var access = (try owner.cache.get(.packed_word, column, 3, 5, transform)).?;
    defer access.release();
    try std.testing.expectEqualSlices(M, reference.values, lookup.values);
    try std.testing.expectEqualSlices(M, reference.values, access.values);
    try std.testing.expect(lookup.values.ptr != access.values.ptr); // Policy identity is never erased.
    try std.testing.expectEqual(@as(usize, 2), owner.stats().recovered_columns);
    try std.testing.expectError(error.InvalidV5LookupRequestSourceDegree, owner.cache.get(.lookup, column, 2, 5, transform));
    try std.testing.expectError(error.InvalidProofShape, owner.cache.get(.packed_word, column, 2, 5, transform));
    var malformed = column;
    malformed.values = source.values[0..8];
    try std.testing.expectError(error.InvalidColumnLength, owner.cache.get(.lookup, malformed, 3, 5, transform));
    var again = (try owner.cache.get(.lookup, column, 3, 5, transform)).?;
    defer again.release();
    try std.testing.expectEqualSlices(M, reference.values, again.values);
    try std.testing.expectEqual(@as(usize, 256), owner.stats().retained_bytes);
}

test "v7 shared cache cap spans windows and no stale evaluation survives a new proof" {
    const a = std.testing.allocator;
    var coefficients: [8]M = undefined;
    for (&coefficients, 0..) |*cell, i| cell.* = M.fromCanonical(@intCast(31 + 11 * i));
    const polynomial = try poly.CircleCoefficients.initBorrowed(&coefficients);
    const source = try polynomial.evaluate(a, canonical.CanonicCoset.new(4).circleDomain());
    defer a.free(source.values);
    const source_values = try a.dupe(M, source.values);
    defer a.free(source_values);
    const reference = try polynomial.evaluate(a, canonical.CanonicCoset.new(5).circleDomain());
    defer a.free(reference.values);
    const other_source = try a.dupe(M, source.values);
    defer a.free(other_source);
    var twiddles = try engine.poly.twiddles.precomputeM31(a, canonical.CanonicCoset.new(5).circleDomain().half_coset);
    defer engine.poly.twiddles.deinitM31(a, &twiddles);
    const transform = engine.poly.twiddles.TwiddleTree([]const M).init(twiddles.root_coset, twiddles.twiddles, twiddles.itwiddles);
    const column: engine.air.component_prover.Poly = .{ .log_size = 4, .values = source_values };
    {
        const first = (try Shared.Owner.create(a, 128)).?;
        defer first.destroy();
        var cached = (try first.cache.get(.lookup, column, 3, 5, transform)).?;
        defer cached.release();
        try std.testing.expectEqualSlices(M, reference.values, cached.values);
        const another_window: engine.air.component_prover.Poly = .{ .log_size = 4, .values = other_source };
        try std.testing.expect(try first.cache.get(.lookup, another_window, 3, 5, transform) == null);
        try std.testing.expectEqual(@as(usize, 128), first.stats().retained_bytes);
        var again = (try first.cache.get(.lookup, column, 3, 5, transform)).?;
        defer again.release();
        try std.testing.expect(cached.values.ptr == again.values.ptr);
        try std.testing.expectEqual(@as(usize, 1), first.stats().reused_columns);
        try std.testing.expectEqual(@as(usize, 3), first.stats().requested_columns);
        try std.testing.expectEqual(@as(usize, 1), first.stats().capacity_misses);
        try std.testing.expectEqual(@as(usize, 0), first.stats().passthrough_columns);
        cached.release();
        again.release();
        var later = (try first.cache.get(.lookup, another_window, 3, 5, transform)).?;
        defer later.release();
        try std.testing.expectEqualSlices(M, reference.values, later.values);
        try std.testing.expectEqual(@as(usize, 1), first.stats().evicted_columns);
        try std.testing.expectEqual(@as(usize, 128), first.stats().retained_bytes);
    }
    // The old proof and cache are gone. Reuse the SAME source address for a
    // distinct committed polynomial in a later proof. It must be recomputed.
    coefficients[1] = coefficients[1].add(M.one());
    const changed_source = try polynomial.evaluate(a, canonical.CanonicCoset.new(4).circleDomain());
    defer a.free(changed_source.values);
    @memcpy(source_values, changed_source.values);
    const changed_reference = try polynomial.evaluate(a, canonical.CanonicCoset.new(5).circleDomain());
    defer a.free(changed_reference.values);
    const next = (try Shared.Owner.create(a, 128)).?;
    defer next.destroy();
    var fresh = (try next.cache.get(.lookup, column, 3, 5, transform)).?;
    defer fresh.release();
    try std.testing.expectEqualSlices(M, changed_reference.values, fresh.values);
    try std.testing.expect(!std.mem.eql(u8, std.mem.sliceAsBytes(reference.values), std.mem.sliceAsBytes(fresh.values)));
    try std.testing.expectEqual(@as(usize, 1), next.stats().recovered_columns);
    try std.testing.expectEqual(@as(usize, 0), next.stats().reused_columns);
}

test "v7 cache disabled budget overflow and allocation failures are explicit" {
    const a = std.testing.allocator;
    try std.testing.expect(try Shared.Owner.create(a, 0) == null);
    try std.testing.expectError(error.InvalidV7QuotientCacheBudget, Shared.Owner.create(a, Shared.MAX_RETAINED_BYTES + 1));
    try std.testing.checkAllAllocationFailures(a, createAndDestroy, .{});
    try std.testing.expectEqual(@as(usize, 256 * 1024 * 1024), Shared.DEFAULT_RETAINED_BYTES);
    for ([_]usize{ 1024, 2048 }) |mib| {
        const explicit = (try Shared.Owner.create(a, mib * 1024 * 1024)).?;
        defer explicit.destroy();
        try std.testing.expectEqual(mib * 1024 * 1024, explicit.cache.value_limit);
        try std.testing.expectEqual(@as(usize, 0), explicit.stats().retained_bytes);
    }
    const unprofiled = (try Shared.Owner.createWithUsage(a, 128, false)).?;
    defer unprofiled.destroy();
    try std.testing.expect(!unprofiled.cache.track_usage);
}
fn createAndDestroy(a: std.mem.Allocator) !void {
    const owner = (try Shared.Owner.create(a, 128)).?;
    owner.destroy();
}

// A gated allocator pauses the real recovery before its first allocation.
// This deterministically exercises pending waiters, not just ready-cache hits.
const GateAllocator = struct {
    backing: std.mem.Allocator,
    entered: std.Thread.ResetEvent = .{},
    proceed: std.Thread.ResetEvent = .{},
    armed: std.atomic.Value(bool) = .init(false),
    fail: bool = false,
    fn allocator(self: *@This()) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
    }
    fn alloc(ctx: *anyopaque, n: usize, alignment: std.mem.Alignment, ra: usize) ?[*]u8 {
        const self: *@This() = @ptrCast(@alignCast(ctx));
        if (self.armed.swap(false, .acq_rel)) {
            self.entered.set();
            self.proceed.wait();
            if (self.fail) return null;
        }
        return self.backing.rawAlloc(n, alignment, ra);
    }
    fn resize(ctx: *anyopaque, b: []u8, alignment: std.mem.Alignment, n: usize, ra: usize) bool {
        const self: *@This() = @ptrCast(@alignCast(ctx));
        return self.backing.rawResize(b, alignment, n, ra);
    }
    fn remap(ctx: *anyopaque, b: []u8, alignment: std.mem.Alignment, n: usize, ra: usize) ?[*]u8 {
        const self: *@This() = @ptrCast(@alignCast(ctx));
        return self.backing.rawRemap(b, alignment, n, ra);
    }
    fn free(ctx: *anyopaque, b: []u8, alignment: std.mem.Alignment, ra: usize) void {
        const self: *@This() = @ptrCast(@alignCast(ctx));
        self.backing.rawFree(b, alignment, ra);
    }
};

test "v7 leased pending success and failure pin waiters before wake and never evict active readers" {
    const a = std.testing.allocator;
    const Lru = @import("../block_v7_leased_quotient_cache_v1.zig");
    var coefficients: [8]M = @splat(M.one());
    const polynomial = try poly.CircleCoefficients.initBorrowed(&coefficients);
    const reference = try polynomial.evaluate(a, canonical.CanonicCoset.new(5).circleDomain());
    defer a.free(reference.values);
    var twiddles = try engine.poly.twiddles.precomputeM31(a, canonical.CanonicCoset.new(5).circleDomain().half_coset);
    defer engine.poly.twiddles.deinitM31(a, &twiddles);
    const transform = engine.poly.twiddles.TwiddleTree([]const M).init(twiddles.root_coset, twiddles.twiddles, twiddles.itwiddles);
    const column: engine.air.component_prover.Poly = .{ .log_size = 3, .values = &.{}, .coefficients = polynomial };
    const Job = struct {
        cache: *Lru.Cache,
        column: engine.air.component_prover.Poly,
        transform: engine.poly.twiddles.TwiddleTree([]const M),
        result: ?Lru.Lease = null,
        failure: ?anyerror = null,
        fn run(self: *@This()) void {
            self.result = self.cache.get(.lookup, self.column, 3, 5, self.transform) catch |failure| {
                self.failure = failure;
                return;
            };
        }
    };
    for ([_]bool{ false, true }) |fail| {
        var gate = GateAllocator{ .backing = a, .fail = fail };
        var cache = try Lru.Cache.initBounded(gate.allocator(), 128, 1);
        defer cache.deinit();
        gate.armed.store(true, .release);
        var producer = Job{ .cache = &cache, .column = column, .transform = transform };
        const first = try std.Thread.spawn(.{}, Job.run, .{&producer});
        var first_joined = false;
        defer {
            gate.proceed.set();
            if (!first_joined) first.join();
            if (producer.result) |*lease| lease.release();
        }
        gate.entered.wait();
        var waiter = Job{ .cache = &cache, .column = column, .transform = transform };
        const second = try std.Thread.spawn(.{}, Job.run, .{&waiter});
        var second_joined = false;
        defer {
            gate.proceed.set();
            if (!second_joined) second.join();
            if (waiter.result) |*lease| lease.release();
        }
        // No guessed sleep: observe both references under the cache lock.
        var joined = false;
        for (0..100_000) |_| {
            cache.mutex.lock();
            joined = cache.entries[0].references == 2;
            cache.mutex.unlock();
            if (joined) break;
            std.Thread.yield() catch {};
        }
        try std.testing.expect(joined);
        try std.testing.expect(try cache.get(.retained, column, 3, 5, transform) == null);
        try std.testing.expectEqual(@as(usize, 128), cache.reserved_bytes);
        gate.proceed.set();
        first.join();
        first_joined = true;
        second.join();
        second_joined = true;
        if (fail) {
            try std.testing.expectEqual(error.OutOfMemory, producer.failure.?);
            try std.testing.expectEqual(error.OutOfMemory, waiter.failure.?);
            try std.testing.expectEqual(@as(usize, 0), cache.reserved_bytes);
            try std.testing.expectEqual(@as(usize, 0), cache.entries[0].references);
            // Failed entries hold no buffers or pins; a distinct policy may
            // replace one and recover normally under the same strict cap.
            var retry = (try cache.get(.retained, column, 3, 5, transform)).?;
            defer retry.release();
            try std.testing.expectEqualSlices(M, reference.values, retry.values);
        } else {
            try std.testing.expect(producer.failure == null and waiter.failure == null);
            try std.testing.expect(producer.result.?.values.ptr == waiter.result.?.values.ptr);
            try std.testing.expectEqualSlices(M, reference.values, waiter.result.?.values);
            producer.result.?.release();
            try std.testing.expect(try cache.get(.retained, column, 3, 5, transform) == null);
            try std.testing.expectEqualSlices(M, reference.values, waiter.result.?.values);
            waiter.result.?.release();
            var replacement = (try cache.get(.retained, column, 3, 5, transform)).?;
            defer replacement.release();
            try std.testing.expectEqual(@as(usize, 1), cache.evicted_columns);
            try std.testing.expectEqualSlices(M, reference.values, replacement.values);
        }
    }
}

test "v7 leased recovery allocation failures release reservations and all owned buffers" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, recoverAndRelease, .{});
}
fn recoverAndRelease(a: std.mem.Allocator) !void {
    var coefficients: [8]M = @splat(M.one());
    const polynomial = try poly.CircleCoefficients.initBorrowed(&coefficients);
    var twiddles = try engine.poly.twiddles.precomputeM31(a, canonical.CanonicCoset.new(5).circleDomain().half_coset);
    defer engine.poly.twiddles.deinitM31(a, &twiddles);
    const transform = engine.poly.twiddles.TwiddleTree([]const M).init(twiddles.root_coset, twiddles.twiddles, twiddles.itwiddles);
    const owner = (try Shared.Owner.create(a, 128)).?;
    defer owner.destroy();
    var lease = (try owner.cache.get(.lookup, .{ .log_size = 3, .values = &.{}, .coefficients = polynomial }, 3, 5, transform)).?;
    defer lease.release();
}

test "v7 leased LRU refresh preserves recently reused columns under a shared cap" {
    const a = std.testing.allocator;
    const Lru = @import("../block_v7_leased_quotient_cache_v1.zig");
    var coefficients: [3][8]M = undefined;
    var columns: [3]engine.air.component_prover.Poly = undefined;
    for (&coefficients, &columns, 0..) |*values, *column, index| {
        @memset(values, M.fromCanonical(@intCast(index + 1)));
        column.* = .{ .log_size = 3, .values = &.{}, .coefficients = try poly.CircleCoefficients.initBorrowed(values) };
    }
    var twiddles = try engine.poly.twiddles.precomputeM31(a, canonical.CanonicCoset.new(5).circleDomain().half_coset);
    defer engine.poly.twiddles.deinitM31(a, &twiddles);
    const transform = engine.poly.twiddles.TwiddleTree([]const M).init(twiddles.root_coset, twiddles.twiddles, twiddles.itwiddles);
    var cache = try Lru.Cache.initBounded(a, 256, 2);
    defer cache.deinit();
    for (columns[0..2]) |column| {
        var lease = (try cache.get(.lookup, column, 3, 5, transform)).?;
        lease.release();
    }
    var touch = (try cache.get(.lookup, columns[0], 3, 5, transform)).?;
    touch.release();
    var incoming = (try cache.get(.lookup, columns[2], 3, 5, transform)).?;
    incoming.release();
    try std.testing.expectEqual(@as(usize, 3), cache.recovered_columns);
    try std.testing.expectEqual(@as(usize, 1), cache.evicted_columns);
    var retained = (try cache.get(.lookup, columns[0], 3, 5, transform)).?;
    defer retained.release();
    try std.testing.expectEqual(@as(usize, 3), cache.recovered_columns);
    var replaced = (try cache.get(.lookup, columns[1], 3, 5, transform)).?;
    defer replaced.release();
    try std.testing.expectEqual(@as(usize, 4), cache.recovered_columns);
    try std.testing.expectEqual(@as(usize, 2), cache.evicted_columns);
    try std.testing.expectEqual(@as(usize, 256), cache.reserved_bytes);
    // Header-space pressure follows the same rule even with ample byte budget.
    var one = try Lru.Cache.initBounded(a, 4096, 1);
    defer one.deinit();
    var first = (try one.get(.lookup, columns[0], 3, 5, transform)).?;
    defer first.release();
    try std.testing.expect(try one.get(.lookup, columns[1], 3, 5, transform) == null);
    first.release();
    var second = (try one.get(.lookup, columns[1], 3, 5, transform)).?;
    defer second.release();
    try std.testing.expectEqual(@as(usize, 1), one.evicted_columns);
}
