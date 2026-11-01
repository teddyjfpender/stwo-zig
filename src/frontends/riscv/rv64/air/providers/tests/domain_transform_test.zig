//! Composition-time expansion parity: `domain_transform.reserve` + `expand`
//! (extension FFT without the zero upper half, cached twiddles, per-worker
//! coefficient copy) against the previous path, `evaluationValues` (copy and
//! zero fill) followed by `evaluateBuffersWithTwiddles` with freshly
//! precomputed twiddles. Exact equality, word for word.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const support = @import("../../../../air/memory_commitment/hash_component_prepared_support.zig");
const transform = @import("../domain_transform.zig");
const M = core.fields.m31.M31;
const Poly = engine.air.component_prover.Poly;
const Twiddles = engine.poly.twiddles.TwiddleTree([]const M);
const a = std.testing.allocator;

fn fill(values: []M, seed: u64) void {
    var rng = std.Random.DefaultPrng.init(seed);
    for (values) |*value| value.* = M.fromCanonical(rng.random().uintLessThan(u32, (1 << 31) - 1));
}

/// `columns` sources at `trace_log`, evaluated on a `trace_log + expansion`
/// canonic domain. Every third source is resident at the evaluation height
/// (borrowed, never transformed), the rest carry only coefficients.
fn compare(trace_log: u32, expansion: u32, columns: usize, pool: ?*engine.work_pool.WorkPool) !void {
    const eval_log = trace_log + expansion;
    const domain = core.poly.circle.canonic.CanonicCoset.new(eval_log).circleDomain();
    const n = domain.size();
    const coefficient_len = @as(usize, 1) << @intCast(trace_log);
    const storage = try a.alloc(M, columns * (coefficient_len + n));
    defer a.free(storage);
    fill(storage, trace_log * 1000 + expansion * 100 + columns);
    const polys = try a.alloc(Poly, columns);
    defer a.free(polys);
    for (polys, 0..) |*poly, i| {
        const coefficients = storage[i * (coefficient_len + n) ..][0..coefficient_len];
        const resident = storage[i * (coefficient_len + n) + coefficient_len ..][0..n];
        poly.* = .{
            .log_size = eval_log,
            .values = if (i % 3 == 2) resident else &.{},
            .coefficients = try engine.poly.circle.CircleCoefficients.initBorrowed(coefficients),
        };
    }
    var count: usize = 0;
    for (polys) |poly| count += @intFromBool(try support.sourceNeedsExtension(poly, trace_log, eval_log));

    const old_owned = try a.alloc([]M, count);
    var old_initialized: usize = 0;
    defer {
        for (old_owned[0..old_initialized]) |values| a.free(values);
        a.free(old_owned);
    }
    const old_values = try a.alloc([]const M, columns);
    defer a.free(old_values);
    for (polys, old_values) |poly, *values| values.* = try support.evaluationValues(a, poly, eval_log, n, old_owned, &old_initialized);
    if (count != 0) {
        var twiddles = try engine.poly.twiddles.precomputeM31(a, domain.half_coset);
        defer engine.poly.twiddles.deinitM31(a, &twiddles);
        try engine.poly.circle.poly.evaluateBuffersWithTwiddles(old_owned, domain, Twiddles.init(twiddles.root_coset, twiddles.twiddles, twiddles.itwiddles));
    }

    const new_owned = try a.alloc([]M, count);
    var new_initialized: usize = 0;
    defer {
        for (new_owned[0..new_initialized]) |values| a.free(values);
        a.free(new_owned);
    }
    const new_values = try a.alloc([]const M, columns);
    defer a.free(new_values);
    for (polys, new_values) |poly, *values| values.* = try transform.reserve(a, poly, eval_log, n, new_owned, &new_initialized);
    try std.testing.expectEqual(old_initialized, new_initialized);
    // Poison the reserved buffers: `expand` must never read what it did not write.
    for (new_owned[0..new_initialized]) |values| @memset(values, M.fromCanonical(0x5a5a5a5));
    try transform.expand(a, new_owned, polys, eval_log, domain, pool);

    for (polys, old_values, new_values) |poly, old, new| {
        if (poly.values.len != 0) try std.testing.expectEqual(poly.values.ptr, new.ptr);
        try std.testing.expectEqualSlices(M, old, new);
    }
}

test "RV64 composition expansion is word-identical to zero-padded evaluation" {
    for ([_]u32{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 13, 16 }) |log| {
        try compare(log, 1, 4, null);
        try compare(log, 2, 4, null);
    }
    try compare(17, 1, 2, null);
    try compare(18, 1, 1, null);
}

test "RV64 composition expansion over a work pool matches the serial path" {
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .stack_size = 16 << 20, .backing_allocator = a });
    defer pool.deinit();
    for ([_]u32{ 5, 9, 12, 15 }) |log| {
        try compare(log, 1, 13, &pool);
        try compare(log, 2, 7, &pool);
    }
}

test "RV64 cached twiddle tower equals a fresh precompute for every canonic domain" {
    // Request a large tower first so smaller logs are served from its suffix,
    // then a size below and above to exercise both cache paths.
    for ([_]u32{ 14, 3, 9, 15, 2, 14 }) |log| {
        const domain = core.poly.circle.canonic.CanonicCoset.new(log).circleDomain();
        const cached = try transform.twiddles(domain);
        var fresh = try engine.poly.twiddles.precomputeM31(a, domain.half_coset);
        defer engine.poly.twiddles.deinitM31(a, &fresh);
        try std.testing.expect(cached.root_coset.eql(fresh.root_coset));
        try std.testing.expectEqualSlices(M, fresh.twiddles, cached.twiddles);
        try std.testing.expectEqualSlices(M, fresh.itwiddles, cached.itwiddles);
    }
}

test "RV64 composition expansion rejects a source list that does not match its buffers" {
    const domain = core.poly.circle.canonic.CanonicCoset.new(5).circleDomain();
    var coefficients: [16]M = undefined;
    fill(&coefficients, 7);
    const poly = Poly{ .log_size = 5, .values = &.{}, .coefficients = try engine.poly.circle.CircleCoefficients.initBorrowed(&coefficients) };
    var buffer: [32]M = undefined;
    var buffers = [_][]M{&buffer};
    try std.testing.expectError(error.InvalidProofShape, transform.expand(a, &buffers, &.{ poly, poly }, 5, domain, null));
    try std.testing.expectError(error.InvalidProofShape, transform.expand(a, &buffers, &.{}, 5, domain, null));
}
