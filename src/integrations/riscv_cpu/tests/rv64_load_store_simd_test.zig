const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const air = @import("stwo_riscv_frontend").rv64_air;
const E = air.evaluation;
const X = air.memory.load_store_v1;
const L = X.layout;
const C = X.component;
const Packed = C.testing.packedRows;
const Column = engine.air.accumulation.ColumnAccumulator;
const M = X.types.M;
const Q = X.types.Q;
const N = 128;
fn scalar(c: *const C.Component, columns: []const []const M, inverses: []const M, output: *Column) void {
    const widths = c.widths();
    for (0..N) |row| {
        var values: [256]Q = undefined;
        var pm: [79]Q = @splat(Q.zero());
        var pi: [116]Q = @splat(Q.zero());
        for (columns, 0..) |column, i| values[i] = Q.fromBase(column[row]);
        const prior = core.utils.previousBitReversedCircleDomainIndex(row, 6, 7);
        for (0..widths[1]) |i| if (L.previousMainFor(c.kind, i)) {
            pm[i] = Q.fromBase(columns[widths[0] + i][prior]);
        };
        for (0..widths[2]) |i| if (L.previousInterFor(c.kind, i)) {
            pi[i] = Q.fromBase(columns[widths[0] + widths[1] + i][prior]);
        };
        var accumulator = E.WeightedAccumulator{ .powers = output.random_coeff_powers };
        var sink = E.Sink{ .values = null, .weighted_accumulator = &accumulator };
        c.emitFor(Q, values[0..widths[0]], values[widths[0]..][0..widths[1]], pm[0..widths[1]], values[widths[0] + widths[1] ..][0..widths[2]], pi[0..widths[2]], &sink);
        std.debug.assert(sink.count == c.nConstraints());
        output.accumulate(row, accumulator.accumulation.mulM31(inverses[row >> 6]));
    }
}
test "LS SIMD complete weighted kernel matches scalar previous masks tails and additive output" {
    var channel = core.channel.blake2s.Blake2sChannel{};
    const ch = @import("../rv64_load_store.zig").draw(&channel);
    var expected: X.types.OwnerRows = undefined;
    for (&expected) |*row| for (row) |*v| {
        v.* = channel.drawSecureFelt().toM31Array()[0];
    };
    var claims = X.types.Claims.zero();
    inline for (std.meta.fields(X.types.Claims)) |field| @field(claims, field.name) = channel.drawSecureFelt();
    var storage: [256][N]M = undefined;
    var views: [256][]const M = undefined;
    for (&storage, &views) |*data, *view| {
        for (data) |*v| v.* = channel.drawSecureFelt().toM31Array()[0];
        view.* = data;
    }
    var powers: [280]Q = undefined;
    for (&powers) |*v| v.* = channel.drawSecureFelt();
    const inverses = [_]M{ M.fromCanonical(3), M.fromCanonical(5) };
    for ([_]L.Kind{ .ls, .owner, .selection }) |kind| {
        const component = C.Component{ .kind = kind, .log_size = 6, .rows = 51, .offsets = .{ 0, 0, 0 }, .public_rows = &expected, .claims = claims, .challenges = ch };
        const widths = component.widths();
        const columns = views[0 .. widths[0] + widths[1] + widths[2]];
        var reference: [4][N]M = @splat(@splat(M.zero()));
        var actual: [4][N]M = @splat(@splat(M.zero()));
        var ref_col = engine.secure_column.SecureColumnByCoords{ .columns = .{ &reference[0], &reference[1], &reference[2], &reference[3] }, .owns_columns = false };
        var actual_col = engine.secure_column.SecureColumnByCoords{ .columns = .{ &actual[0], &actual[1], &actual[2], &actual[3] }, .owns_columns = false };
        var ref_output = Column{ .random_coeff_powers = powers[0..component.nConstraints()], .col = &ref_col, .next_fresh_index = 0 };
        var actual_output = Column{ .random_coeff_powers = powers[0..component.nConstraints()], .col = &actual_col, .next_fresh_index = 0 };
        scalar(&component, columns, &inverses, &ref_output);
        try Packed.evaluate(&component, columns, 0, N, &inverses, &actual_output);
        for (reference, actual) |a, b| try std.testing.expectEqualSlices(M, &a, &b);
        scalar(&component, columns, &inverses, &ref_output);
        for ([_][2]usize{ .{ 0, 7 }, .{ 7, 65 }, .{ 65, 113 }, .{ 113, N } }) |range| try Packed.evaluate(&component, columns, range[0], range[1], &inverses, &actual_output);
        for (reference, actual) |a, b| try std.testing.expectEqualSlices(M, &a, &b);
        const before = actual;
        try std.testing.expectError(error.InvalidLoadStoreDomain, Packed.evaluate(&component, columns[0 .. columns.len - 1], 0, N, &inverses, &actual_output));
        for (before, actual) |a, b| try std.testing.expectEqualSlices(M, &a, &b);
    }
}
test "LS SIMD q70 complete proof is identical under pooled and serial domain evaluation" {
    const Proof = @import("../rv64_load_store.zig");
    const data = @import("../rv64_load_store_data.zig").fixture();
    var serial = try Proof.produce(std.testing.allocator, data.expected(), .none);
    defer serial.deinit(std.testing.allocator);
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .stack_size = 256 * 1024 });
    defer pool.deinit();
    var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    var parallel = try Proof.produce(std.testing.allocator, data.expected(), .none);
    defer parallel.deinit(std.testing.allocator);
    try std.testing.expectEqualSlices(u8, serial.bytes, parallel.bytes);
    for (serial.claims, parallel.claims) |a, b| for (a.values(), b.values()) |x, y| try std.testing.expect(x.eql(y));
    try Proof.verify(std.testing.allocator, data.expected(), parallel);
}

test "LS 280-residual packed kernel runs on four joined workers with 256 KiB stacks" {
    const a = std.testing.allocator;
    const size = 16384;
    const widths = L.widths(.ls);
    const count = widths[0] + widths[1] + widths[2];
    const data = try a.alloc(M, count * size);
    defer a.free(data);
    var views: [256][]const M = undefined;
    for (views[0..count], 0..) |*view, c| {
        const column = data[c * size ..][0..size];
        for (column, 0..) |*v, row| v.* = M.fromCanonical(@intCast(c * size + row + 1));
        view.* = column;
    }
    var ch = core.channel.blake2s.Blake2sChannel{};
    const component = C.Component{ .kind = .ls, .log_size = 13, .rows = 8191, .offsets = .{ 0, 0, 0 }, .claims = X.types.Claims.zero(), .challenges = @import("../rv64_load_store.zig").draw(&ch) };
    var powers: [280]Q = undefined;
    for (&powers) |*v| v.* = ch.drawSecureFelt();
    const inverses = [_]M{ M.fromCanonical(3), M.fromCanonical(5) };
    const reference = try a.alloc(M, 4 * size);
    defer a.free(reference);
    const actual = try a.alloc(M, 4 * size);
    defer a.free(actual);
    @memset(reference, M.zero());
    @memset(actual, M.zero());
    var ref_col = engine.secure_column.SecureColumnByCoords{ .columns = .{ reference[0..size], reference[size..][0..size], reference[2 * size ..][0..size], reference[3 * size ..][0..size] }, .owns_columns = false };
    var actual_col = engine.secure_column.SecureColumnByCoords{ .columns = .{ actual[0..size], actual[size..][0..size], actual[2 * size ..][0..size], actual[3 * size ..][0..size] }, .owns_columns = false };
    var ref_output = Column{ .random_coeff_powers = &powers, .col = &ref_col, .next_fresh_index = 0 };
    var actual_output = Column{ .random_coeff_powers = &powers, .col = &actual_col, .next_fresh_index = 0 };
    try Packed.evaluate(&component, views[0..count], 0, size, &inverses, &ref_output);
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .stack_size = 256 * 1024 });
    defer pool.deinit();
    try C.testing.evaluateRows(&component, views[0..count], &inverses, &actual_output, &pool);
    try std.testing.expectEqualSlices(M, reference, actual);
}
