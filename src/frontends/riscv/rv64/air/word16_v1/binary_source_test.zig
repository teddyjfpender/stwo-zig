const std = @import("std");
const core = @import("stwo_core");
const E = @import("../evaluation.zig");
const S = @import("binary_source.zig");
const B = @import("binary.zig");
const P = @import("binary_lookup.zig");
const T = @import("../providers/tables.zig");
const O = @import("operations.zig");
const physical = @import("../witness.zig").physical;
const M = core.fields.m31.M31;
const Q = E.Q;
const a = std.testing.allocator;
fn fact(op: O.Binary, x: u64, y: u64) S.Fact {
    return .{ .op = op, .a = x, .b = y, .c = switch (op) {
        .and_ => x & y,
        .or_ => x | y,
        .xor => x ^ y,
    } };
}
fn facts() [3]S.Fact {
    return .{ fact(.and_, 0x12, 0x34), fact(.or_, 0x8000000000000000, 0xffff), fact(.xor, 0x0123456789abcdef, 0xfedcba9876543210) };
}
fn challenges() P.Challenges {
    // Native witness oracle only; accepting integrations draw after all roots.
    var channel = core.channel.blake2s.Blake2sChannel{};
    channel.mixU32s(&.{ 0x42494e53, 1 });
    var ch = P.Challenges{ .and_ = T.Challenges.draw(&channel), .function = undefined };
    ch.function.offset = channel.drawSecureFelt();
    for (&ch.function.coefficients) |*v| v.* = channel.drawSecureFelt();
    return ch;
}
fn store(data: []M, n: usize, row: usize, start: usize, value: Q) void {
    for (value.toM31Array(), 0..) |v, c| data[(start + c) * n + row] = v;
}
const Oracle = struct { data: []M, claims: P.Claims };
fn oracle(main: []const M, log: u32, ch: P.Challenges) !Oracle {
    const n = @as(usize, 1) << @intCast(log);
    const data = try a.alloc(M, S.INTERACTION * n);
    errdefer a.free(data);
    var and_sum = Q.zero();
    var function_sum = Q.zero();
    for (0..n) |i| {
        const r = physical(i, log);
        var values: [S.MAIN]Q = undefined;
        for (&values, 0..) |*v, c| v.* = Q.fromBase(main[c * n + r]);
        const row = P.rowFromColumnsFor(Q, &values);
        for (0..4) |batch| {
            const x = B.andTupleFor(Q, &row, 2 * batch);
            const y = B.andTupleFor(Q, &row, 2 * batch + 1);
            const ix = try ch.and_.denominator(&x).inv();
            const iy = try ch.and_.denominator(&y).inv();
            store(data, n, r, 4 * batch, ix.mul(iy));
            and_sum = and_sum.add(ix).add(iy);
        }
        store(data, n, r, 16, and_sum);
        const inverse = try ch.function.denominatorFor(Q, row.payload).inv();
        store(data, n, r, 20, inverse);
        function_sum = function_sum.sub(inverse.mul(values[B.LOCAL_MAIN]));
        store(data, n, r, 24, function_sum);
    }
    for ([_]usize{ 16, 24 }, [_]Q{ and_sum, function_sum }) |start, claim| {
        const correction = claim.toM31Array();
        for (correction, 0..) |v, c| for (0..n) |r| {
            data[(start + c) * n + r] = data[(start + c) * n + r].sub(v);
        };
    }
    return .{ .data = data, .claims = .{ .and_ = and_sum, .function = function_sum } };
}
fn nativeRows(main: []const M, source: *const S.Source, claims: P.Claims, ch: P.Challenges) !void {
    const n = source.size();
    for (0..n) |i| {
        const r = physical(i, source.log_size);
        const prev = physical((i + n - 1) % n, source.log_size);
        var values: [S.MAIN]Q = undefined;
        var current: [S.INTERACTION]Q = undefined;
        var previous: [S.INTERACTION]Q = undefined;
        for (&values, 0..) |*v, c| v.* = Q.fromBase(main[c * n + r]);
        for (&current, &previous, 0..) |*v, *p, c| {
            v.* = Q.fromBase(source.interaction[c * n + r]);
            p.* = Q.fromBase(source.interaction[c * n + prev]);
        }
        var residuals: [P.CONSTRAINTS]Q = undefined;
        var sink = E.Sink{ .values = &residuals };
        P.emitFor(Q, &values, &current, &previous, Q.fromBase(source.fixed[r]), Q.fromBase(source.fixed[n + r]), claims, ch, &sink);
        try std.testing.expectEqual(P.CONSTRAINTS, sink.count);
        for (residuals) |v| try std.testing.expect(v.isZero());
    }
}
test "BinarySource native matrices match qualified Q witness with geometry-only keys and exact AND indexing" {
    const inputs = facts();
    var source = try S.Source.init(a, &inputs, 5);
    defer source.deinit();
    var empty = try S.Source.init(a, &.{}, 5);
    defer empty.deinit();
    try std.testing.expectEqualSlices(M, source.fixed, empty.fixed);
    try std.testing.expectEqual(@as(usize, 46), @sizeOf(S.Metadata));
    const n = source.size();
    for (0..n) |i| {
        var row = if (i < inputs.len) B.witness(inputs[i].op, inputs[i].a, inputs[i].b) else B.witness(.and_, 0, 0);
        if (i >= inputs.len) {
            row.active = Q.zero();
            row.selectors[0] = Q.zero();
            row.payload[0] = Q.zero();
        }
        const expected = P.rowToColumnsFor(Q, row);
        const p = physical(i, 5);
        for (expected, 0..) |v, c| try std.testing.expect(v.eql(Q.fromBase(source.main[c * n + p])));
    }
    var singleton = try S.Source.init(a, inputs[0..1], 5);
    defer singleton.deinit();
    try std.testing.expectEqual(@as(u64, 1), singleton.and_counts[0x1234]);
    try std.testing.expectEqual(@as(u64, 0), singleton.and_counts[0x3412]);
    var total: u64 = 0;
    for (source.and_counts) |v| total += v;
    try std.testing.expectEqual((try S.massForLog(5)).and_queries, total);
    try std.testing.expectError(error.InvalidBinaryGeometry, S.massForLog(28));
}
test "BinarySource owned borrowed detached main and empty native interactions equal scalar oracle" {
    const inputs = facts();
    var source = try S.Source.init(a, &inputs, 5);
    defer source.deinit();
    const saved = try a.dupe(M, source.main);
    defer a.free(saved);
    const borrowed_main = try a.alloc(M, S.MAIN * source.size());
    defer a.free(borrowed_main);
    var borrowed = try S.Source.initWithMainBuffers(a, &inputs, 5, .{ .main = borrowed_main });
    defer borrowed.deinit();
    try std.testing.expectEqualSlices(M, source.main, borrowed.main);
    try std.testing.expectError(error.BorrowedBinaryMain, borrowed.takeMainForCommit());
    const ch = challenges();
    const expected = try oracle(saved, 5, ch);
    defer a.free(expected.data);
    const detached = try source.takeMainForCommit();
    a.free(detached);
    borrowed.releaseMain();
    @memset(borrowed_main, M.fromCanonical(999));
    const claims = try source.generate(ch);
    const borrowed_claims = try borrowed.generate(ch);
    try std.testing.expect(claims.and_.eql(expected.claims.and_) and claims.function.eql(expected.claims.function));
    try std.testing.expect(claims.and_.eql(borrowed_claims.and_) and claims.function.eql(borrowed_claims.function));
    try std.testing.expectEqualSlices(M, expected.data, source.interaction);
    try std.testing.expectEqualSlices(M, source.interaction, borrowed.interaction);
    try nativeRows(saved, &source, claims, ch);
    try std.testing.expectEqual(@as(usize, 0), source.metadata.len);
    try std.testing.expectError(error.InvalidBinarySourcePhase, source.generate(ch));
    var empty = try S.Source.init(a, &.{}, 5);
    defer empty.deinit();
    const empty_expected = try oracle(empty.main, 5, ch);
    defer a.free(empty_expected.data);
    const empty_claims = try empty.generate(ch);
    try std.testing.expect(empty_claims.function.isZero());
    try std.testing.expectEqualSlices(M, empty_expected.data, empty.interaction);
}
test "BinarySource allocation invalid fact pole and late ledger failures preserve ownership and publication" {
    const Runner = struct {
        fn run(allocator: std.mem.Allocator) !void {
            const inputs = facts();
            var source = try S.Source.init(allocator, &inputs, 5);
            defer source.deinit();
            source.releaseMain();
            _ = try source.generate(challenges());
        }
    };
    try std.testing.checkAllAllocationFailures(a, Runner.run, .{});
    var buffer: [S.MAIN * 32]M = @splat(M.fromCanonical(77));
    var inputs = facts();
    inputs[0].c ^= 1;
    try std.testing.expectError(error.InvalidBinaryFact, S.Source.initWithMainBuffers(a, &inputs, 5, .{ .main = &buffer }));
    for (buffer) |v| try std.testing.expectEqual(@as(u32, 77), v.v);
    const good = facts();
    for (0..3) |failure| {
        var failing = std.testing.FailingAllocator.init(a, .{ .fail_index = failure });
        try std.testing.expectError(error.OutOfMemory, S.Source.initWithMainBuffers(failing.allocator(), &good, 5, .{ .main = &buffer }));
        for (buffer) |v| try std.testing.expectEqual(@as(u32, 77), v.v);
    }
    var source = try S.Source.init(a, &good, 5);
    defer source.deinit();
    source.releaseMain();
    var pole = challenges();
    pole.function.offset = Q.zero();
    pole.function.coefficients = @splat(Q.zero());
    try std.testing.expectError(error.DivisionByZero, source.generate(pole));
    try std.testing.expectEqual(@as(usize, 0), source.interaction.len);
    try std.testing.expectEqual(@as(usize, 32), source.metadata.len);
    source.and_counts[0] += 1;
    try std.testing.expectError(error.InvalidBinaryMetadata, source.generate(challenges()));
    try std.testing.expectEqual(@as(usize, 0), source.interaction.len);
    source.and_counts[0] -= 1;
    _ = try source.generate(challenges());
}

test "weighted BinarySource owns full u32 weights and keeps eight AND queries per physical row" {
    var inputs = facts();
    var weights: [3]u32 = .{ 70000, 0, 13 };
    var source = try S.Source.initWeighted(a, &inputs, &weights, 5);
    defer source.deinit();
    var buffer: [S.MAIN * 32]M = undefined;
    var borrowed = try S.Source.initWeightedWithMainBuffers(a, &inputs, &weights, 5, .{ .main = &buffer });
    defer borrowed.deinit();
    const main = try a.dupe(M, source.main);
    defer a.free(main);
    try std.testing.expectEqualSlices(M, main, borrowed.main);
    try std.testing.expectEqual(@as(u32, 70000), source.metadata[0].multiplicity());
    var mass: u64 = 0;
    for (source.and_counts) |count| mass += count;
    try std.testing.expectEqual(@as(u64, 256), mass);
    const ch = challenges();
    const expected = try oracle(main, 5, ch);
    defer a.free(expected.data);
    @memset(&weights, 0);
    @memset(&inputs, .{ .op = .and_, .a = 0, .b = 0, .c = 0 });
    const transferred = try source.takeMainForCommit();
    a.free(transferred);
    borrowed.releaseMain();
    @memset(&buffer, M.fromCanonical(17));
    const actual = try source.generate(ch);
    const other = try borrowed.generate(ch);
    try std.testing.expectEqualDeep(expected.claims, actual);
    try std.testing.expectEqualDeep(actual, other);
    try std.testing.expectEqualSlices(M, expected.data, source.interaction);
    try std.testing.expectEqualSlices(M, source.interaction, borrowed.interaction);
    try nativeRows(main, &source, actual, ch);
}

test "weighted BinarySource canonical mass alias shape and allocator failures preserve borrowed main" {
    const inputs = facts();
    var buffer: [S.MAIN * 32]M = @splat(M.fromCanonical(23));
    try std.testing.expectError(error.InvalidBinaryWeights, S.Source.initWeightedWithMainBuffers(a, &inputs, &.{1}, 5, .{ .main = &buffer }));
    try std.testing.expectError(error.InvalidBinaryWeights, S.Source.initWeightedWithMainBuffers(a, &inputs, &.{ core.fields.m31.Modulus, 1, 1 }, 5, .{ .main = &buffer }));
    try std.testing.expectError(error.BinaryMultiplicityMassExceeded, S.Source.initWeightedWithMainBuffers(a, &inputs, &.{ core.fields.m31.Modulus - 1, 1, 0 }, 5, .{ .main = &buffer }));
    const alias: [*]const u32 = @ptrCast(&buffer);
    try std.testing.expectError(error.OverlappingBinaryInputs, S.Source.initWeightedWithMainBuffers(a, &inputs, alias[0..3], 5, .{ .main = &buffer }));
    for (0..3) |index| {
        var failing = std.testing.FailingAllocator.init(a, .{ .fail_index = index });
        try std.testing.expectError(error.OutOfMemory, S.Source.initWeightedWithMainBuffers(failing.allocator(), &inputs, &.{ 7, 11, 13 }, 5, .{ .main = &buffer }));
    }
    for (buffer) |v| try std.testing.expectEqual(@as(u32, 23), v.v);
    const Runner = struct {
        fn run(allocator: std.mem.Allocator, values: []const S.Fact) !void {
            var source = try S.Source.initWeighted(allocator, values, &.{ 7, 11, 13 }, 5);
            defer source.deinit();
            source.releaseMain();
            _ = try source.generate(challenges());
        }
    };
    try std.testing.checkAllAllocationFailures(a, Runner.run, .{&inputs});
}

test "weighted BinarySource corrupt weight ledger and strict padding pole publish nothing and retry" {
    const inputs = facts();
    var source = try S.Source.initWeighted(a, &inputs, &.{ 7, 11, 13 }, 5);
    defer source.deinit();
    source.releaseMain();
    source.metadata[0].multiplicity_words[0] += 1;
    try std.testing.expectError(error.InvalidBinaryMetadata, source.generate(challenges()));
    source.metadata[0].multiplicity_words[0] -= 1;
    var ch = challenges();
    ch.function.offset = Q.zero();
    ch.function.coefficients = @splat(Q.zero());
    try std.testing.expectError(error.DivisionByZero, source.generate(ch));
    try std.testing.expectEqual(@as(usize, 0), source.interaction.len);
    _ = try source.generate(challenges());
}
