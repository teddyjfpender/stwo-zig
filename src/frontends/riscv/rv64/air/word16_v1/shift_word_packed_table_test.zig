const std = @import("std");
const core = @import("stwo_core");
const E = @import("../evaluation.zig");
const T = @import("shift_word_packed_table.zig");
const Word = @import("shift_word_table.zig");
const physical = @import("../witness.zig").physical;
const M = core.fields.m31.M31;
const Q = E.Q;
fn secure(x: u32) Q {
    return Q.fromU32Unchecked(x, x + 1, x + 2, x + 3);
}
fn challenges() T.Challenges {
    return .{ .offset = secure(5), .coefficients = .{ E.q(3), E.q(7), E.q(11), E.q(13), E.q(17), E.q(19) } };
}
test "packed Word16 immutable quotient columns derive every one of the million semantic facts" {
    var setup = try T.Setup.init(std.testing.allocator);
    defer setup.deinit();
    for (0..T.SIZE) |x| {
        var fields: [T.FIXED]Q = undefined;
        for (&fields, 0..) |*v, c| v.* = Q.fromBase(setup.fixed[c * T.SIZE + physical(x, T.LOG)]);
        for (0..16) |r| {
            const tuple = T.tupleFor(Q, &fields, r);
            const left = @as(u64, x) << @as(u6, @intCast(r));
            const right = (@as(u64, x) << 16) >> @as(u6, @intCast(r));
            const expected = [_]u32{ @intCast(x), @intCast(r), @intCast(left & 65535), @intCast(left >> 16), @intCast(right >> 16), @intCast(right & 65535) };
            try std.testing.expectEqualSlices(u32, &Word.tupleAt(16 * x + r), &expected);
            for (tuple, expected) |v, value| try std.testing.expectEqual(value, (try v.tryIntoM31()).v);
        }
    }
}
test "packed Word16 prepared affine denominators and weighted D3 residuals agree for arbitrary secure coordinates" {
    var ch = challenges();
    for (&ch.coefficients, 0..) |*v, i| v.* = secure(@intCast(31 + 4 * i));
    const prepared = T.Prepared.init(ch);
    var samples: [5][T.CONSTRAINTS]Q = undefined;
    for (0..5) |t| {
        var fields: [T.FIXED]Q = undefined;
        var main: [T.MAIN]Q = undefined;
        var current: [T.INTERACTION]Q = undefined;
        var previous: [T.INTERACTION]Q = undefined;
        var counter: u32 = 101;
        inline for (.{ &fields, &main, &current, &previous }) |values| for (values) |*v| {
            v.* = secure(counter).add(secure(counter + 4).mul(E.q(@intCast(t))));
            counter += 8;
        };
        for (0..16) |r| {
            const tuple = T.tupleFor(Q, &fields, r);
            try std.testing.expect(prepared.denominatorFor(Q, &fields, r).eql(ch.denominator(&tuple)));
        }
        var sink = E.Sink{ .values = &samples[t] };
        T.emitFor(Q, &fields, &main, &current, &previous, secure(11), &prepared, &sink);
        try std.testing.expectEqual(T.CONSTRAINTS, sink.count);
    }
    var cubic = false;
    for (0..T.CONSTRAINTS) |c| {
        var d: [5]Q = undefined;
        for (&d, 0..) |*v, i| v.* = samples[i][c];
        for (0..3) |order| for (0..4 - order) |i| {
            d[i] = d[i + 1].sub(d[i]);
        };
        cubic = cubic or !d[0].isZero();
        try std.testing.expect(d[1].sub(d[0]).isZero());
    }
    try std.testing.expect(cubic);
    inline for (.{ E.PackedBase, E.PackedSecure }) |F| {
        var fields: [T.FIXED]F = undefined;
        var main: [T.MAIN]F = undefined;
        var current: [T.INTERACTION]F = undefined;
        var previous: [T.INTERACTION]F = undefined;
        var references: [16][T.FIXED + T.MAIN + 2 * T.INTERACTION]Q = undefined;
        var column: usize = 0;
        inline for (.{ &fields, &main, &current, &previous }) |values| for (values) |*v| {
            var base: [16]M = undefined;
            var extension: [16]Q = undefined;
            for (0..16) |lane| {
                const x: u32 = @intCast(1 + 4 * (16 * column + lane));
                base[lane] = M.fromCanonical(x);
                extension[lane] = if (F == E.PackedBase) E.q(x) else secure(x);
                references[lane][column] = extension[lane];
            }
            v.* = if (F == E.PackedBase) F.fromLanes(base) else F.fromLanes(extension);
            column += 1;
        };
        var actual: [T.CONSTRAINTS]E.PackedSecure = undefined;
        var sink = E.SinkFor(F){ .values = &actual };
        T.emitFor(F, &fields, &main, &current, &previous, secure(11), &prepared, &sink);
        for (0..16) |lane| {
            const values = references[lane];
            var expected: [T.CONSTRAINTS]Q = undefined;
            var scalar = E.Sink{ .values = &expected };
            T.emitFor(Q, values[0..18], values[18..34], values[34..70], values[70..106], secure(11), &prepared, &scalar);
            for (actual, expected) |a, b| try std.testing.expect(a.lane(lane).eql(b));
        }
    }
}
fn ownedFailure(a: std.mem.Allocator, setup: *const T.Setup, counts: []const u64) !void {
    var request = try T.Request.init(a, setup, counts);
    defer request.deinit();
    _ = try request.generateInteraction(challenges());
}
test "packed Word16 source publishes no inverse output on allocation or pole failure and all native residuals close" {
    const a = std.testing.allocator;
    var setup = try T.Setup.init(a);
    defer setup.deinit();
    const counts = try a.alloc(u64, T.SEMANTIC_FACTS);
    defer a.free(counts);
    @memset(counts, 0);
    counts[17] = 3;
    counts[T.SEMANTIC_FACTS - 1] = 2;
    try std.testing.checkAllAllocationFailures(a, ownedFailure, .{ &setup, counts });
    var request = try T.Request.init(a, &setup, counts);
    defer request.deinit();
    try std.testing.expectError(error.DivisionByZero, request.generateInteraction(.{ .offset = Q.zero(), .coefficients = @splat(Q.zero()) }));
    try std.testing.expectEqual(@as(usize, 0), request.interaction.len);
    try std.testing.expectEqual(@as(usize, 0), request.dictionary.len);
    const ch = challenges();
    const claim = try request.generateInteraction(ch);
    const prepared = T.Prepared.init(ch);
    try std.testing.expect(claim.eql(request.dictionary[17].mulM31(M.fromCanonical(3)).add(request.dictionary[T.SEMANTIC_FACTS - 1].mulM31(M.fromCanonical(2))).neg()));
    for (0..T.SIZE) |x| {
        const row = physical(x, T.LOG);
        const prior = physical(if (x == 0) T.SIZE - 1 else x - 1, T.LOG);
        var fixed: [T.FIXED]Q = undefined;
        var main: [T.MAIN]Q = undefined;
        var current: [T.INTERACTION]Q = undefined;
        var previous: [T.INTERACTION]Q = undefined;
        for (&fixed, 0..) |*v, c| v.* = Q.fromBase(setup.fixed[c * T.SIZE + row]);
        for (&main, 0..) |*v, c| v.* = Q.fromBase(request.main[c * T.SIZE + row]);
        for (&current, &previous, 0..) |*v, *p, c| {
            v.* = Q.fromBase(request.interaction[c * T.SIZE + row]);
            p.* = Q.fromBase(request.interaction[c * T.SIZE + prior]);
        }
        var residuals: [T.CONSTRAINTS]Q = undefined;
        var sink = E.Sink{ .values = &residuals };
        T.emitFor(Q, &fixed, &main, &current, &previous, claim, &prepared, &sink);
        for (residuals) |v| try std.testing.expect(v.isZero());
    }
    try std.testing.expectError(error.InvalidPackedWordShiftPhase, request.generateInteraction(ch));
}
