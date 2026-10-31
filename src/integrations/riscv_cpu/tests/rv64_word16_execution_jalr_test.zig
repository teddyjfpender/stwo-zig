const std = @import("std");
const core = @import("stwo_core");
const front = @import("stwo_riscv_frontend");
const X = front.rv64_air.word16_execution;
const E = front.rv64_air.evaluation;
const J = X.jalr_equations;
const Q = E.Q;
const M = core.fields.m31.M31;
const Source = @import("../word16_execution/jalr_source.zig").Source;
const Fact = @import("../word16_execution/jalr_source.zig").Fact;
const a = std.testing.allocator;
fn challenge() X.types.FunctionChallenges {
    var channel = core.channel.blake2s.Blake2sChannel{};
    var ch: X.types.FunctionChallenges = undefined;
    ch.offset = channel.drawSecureFelt();
    for (&ch.coefficients) |*v| v.* = channel.drawSecureFelt();
    return ch;
}
fn toQ(comptime N: usize, values: [N]M) [N]Q {
    var out: [N]Q = undefined;
    for (values, &out) |v, *o| o.* = Q.fromBase(v);
    return out;
}
const facts = [_]Fact{ .{ .a = 0, .b = 8, .c = 8 }, .{ .a = std.math.maxInt(u64), .b = 1, .c = 0 }, .{ .a = 0, .b = std.math.maxInt(u64), .c = std.math.maxInt(u64) - 1 } };
fn audit(source: *const Source, claim: Q, ch: X.types.FunctionChallenges) !void {
    for (0..source.size()) |logical| {
        const pos = X.layout.physical(logical, source.log_size);
        const previous = X.layout.physical((logical + source.size() - 1) % source.size(), source.log_size);
        var current: [12]Q = undefined;
        var prior: [12]Q = undefined;
        for (0..12) |c| {
            current[c] = Q.fromBase(source.interaction[c * source.size() + pos]);
            prior[c] = Q.fromBase(source.interaction[c * source.size() + previous]);
        }
        var residuals: [6]Q = undefined;
        var sink = E.Sink{ .values = &residuals };
        J.emitFor(Q, &.{ E.q(@intFromBool(logical == 0)), E.q(@intFromBool(logical + 1 == source.size())) }, &toQ(18, source.rowValues(logical)), &current, &prior, claim, ch, &sink);
        try std.testing.expectEqual(@as(usize, 6), sink.count);
        for (residuals) |v| try std.testing.expect(v.isZero());
    }
}
fn allocationProbe(allocator: std.mem.Allocator) !void {
    var source = try Source.init(allocator, &facts, 5);
    defer source.deinit();
    source.releaseMain();
    const claim = try source.generate(challenge());
    try audit(&source, claim, challenge());
}
test "unit JALR native source survives main retirement and all allocation failures with real support facts" {
    var source = try Source.init(a, &facts, 5);
    defer source.deinit();
    const alu = try source.aluFacts(a);
    defer a.free(alu);
    const binary = try source.binaryFacts(a);
    defer a.free(binary);
    try std.testing.expectEqual(facts.len, alu.len);
    try std.testing.expectEqual(facts.len, binary.len);
    for (facts, alu, binary) |fact, add, and_| {
        try std.testing.expectEqual(fact.a +% fact.b, add.c);
        try std.testing.expectEqual(add.c, and_.a);
        try std.testing.expectEqual(~@as(u64, 1), and_.b);
        try std.testing.expectEqual(fact.c, and_.c);
        try std.testing.expectEqual((fact.a +% fact.b) & ~@as(u64, 1), fact.c);
    }
    source.releaseMain();
    const ch = challenge();
    const claim = try source.generate(ch);
    try audit(&source, claim, ch);
    try std.testing.expectError(error.InvalidJalrPhase, source.generate(ch));
    try std.testing.checkAllAllocationFailures(a, allocationProbe, .{});
    var clean = try Source.init(a, &facts, 5);
    defer clean.deinit();
    try std.testing.expectError(error.DivisionByZero, clean.generate(.{ .offset = Q.zero(), .coefficients = @splat(Q.zero()) }));
    try std.testing.expect(clean.claim == null and clean.interaction.len == 0);
    _ = try clean.generate(ch);
}
test "unit JALR six residuals are cubic and packed lanes equal full QM31" {
    const ch = challenge();
    var channel = core.channel.blake2s.Blake2sChannel{};
    const claim = channel.drawSecureFelt();
    var constant: [4][18]Q = undefined;
    var slope: [4][18]Q = undefined;
    for (&constant, &slope) |*x, *y| for (x, y) |*v, *w| {
        v.* = channel.drawSecureFelt();
        w.* = channel.drawSecureFelt();
    };
    var results: [5][6]Q = undefined;
    for (0..5) |point| {
        var data: [4][18]Q = undefined;
        for (&data, constant, slope) |*x, y, z| {
            for (x, y, z) |*v, c, s| v.* = c.add(s.mulM31(M.fromCanonical(@intCast(point))));
        }
        var sink = E.Sink{ .values = &results[point] };
        J.emitFor(Q, data[0][0..2], &data[1], data[2][0..12], data[3][0..12], claim, ch, &sink);
    }
    for (0..6) |i| try std.testing.expect(results[4][i].sub(results[3][i].mulM31(M.fromCanonical(4))).add(results[2][i].mulM31(M.fromCanonical(6))).sub(results[1][i].mulM31(M.fromCanonical(4))).add(results[0][i]).isZero());
    var native: [4][18][16]M = undefined;
    var simd: [4][18]E.PackedBase = undefined;
    for (&native, &simd) |*x, *y| for (x, y) |*lanes, *v| {
        for (lanes) |*lane| lane.* = channel.drawSecureFelt().toM31Array()[0];
        v.* = E.PackedBase.fromLanes(lanes.*);
    };
    var got: [6]E.PackedSecure = undefined;
    var sink = E.PackedSink{ .values = &got };
    J.emitFor(E.PackedBase, simd[0][0..2], &simd[1], simd[2][0..12], simd[3][0..12], claim, ch, &sink);
    for (0..16) |lane| {
        var data: [4][18]Q = undefined;
        for (&data, native) |*x, y| {
            for (x, y) |*v, lanes| v.* = Q.fromBase(lanes[lane]);
        }
        var expected: [6]Q = undefined;
        var out = E.Sink{ .values = &expected };
        J.emitFor(Q, data[0][0..2], &data[1], data[2][0..12], data[3][0..12], claim, ch, &out);
        for (expected, got) |v, w| try std.testing.expect(v.eql(w.lane(lane)));
    }
    const c = X.jalr_component.Component{ .log_size = 5, .offsets = .{ 0, 0, 0 }, .claim = claim, .challenges = ch };
    _ = c.asProverComponent();
    _ = c.asVerifierComponent();
}
fn row(av: u64, bv: u64, cv: u64, sum: u64, weight: Q) [18]Q {
    var native: [18]M = @splat(M.zero());
    X.features.put(&native, 0, av);
    X.features.put(&native, 4, bv);
    X.features.put(&native, 8, cv);
    X.features.put(&native, 12, sum);
    var out = toQ(18, native);
    out[16] = Q.one();
    out[17] = weight;
    return out;
}
test "signed composite marginal forgery closes global FUNCTION claims but the unit polynomial rejects it" {
    const ch = challenge();
    // Net FN10 requests are FALSE (0+0)->2 and (1+1)->0. With signed
    // composite weights, ADD and AND marginals nevertheless contain only TRUE
    // facts. Acyclic operation IDs alone do not make this join sound.
    const rows = [_][18]Q{ row(0, 0, 2, 0, Q.one()), row(1, 1, 0, 0, Q.one()), row(1, 1, 2, 0, Q.one().neg()), row(1, 1, 2, 2, Q.one()) };
    var inter: [4][12]Q = undefined;
    var contributions: [4]Q = undefined;
    var claim = Q.zero();
    for (rows, 0..) |r, i| {
        const ds = J.denominatorsFor(Q, &r, ch);
        const inv = try ds.request.inv();
        const pair = try ds.add.mul(ds.and_).inv();
        for (inv.toM31Array(), 0..) |v, c| inter[i][c] = Q.fromBase(v);
        for (pair.toM31Array(), 0..) |v, c| inter[i][4 + c] = Q.fromBase(v);
        contributions[i] = J.contributionFor(Q, ds, r[17], inv, pair);
        claim = claim.add(contributions[i]);
    }
    var prefix = claim.neg();
    for (contributions, 0..) |value, i| {
        prefix = prefix.add(value);
        for (prefix.toM31Array(), 0..) |v, c| inter[i][8 + c] = Q.fromBase(v);
    }
    var global = claim;
    global = global.add(try ch.denominatorFor(Q, J.request(Q, &rows[0])).inv()).add(try ch.denominatorFor(Q, J.request(Q, &rows[1])).inv());
    const good0 = row(0, 0, 0, 0, Q.one());
    const good1 = row(1, 1, 2, 2, Q.one());
    global = global.sub(try ch.denominatorFor(Q, J.add(Q, &good0)).inv()).sub(try ch.denominatorFor(Q, J.add(Q, &good1)).inv());
    global = global.sub(try ch.denominatorFor(Q, J.and_(Q, &good0)).inv()).sub(try ch.denominatorFor(Q, J.and_(Q, &good1)).inv());
    try std.testing.expect(global.isZero());
    for (rows, 0..) |r, i| {
        var residuals: [6]Q = undefined;
        var sink = E.Sink{ .values = &residuals };
        J.emitFor(Q, &.{ E.q(@intFromBool(i == 0)), E.q(@intFromBool(i == 3)) }, &r, &inter[i], &inter[(i + 3) % 4], claim, ch, &sink);
        for (residuals, 0..) |value, index| if (index == 1 and i == 2) {
            try std.testing.expect(value.eql(E.q(2).neg()));
        } else try std.testing.expect(value.isZero());
        // The old proposed inactive*weight guard would be zero on every row.
        try std.testing.expect(Q.one().sub(r[16]).mul(r[17]).isZero());
    }
}
