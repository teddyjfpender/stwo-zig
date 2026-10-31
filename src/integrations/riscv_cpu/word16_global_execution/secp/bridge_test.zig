const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const Secp = A.crypto.secp256k1;
const K = Secp.word16_bridge;
const E = A.evaluation;
const M = core.fields.m31.M31;
const Q = E.Q;
const a = std.testing.allocator;
fn draw(comptime T: type, ch: anytype) T {
    var x: T = undefined;
    x.offset = ch.drawSecureFelt();
    for (&x.coefficients) |*v| v.* = ch.drawSecureFelt();
    return x;
}
pub fn challenges() K.types.Challenges {
    var ch = A.protocol.Channel{};
    return .{ .ram = draw(A.memory.closed_ram.types.RamChallenges, &ch), .owner = draw(A.memory.load_store_v2.types.OwnerChallenges, &ch), .wire = Secp.equations.Wire.draw(&ch), .range16 = .{ .offset = ch.drawSecureFelt(), .coefficient = ch.drawSecureFelt() }, .range8 = .{ .offset = ch.drawSecureFelt(), .coefficient = Q.one() } };
}
pub fn dict(allocator: std.mem.Allocator, n: usize, ch: A.word16_cpu.lookup.RangeChallenges) ![]Q {
    const input = try allocator.alloc(Q, n);
    defer allocator.free(input);
    const out = try allocator.alloc(Q, n);
    errdefer allocator.free(out);
    for (input, 0..) |*v, i| v.* = ch.denominatorFor(Q, Q.fromBase(M.fromCanonical(@intCast(i))));
    try core.fields.batchInverseInPlace(Q, input, out);
    return out;
}
pub fn call() K.types.Call {
    var c: K.types.Call = .{ .pointer = 0xfffffffffffffe00, .epoch = 2, .tick = 8, .before = undefined, .after = undefined, .predecessors = undefined };
    for (0..24) |i| {
        c.before[i] = 0xa5000000 + i;
        c.after[i] = if (i < 12) 0xbeef0000 + i else c.before[i];
        c.predecessors[i] = .{ .value = c.before[i], .epoch = if (i % 2 == 0) 1 else 2, .tick = if (i % 2 == 0) 100 else 4, .rights = if (i < 12) 3 else 1 };
    }
    return c;
}
fn checkRows(s: *const K.source.Source, count: u32, ch: K.types.Challenges, claims: K.types.Claims) !void {
    const n = s.size();
    for (0..n) |row| {
        const p = A.witness.physical(row, s.log_size);
        const prev = A.witness.physical((row + n - 1) % n, s.log_size);
        var f: [K.layout.FIXED]Q = undefined;
        var m: [K.layout.MAIN]Q = undefined;
        var pm: [K.layout.MAIN]Q = undefined;
        var inter: [K.layout.INTERACTION]Q = undefined;
        var pi: [K.layout.INTERACTION]Q = undefined;
        for (&f, 0..) |*v, c| v.* = Q.fromBase(s.fixed[c * n + p]);
        for (&m, &pm, 0..) |*v, *old, c| {
            v.* = Q.fromBase(s.main[c * n + p]);
            old.* = Q.fromBase(s.main[c * n + prev]);
        }
        for (&inter, &pi, 0..) |*v, *old, c| {
            v.* = Q.fromBase(s.interaction[c * n + p]);
            old.* = Q.fromBase(s.interaction[c * n + prev]);
        }
        var residual: [K.layout.CONSTRAINTS]Q = undefined;
        var sink = E.Sink{ .values = &residual };
        K.equations.emitFor(Q, s.kind, &f, &m, &pm, &inter, &pi, count, s.first_id, claims, ch, &sink);
        try std.testing.expectEqual(K.layout.CONSTRAINTS, sink.count);
        for (residual, 0..) |v, index| if (!v.isZero()) {
            std.debug.print("secp bridge row{d} residual{d}\n", .{ row, index });
            return error.InvalidSecpBridgeResidual;
        };
    }
}
test "Secp coordinate bridge native RAM permissions owner tags and exact Wire35 bytes" {
    const ch = challenges();
    const d16 = try dict(a, 65536, ch.range16);
    defer a.free(d16);
    const d8 = try dict(a, 256, ch.range8);
    defer a.free(d8);
    for ([_]Secp.program.Kind{ .add, .double }) |kind| {
        var s = try K.source.Source.init(a, kind, &.{call()}, 7, 5);
        defer s.deinit();
        const claims = try s.generate(ch, d16, d8);
        try checkRows(&s, 1, ch, claims);
        var row: [K.layout.MAIN]Q = undefined;
        const native = K.source.nativeRow(kind, call(), 0, 7);
        for (native, &row) |v, *q| q.* = Q.fromBase(v);
        const owner = K.equations.ownerTuple(Q, kind, &row);
        try std.testing.expect(owner[9].eql(Q.fromBase(M.fromCanonical(@as(u16, @truncate(K.types.tag(kind)))))));
        var f: [K.layout.FIXED]Q = @splat(Q.zero());
        f[7] = Q.fromBase(M.fromCanonical(Secp.program.get(kind).outputs[0]));
        var bytes: [32]u8 = undefined;
        for (0..4) |i| std.mem.writeInt(u64, bytes[8 * i ..][0..8], call().before[i], .little);
        try std.testing.expectEqualSlices(Q, &Secp.equations.externalTuple(Secp.program.get(kind), 7, 0, std.mem.readInt(u256, &bytes, .little)), &K.equations.wireTuple(Q, kind, &f, &row, false));
    }
}
test "Secp bridge borrowed MAIN release retains exact interactions for empty odd and padded calls" {
    const ch = challenges();
    const d16 = try dict(a, 65536, ch.range16);
    defer a.free(d16);
    const d8 = try dict(a, 256, ch.range8);
    defer a.free(d8);
    var second = call();
    second.tick = 12;
    for ([_]usize{ 0, 1, 2 }) |count| {
        var s = try K.source.Source.init(a, .add, (&[_]K.types.Call{ call(), second })[0..count], 11, 5);
        defer s.deinit();
        const main = try a.alloc(M, K.layout.MAIN * s.size());
        defer a.free(main);
        var b = try K.source.Source.initWithMainBuffer(a, .add, (&[_]K.types.Call{ call(), second })[0..count], 11, 5, main);
        defer b.deinit();
        try std.testing.expectEqualSlices(M, s.main, b.main);
        const x = try s.generate(ch, d16, d8);
        try checkRows(&s, @intCast(count), ch, x);
        b.releaseMain();
        try std.testing.expectError(error.Word16SecpMainNotOwned, b.takeMain());
        const y = try b.generate(ch, d16, d8);
        try std.testing.expectEqualSlices(Q, &x.values(), &y.values());
        try std.testing.expectEqualSlices(M, s.interaction, b.interaction);
    }
}
test "Secp coordinate bridge authority preserves every packed native residual and dense arbitrary QM31 cubic bound" {
    const ch = challenges();
    const total = K.layout.FIXED + 2 * K.layout.MAIN + 2 * K.layout.INTERACTION;
    var base: [total]E.PackedBase = undefined;
    for (&base, 0..) |*v, c| {
        var lanes: [16]M = undefined;
        for (&lanes, 0..) |*x, lane| x.* = M.fromCanonical(@intCast(1 + c * 17 + lane));
        v.* = E.PackedBase.fromLanes(lanes);
    }
    const fs = K.layout.FIXED;
    const ms = fs + K.layout.MAIN;
    const ps = ms + K.layout.MAIN;
    const is = ps + K.layout.INTERACTION;
    var packed_residuals: [K.layout.CONSTRAINTS]E.PackedSecure = undefined;
    var sink = E.PackedSink{ .values = &packed_residuals };
    K.equations.emitFor(E.PackedBase, .add, base[0..fs], base[fs..ms], base[ms..ps], base[ps..is], base[is..], 2, 3, K.types.Claims.zero(), ch, &sink);
    try std.testing.expectEqual(K.layout.CONSTRAINTS, sink.count);
    for (0..16) |lane| {
        var q: [total]Q = undefined;
        for (base, &q) |v, *x| x.* = Q.fromBase(v.lane(lane));
        var residual: [K.layout.CONSTRAINTS]Q = undefined;
        var out = E.Sink{ .values = &residual };
        K.equations.emitFor(Q, .add, q[0..fs], q[fs..ms], q[ms..ps], q[ps..is], q[is..], 2, 3, K.types.Claims.zero(), ch, &out);
        for (residual, packed_residuals) |x, y| try std.testing.expect(x.eql(y.lane(lane)));
    }
    var rows: [5][K.layout.CONSTRAINTS]Q = undefined;
    for (&rows, 0..) |*residual, step| {
        var q: [total]Q = undefined;
        for (&q, 0..) |*x, c| {
            const intercept = Q.fromU32Unchecked(@intCast(1 + c), 2, 3, 4);
            const slope = Q.fromU32Unchecked(5, @intCast(6 + c), 7, 8);
            x.* = intercept.add(slope.mulM31(M.fromCanonical(@intCast(step))));
        }
        var out = E.Sink{ .values = residual };
        K.equations.emitFor(Q, .add, q[0..fs], q[fs..ms], q[ms..ps], q[ps..is], q[is..], 2, 3, K.types.Claims.zero(), ch, &out);
        try std.testing.expectEqual(K.layout.CONSTRAINTS, out.count);
    }
    var cubic = false;
    for (0..K.layout.CONSTRAINTS) |c| {
        const third = rows[3][c].sub(rows[2][c].mulM31(M.fromCanonical(3))).add(rows[1][c].mulM31(M.fromCanonical(3))).sub(rows[0][c]);
        cubic = cubic or !third.isZero();
        const fourth = rows[4][c].sub(rows[3][c].mulM31(M.fromCanonical(4))).add(rows[2][c].mulM31(M.fromCanonical(6))).sub(rows[1][c].mulM31(M.fromCanonical(4))).add(rows[0][c]);
        try std.testing.expect(fourth.isZero());
    }
    try std.testing.expect(cubic);
}
fn allocationCase(allocator: std.mem.Allocator, d16: []const Q, d8: []const Q) !void {
    var s = try K.source.Source.init(allocator, .add, &.{call()}, 1, 5);
    defer s.deinit();
    s.releaseMain();
    _ = try s.generate(challenges(), d16, d8);
}
test "Secp bridge allocation failures strict wire poles and retry retain packet metadata" {
    const ch = challenges();
    const d16 = try dict(a, 65536, ch.range16);
    defer a.free(d16);
    const d8 = try dict(a, 256, ch.range8);
    defer a.free(d8);
    try std.testing.checkAllAllocationFailures(a, allocationCase, .{ d16, d8 });
    var s = try K.source.Source.init(a, .add, &.{call()}, 1, 5);
    defer s.deinit();
    s.releaseMain();
    var bad = ch;
    bad.wire.offset = Q.zero();
    bad.wire.coefficients = @splat(Q.zero());
    try std.testing.expectError(error.DivisionByZero, s.generate(bad, d16, d8));
    try std.testing.expectEqual(@as(usize, 0), s.interaction.len);
    try std.testing.expectEqual(@as(usize, 1), s.calls.len);
    _ = try s.generate(ch, d16, d8);
    var c = call();
    c.pointer += 8;
    try std.testing.expectError(error.InvalidWord16SecpCall, K.source.Source.init(a, .add, &.{c}, 1, 5));
    c = call();
    c.predecessors[13].rights = 0;
    try std.testing.expectError(error.InvalidWord16SecpPredecessor, K.source.Source.init(a, .add, &.{c}, 1, 5));
}
