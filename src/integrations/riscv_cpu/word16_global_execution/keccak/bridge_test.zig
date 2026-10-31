const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const K = A.crypto.keccak.word16_bridge;
const E = A.evaluation;
const M = core.fields.m31.M31;
const Q = E.Q;
const a = std.testing.allocator;
pub fn challenges() K.types.Challenges {
    var channel = A.protocol.Channel{};
    return .{ .ram = draw(A.memory.closed_ram.types.RamChallenges, &channel), .owner = draw(A.memory.load_store_v2.types.OwnerChallenges, &channel), .io = draw(A.crypto.keccak.equations.Io, &channel), .range16 = .{ .offset = channel.drawSecureFelt(), .coefficient = channel.drawSecureFelt() }, .range8 = .{ .offset = channel.drawSecureFelt(), .coefficient = Q.one() } };
}
fn draw(comptime T: type, ch: anytype) T {
    var x: T = undefined;
    x.offset = ch.drawSecureFelt();
    for (&x.coefficients) |*v| v.* = ch.drawSecureFelt();
    return x;
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
    for (0..25) |i| {
        c.before[i] = 0xa5000000 + i;
        c.after[i] = 0xbeef0000 + i;
        c.predecessors[i] = .{ .value = c.before[i], .epoch = if (i % 2 == 0) 1 else 2, .tick = if (i % 2 == 0) 100 else 4, .rights = 3 };
    }
    return c;
}
pub fn checkRows(s: *const K.source.Source, count: u32, ch: K.types.Challenges, claims: K.types.Claims) !void {
    const n = s.size();
    for (0..n) |row| {
        const pos = A.witness.physical(row, s.log_size);
        const prev = A.witness.physical((row + n - 1) % n, s.log_size);
        var f: [K.layout.FIXED]Q = undefined;
        var m: [K.layout.MAIN]Q = undefined;
        var pm: [K.layout.MAIN]Q = undefined;
        var inter: [K.layout.INTERACTION]Q = undefined;
        var pi: [K.layout.INTERACTION]Q = undefined;
        for (&f, 0..) |*v, c| v.* = Q.fromBase(s.fixed[c * n + pos]);
        for (&m, &pm, 0..) |*v, *p, c| {
            v.* = Q.fromBase(s.main[c * n + pos]);
            p.* = Q.fromBase(s.main[c * n + prev]);
        }
        for (&inter, &pi, 0..) |*v, *p, c| {
            v.* = Q.fromBase(s.interaction[c * n + pos]);
            p.* = Q.fromBase(s.interaction[c * n + prev]);
        }
        var residuals: [512]Q = undefined;
        var sink = E.Sink{ .values = &residuals };
        K.equations.emitFor(Q, .bridge, &f, &m, &pm, &inter, &pi, count, s.first_id, claims, ch, &sink);
        try std.testing.expectEqual(K.layout.CONSTRAINTS, sink.count);
        for (residuals[0..sink.count], 0..) |v, index| if (!v.isZero()) {
            std.debug.print("bridge row{d} residual{d}: {any}\n", .{ row, index, v });
            return error.InvalidBridgeResidual;
        };
    }
}
test "Word16 Keccak bridge ordered epochs rights pointer and native residuals" {
    const ch = challenges();
    const d16 = try dict(a, 65536, ch.range16);
    defer a.free(d16);
    const d8 = try dict(a, 256, ch.range8);
    defer a.free(d8);
    var c = call();
    var s = try K.source.Source.init(a, &.{c}, 9, 5);
    defer s.deinit();
    const claims = try s.generate(ch, d16, d8);
    try checkRows(&s, 1, ch, claims);
    c.predecessors[0].rights = 1;
    try std.testing.expectError(error.InvalidWord16KeccakPredecessor, K.source.Source.init(a, &.{c}, 1, 5));
    c = call();
    c.pointer = std.math.maxInt(u64) - 7;
    try std.testing.expectError(error.InvalidWord16KeccakCall, K.source.Source.init(a, &.{c}, 1, 5));
    c = call();
    c.predecessors[0].epoch = 3;
    try std.testing.expectError(error.InvalidWord16KeccakPredecessor, K.source.Source.init(a, &.{c}, 1, 5));
}
test "Word16 Keccak main release and borrowed parity with empty and padded calls" {
    const ch = challenges();
    const d16 = try dict(a, 65536, ch.range16);
    defer a.free(d16);
    const d8 = try dict(a, 256, ch.range8);
    defer a.free(d8);
    const c = call();
    var d = c;
    d.tick = 12;
    for ([_]usize{ 0, 1, 2 }) |count| {
        var s = try K.source.Source.init(a, (&[_]K.types.Call{ c, d })[0..count], 17, 6);
        defer s.deinit();
        const external = try a.alloc(M, K.layout.MAIN * s.size());
        defer a.free(external);
        var b = try K.source.Source.initWithMainBuffer(a, (&[_]K.types.Call{ c, d })[0..count], 17, 6, external);
        defer b.deinit();
        try std.testing.expectEqualSlices(M, s.main, b.main);
        try std.testing.expectError(error.Word16KeccakMainNotOwned, b.takeMain());
        const x = try s.generate(ch, d16, d8);
        try checkRows(&s, @intCast(count), ch, x);
        b.releaseMain();
        const y = try b.generate(ch, d16, d8);
        try std.testing.expectEqualSlices(Q, &x.values(), &y.values());
        try std.testing.expectEqualSlices(M, s.interaction, b.interaction);
    }
}

test "One bridge authority preserves every packed native residual and dense arbitrary QM31 cubic bound" {
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
    K.equations.emitFor(E.PackedBase, .bridge, base[0..fs], base[fs..ms], base[ms..ps], base[ps..is], base[is..], 2, 3, K.types.Claims.zero(), ch, &sink);
    try std.testing.expectEqual(K.layout.CONSTRAINTS, sink.count);
    for (0..16) |lane| {
        var q: [total]Q = undefined;
        for (base, &q) |v, *x| x.* = Q.fromBase(v.lane(lane));
        var residual: [K.layout.CONSTRAINTS]Q = undefined;
        var out = E.Sink{ .values = &residual };
        K.equations.emitFor(Q, .bridge, q[0..fs], q[fs..ms], q[ms..ps], q[ps..is], q[is..], 2, 3, K.types.Claims.zero(), ch, &out);
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
        K.equations.emitFor(Q, .bridge, q[0..fs], q[fs..ms], q[ms..ps], q[ps..is], q[is..], 2, 3, K.types.Claims.zero(), ch, &out);
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
    var s = try K.source.Source.init(allocator, &.{call()}, 1, 5);
    defer s.deinit();
    s.releaseMain();
    _ = try s.generate(challenges(), d16, d8);
}
test "Bridge allocation failures strict pole rollback and main-independent retry" {
    const ch = challenges();
    const d16 = try dict(a, 65536, ch.range16);
    defer a.free(d16);
    const d8 = try dict(a, 256, ch.range8);
    defer a.free(d8);
    try std.testing.checkAllAllocationFailures(a, allocationCase, .{ d16, d8 });
    var s = try K.source.Source.init(a, &.{call()}, 1, 5);
    defer s.deinit();
    s.releaseMain();
    var pole = ch;
    pole.owner.offset = Q.zero();
    pole.owner.coefficients = @splat(Q.zero());
    try std.testing.expectError(error.DivisionByZero, s.generate(pole, d16, d8));
    try std.testing.expectEqual(@as(usize, 0), s.interaction.len);
    try std.testing.expectEqual(@as(usize, 1), s.calls.len);
    _ = try s.generate(ch, d16, d8);
    try std.testing.expectError(error.InvalidWord16KeccakGeometry, K.types.validateGeometry(2, 1, 5));
    try std.testing.expectError(error.InvalidWord16KeccakGeometry, K.types.validateGeometry(1, core.fields.m31.Modulus, 5));
}
