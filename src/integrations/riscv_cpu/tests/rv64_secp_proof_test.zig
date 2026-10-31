const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const rv = @import("stwo_riscv_frontend").rv64_air;
const S = rv.crypto.secp256k1;
const L = S.layout;
const P = S.program;
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const physical = rv.witness.physical;
const F = @import("../crypto/secp_fixture.zig");
fn challenges() S.equations.Challenges {
    var channel = core.channel.blake2s.Blake2sChannel{};
    channel.mixU32s(&.{ 0x53544553, 23 });
    return S.equations.Challenges.draw(&channel);
}
fn inputs() [3]S.trace.Input {
    const p = P.field.base_modulus.integer();
    return .{ .{ .coordinates = .{ 1, 2, 3, 4, 5, 6 } }, .{ .coordinates = .{ p - 1, p, p + 1, 0, 1, 0 } }, .{ .coordinates = .{ std.math.maxInt(u256), p - 17, 31, p + 9, p - 3, p + 2 } } };
}
fn checkTrace(trace: *const S.trace.Trace, ch: S.equations.Challenges, claim: Q) !void {
    const a = std.testing.allocator;
    const n = trace.size();
    const width = L.main(trace.kind);
    const count = L.batches(trace.kind);
    const main = try a.alloc(Q, width);
    defer a.free(main);
    const current = try a.alloc(Q, count);
    defer a.free(current);
    const values = try a.alloc(Q, L.constraints(trace.kind));
    defer a.free(values);
    for (0..n) |logical| {
        const row = physical(logical, trace.log_size);
        const prev = physical((logical + n - 1) % n, trace.log_size);
        var f: [L.FIXED]Q = undefined;
        for (&f, 0..) |*v, c| v.* = Q.fromBase(trace.fixed[c * n + row]);
        for (main, 0..) |*v, c| v.* = Q.fromBase(trace.main[c * n + row]);
        for (current, 0..) |*v, b| v.* = secure(trace.interaction, n, row, 4 * b);
        var sink = rv.evaluation.Sink{ .values = values };
        S.equations.emit(trace.kind, trace.program, .{ .fixed = &f, .main = main, .previous_active = Q.fromBase(trace.main[prev]), .previous_id = Q.fromBase(trace.main[L.base(trace.kind) * n + prev]) }, current, secure(trace.interaction, n, prev, 4 * (count - 1)), claim, ch, .{ .calls = trace.calls, .first_id = trace.first_id }, &sink);
        try std.testing.expectEqual(values.len, sink.count);
        for (values, 0..) |v, i| if (!v.isZero()) {
            std.debug.print("secp residual {s} row{} term{}={any}\n", .{ @tagName(trace.kind), logical, i, v });
            return error.NonzeroSecpResidual;
        };
    }
}
fn secure(data: []const M, n: usize, row: usize, column: usize) Q {
    return Q.fromM31(data[column * n + row], data[(column + 1) * n + row], data[(column + 2) * n + row], data[(column + 3) * n + row]);
}
test "projective modular providers preserve exact topology and close typed wires" {
    const a = std.testing.allocator;
    const in = inputs();
    const ch = challenges();
    for ([_]*const P.Program{ &P.add, &P.double }) |program| {
        var product = try S.trace.Trace.init(a, .product, program, &in, 37);
        defer product.deinit();
        var linear = try S.trace.Trace.init(a, .linear, program, &in, 37);
        defer linear.deinit();
        var counts: [256]u64 = undefined;
        for (&counts, product.byte_counts, linear.byte_counts) |*v, x, y| v.* = x + y;
        var bytes = try rv.range.provider.Trace.init(a, &counts);
        defer bytes.deinit();
        const pc = try product.generateInteraction(ch);
        const lc = try linear.generateInteraction(ch);
        const bc = try bytes.generateInteraction(ch.bytes);
        try std.testing.expect(pc.add(lc).add(bc).eql(try F.expectedWireClaim(program, &in, 37, ch.wire)));
        try checkTrace(&product, ch, pc);
        try checkTrace(&linear, ch, lc);
    }
}
test "projective immutable geometry rejects unsafe spans before allocation" {
    const a = std.testing.allocator;
    const in = inputs();
    const log = try L.logSize(.product, &P.add, in.len);
    try std.testing.expectError(error.InvalidSecpCallSpan, S.trace.Trace.initWithLog(std.testing.failing_allocator, .product, &P.add, &in, core.fields.m31.Modulus - 2, log));
    var x = try S.trace.Trace.initWithLog(a, .product, &P.add, in[0..1], 1, log);
    defer x.deinit();
    var y = try S.trace.Trace.initWithLog(a, .product, &P.add, &in, 91, log);
    defer y.deinit();
    try std.testing.expectEqualSlices(M, x.fixed, y.fixed);
    try std.testing.expectError(error.InvalidSecpGeometry, L.validate(.product, &P.add, 0, 1, 23));
}
test "projective complete formulas cover identity inverse and scaled homogeneous points" {
    const p = P.field.base_modulus.integer();
    const gx: u256 = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798;
    const gy: u256 = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8;
    const g = [_]u256{ gx, gy, 1 };
    const identity = [_]u256{ 0, 1, 0 };
    const cases = [_][6]u256{ g ++ identity, identity ++ g, g ++ [_]u256{ gx, p - gy, 1 }, g ++ g };
    for (cases, 0..) |input, i| {
        const values = try P.execute(&P.add, &input);
        const x = values[P.add.outputs[0]];
        const y = values[P.add.outputs[1]];
        const z = values[P.add.outputs[2]];
        if (i < 2) {
            try std.testing.expectEqual(@as(u256, @intCast(@as(u512, gx) * z % p)), x);
            try std.testing.expectEqual(@as(u256, @intCast(@as(u512, gy) * z % p)), y);
        } else if (i == 2) {
            try std.testing.expectEqual(@as(u256, 0), z);
        } else {
            const doubled = try P.execute(&P.double, &g);
            const dx = doubled[P.double.outputs[0]];
            const dy = doubled[P.double.outputs[1]];
            const dz = doubled[P.double.outputs[2]];
            try std.testing.expectEqual(@as(u256, @intCast(@as(u512, x) * dz % p)), @as(u256, @intCast(@as(u512, dx) * z % p)));
            try std.testing.expectEqual(@as(u256, @intCast(@as(u512, y) * dz % p)), @as(u256, @intCast(@as(u512, dy) * z % p)));
        }
    }
}
test "projective add and double prove once with heterogeneous modular providers and fresh verification" {
    const in = inputs();
    try F.proveAndVerify(std.testing.allocator, &P.add, &in, false);
    try F.proveAndVerify(std.testing.allocator, &P.double, &in, false);
}
test "projective provider rejects forged final predecessor sample" {
    const in = inputs();
    try F.proveAndVerify(std.testing.allocator, &P.add, in[0..1], true);
}
test "projective programs crosscheck independent standard secp256k1 points and arbitrary rescaling" {
    const Secp = std.crypto.ecc.Secp256k1;
    const p = P.field.base_modulus.integer();
    for (1..12) |i| {
        const left = try Secp.basePoint.mul(P.bytes(@intCast(i * 17 + 1)), .little);
        const right = try Secp.basePoint.mul(P.bytes(@intCast(i * 7 + 19)), .little);
        const a = left.affineCoordinates();
        const b = right.affineCoordinates();
        const az: u256 = @intCast(i + 1);
        const bz: u256 = @intCast(2 * i + 3);
        const ax = std.mem.readInt(u256, &a.x.toBytes(.little), .little);
        const ay = std.mem.readInt(u256, &a.y.toBytes(.little), .little);
        const bx = std.mem.readInt(u256, &b.x.toBytes(.little), .little);
        const by = std.mem.readInt(u256, &b.y.toBytes(.little), .little);
        const input = [_]u256{ @intCast(@as(u512, ax) * az % p), @intCast(@as(u512, ay) * az % p), az, @intCast(@as(u512, bx) * bz % p), @intCast(@as(u512, by) * bz % p), bz };
        for ([_]*const P.Program{ &P.add, &P.double }) |program| {
            const values = try P.execute(program, input[0..program.inputs]);
            const expected = (if (program.kind == .add) left.add(right) else left.dbl()).affineCoordinates();
            const ex = std.mem.readInt(u256, &expected.x.toBytes(.little), .little);
            const ey = std.mem.readInt(u256, &expected.y.toBytes(.little), .little);
            const z = values[program.outputs[2]];
            try std.testing.expect(z != 0);
            try std.testing.expectEqual(@as(u256, @intCast(@as(u512, ex) * z % p)), values[program.outputs[0]]);
            try std.testing.expectEqual(@as(u256, @intCast(@as(u512, ey) * z % p)), values[program.outputs[1]]);
        }
    }
}
test "projective empty roster closes and proves without changing provider presence" {
    try F.proveAndVerify(std.testing.allocator, &P.add, &.{}, false);
}
