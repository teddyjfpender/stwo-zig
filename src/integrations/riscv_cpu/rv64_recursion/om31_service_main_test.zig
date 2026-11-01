const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const E = A.evaluation;
const K = A.crypto.keccak;
const S = A.crypto.secp256k1;
const lane = @import("om31_circuit_lane.zig");
const W = lane.Lane;
const O = core.fields.om31.OM31;
const M = core.fields.m31.M31;
const a = std.testing.allocator;
const Role = enum { keccak_bridge, secp_add_bridge, secp_double_bridge, secp_product, secp_linear, keccak_truth };
fn dense(n: u32) O {
    var out: [8]M = undefined;
    for (&out, 0..) |*v, i| v.* = M.fromCanonical(n + @as(u32, @intCast(i * 79)));
    return O.fromM31Array(out);
}
fn lift(comptime F: type, ctx: *lane.Context, n: usize, t: usize) !F {
    const value = dense(@intCast(n * 71 + 3)).add(dense(@intCast(n * 17 + 97)).mul(O.fromBase(M.fromCanonical(@intCast(t)))));
    if (F == O) return value;
    return W.guess(ctx, value);
}
fn array(comptime F: type, comptime n: usize, ctx: *lane.Context, seed: usize, t: usize) ![n]F {
    var out: [n]F = undefined;
    for (&out, 0..) |*v, i| v.* = try lift(F, ctx, seed + i, t);
    return out;
}
fn span(comptime F: type, ctx: *lane.Context) !E.CallSpanFor(E.ConstFor(F)) {
    if (F == O) return .{ .calls = 3, .first_id = 5 };
    return .{ .calls = try W.guess(ctx, O.fromBase(M.fromCanonical(3))), .first_id = try W.guess(ctx, O.fromBase(M.fromCanonical(5))), .nonempty = try W.guess(ctx, O.one()) };
}
fn emit(comptime F: type, ctx: *lane.Context, role: Role, t: usize, values: []F) !usize {
    var sink = E.SinkFor(F){ .values = values };
    const public = try span(F, ctx);
    switch (role) {
        .keccak_bridge => {
            const f = try array(F, K.word16_bridge.layout.FIXED, ctx, 1, t);
            const m = try array(F, K.word16_bridge.layout.MAIN, ctx, 101, t);
            const p = try array(F, K.word16_bridge.layout.MAIN, ctx, 211, t);
            K.word16_bridge.equations.emitMainFor(F, &f, &m, &p, public, &sink);
        },
        .secp_add_bridge, .secp_double_bridge => {
            const f = try array(F, S.word16_bridge.layout.FIXED, ctx, 1, t);
            const m = try array(F, S.word16_bridge.layout.MAIN, ctx, 101, t);
            const p = try array(F, S.word16_bridge.layout.MAIN, ctx, 211, t);
            S.word16_bridge.equations.emitMainFor(F, if (role == .secp_add_bridge) .add else .double, &f, &m, &p, public, &sink);
        },
        .secp_product, .secp_linear => {
            const kind: S.layout.Kind = if (role == .secp_product) .product else .linear;
            const f = try array(F, S.layout.FIXED, ctx, 1, t);
            const m = try array(F, 512, ctx, 101, t);
            const row = S.equations.RowFor(F){ .fixed = &f, .main = m[0..S.layout.main(kind)], .previous_active = try lift(F, ctx, 777, t), .previous_id = try lift(F, ctx, 889, t) };
            const polynomial = if (F == O) dense(999) else try W.guess(ctx, dense(999));
            S.equations.emitMainFor(F, kind, row, polynomial, public, &sink);
        },
        .keccak_truth => {
            const f = try array(F, K.layout.FIXED, ctx, 1, t);
            const m = try array(F, K.layout.MAIN, ctx, 101, t);
            const h = try array(F, 3, ctx, 2101, t);
            const minus_two = try array(F, K.layout.STATE, ctx, 3101, t);
            const minus_one = try array(F, K.layout.STATE, ctx, 5101, t);
            const plus_one = try array(F, K.layout.STATE, ctx, 7101, t);
            const plus_two = try array(F, K.layout.STATE, ctx, 9101, t);
            const row = K.equations.RowFor(F){ .fixed = &f, .main = &m, .previous_header = &h, .state_minus_two = &minus_two, .state_minus_one = &minus_one, .state_plus_one = &plus_one, .state_plus_two = &plus_two };
            // The existing qualified pair2n boundary gate: padding bits are
            // already forcedzero; no extra ACTIVE factor is necessary here.
            K.equations.emitDirectFor(F, row, public, &sink, false);
        },
    }
    return sink.count;
}
test "OM31 service MAIN seams match all8 actual circuit coordinates and stay degree3" {
    // Residual buffers use heap scratch; state arrays here belong to the test runner.
    const native = try a.alloc(O, 8192);
    defer a.free(native);
    const wires = try a.alloc(W, 8192);
    defer a.free(wires);
    const differences = try a.alloc(O, 5 * 8192);
    defer a.free(differences);
    for (std.enums.values(Role)) |role| {
        var ctx = try lane.Context.init(a, 0);
        defer ctx.deinit();
        lane.begin(&ctx);
        var bound = true;
        defer if (bound) lane.finish() catch {};
        const n = try emit(O, &ctx, role, 0, native);
        try std.testing.expectEqual(n, try emit(W, &ctx, role, 0, wires));
        for (native[0..n], wires[0..n]) |expected, actual| try std.testing.expectEqualDeep(expected.toM31Array(), actual.value().toM31Array());
        bound = false;
        try lane.finish();
        try ctx.finalize(false);
        try std.testing.expect(try ctx.isCircuitValid());
        for (0..5) |t| try std.testing.expectEqual(n, try emit(O, &ctx, role, t, differences[t * 8192 ..][0..8192]));
        for (0..4) |order| for (0..4 - order) |t| for (0..n) |c| {
            differences[t * 8192 + c] = differences[(t + 1) * 8192 + c].sub(differences[t * 8192 + c]);
        };
        for (differences[0..n]) |residual| try std.testing.expect(residual.isZero());
        std.debug.print("OM_SERVICE_MAIN {s} {d}\n", .{ @tagName(role), n });
    }
}
