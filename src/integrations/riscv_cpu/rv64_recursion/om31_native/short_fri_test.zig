const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const C = @import("common.zig");
const P = @import("proof.zig");
const Fri = @import("fri.zig");
const O = C.O;
const F = C.F;
const H = core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleHasher;
const M = core.fields.m31.M31;
const a = std.testing.allocator;

test "OM31 native PCS short FRI policy comes from geometry" {
    const groups = circuit.native_verifier.fri.shortLineGroups;
    try std.testing.expectEqual(8, groups(2, 3, 4, 54, 0));
    try std.testing.expectEqual(4, groups(4, 2, 1, 54, 0));
    for ([_][5]usize{ .{ 0, 3, 4, 54, 0 }, .{ 1, 4, 4, 54, 0 }, .{ 1, 3, 4, 54, 2 }, .{ 1, 3, 4, 7, 0 }, .{ 1, 3, 4, core.fields.m31.Modulus, 0 }, .{ 1, 3, 0, 54, 0 } }) |x| {
        try std.testing.expectEqual(0, groups(x[0], x[1], x[2], x[3], x[4]));
    }
}

const Fault = enum { none, selected_value, selected_path, target, padding };
fn hashWire(ctx: *C.Context, digest: H.Hash) !C.Hash {
    return circuit.builder.blake.guessHash(C.Q, ctx, circuit.builder.blake.hashValueFromDigest(C.Q, digest));
}
fn check(sparse: bool, fault: Fault) !usize {
    var ctx = try C.Context.init(a, 0);
    defer ctx.deinit();
    C.lane.begin(&ctx);
    defer C.lane.finish() catch unreachable;
    const s = ctx.scratch();
    const lifting = 7;
    const log = 4;
    const step = 2;
    const groups = 4;
    const nq = 32;
    var ch = core.channel.raw_mod_m31.Om31Channel.init();
    var fields: [16]O = undefined;
    var hashes: [8]H.Hash = undefined;
    for (&fields) |*v| v.* = ch.drawSecureFelt();
    for (0..groups) |i| {
        var h = H.defaultWithInitialState();
        for (fields[i * 4 ..][0..4]) |v| h.updateLeaf(&v.toM31Array());
        hashes[4 + i] = h.finalize();
    }
    var i: usize = 4;
    while (i > 1) {
        i -= 1;
        hashes[i] = H.hashChildren(.{ .left = hashes[2 * i], .right = hashes[2 * i + 1] });
    }
    const alpha = ch.drawSecureFelt();
    const powers = [2]F{ try F.guess(&ctx, alpha), try F.guess(&ctx, alpha.square()) };
    const line = core.poly.line.LineDomain.fromCircleDomain(core.poly.circle.canonic.CanonicCoset.new(lifting).circleDomain()).repeatedDouble(lifting - 1 - log);
    const Fold = core.fri.ForField(O);
    var ws = try Fold.FoldLineWorkspace.init(s, 8);
    const expected = try Fold.foldLineNWithWorkspace(s, &fields, line, alpha, &ws, step);
    const cosets = try s.alloc([]const F, groups);
    const paths = try s.alloc([]const C.Hash, groups);
    for (cosets, paths, 0..) |*raw, *p, g| {
        const vs = try s.alloc(F, 4);
        const used = !sparse or g == 0;
        for (vs, 0..) |*v, j| {
            var value = if (used) fields[g * 4 + j] else O.zero();
            if ((fault == .selected_value and g == 0 or fault == .padding and !used) and j == 2) value = value.add(O.one());
            v.* = try F.guess(&ctx, value);
        }
        raw.* = vs;
        const ss = try s.alloc(C.Hash, 2);
        for (ss, 0..) |*h, k| {
            var d: H.Hash = if (used) hashes[((g + 4) >> @intCast(k)) ^ 1] else @splat(0);
            if (fault == .selected_path and g == 0) d[0] ^= 1;
            h.* = try hashWire(&ctx, d);
        }
        p.* = ss;
    }
    const layer = P.Layer{ .commitment = try hashWire(&ctx, hashes[1]), .cosets = cosets, .auth_paths = paths };
    var columns: [log][]C.Var = undefined;
    for (&columns) |*col| col.* = try s.alloc(C.Var, nq);
    var inputs: [nq]F = undefined;
    var positions: [nq]usize = undefined;
    for (&inputs, &positions, 0..) |*v, *pos, q| {
        pos.* = if (sparse) q % 4 else q % 16;
        v.* = try F.guess(&ctx, fields[pos.*]);
        for (columns, 0..) |col, k| col[q] = try ctx.guess(C.Q.fromBase(M.fromU64(pos.* >> @intCast(k) & 1)));
    }
    const outputs = try Fri.verifyShortLine(&ctx, layer, lifting, log, step, &columns, &inputs, &powers);
    for (outputs, positions, 0..) |out, pos, q| {
        const v = expected.values[pos / 4];
        try C.eq(&ctx, out, try F.guess(&ctx, if (fault == .target and q == 0) v.add(O.one()) else v));
    }
    try C.lane.check();
    try ctx.finalize(false);
    try std.testing.expectEqual(fault == .none or fault == .padding, try ctx.isCircuitValid());
    return ctx.gate_counts.blake_g_gate;
}
test "OM31 native PCS short FRI authenticates dense, repeated and sparse queries at fixed shape" {
    const gates = try check(false, .none);
    try std.testing.expectEqual(gates, try check(true, .none));
    for ([_]Fault{ .selected_value, .selected_path, .target, .padding }) |f|
        try std.testing.expectEqual(gates, try check(true, f));
}

test "OM31 native PCS short FRI capture checks duplicates and zero fills absent groups" {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const s = arena.allocator();
    var pos = [_]usize{ 2, 3, 4 };
    var vals = [_]O{ O.one(), O.zero(), O.one(), O.zero(), O.zero(), O.one() };
    var siblings = [_]H.Hash{ @splat(3), @splat(4), @splat(3), @splat(4), @splat(5), @splat(6) };
    const raw = core.fri.ForField(O).FriLayerQueryCapture(H){ .commitment = @splat(77), .folding_alpha = O.one(), .fold_step = 1, .fold_width = 2, .path_depth = 2, .query_count = 3, .positions = &pos, .values = &vals, .siblings = &siblings };
    const compact = try P.packLineGroups(s, raw, 4);
    try std.testing.expectEqual(@as(usize, 4), compact.cosets.len);
    try std.testing.expect(compact.cosets[0][0].isZero() and compact.cosets[1][0].eql(O.one()) and compact.cosets[2][1].eql(O.one()));
    try std.testing.expectEqual([_]u8{0} ** 32, compact.auth_paths[3][0]);
    vals[2] = O.zero();
    try std.testing.expectError(error.ShapeMismatch, P.packLineGroups(s, raw, 4));
    vals[2] = O.one();
    siblings[2][0] ^= 1;
    try std.testing.expectError(error.ShapeMismatch, P.packLineGroups(s, raw, 4));
    siblings[2][0] ^= 1;
    pos[2] = 8;
    try std.testing.expectError(error.ShapeMismatch, P.packLineGroups(s, raw, 4));
}
