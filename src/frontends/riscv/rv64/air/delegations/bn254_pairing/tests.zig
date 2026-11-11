const std = @import("std");
const S = @import("spec.zig");
const W = @import("witness.zig");
const V = @import("../bn254_miller/vectors.zig");
const R = @import("../bn254_residue/vectors.zig");
fn private() W.Private {
    return .{ .seed = R.POSITIVE.seed, .scale = R.POSITIVE.c[0..6].*, .inverse2 = R.POSITIVE.inverse2 };
}
fn one(x: [12]u256) bool {
    if (x[0] != 1) return false;
    for (x[1..]) |v| if (v != 0) return false;
    return true;
}
test "complete shared pairing source joins same Q subgroup preparation and actual Miller z residue" {
    var w = try W.Witness.init(std.testing.allocator, V.INPUT, private());
    defer w.deinit();
    try std.testing.expect(w.satisfied());
    try std.testing.expect(one(w.result()));
    for (0..4) |g| for (0..4) |j| try std.testing.expectEqual(@as(u32, @intCast(g * 6 + 2 + j)), W.ROM.subgroupId(g, @intCast(j)));
    for (0..12) |j| try std.testing.expectEqual(W.ROM.millerId(S.MW.ROM.output[j]), W.ROM.residueId(@intCast(j)));
    for (0..6) |j| try std.testing.expectEqual(S.literalId(0), W.ROM.residueId(S.RW.ROM.scale[6 + j]));
}
test "complete pairing source swapped subgroup Q and canonical hint alias cannot disconnect valid subarguments" {
    inline for (.{ W.Witness.Mutation.swapped_subgroup_q, W.Witness.Mutation.hint_modulus_alias }) |mutation| {
        var w = try W.Witness.init(std.testing.allocator, V.INPUT, private());
        defer w.deinit();
        try w.corruptForTesting(mutation);
        try std.testing.expect(one(w.result()));
        try std.testing.expect(!w.satisfied());
    }
}
test "complete pairing source fake standalone zONE certificate cannot replace actual Miller output" {
    const p = W.Private{ .seed = .{ 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, .scale = .{ 1, 0, 0, 0, 0, 0 }, .inverse2 = .{ 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 } };
    var w = try W.Witness.init(std.testing.allocator, V.INPUT, p);
    defer w.deinit();
    try std.testing.expect(!w.satisfied());
    try w.corruptForTesting(.disconnected_residue_z);
    try std.testing.expect(one(w.result()));
    try std.testing.expect(!w.satisfied());
}
test "complete pairing source unique writers fixed assertions and hint counts" {
    var arithmetic: usize = 0;
    var hints: usize = 0;
    for (W.ROM.nodes, 0..) |node, i| {
        try std.testing.expectEqual(@as(u32, @intCast(S.INITIAL + i)), node.writer);
        if (node.kind == .hint) {
            hints += 1;
            if (node.hint == .inverse) try std.testing.expect(node.hint_denominator < node.writer);
        } else {
            arithmetic += 1;
            const e = S.expression(node);
            for (e.terms[0..e.len]) |term| {
                try std.testing.expect(term.a < node.writer);
                if (term.b) |id| try std.testing.expect(id < node.writer);
            }
        }
    }
    try std.testing.expectEqual(1438, hints);
    try std.testing.expectEqual(31996, arithmetic);
    try std.testing.expectEqual(1460, W.ROM.assertion_count);
    const counts = S.fanout(&W.ROM);
    var total: usize = 0;
    for (counts) |n| total += n;
    try std.testing.expect(total < 2147483647);
}

test "complete finite pairing public authority rejects aliases and infinities" {
    var input = V.INPUT;
    input.p[0][0] = S.B.BN254_P;
    try std.testing.expectError(error.NonCanonicalMillerP, S.initialValues(input));
    input = V.INPUT;
    input.q[0][0][0] = S.B.BN254_P;
    try std.testing.expectError(error.NonCanonicalPreparationQ, S.initialValues(input));
    input = V.INPUT;
    input.p[0] = .{ 0, 0 };
    try std.testing.expectError(error.PairingG1InfinityExcluded, S.initialValues(input));
    input = V.INPUT;
    input.q[0] = .{ .{ 0, 0 }, .{ 0, 0 } };
    try std.testing.expectError(error.SubgroupInfinityExcluded, S.initialValues(input));
}
test "complete pairing unique zero one obligations and mapped input statement" {
    const module = @import("mod.zig");
    var seen: [S.VALUES]bool = @splat(false);
    var ones: usize = 0;
    for (W.ROM.assertions) |obligation| {
        try std.testing.expect(!seen[obligation.id]);
        seen[obligation.id] = true;
        try std.testing.expect(obligation.value <= 1);
        ones += obligation.value;
    }
    try std.testing.expectEqual(2, ones);
    for (S.RW.ROM.inverse_check, 0..) |id, i| {
        const global = W.ROM.residueId(id);
        try std.testing.expect(seen[global]);
        try std.testing.expectEqual(@as(u8, @intFromBool(i == 0)), W.ROM.nodes[global - S.INITIAL].asserted.?);
    }
    for (S.RW.ROM.final, 0..) |id, i| {
        const global = W.ROM.residueId(id);
        try std.testing.expect(seen[global]);
        try std.testing.expectEqual(@as(u8, @intFromBool(i == 0)), W.ROM.nodes[global - S.INITIAL].asserted.?);
    }
    const original = try module.statement(V.INPUT);
    var input = V.INPUT;
    const q = input.q[0];
    input.q[0] = input.q[1];
    input.q[1] = q;
    try std.testing.expect(!std.mem.eql(u8, &original, &try module.statement(input)));
}
