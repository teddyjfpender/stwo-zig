const std = @import("std");
const S = @import("spec.zig");
const W = @import("witness.zig");
const V = @import("vectors.zig");
test "complete four-pair shared Miller matches original independent oracle and residue z" {
    var w = try W.Witness.init(std.testing.allocator, V.INPUT);
    defer w.deinit();
    try std.testing.expect(w.satisfied());
    try std.testing.expectEqualSlices(u256, &V.EXPECTED_Z, &w.result());
    try std.testing.expectEqualSlices(u256, &@import("../bn254_residue/vectors.zig").POSITIVE.z, &w.result());
}
test "shared Miller source consumes every preparation line in order and folds only literal ONE" {
    const p = &W.ROM;
    try std.testing.expectEqual(63, p.square_count);
    try std.testing.expectEqual(348, p.line_count);
    var counts: [6]usize = @splat(0);
    var next: S.ID = S.INITIAL;
    for (p.nodes) |node| {
        try std.testing.expectEqual(next, node.writer);
        for (node.input[0..S.inputs(node.kind)]) |id| if (id != S.NONE) {
            try std.testing.expect(id < node.writer);
        };
        counts[@intFromEnum(node.kind)] += 1;
        next += 1;
    }
    try std.testing.expectEqual(S.VALUES, next);
    try std.testing.expectEqual(16, counts[0]);
    try std.testing.expectEqual(4 * S.Prep.DOUBLE_ROWS, counts[1]);
    try std.testing.expectEqual(4 * S.Prep.ADD_ROWS, counts[2]);
    try std.testing.expectEqual(1392, counts[3]);
    try std.testing.expectEqual(63 * 12, counts[4]);
    try std.testing.expectEqual(347 * 12, counts[5]);
    for (p.lines, 0..) |line, i| {
        try std.testing.expectEqual(i % 4, line.group);
        try std.testing.expectEqual(i / 4, line.ordinal);
        try std.testing.expectEqual(i == 0, line.aliased_one);
        const transition = (comptime S.Prep.program()).transitions[line.ordinal];
        for (transition.line, line.raw) |old, actual| try std.testing.expectEqual(p.prepId(line.group, old), actual);
        try std.testing.expectEqualSlices(S.ID, line.raw[4..], line.scaled[4..]);
    }
}
test "shared Miller canonical input on-curve and local state mutations reject" {
    var input = V.INPUT;
    input.p[0][0] = S.B.BN254_P;
    try std.testing.expectError(error.NonCanonicalMillerP, W.Witness.init(std.testing.allocator, input));
    input = V.INPUT;
    input.p[0][1] += 1;
    var off = try W.Witness.init(std.testing.allocator, input);
    defer off.deinit();
    try std.testing.expect(!off.satisfied());
    var w = try W.Witness.init(std.testing.allocator, V.INPUT);
    defer w.deinit();
    const ids = [_]S.ID{ W.ROM.checks[0], W.ROM.prep_base[0], W.ROM.lines[0].scaled[0], W.ROM.lines[17].after[8], W.ROM.output[11] };
    for (ids) |id| {
        const original = w.values[id];
        w.values[id] = (original + 1) % S.B.BN254_P;
        try std.testing.expect(!w.satisfied());
        w.values[id] = original;
    }
    try std.testing.expect(w.satisfied());
}

test "shared Miller coherent wrong line order sign and preparation state reject" {
    inline for (std.meta.tags(W.Witness.Mutation)) |mutation| {
        var w = try W.Witness.init(std.testing.allocator, V.INPUT);
        defer w.deinit();
        w.corruptSourceForTesting(mutation);
        try std.testing.expect(!w.satisfied());
        try std.testing.expect(!std.mem.eql(u256, &V.EXPECTED_Z, &w.result()));
    }
}
test "shared Miller source fanout includes all line scaling sparse reads and z exports" {
    const counts = S.fanout(&W.ROM);
    var reads: usize = 12 + S.GROUPS;
    var mass: usize = 0;
    for (W.ROM.nodes) |node| for (node.input[0..S.inputs(node.kind)]) |id| {
        if (id != S.NONE) reads += 1;
    };
    for (counts) |n| mass += n;
    try std.testing.expectEqual(reads, mass);
    try std.testing.expect(mass < 2147483647);
    for (W.ROM.output) |id| try std.testing.expect(counts[id] >= 1);
}
test "shared Miller source expression export and initial output framing are exact" {
    const module = @import("mod.zig");
    var w = try W.Witness.init(std.testing.allocator, V.INPUT);
    defer w.deinit();
    for (W.ROM.nodes) |node| {
        const e = S.expression(node);
        try std.testing.expectEqual(node.writer, e.output);
        var positive: S.B.Big = 0;
        var negative: S.B.Big = 0;
        for (e.terms[0..e.len]) |term| {
            const n = @as(S.B.Big, w.values[term.a]) * (if (term.b) |b| w.values[b] else 1) * @as(u32, @intCast(@abs(term.coefficient)));
            if (term.coefficient > 0) positive += n else negative += n;
        }
        try std.testing.expectEqual(w.values[node.writer], @as(u256, @intCast((positive % S.B.BN254_P + S.B.BN254_P - negative % S.B.BN254_P) % S.B.BN254_P)));
    }
    const original = try module.statement(V.INPUT, V.EXPECTED_Z);
    var input = V.INPUT;
    input.p[0][0] += 1;
    try std.testing.expect(!std.mem.eql(u8, &original, &try module.statement(input, V.EXPECTED_Z)));
    var wrong = V.EXPECTED_Z;
    wrong[11] += 1;
    try std.testing.expect(!std.mem.eql(u8, &original, &try module.statement(V.INPUT, wrong)));
}
