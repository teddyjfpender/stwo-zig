const std = @import("std");
const S = @import("spec.zig");
const W = @import("witness.zig");
test "G2 preparation immutable complete DAG and exact carry class" {
    @setEvalBranchQuota(10_000_000);
    const p = &W.ROM;
    try std.testing.expectEqual(@as(usize, 1546), p.double_count);
    try std.testing.expectEqual(@as(usize, 506), p.add_count);
    try std.testing.expectEqual(@as(usize, 87), p.transition_count);
    var writers: [S.VALUES]bool = @splat(false);
    @memset(writers[0..S.INITIAL], true);
    var reads: u32 = S.EXPORTS;
    for (p.doubles) |node| {
        try std.testing.expect(!writers[node.writer]);
        writers[node.writer] = true;
        for (node.input[0..6]) |id| if (id != S.UNUSED) {
            try std.testing.expect(id < node.writer);
            reads += 1;
        };
    }
    for (p.adds) |node| {
        try std.testing.expect(!writers[node.writer]);
        writers[node.writer] = true;
        for (node.input) |id| if (id != S.UNUSED) {
            try std.testing.expect(id < node.writer);
            reads += 1;
        };
    }
    for (writers) |written| try std.testing.expect(written);
    const fanout = S.fanout(p);
    var weighted: u32 = 0;
    for (fanout) |count| weighted += count;
    try std.testing.expectEqual(reads, weighted);
    try std.testing.expectEqual(@as(u32, 8130), weighted);
    var max_fanout: u32 = 0;
    for (fanout) |count| max_fanout = @max(max_fanout, count);
    try std.testing.expectEqual(@as(u32, 256), max_fanout);
    try std.testing.expect(weighted < S.B.M31);
    inline for (.{ S.Kind.doubling, S.Kind.addition }) |kind| {
        try std.testing.expectEqualDeep(comptime S.Base.commonGeometry(kind), comptime S.commonGeometry(kind));
        try std.testing.expectEqual(@as(usize, if (kind == .doubling) 498 else 626), W.Layout(kind).MAIN);
    }
    try std.testing.expectEqual(@as(i8, 2), p.transitions[85].digit);
    try std.testing.expectEqual(@as(i8, 3), p.transitions[86].digit);
}
test "G2 preparation all87 exact line outputs and complete canonical witnesses match oracle" {
    for (@import("vectors.zig").DATA) |vector| {
        var witness = try W.Witness.init(std.testing.allocator, vector.q);
        defer witness.deinit();
        try std.testing.expectEqual(vector.point, witness.finalPoint());
        try std.testing.expectEqual(vector.digest, witness.linesDigest());
        inline for (.{ S.Kind.doubling, S.Kind.addition }) |kind| {
            const nodes = if (kind == .doubling) W.ROM.doubles[0..] else W.ROM.adds[0..];
            inline for (0..comptime S.rows(kind)) |opcode| for (nodes, 0..) |node, index| if (node.opcode == opcode) {
                const row = witness.row(kind, index);
                try std.testing.expect(W.Layout(kind).valid(opcode, &row));
            };
        }
    }
}

test "G2 preparation canonical Frobenius prefix writer mutations reject" {
    var witness = try W.Witness.init(std.testing.allocator, @import("vectors.zig").DATA[0].q);
    defer witness.deinit();
    const L = W.Layout(.doubling);
    inline for (0..S.PREFIX) |opcode| {
        const row = witness.row(.doubling, opcode);
        var input: [S.inputs(.doubling)]u256 = @splat(0);
        for (W.ROM.doubles[opcode].input[0..6], &input) |id, *value| if (id != S.UNUSED) {
            value.* = witness.values[id];
        };
        const forged = L.congruentForgeryForTesting(opcode, &input);
        try std.testing.expect(L.rangeValid(&forged));
        try std.testing.expect(L.carriedValid(opcode, &forged));
        try std.testing.expect(!L.valid(opcode, &forged));
        var bad = row;
        bad[L.OUTPUT] ^= 1;
        try std.testing.expect(!L.valid(opcode, &bad));
        bad = row;
        bad[L.QUOTIENT] ^= 1;
        try std.testing.expect(!L.valid(opcode, &bad));
        bad = row;
        bad[L.CARRY] ^= 1;
        try std.testing.expect(!L.valid(opcode, &bad));
    }
}
