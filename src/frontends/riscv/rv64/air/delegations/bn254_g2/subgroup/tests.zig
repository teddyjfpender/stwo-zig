const std = @import("std");
const S = @import("spec.zig");
const W = @import("witness.zig");
const V = @import("vectors.zig");
test "G2 exact subgroup immutable source r program hints and zero assertions" {
    @setEvalBranchQuota(2_000_000);
    const rom = &W.ROM;
    try std.testing.expectEqual(@as(usize, 4390), rom.count);
    try std.testing.expectEqual(@as(usize, 352), rom.hints);
    try std.testing.expectEqual(@as(usize, 358), rom.assertion_count);
    try std.testing.expectEqual(@as(usize, 253), rom.doubles);
    try std.testing.expectEqual(@as(usize, 99), rom.additions);
    var writers: [S.INITIAL + S.MAX_NODES]bool = @splat(false);
    @memset(writers[0..S.INITIAL], true);
    var hint_count: usize = 0;
    for (rom.nodes[0..rom.count], 0..) |node, i| {
        try std.testing.expectEqual(@as(S.ID, @intCast(S.INITIAL + i)), node.writer);
        try std.testing.expect(!writers[node.writer]);
        writers[node.writer] = true;
        for (node.input[0..S.arity(node.op)]) |id| try std.testing.expect(id < node.writer);
        if (node.op == .hint_norm_inverse) {
            hint_count += 1;
            const obligation = try rom.hintObligation(i);
            try std.testing.expectEqual(node.writer, obligation.writer);
            try std.testing.expectEqual(node.input[0], obligation.denominator);
            const check = rom.nodes[i + 1];
            try std.testing.expectEqual(S.Op.inverse_check, check.op);
            try std.testing.expectEqual(node.input[0], check.input[0]);
            try std.testing.expectEqual(node.writer, check.input[1]);
            try std.testing.expectEqual(@as(S.ID, 6), check.input[2]);
            try std.testing.expect(std.mem.indexOfScalar(S.ID, rom.assertions[0..rom.assertion_count], check.writer) != null);
        }
    }
    try std.testing.expectEqual(rom.hints, hint_count);
    const uses = S.fanout(rom);
    var reads: u64 = rom.assertion_count;
    var weighted: u64 = 0;
    var max: u32 = 0;
    for (rom.nodes[0..rom.count]) |node| reads += S.arity(node.op);
    for (uses) |n| {
        weighted += n;
        max = @max(max, n);
    }
    try std.testing.expectEqual(reads, weighted);
    try std.testing.expect(weighted < S.B.M31 and max < S.B.M31);
    try std.testing.expectEqual(@as(usize, 1), W.Layout.G.group);
    try std.testing.expect(W.Layout.G.residual_positive_bound < S.B.M31 and W.Layout.G.residual_negative_bound < S.B.M31);
    std.debug.print("G2_SUBGROUP_SOURCE nodes={} arithmetic={} canonical_hint_writers={} assertions={} MAIN={} BYTE={} SSA_mass={} max_fanout={} residual_pos={} residual_neg={}\n", .{ rom.count, rom.count - rom.hints, rom.hints, rom.assertion_count, W.Layout.MAIN, W.Layout.BYTE_QUERIES, weighted, max, W.Layout.G.residual_positive_bound, W.Layout.G.residual_negative_bound });
}
test "G2 exact subgroup canonical curve and r-minus-one predicate independent oracle" {
    for (V.DATA) |vector| {
        if (vector.positive) {
            var w = try W.Witness.init(std.testing.allocator, vector.q);
            defer w.deinit();
            try std.testing.expectEqualDeep(vector.final, w.finalPoint());
            try std.testing.expectEqualDeep(vector.hint_digest, w.hintDigest());
            try w.validate(vector.q);
        } else {
            // Independent exact scalar result remains a field-well-formed
            // witness but cannot satisfy the source final zero assertions.
            var candidate = try W.Witness.candidateForTesting(std.testing.allocator, vector.q);
            defer candidate.deinit();
            try std.testing.expectEqualDeep(vector.final, candidate.finalPoint());
            try std.testing.expectEqualDeep(vector.hint_digest, candidate.hintDigest());
            try candidate.validateRows();
            try std.testing.expectError(error.SubgroupZeroAssertion, candidate.validate(vector.q));
            try std.testing.expectError(error.SubgroupZeroAssertion, W.Witness.init(std.testing.allocator, vector.q));
        }
    }
}
test "G2 exact subgroup initial authority aliases offcurve and infinity excluded" {
    const q = V.DATA[0].q;
    var alias = q;
    alias[0][0] += S.B.BN254_P;
    try std.testing.expectError(error.NonCanonicalSubgroupInput, W.Witness.init(std.testing.allocator, alias));
    try std.testing.expectError(error.SubgroupInfinityExcluded, W.Witness.init(std.testing.allocator, .{ .{ 0, 0 }, .{ 0, 0 } }));
    var denominator_zero = q;
    denominator_zero[1] = .{ 0, 0 };
    try std.testing.expectError(error.SubgroupZeroDenominator, W.Witness.init(std.testing.allocator, denominator_zero));
    var off = q;
    off[1][0] += 1;
    if (W.Witness.init(std.testing.allocator, off)) |value| {
        var w = value;
        w.deinit();
        return error.AcceptedOffCurve;
    } else |err| try std.testing.expect(err == error.SubgroupZeroAssertion or err == error.SubgroupZeroDenominator);
    var w = try W.Witness.init(std.testing.allocator, V.DATA[1].q);
    defer w.deinit();
    try std.testing.expectError(error.SubgroupInitialAuthority, w.validate(q));
}
test "G2 exact subgroup coherent inverse slope and output forgeries reject" {
    const q = V.DATA[0].q;
    var w = try W.Witness.init(std.testing.allocator, q);
    defer w.deinit();
    var hints: [352]u256 = undefined;
    var at: usize = 0;
    for (W.ROM.nodes[0..W.ROM.count]) |node| if (node.op == .hint_norm_inverse) {
        hints[at] = w.values[node.writer];
        at += 1;
    };
    hints[0] = (hints[0] + 1) % S.B.BN254_P;
    var inverse = try W.Witness.withHintsForTesting(std.testing.allocator, q, &hints);
    defer inverse.deinit();
    // Every modular arithmetic row can be valid while inverse residuals are
    // nonzero: the source-owned literal-zero obligations are indispensable.
    try inverse.validateRows();
    try std.testing.expectError(error.SubgroupZeroAssertion, inverse.validate(q));
    hints[0] = S.B.BN254_P;
    try std.testing.expectError(error.NonCanonicalSubgroupHint, W.Witness.withHintsForTesting(std.testing.allocator, q, &hints));
    try w.corruptSlopeForTesting();
    try std.testing.expectError(error.SubgroupArithmeticConstraint, w.validate(q));
    // Separate canonical output mutation must fail its source arithmetic row.
    var good = try W.Witness.init(std.testing.allocator, q);
    defer good.deinit();
    const writer = W.ROM.nodes[W.ROM.count - 1].writer;
    good.values[writer] ^= 1;
    try std.testing.expectError(error.SubgroupSsaWriterMismatch, good.validate(q));
}

fn allocationProbe(a: std.mem.Allocator) !void {
    var w = try W.Witness.init(a, V.DATA[0].q);
    defer w.deinit();
}
test "G2 exact subgroup witness allocation failure preserves custody" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationProbe, .{});
}
