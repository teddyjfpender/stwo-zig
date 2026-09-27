const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const air = @import("qm31_quotient_accumulate_v1.zig");
const binding = @import("universal_relation_binding.zig");
const support = @import("test_support.zig");
const schedule = air.Schedule{ .circuit = 1502, .denominator = 1, .numerator = 2, .accumulator = 3, .output = 6, .uses = 7 };
fn valid(definition: *const air.Definition, row: air.Row) !bool {
    const values = try support.evaluateArena(std.testing.allocator, &definition.arena, &row);
    defer std.testing.allocator.free(values);
    for (definition.roots) |root| if (!values[@intFromEnum(root)].isZero()) return false;
    return true;
}
test "quotient accumulation pins degree two and semantic identity" {
    const a = std.testing.allocator;
    const identity = try air.computeSemanticDigest(a);
    std.debug.print("QUOTIENT_ACCUMULATE_DIGEST {s}\n", .{std.fmt.bytesToHex(identity, .lower)});
    try std.testing.expectEqualSlices(u8, &air.SEMANTIC_DIGEST, &identity);
    var definition = try air.build(a);
    defer definition.deinit();
    var degrees = try @import("../../air/lang/degree.zig").analyze(a, &definition.arena);
    defer degrees.deinit();
    try std.testing.expectEqual(@as(@import("../../air/lang/degree.zig").Degree, 2), degrees.maximumConstraintDegree());
}
test "quotient accumulation rejects zero denominators and every main mutation" {
    var definition = try air.build(std.testing.allocator);
    defer definition.deinit();
    var rng = std.Random.DefaultPrng.init(174391);
    for (0..24) |sample| {
        var words: [12]u32 = undefined;
        for (&words) |*word| word.* = rng.random().uintLessThan(u32, core.fields.m31.Modulus);
        const d = Q.fromU32Unchecked(words[0], words[1], words[2], words[3]);
        const n = if (sample == 0) Q.zero() else Q.fromU32Unchecked(words[4], words[5], words[6], words[7]);
        const acc = Q.fromU32Unchecked(words[8], words[9], words[10], words[11]);
        const row = try air.logicalRow(schedule, d, n, acc);
        try std.testing.expect(try valid(&definition, row));
        // Nonzero numerator ensures changing the denominator cannot happen to
        // leave the quotient equation unchanged; reciprocal check also binds it.
        for (0..air.PHYSICAL_MAIN_COLUMN_COUNT) |column| {
            var bad = row;
            bad[column] = bad[column].add(M.one());
            try std.testing.expect(!try valid(&definition, bad));
        }
        var forged = row;
        @memset(forged[1..9], M.zero());
        @memset(forged[17..21], M.zero());
        forged[13..17].* = forged[9..13].*;
        try std.testing.expect(!try valid(&definition, forged));
    }
    try std.testing.expect(try valid(&definition, @splat(M.zero())));
    if (air.logicalRow(schedule, Q.zero(), Q.zero(), Q.zero())) |_| return error.AcceptedZeroDenominator else |_| {}
    var bad_schedule = schedule;
    bad_schedule.uses = core.fields.m31.Modulus;
    try std.testing.expectError(error.InvalidQm31QuotientAccumulate, air.logicalRow(bad_schedule, Q.one(), Q.one(), Q.one()));
}
test "quotient accumulation preserves inverse and FMA external lookup multiset" {
    const a = std.testing.allocator;
    const inv = @import("qm31_inv.zig");
    const iw = @import("qm31_inv_witness.zig");
    const fma = @import("qm31_mul_add_v1.zig");
    var definition = try air.build(a);
    defer definition.deinit();
    var inverse_definition = try inv.build(a, .generated);
    defer inverse_definition.deinit();
    var fma_definition = try fma.build(a);
    defer fma_definition.deinit();
    const fused_plan = try binding.Binding(air).authenticate(&definition);
    const inverse_plan = try binding.Binding(inv).authenticate(&inverse_definition);
    const fma_plan = try binding.Binding(fma).authenticate(&fma_definition);
    const d = Q.fromU32Unchecked(3, 5, 7, 11);
    const n = Q.fromU32Unchecked(13, 17, 19, 23);
    const acc = Q.fromU32Unchecked(29, 31, 37, 41);
    const metadata = iw.CircuitMetadata{ .circuit_id = M.fromCanonical(1502), .node_id = M.fromCanonical(4), .lhs_id = M.one(), .uses = M.one() };
    const inverse_row = iw.logicalInputs(try iw.mainRow(.{ .a = d, .circuit = metadata }), iw.preprocessedRow(.{ .segment = metadata }), .segment_leaf);
    const fma_row = try fma.logicalRow(.{ .circuit = 1502, .output = 6, .lhs = 4, .rhs = 2, .addend = 3, .uses = 7, .operation = .product_plus_addend }, try d.inv(), n, acc);
    const row = try air.logicalRow(schedule, d, n, acc);
    var entries = inverse_plan.preparedEntries(inverse_row) ++ fma_plan.preparedEntries(fma_row) ++ fused_plan.preparedEntries(row);
    const first_new = inv.RELATION_EVENT_COUNT + fma.RELATION_EVENT_COUNT;
    for (entries[first_new..]) |*entry| entry.numerator = entry.numerator.neg();
    for (entries) |entry| {
        var sum = Q.zero();
        for (entries) |candidate| {
            if (entry.domain != candidate.domain or entry.arity != candidate.arity) continue;
            var equal = true;
            for (entry.values[0..entry.arity], candidate.values[0..candidate.arity]) |left, right| equal = equal and left.eql(right);
            if (equal) sum = sum.add(candidate.numerator);
        }
        try std.testing.expect(sum.isZero());
    }
}

test "quotient accumulation matcher protects shared exported reserved and signed operations" {
    const graph = @import("composition_circuit.zig");
    const lower = @import("verifier_arithmetic_lowering.zig");
    const matcher = @import("quotient_accumulation_plan.zig");
    var nodes = [_]graph.Node{
        .{ .op = .input },            .{ .op = .input },                              .{ .op = .input },
        .{ .op = .{ .inverse = 0 } }, .{ .op = .{ .mul = .{ .lhs = 3, .rhs = 1 } } }, .{ .op = .{ .add = .{ .lhs = 4, .rhs = 2 } } },
    };
    const outputs = [_]u32{5};
    for ([_]bool{ false, true }) |reverse| {
        nodes[4].op.mul = if (reverse) .{ .lhs = 1, .rhs = 3 } else .{ .lhs = 3, .rhs = 1 };
        const g = try graph.CircuitGraph.authenticate(&nodes, &outputs, graph.computeGraphDigest(&nodes, &outputs));
        var uses: [nodes.len]u32 = undefined;
        var lane = lower.Lane{ .circuit_id = 1502, .active_in = .segment, .circuit_identity = g.identity_digest, .graph = g };
        _ = try lower.computeLaneUseCountsInto(lane, &uses);
        var reserved = [_]bool{false} ** nodes.len;
        const item = matcher.matchAt(g, &uses, &reserved, 5).?;
        try std.testing.expectEqual(@as(u32, 0), item.denominator_node);
        try std.testing.expectEqual(@as(u32, 1), item.numerator_node);
        for ([_]u32{ 3, 4 }) |exported| {
            lane.exports = &.{.{ .node_id = exported, .uses = 1 }};
            _ = try lower.computeLaneUseCountsInto(lane, &uses);
            try std.testing.expect(matcher.matchAt(g, &uses, &reserved, 5) == null);
        }
        lane.exports = &.{};
        _ = try lower.computeLaneUseCountsInto(lane, &uses);
        for ([_]usize{ 3, 4, 5 }) |protected| {
            reserved[protected] = true;
            try std.testing.expect(matcher.matchAt(g, &uses, &reserved, 5) == null);
            reserved[protected] = false;
        }
        var matches: std.ArrayList(matcher.Match) = .empty;
        defer matches.deinit(std.testing.allocator);
        try matcher.reserve(&matches, std.testing.allocator, g, &uses, &reserved);
        try std.testing.expectEqual(@as(usize, 1), matches.items.len);
        try std.testing.expect(reserved[3] and reserved[4] and reserved[5]);
        try std.testing.expect(matcher.matchAt(g, &uses, &reserved, 5) == null);
    }
    nodes[5].op = .{ .sub = .{ .lhs = 4, .rhs = 2 } };
    const signed = try graph.CircuitGraph.authenticate(&nodes, &outputs, graph.computeGraphDigest(&nodes, &outputs));
    var uses: [nodes.len]u32 = undefined;
    _ = try lower.computeUseCountsInto(signed, &uses);
    const reserved = [_]bool{false} ** nodes.len;
    try std.testing.expect(matcher.matchAt(signed, &uses, &reserved, 5) == null);
    var invalid_matches: std.ArrayList(matcher.Match) = .empty;
    defer invalid_matches.deinit(std.testing.allocator);
    var invalid_reserved = reserved;
    try std.testing.expectError(error.InvalidFusionShape, matcher.reserve(&invalid_matches, std.testing.allocator, signed, uses[1..], &invalid_reserved));
}
