const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Word = @import("block_v5_word_memory_component_v1.zig").Spec;
const Range = @import("block_v5_range16_component_v1.zig").Spec;
const Protocol = @import("block_v5_word_memory_protocol_v1.zig");
const Adapter = @import("block_v5_word_quotient_adapter_v1.zig");
const Rows = @import("block_v5_word_domain_rows_v1.zig");

fn value(seed: usize) Q {
    return Q.fromU32Unchecked(@intCast(3 + seed * 7), @intCast(5 + seed * 11), @intCast(7 + seed * 13), @intCast(11 + seed * 17));
}
fn challenges() Protocol.Challenges {
    return .{ .transition = .dummy(), .link = .dummy(), .initial = .dummy(), .endpoint = .dummy(), .range16 = .dummy(), .universal_prefix = .dummy() };
}
fn wordSpec(c: *const Protocol.Challenges, log: u32) Word {
    const event = @import("../air/block/memory_transition.zig").Transition{ .space = 1, .address = 0xffff_fffc, .clock = std.math.maxInt(u64), .before = 0xffff_ffff, .after = 7 };
    return .{ .claim = .{ .first_row = 0, .total_rows = 1, .rows = 1, .log_size = log, .first = event, .last = event, .preceding = null }, .interaction_claim = .{ .transition_sum = value(1), .link_sum = value(2), .initial_sum = value(3), .endpoint_sum = value(4), .endpoint_count = 1, .register_endpoint_sum = value(5), .register_endpoint_count = 0, .range_count = 10, .range_sums = @splat(value(6)) }, .challenges = c };
}

fn checkPoint(comptime Spec: type, spec: Spec, log: u32, expected_previous: usize) !void {
    const a = std.testing.allocator;
    const component = Adapter.For(Spec){ .log_size = log, .spec = spec };
    const point = core.circle.secureFieldPoint(127);
    const prior_point = @import("../air/logup.zig").prevRowPoint(log, point);
    var points = try component.maskPoints(a, point, log);
    defer points.deinitDeep(a);
    var observed_previous: usize = 0;
    for (points.items[0]) |column| {
        try std.testing.expectEqual(@as(usize, 1), column.len);
        try std.testing.expect(column[0].eql(point));
    }
    for (points.items[1], 0..) |column, i| {
        try std.testing.expectEqual(@as(usize, if (Spec.PREVIOUS_MAIN_MASK[i]) 2 else 1), column.len);
        try std.testing.expect(column[0].eql(point));
        if (Spec.PREVIOUS_MAIN_MASK[i]) {
            observed_previous += 1;
            try std.testing.expect(column[1].eql(prior_point));
        }
    }
    try std.testing.expectEqual(expected_previous, observed_previous);
    for (points.items[2]) |column| {
        try std.testing.expectEqual(@as(usize, 2), column.len);
        try std.testing.expect(column[0].eql(point) and column[1].eql(prior_point));
    }
    var fixed: [Spec.FIXED_COUNT]Q = undefined;
    var main: [Spec.MAIN_COUNT]Q = undefined;
    var full_previous: [Spec.MAIN_COUNT]Q = undefined;
    var current: [Spec.INTERACTION_COUNT]Q = undefined;
    var previous: [Spec.INTERACTION_COUNT]Q = undefined;
    var fixed_storage: [Spec.FIXED_COUNT][1]Q = undefined;
    var main_storage: [Spec.MAIN_COUNT][2]Q = undefined;
    var interaction_storage: [Spec.INTERACTION_COUNT][2]Q = undefined;
    var fixed_mask: [Spec.FIXED_COUNT][]Q = undefined;
    var main_mask: [Spec.MAIN_COUNT][]Q = undefined;
    var interaction_mask: [Spec.INTERACTION_COUNT][]Q = undefined;
    for (&fixed, &fixed_storage, &fixed_mask, 0..) |*cell, *storage, *mask, i| {
        cell.* = value(100 + i);
        storage.* = .{cell.*};
        mask.* = storage;
    }
    for (&main, &full_previous, &main_storage, &main_mask, 0..) |*cell, *before, *storage, *mask, i| {
        cell.* = value(200 + i);
        before.* = value(300 + i);
        storage.* = .{ cell.*, before.* };
        mask.* = storage[0..if (Spec.PREVIOUS_MAIN_MASK[i]) @as(usize, 2) else 1];
    }
    for (&current, &previous, &interaction_storage, &interaction_mask, 0..) |*cell, *before, *storage, *mask, i| {
        cell.* = value(400 + i);
        before.* = value(500 + i);
        storage.* = .{ cell.*, before.* };
        mask.* = storage;
    }
    var trees: [3][][]Q = .{ &fixed_mask, &main_mask, &interaction_mask };
    const sampled = core.air.components.MaskValues{ .items = &trees };
    // Independent reference retains all previous cells, including arbitrary
    // nonzero values for omitted cells. The actual point adapter receives only
    // its authenticated static subset, with zero placeholders elsewhere.
    const equations = try spec.evaluate(fixed, main, full_previous, current, previous, @as(u32, 1) << @intCast(log));
    const inverse = try core.constraints.cosetVanishing(Q, core.poly.circle.canonic.CanonicCoset.new(log).coset(), point).inv();
    var expected = core.air.accumulation.PointEvaluationAccumulator.init(value(29));
    for (equations) |equation| expected.accumulate(equation.mul(inverse));
    var actual = core.air.accumulation.PointEvaluationAccumulator.init(value(29));
    try component.evaluateConstraintQuotientsAtPoint(point, &sampled, &actual, log);
    try std.testing.expectEqual(expected.finalize(), actual.finalize());
    // A missing required predecessor or an extra omitted opening changes the
    // proof grammar and must be rejected before evaluating any equation.
    for (main_mask[0..], 0..) |*column, i| {
        const original = column.*;
        column.* = main_storage[i][0..if (Spec.PREVIOUS_MAIN_MASK[i]) @as(usize, 1) else 2];
        try std.testing.expectError(error.InvalidV5WordMask, component.evaluateConstraintQuotientsAtPoint(point, &sampled, &actual, log));
        column.* = original;
    }
    const interaction_original = interaction_mask[0];
    interaction_mask[0] = interaction_storage[0][0..1];
    try std.testing.expectError(error.InvalidV5WordMask, component.evaluateConstraintQuotientsAtPoint(point, &sampled, &actual, log));
    interaction_mask[0] = interaction_original;
}

test "block-v5 authenticated previous openings preserve exact word and range OODS equations" {
    var c = challenges();
    try checkPoint(Word, wordSpec(&c, 3), 3, 9);
    try checkPoint(Range, .{ .claim = .{ .sum = value(37), .count = 1234 }, .challenges = &c }, 16, 0);
}

test "block-v5 masked previous gathers preserve all scalar and packed quotient rows" {
    const a = std.testing.allocator;
    var c = challenges();
    for ([_]u32{ 1, 4 }) |trace_log| {
        const spec = wordSpec(&c, trace_log);
        const eval_log = trace_log + Word.EXPANSION_BITS;
        const size = @as(usize, 1) << @intCast(eval_log);
        const domain = try spec.prepareDomain(@as(u32, 1) << @intCast(trace_log));
        const storage = try a.alloc(M, size * (Word.FIXED_COUNT + Word.MAIN_COUNT + Word.INTERACTION_COUNT));
        defer a.free(storage);
        for (storage, 0..) |*cell, i| cell.* = M.fromCanonical(@intCast((i * 17 + 13) % 65536));
        var values: Rows.For(Word).Values = undefined;
        for (&values, 0..) |*column, i| column.* = storage[i * size ..][0..size];
        const inverses = Rows.For(Word).Inverses{ M.fromCanonical(7), M.fromCanonical(11), M.fromCanonical(13), M.fromCanonical(19) };
        var powers: [Word.CONSTRAINT_COUNT]Q = undefined;
        for (&powers, 0..) |*power, i| power.* = value(600 + i);
        var actual = try engine.secure_column.SecureColumnByCoords.zeros(a, size);
        defer actual.deinit(a);
        var result = engine.air.accumulation.ColumnAccumulator{ .random_coeff_powers = &powers, .col = &actual, .next_fresh_index = 0 };
        try Rows.For(Word).evaluateWithPool(domain, &values, &inverses, trace_log, eval_log, &result, null);
        for (0..size) |row| {
            const prior = core.utils.previousBitReversedCircleDomainIndex(row, trace_log, eval_log);
            var fixed: [Word.FIXED_COUNT]Q = undefined;
            var main: [Word.MAIN_COUNT]Q = undefined;
            var before_main: [Word.MAIN_COUNT]Q = undefined;
            var current: [Word.INTERACTION_COUNT]Q = undefined;
            var before: [Word.INTERACTION_COUNT]Q = undefined;
            for (&fixed, 0..) |*cell, i| cell.* = Q.fromBase(values[i][row]);
            for (&main, &before_main, 0..) |*cell, *previous, i| {
                cell.* = Q.fromBase(values[Word.FIXED_COUNT + i][row]);
                previous.* = Q.fromBase(values[Word.FIXED_COUNT + i][prior]);
            }
            for (&current, &before, 0..) |*cell, *previous, i| {
                cell.* = Q.fromBase(values[Word.FIXED_COUNT + Word.MAIN_COUNT + i][row]);
                previous.* = Q.fromBase(values[Word.FIXED_COUNT + Word.MAIN_COUNT + i][prior]);
            }
            const equations = try domain.evaluate(fixed, main, before_main, current, before, @as(u32, 1) << @intCast(trace_log));
            var folded = Q.zero();
            for (equations, 0..) |equation, i| folded = folded.add(powers[powers.len - 1 - i].mul(equation));
            try std.testing.expectEqual(folded.mulM31(inverses[row >> @intCast(trace_log)]), actual.at(row));
        }
    }
}
