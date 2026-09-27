const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const P = core.fields.packed_qm31.PackedQM31;
const width = core.fields.m31.PACK_WIDTH;
const relation = @import("../air/relation_challenges.zig");
const Inverse = @import("block_v5_range16_inverse_table_v1.zig").Table;
const protocol = @import("block_v5_word_memory_protocol_v1.zig");
const Word = @import("block_v5_word_memory_component_v1.zig").Spec;
const Range = @import("block_v5_range16_component_v1.zig").Spec;
const interaction = @import("block_v5_word_memory_interaction_v1.zig");
const rows = @import("block_v5_word_domain_rows_v1.zig");

fn challenges() protocol.Challenges {
    return .{ .transition = .dummy(), .link = .dummy(), .initial = .dummy(), .endpoint = .dummy(), .range16 = .dummy(), .universal_prefix = .dummy() };
}
fn value(seed: usize) Q {
    return Q.fromU32Unchecked(@intCast((seed * 17 + 3) % 65536), @intCast((seed * 31 + 7) % 65536), @intCast((seed * 41 + 11) % 65536), @intCast((seed * 61 + 13) % 65536));
}
fn packedCells(comptime count: usize, seed: usize) [count]P {
    var result: [count]P = undefined;
    for (&result, 0..) |*cell, column| {
        var lanes: [width]Q = undefined;
        for (&lanes, 0..) |*lane, index| lane.* = value(seed + column * width + index);
        cell.* = P.fromLanes(lanes);
    }
    return result;
}
fn scalarCells(comptime count: usize, vectors: [count]P, lane: usize) [count]Q {
    var result: [count]Q = undefined;
    for (&result, vectors) |*cell, item| cell.* = item.lane(lane);
    return result;
}

test "block-v5 range inverse table exhaustively preserves sealed denominators and active zero rejection" {
    const a = std.testing.allocator;
    const r = relation.RelationElements(1).dummy();
    var table = try Inverse.init(a, r);
    defer table.deinit();
    try table.requireRelation(r);
    for (0..Inverse.VALUE_COUNT) |index| {
        const denominator = r.combineBase(.{M.fromCanonical(@intCast(index))});
        try std.testing.expectEqual(Q.one(), denominator.mul(try table.inverse(@intCast(index))));
    }
    try std.testing.expectError(error.InvalidWordRangeValue, table.inverse(65536));
    try std.testing.expectError(error.InvalidWordRangeValue, table.fraction(value(77), Q.one()));
    try std.testing.expectEqual(Q.zero(), try table.fraction(value(77), Q.zero()));
    var changed = r;
    changed.alpha = changed.alpha.add(Q.one());
    try std.testing.expectError(error.ChangedV5RangeInverseChallenge, table.requireRelation(changed));
    var singular = try Inverse.init(a, relation.RelationElements(1).init(Q.fromBase(M.fromCanonical(65535)), Q.one()));
    defer singular.deinit();
    try std.testing.expectError(error.DivisionByZero, singular.inverse(65535));
    try std.testing.expectEqual(Q.one(), (try singular.inverse(0)).mul(singular.relation.combineBase(.{M.zero()})));
    try std.testing.expectEqual(Q.zero(), try singular.fraction(Q.fromBase(M.fromCanonical(65535)), Q.zero()));
}

test "block-v5 packed quotient equations match scalar extension field constraints lane by lane" {
    var c = challenges();
    const event = @import("../air/block/memory_transition.zig").Transition{ .space = 1, .address = 0xffff_fffc, .clock = (@as(u64, 1) << 61) + 0xffff, .before = 0xdead_beef, .after = 0xabcd_ef01 };
    const spec = Word{
        .claim = .{ .first_row = 0, .total_rows = 1, .rows = 1, .log_size = 8, .first = event, .last = event, .preceding = null },
        .interaction_claim = .{ .transition_sum = value(1), .link_sum = value(2), .initial_sum = value(3), .endpoint_sum = value(4), .endpoint_count = 1, .register_endpoint_sum = value(5), .register_endpoint_count = 0, .range_count = 25, .range_sums = @splat(value(6)) },
        .challenges = &c,
    };
    const domain = try spec.prepareDomain(256);
    const fixed = packedCells(Word.FIXED_COUNT, 100);
    const main = packedCells(Word.MAIN_COUNT, 200);
    const previous = packedCells(Word.MAIN_COUNT, 300);
    const current = packedCells(Word.INTERACTION_COUNT, 400);
    const before = packedCells(Word.INTERACTION_COUNT, 500);
    const vectors = domain.evaluatePacked(fixed, main, previous, current, before);
    for (0..width) |lane| {
        const expected = try spec.evaluate(scalarCells(Word.FIXED_COUNT, fixed, lane), scalarCells(Word.MAIN_COUNT, main, lane), scalarCells(Word.MAIN_COUNT, previous, lane), scalarCells(Word.INTERACTION_COUNT, current, lane), scalarCells(Word.INTERACTION_COUNT, before, lane), 256);
        for (expected, vectors) |scalar, vector| try std.testing.expectEqual(scalar, vector.lane(lane));
    }
    const range_spec = Range{ .claim = .{ .sum = value(11), .count = 100 }, .challenges = &c };
    const range_domain = try range_spec.prepareDomain(65536);
    const rf = packedCells(1, 777);
    const rm = packedCells(1, 888);
    const rc = packedCells(8, 999);
    const rb = packedCells(8, 1111);
    const range_packed = range_domain.evaluatePacked(rf, rm, rm, rc, rb);
    for (0..width) |lane| {
        const expected = try range_spec.evaluate(scalarCells(1, rf, lane), scalarCells(1, rm, lane), scalarCells(1, rm, lane), scalarCells(8, rc, lane), scalarCells(8, rb, lane), 65536);
        for (expected, range_packed) |scalar, vector| try std.testing.expectEqual(scalar, vector.lane(lane));
    }
    try std.testing.expectError(error.InvalidWordMemoryClaim, interaction.normalize(spec.interaction_claim, 0));
}

fn reference(comptime Spec: type, domain: Spec.Domain, values: *const rows.For(Spec).Values, inverses: *const rows.For(Spec).Inverses, trace_log: u32, eval_log: u32, powers: []const Q, result: *engine.secure_column.SecureColumnByCoords) !void {
    for (0..@as(usize, 1) << @intCast(eval_log)) |row| {
        const prior = core.utils.previousBitReversedCircleDomainIndex(row, trace_log, eval_log);
        var fixed: [Spec.FIXED_COUNT]Q = undefined;
        var main: [Spec.MAIN_COUNT]Q = undefined;
        var before_main: [Spec.MAIN_COUNT]Q = undefined;
        var current: [Spec.INTERACTION_COUNT]Q = undefined;
        var before: [Spec.INTERACTION_COUNT]Q = undefined;
        for (&fixed, 0..) |*cell, i| cell.* = Q.fromBase(values[i][row]);
        for (&main, &before_main, 0..) |*cell, *previous, i| {
            cell.* = Q.fromBase(values[Spec.FIXED_COUNT + i][row]);
            previous.* = Q.fromBase(values[Spec.FIXED_COUNT + i][prior]);
        }
        for (&current, &before, 0..) |*cell, *previous, i| {
            cell.* = Q.fromBase(values[Spec.FIXED_COUNT + Spec.MAIN_COUNT + i][row]);
            previous.* = Q.fromBase(values[Spec.FIXED_COUNT + Spec.MAIN_COUNT + i][prior]);
        }
        const equations = try domain.spec.evaluate(fixed, main, before_main, current, before, @as(u32, 1) << @intCast(trace_log));
        var folded = Q.zero();
        for (equations, 0..) |equation, i| folded = folded.add(powers[powers.len - 1 - i].mul(equation));
        result.set(row, folded.mulM31(inverses[row >> @intCast(trace_log)]));
    }
}

test "block-v5 parallel quotient rows preserve fresh and additive accumulation under shared lease contention" {
    const a = std.testing.allocator;
    var c = challenges();
    const spec = Range{ .claim = .{ .sum = value(37), .count = 987654 }, .challenges = &c };
    const domain = try spec.prepareDomain(65536);
    const size = 1 << 17;
    const storage = try a.alloc(M, size * (Range.FIXED_COUNT + Range.MAIN_COUNT + Range.INTERACTION_COUNT));
    defer a.free(storage);
    for (storage, 0..) |*cell, i| cell.* = M.fromCanonical(@intCast((i * 17 + 3) % 65536));
    var values: rows.For(Range).Values = undefined;
    for (&values, 0..) |*column, i| column.* = storage[i * size ..][0..size];
    const inverses = rows.For(Range).Inverses{ M.fromCanonical(7), M.fromCanonical(11) };
    const powers = [_]Q{ value(12), value(34) };
    var expected = try engine.secure_column.SecureColumnByCoords.zeros(a, size);
    defer expected.deinit(a);
    try reference(Range, domain, &values, &inverses, 16, 17, &powers, &expected);
    var actual = try engine.secure_column.SecureColumnByCoords.zeros(a, size);
    defer actual.deinit(a);
    var result = engine.air.accumulation.ColumnAccumulator{ .random_coeff_powers = &powers, .col = &actual, .next_fresh_index = 0 };
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 3 });
    defer pool.deinit();
    var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    try rows.For(Range).evaluate(domain, &values, &inverses, 16, 17, &result);
    try std.testing.expectEqual(@as(?usize, size), result.next_fresh_index);
    for (0..size) |row| try std.testing.expectEqual(expected.at(row), actual.at(row));
    result.next_fresh_index = null;
    var competing = try pool.acquire(try engine.work_pool.WorkerBudget.init(3));
    try rows.For(Range).evaluate(domain, &values, &inverses, 16, 17, &result);
    competing.deinit();
    for (0..size) |row| try std.testing.expectEqual(expected.at(row).add(expected.at(row)), actual.at(row));
    try std.testing.expectEqual(@as(usize, 3), pool.availableWorkers());
}

test "block-v5 assembled driver integration compiles without launching segment proving" {
    // Keep the production orchestration in the semantic/codegen gate, without
    // executing its segment producer or using an empty fake complete bundle.
    std.mem.doNotOptimizeAway(&@import("block_v5_cpu_driver_v1.zig").run);
}

test "block-v5 word quotient kernel benchmark scalar packed and shared pool" {
    const a = std.testing.allocator;
    var c = challenges();
    const event = @import("../air/block/memory_transition.zig").Transition{ .space = 1, .address = 0x2000, .clock = 0xffff_ffff, .before = 5, .after = 6 };
    const spec = Word{
        .claim = .{ .first_row = 0, .total_rows = 1, .rows = 1, .log_size = 13, .first = event, .last = event, .preceding = null },
        .interaction_claim = .{ .transition_sum = value(1), .link_sum = value(2), .initial_sum = value(3), .endpoint_sum = value(4), .endpoint_count = 1, .register_endpoint_sum = value(5), .register_endpoint_count = 0, .range_count = 17, .range_sums = @splat(value(6)) },
        .challenges = &c,
    };
    const domain = try spec.prepareDomain(1 << 13);
    const size = 1 << 15;
    const storage = try a.alloc(M, size * (Word.FIXED_COUNT + Word.MAIN_COUNT + Word.INTERACTION_COUNT));
    defer a.free(storage);
    for (storage, 0..) |*cell, i| cell.* = M.fromCanonical(@intCast((i * 17 + 3) % 65536));
    var values: rows.For(Word).Values = undefined;
    for (&values, 0..) |*column, i| column.* = storage[i * size ..][0..size];
    const inverses = rows.For(Word).Inverses{ M.fromCanonical(7), M.fromCanonical(11), M.fromCanonical(13), M.fromCanonical(19) };
    var powers: [Word.CONSTRAINT_COUNT]Q = undefined;
    for (&powers, 0..) |*power, i| power.* = value(i + 17);
    var expected = try engine.secure_column.SecureColumnByCoords.zeros(a, size);
    defer expected.deinit(a);
    var actual = try engine.secure_column.SecureColumnByCoords.zeros(a, size);
    defer actual.deinit(a);
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 3 });
    defer pool.deinit();
    var scalar_times: [3]u64 = undefined;
    var packed_times: [3]u64 = undefined;
    var parallel_times: [3]u64 = undefined;
    var timer = try std.time.Timer.start();
    for (0..3) |repeat| {
        timer.reset();
        try reference(Word, domain, &values, &inverses, 13, 15, &powers, &expected);
        scalar_times[repeat] = timer.read();
        var result = engine.air.accumulation.ColumnAccumulator{ .random_coeff_powers = &powers, .col = &actual, .next_fresh_index = 0 };
        timer.reset();
        try rows.For(Word).evaluateWithPool(domain, &values, &inverses, 13, 15, &result, null);
        packed_times[repeat] = timer.read();
        for (0..size) |row| try std.testing.expectEqual(expected.at(row), actual.at(row));
        result.next_fresh_index = 0;
        timer.reset();
        try rows.For(Word).evaluateWithPool(domain, &values, &inverses, 13, 15, &result, &pool);
        parallel_times[repeat] = timer.read();
        for (0..size) |row| try std.testing.expectEqual(expected.at(row), actual.at(row));
    }
    std.mem.sort(u64, &scalar_times, {}, std.sort.asc(u64));
    std.mem.sort(u64, &packed_times, {}, std.sort.asc(u64));
    std.mem.sort(u64, &parallel_times, {}, std.sort.asc(u64));
    std.debug.print("WORD_QUOTIENT_KERNEL rows={d} constraints={d} main_columns={d} interaction_columns={d} scalar_median_ns={d} packed_median_ns={d} parallel_median_ns={d} workers=3 verified_all_rows=true scope=quotient_rows_only\n", .{ size, Word.CONSTRAINT_COUNT, Word.MAIN_COUNT, Word.INTERACTION_COUNT, scalar_times[1], packed_times[1], parallel_times[1] });
}
