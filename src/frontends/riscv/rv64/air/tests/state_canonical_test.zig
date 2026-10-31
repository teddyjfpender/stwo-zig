const std = @import("std");
const core = @import("stwo_core");
const E = @import("../evaluation.zig");
const L = E.L;
const Q = E.Q;
const M = core.fields.m31.M31;
const Encoding = @import("../encoding.zig");
const Plan = Encoding.Plan;
const Policy = @import("../state_policy.zig");
const Cyclic = @import("../state_cyclic.zig");
const Relations = @import("../relations.zig");
const Range = @import("../range/constraints.zig");
const Bytes = @import("../range/cpu.zig");
const R = @import("../rows.zig");
const a = std.testing.allocator;

// Immutable whole-program mask, not the observed execution histogram.
// Source identity and complete mask: rv64-state-range-model.json.
fn actualPlan() !Plan {
    const ids = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 52, 54, 56, 59, 62, 63 };
    var ops: [ids.len]E.O = undefined;
    for (&ops, ids) |*op, id| op.* = @enumFromInt(id);
    var plan = try Plan.fromOpcodesWithProfiles(&ops, .division_multiplication_services_v3, .ethereum_services_v2);
    plan.setStatePolicy(.cyclic_v2);
    plan.control_policy = .limbs24_v2;
    return plan;
}
fn inferred(word: L.Word) bool {
    return word == .b or word == .previous_rd or word == .memory_after;
}
test "canonical state v3 removes exactly three read-derived byte words and restores v2" {
    var plan = try actualPlan();
    const legacy = plan;
    plan.setStatePolicy(.cyclic_canonical_v3);
    try std.testing.expectEqual(@as(usize, 70), legacy.range_count);
    try std.testing.expectEqual(@as(usize, 46), plan.range_count);
    try std.testing.expectEqual(@as(usize, 32), Bytes.interactionCount(&legacy) - Bytes.interactionCount(&plan));
    try std.testing.expectEqual(legacy.main_count, plan.main_count);
    try std.testing.expectEqualSlices(u16, legacy.main_sources[0..legacy.main_count], plan.main_sources[0..plan.main_count]);
    try std.testing.expectEqualDeep(legacy.main_map, plan.main_map);
    try std.testing.expectEqualDeep(legacy.byte_bits, plan.byte_bits);
    var retained: usize = 0;
    var removed: [L.WORDS]usize = @splat(0);
    for (legacy.range_sources[0..legacy.range_count]) |physical| {
        const source = legacy.main_sources[physical];
        if (source < L.carry_start and inferred(@enumFromInt(source / L.WORD_COLUMNS))) {
            removed[source / L.WORD_COLUMNS] += 1;
        } else {
            try std.testing.expectEqual(physical, plan.range_sources[retained]);
            retained += 1;
        }
    }
    try std.testing.expectEqual(plan.range_count, retained);
    for (removed, 0..) |count, word| try std.testing.expectEqual(@as(usize, if (inferred(@enumFromInt(word))) 8 else 0), count);
    plan.setStatePolicy(.cyclic_v2);
    try std.testing.expectEqualSlices(u16, legacy.range_sources[0..legacy.range_count], plan.range_sources[0..plan.range_count]);
    try std.testing.expectEqual(@as(usize, 12), Policy.interactionCount(.cyclic_canonical_v3));
}

test "canonical state v3 challenge schema cannot downgrade to cyclic v2" {
    var old = @import("../protocol.zig").Channel{};
    var explicit = @import("../protocol.zig").Channel{};
    var new = @import("../protocol.zig").Channel{};
    const original = Cyclic.draw(&old);
    const v2 = Cyclic.drawWithPolicy(&explicit, .cyclic_v2);
    const v3 = Cyclic.drawWithPolicy(&new, .cyclic_canonical_v3);
    try std.testing.expect(original.offset.eql(v2.offset));
    for (original.coefficients, v2.coefficients) |left, right| try std.testing.expect(left.eql(right));
    try std.testing.expect(!v3.offset.eql(v2.offset));
}

fn project(plan: *const Plan, native: *const R.Main, physical: []Q) E.Main {
    for (physical, 0..) |*value, column| value.* = Q.fromBase(plan.projectValue(native, column));
    return plan.inflateMain(physical);
}
fn anyNonzero(values: []const Q) bool {
    for (values) |v| if (!v.isZero()) return true;
    return false;
}
fn clocks(fixed: *const E.Fixed, main: *const E.Main, plan: *const Plan) bool {
    var residuals: [12]Q = undefined;
    var sink = E.Sink{ .values = &residuals };
    Range.clockRanges(.{ .f = fixed, .m = main }, &sink, plan);
    return anyNonzero(residuals[0..sink.count]);
}
test "canonical state future and self cycles cannot survive checked predecessor gap projection" {
    var plan = Plan.fromOpcodes(&.{.ADD});
    plan.setStatePolicy(.cyclic_canonical_v3);
    var native: R.Main = @splat(M.zero());
    // A nonbyte read word can close a future-before cycle as a multiset.
    native[L.byte(.b, 0)] = M.fromCanonical(257);
    var fixed: E.Fixed = @splat(Q.zero());
    fixed[L.fixed.slot_start + 1] = Q.one();
    fixed[L.fixed.rs2] = E.q(2);
    var channel = @import("../protocol.zig").Channel{};
    const ch = Cyclic.drawWithPolicy(&channel, .cyclic_canonical_v3);
    var claim = Q.zero();
    var physical: [L.MAIN]Q = undefined;
    for ([_]struct { tick: u32, previous: u32, gap: u32 }{
        .{ .tick = 2, .previous = 6, .gap = core.fields.m31.Modulus - 5 },
        .{ .tick = 6, .previous = 2, .gap = 3 },
    }, 0..) |event, i| {
        native[L.previousClock(1)] = M.fromCanonical(event.previous);
        native[L.gap(1)] = M.fromCanonical(event.gap);
        fixed[L.fixed.tick_start + 1] = E.q(event.tick);
        var raw: E.Main = undefined;
        for (&raw, native) |*value, base| value.* = Q.fromBase(base);
        const v = E.View{ .f = &fixed, .m = &raw };
        claim = claim.add(try ch.denominator(Relations.tuple(v, 1, true)).inv()).sub(try ch.denominator(Relations.tuple(v, 1, false)).inv());
        // Without reconstruction/ranges the wrapped gap satisfies the field equation.
        try std.testing.expect(!clocks(&fixed, &raw, &plan));
        const inflated = project(&plan, &native, physical[0..plan.main_count]);
        try std.testing.expectEqual(i == 0, clocks(&fixed, &inflated, &plan));
    }
    try std.testing.expect(claim.isZero());
    native[L.previousClock(1)] = M.fromCanonical(2);
    native[L.gap(1)] = M.fromCanonical(core.fields.m31.Modulus - 1);
    fixed[L.fixed.tick_start + 1] = E.q(2);
    const self_loop = project(&plan, &native, physical[0..plan.main_count]);
    try std.testing.expect(clocks(&fixed, &self_loop, &plan));
    native[L.previousClock(1)] = M.one();
    native[L.gap(1)] = M.zero();
    const honest = project(&plan, &native, physical[0..plan.main_count]);
    try std.testing.expect(!clocks(&fixed, &honest, &plan));
}

test "canonical state keeps disabled read words zero and independent register writes byte checked" {
    var plan = Plan.fromOpcodes(&.{.ADD});
    plan.setStatePolicy(.cyclic_canonical_v3);
    var native: R.Main = @splat(M.zero());
    native[L.byte(.b, 0)] = M.fromCanonical(257);
    var physical: [L.MAIN]Q = undefined;
    const logical = project(&plan, &native, physical[0..plan.main_count]);
    const fixed: E.Fixed = @splat(Q.zero());
    var residuals: [512]Q = undefined;
    var sink = E.Sink{ .values = &residuals };
    Range.wordRanges(.{ .f = &fixed, .m = &logical }, &sink, &plan);
    try std.testing.expect(anyNonzero(residuals[0..sink.count]));

    const data = try a.alloc(M, 32 * plan.main_count);
    defer a.free(data);
    @memset(data, M.zero());
    const columns = try a.alloc([]const M, plan.main_count);
    defer a.free(columns);
    for (columns, 0..) |*column, c| column.* = data[c * 32 ..][0..32];
    const counts = try plan.counts(columns);
    var provider = try @import("../range/provider.zig").Trace.init(a, &counts);
    defer provider.deinit();
    const alpha = Q.fromU32Unchecked(911, 3, 5, 7);
    const provider_claim = try provider.generateInteraction(alpha);
    // Seal honest multiplicities first. Retained result byte lookup detects a
    // nonbyte write through actual rational closure, not only host validation.
    const result_column = plan.main_map[L.byte(.result, 0)];
    data[result_column * 32] = M.fromCanonical(256);
    var forged = try Bytes.buildInteraction(a, &plan, columns, 5, alpha);
    defer forged.deinit();
    try std.testing.expect(!forged.claim.add(provider_claim).isZero());
}

fn randomQ(rng: std.Random) Q {
    const p = core.fields.m31.Modulus;
    return Q.fromU32Unchecked(rng.int(u32) % p, rng.int(u32) % p, rng.int(u32) % p, rng.int(u32) % p);
}
test "canonical state filtered BYTE equations retain degree four over arbitrary QM31" {
    var plan = try actualPlan();
    plan.setStatePolicy(.cyclic_canonical_v3);
    const width = plan.main_count + 2 * Bytes.interactionCount(&plan) + 2;
    const values = try a.alloc(Q, width);
    defer a.free(values);
    const base = try a.alloc(Q, width);
    defer a.free(base);
    const slope = try a.alloc(Q, width);
    defer a.free(slope);
    var prng = std.Random.DefaultPrng.init(0x43414e4f4e494341);
    const rng = prng.random();
    for (base, slope) |*b, *s| {
        b.* = randomQ(rng);
        s.* = randomQ(rng);
    }
    const n = Bytes.interactionCount(&plan);
    var differences: [6][32]Q = undefined;
    const alpha = randomQ(rng);
    const claim = randomQ(rng);
    for (&differences, 0..) |*output, t| {
        for (values, base, slope) |*value, b, s| value.* = b.add(s.mul(E.q(@intCast(t))));
        var sink = E.Sink{ .values = output };
        Bytes.evaluate(&plan, values[0..plan.main_count], values[plan.main_count..][0..n], values[plan.main_count + n ..][0..n], values[width - 2], values[width - 1], alpha, claim, &sink);
    }
    for (0..5) |order| for (0..5 - order) |row| for (0..Bytes.constraintCount(&plan)) |column| {
        differences[row][column] = differences[row + 1][column].sub(differences[row][column]);
    };
    for (differences[0][0..Bytes.constraintCount(&plan)]) |value| try std.testing.expect(value.isZero());
}

test "canonical state cannot originate a nonbyte read from a canonical register boundary" {
    var fixed: E.Fixed = @splat(Q.zero());
    var main: E.Main = @splat(Q.zero());
    fixed[L.fixed.rs2] = E.q(2);
    fixed[L.fixed.tick_start + 1] = E.q(2);
    main[L.byte(.b, 0)] = E.q(257);
    const view = E.View{ .f = &fixed, .m = &main };
    var channel = @import("../protocol.zig").Channel{};
    const ch = Cyclic.drawWithPolicy(&channel, .cyclic_canonical_v3);
    const forged = (try ch.denominator(Relations.tuple(view, 1, true)).inv()).sub(try ch.denominator(Relations.tuple(view, 1, false)).inv());
    const expected = (try ch.denominator(Relations.boundaryTuple(0, 2, 0, 257, true, true)).inv()).sub(try ch.denominator(Relations.boundaryTuple(0, 2, 2, 257, true, true)).inv());
    // The same integer as a u64 has bytes {1,1}; it cannot authenticate a single
    // field coordinate257 merely because summing the byte word would agree.
    try std.testing.expect(!forged.eql(expected));
}

test "canonical state actual52 full CPU authority retains degree four at dense QM31 points" {
    var plan = try actualPlan();
    plan.setStatePolicy(.cyclic_canonical_v3);
    const component = try @import("../full/tests/prepared_view_test.zig").componentForPlan(&plan);
    const m = component.mainCount();
    const n = component.interactionCount();
    const width = 3 + 2 * m + 2 * n;
    const values = try a.alloc(Q, width);
    defer a.free(values);
    const base = try a.alloc(Q, width);
    defer a.free(base);
    const slope = try a.alloc(Q, width);
    defer a.free(slope);
    const differences = try a.alloc(Q, 6 * component.constraint_count);
    defer a.free(differences);
    var prng = std.Random.DefaultPrng.init(0x43414e4f4e444547);
    const rng = prng.random();
    for (base, slope) |*b, *s| {
        b.* = randomQ(rng);
        s.* = randomQ(rng);
    }
    for (0..6) |t| {
        for (values, base, slope) |*value, b, s| value.* = b.add(s.mul(E.q(@intCast(t))));
        var sink = E.Sink{ .values = differences[t * component.constraint_count ..][0..component.constraint_count] };
        component.emit(values[0..3].*, values[3..][0..m], values[3 + m ..][0..m], values[3 + 2 * m ..][0..n], values[3 + 2 * m + n ..][0..n], &sink);
        try std.testing.expectEqual(component.constraint_count, sink.count);
    }
    for (0..5) |order| for (0..5 - order) |row| for (0..component.constraint_count) |column| {
        const at = row * component.constraint_count + column;
        differences[at] = differences[at + component.constraint_count].sub(differences[at]);
    };
    for (differences[0..component.constraint_count]) |value| try std.testing.expect(value.isZero());
}
