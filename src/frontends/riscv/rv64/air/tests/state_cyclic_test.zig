const std = @import("std");
const E = @import("../evaluation.zig");
const C = @import("../state_cyclic.zig");
const R = @import("../relations.zig");
const S = @import("../statement.zig");
const W = @import("../witness.zig");
const T = @import("../trace.zig");
const P = @import("../protocol.zig");
const Q = E.Q;
const a = std.testing.allocator;

fn store(values: [3]Q) C.Values {
    var result: C.Values = undefined;
    for (values, 0..) |value, group| for (value.toM31Array(), 0..) |coordinate, i| {
        result[group * 4 + i] = Q.fromBase(coordinate);
    };
    return result;
}

test "rv64 cyclic state: aliases and padding preserve independently expected boundary claim" {
    const program = [_]u32{ 0x001080b3, 0x001080b3, 0x001080b3 };
    var initial: [32]u64 = @splat(0);
    initial[1] = 0x87654321ffffffff;
    var final = initial;
    final[1] *%= 8;
    const public = S.Statement{ .program_base = 0x100001000, .program = &program, .initial_pc = 0x100001000, .final_pc = 0x10000100c, .initial_registers = initial, .final_registers = final, .memory = &.{}, .steps = 3 };
    try qualify(public);
}

test "rv64 cyclic state: full-width RAM loads stores and register boundaries close together" {
    const program = [_]u32{ 0x0020b023, 0x0000b183, 0x0030b423 }; // sd x2,0(x1); ld x3,0(x1); sd x3,8(x1)
    var initial: [32]u64 = @splat(0);
    initial[1] = 0x1000010000;
    initial[2] = 0xfedcba9876543210;
    var final = initial;
    final[3] = initial[2];
    const memory = [_]S.Cell{
        .{ .address = initial[1], .initial = 7, .final = initial[2], .readable = true, .writable = true },
        .{ .address = initial[1] + 8, .initial = 11, .final = initial[2], .readable = true, .writable = true },
    };
    try qualify(.{ .program_base = 0x100001000, .program = &program, .initial_pc = 0x100001000, .final_pc = 0x10000100c, .initial_registers = initial, .final_registers = final, .memory = &memory, .steps = 3 });
}

fn qualify(public: S.Statement) !void {
    var witness = try W.Witness.build(a, public);
    defer witness.deinit();
    var trace = try T.Trace.init(a, public, witness.metadata, witness.rows);
    defer trace.deinit();
    var channel = P.Channel{};
    const challenges = C.draw(&channel);
    const expected = try R.expected(public, witness.metadata, challenges);
    const values = try a.alloc(C.Values, trace.domainSize());
    defer a.free(values);
    var prefix = Q.zero();
    for (values, 0..) |*current, logical| {
        const physical = W.physical(logical, trace.log_size);
        const fixed = trace.fixedAt(physical);
        const main = trace.mainAt(physical);
        const next = try C.advance(.{ .f = &fixed, .m = &main }, E.q(@intCast(logical)), challenges, prefix);
        current.* = store(next);
        prefix = next[2];
        // Independent eight-inverse oracle, using the original active tuples.
        var oracle = if (logical == 0) Q.zero() else C.secure(&values[logical - 1], 2);
        for (0..4) |slot| if (!fixed[E.L.fixed.slot_start + slot].isZero()) {
            const view = E.View{ .f = &fixed, .m = &main };
            oracle = oracle.add(try challenges.denominator(R.tuple(view, slot, true)).inv())
                .sub(try challenges.denominator(R.tuple(view, slot, false)).inv());
        };
        try std.testing.expect(oracle.eql(prefix));
    }
    try std.testing.expect(expected.eql(prefix));
    for (values, 0..) |current, logical| {
        const physical = W.physical(logical, trace.log_size);
        const fixed = trace.fixedAt(physical);
        const main = trace.mainAt(physical);
        const previous = &values[(logical + values.len - 1) % values.len];
        var output: [C.CONSTRAINTS]Q = undefined;
        var sink = E.Sink{ .values = &output };
        const view = E.View{ .f = &fixed, .m = &main };
        const index = E.q(@intCast(logical));
        const first = E.q(@intFromBool(logical == 0));
        C.evaluate(view, index, first, &current, previous, challenges, expected, &sink);
        try std.testing.expectEqual(C.CONSTRAINTS, sink.count);
        for (output) |residual| try std.testing.expect(residual.isZero());
        for (0..C.INTERACTION) |column| {
            var changed = current;
            changed[column] = changed[column].add(Q.one());
            sink.count = 0;
            C.evaluate(view, index, first, &changed, previous, challenges, expected, &sink);
            try std.testing.expect(anyNonzero(&output));
            var changed_previous = previous.*;
            changed_previous[column] = changed_previous[column].add(Q.one());
            sink.count = 0;
            C.evaluate(view, index, first, &current, &changed_previous, challenges, expected, &sink);
            try std.testing.expectEqual(C.needsPrevious(column), anyNonzero(&output));
        }
        if (logical == 0) {
            sink.count = 0;
            C.evaluate(view, index, first, &current, previous, challenges, expected.add(Q.one()), &sink);
            try std.testing.expect(anyNonzero(&output));
        }
    }
    for (0..C.INTERACTION) |column| try std.testing.expectEqual(column >= 8, C.needsPrevious(column));
}

test "rv64 cyclic state: dense arbitrary QM31 authority has degree at most four" {
    const width = E.L.fixed.COUNT + E.L.MAIN + 2 * C.INTERACTION + 2;
    const base = try a.alloc(Q, width);
    defer a.free(base);
    const slope = try a.alloc(Q, width);
    defer a.free(slope);
    const values = try a.alloc(Q, width);
    defer a.free(values);
    var rng = std.Random.DefaultPrng.init(0xc597a7e);
    for (base, slope) |*b, *s| {
        b.* = randomQ(rng.random());
        s.* = randomQ(rng.random());
    }
    var challenges = C.Challenges{ .offset = randomQ(rng.random()), .coefficients = undefined };
    for (&challenges.coefficients) |*coefficient| coefficient.* = randomQ(rng.random());
    const claim = randomQ(rng.random());
    var differences: [6][3]Q = undefined;
    for (&differences, 0..) |*output, t| {
        for (values, base, slope) |*value, b, s| value.* = b.add(s.mul(E.q(@intCast(t))));
        const main_start = E.L.fixed.COUNT;
        const current_start = main_start + E.L.MAIN;
        const previous_start = current_start + C.INTERACTION;
        const index_start = previous_start + C.INTERACTION;
        var sink = E.Sink{ .values = output };
        C.evaluate(.{ .f = values[0..main_start], .m = values[main_start..][0..E.L.MAIN] }, values[index_start], values[index_start + 1], values[current_start..][0..C.INTERACTION], values[previous_start..][0..C.INTERACTION], challenges, claim, &sink);
        try std.testing.expectEqual(C.CONSTRAINTS, sink.count);
    }
    for (0..5) |order| for (0..5 - order) |row| for (0..3) |column| {
        differences[row][column] = differences[row + 1][column].sub(differences[row][column]);
    };
    for (differences[0]) |value| try std.testing.expect(value.isZero());
}

fn anyNonzero(values: []const Q) bool {
    for (values) |value| if (!value.isZero()) return true;
    return false;
}
fn randomQ(random: std.Random) Q {
    return Q.fromU32Unchecked(random.uintLessThan(u32, 2147483647), random.uintLessThan(u32, 2147483647), random.uintLessThan(u32, 2147483647), random.uintLessThan(u32, 2147483647));
}

// Independent original 3/3/2 common-denominator expansion. Keep this oracle
// deliberately unfactored so sharing mistakes remain visible at dense OODS.
fn expandedTerms(v: E.View, index: Q, challenges: C.Challenges) [3]C.Term {
    var d: [8]Q = undefined;
    var weight: [8]Q = undefined;
    for (0..4) |slot| {
        const before = R.tuple(v, slot, true);
        var after = R.tuple(v, slot, false);
        after[9] = index.mul(E.q(4)).add(E.q(@intCast(slot + 1)));
        d[2 * slot] = challenges.denominator(before);
        d[2 * slot + 1] = challenges.denominator(after);
        weight[2 * slot] = v.f[E.L.fixed.slot_start + slot];
        weight[2 * slot + 1] = weight[2 * slot].neg();
    }
    var result: [3]C.Term = undefined;
    for (&result, 0..) |*entry, group| {
        entry.* = .{ .denominator = Q.one(), .numerator = Q.zero() };
        const start = group * 3;
        const count: usize = if (group == 2) 2 else 3;
        for (0..count) |i| {
            entry.denominator = entry.denominator.mul(d[start + i]);
            var numerator = weight[start + i];
            for (0..count) |j| if (i != j) {
                numerator = numerator.mul(d[start + j]);
            };
            entry.numerator = entry.numerator.add(numerator);
        }
    }
    return result;
}
test "rv64 cyclic state factored terms equal original eight-event expansion at arbitrary QM31 points" {
    var rng = std.Random.DefaultPrng.init(0xa6e1a1d0);
    var fixed: E.Fixed = undefined;
    const main = try a.create(E.Main);
    defer a.destroy(main);
    for (0..64) |_| {
        for (&fixed) |*value| value.* = randomQ(rng.random());
        for (main) |*value| value.* = randomQ(rng.random());
        var ch = C.Challenges{ .offset = randomQ(rng.random()), .coefficients = undefined };
        for (&ch.coefficients) |*value| value.* = randomQ(rng.random());
        const index = randomQ(rng.random());
        const v = E.View{ .f = &fixed, .m = main };
        const denominators = @import("../state_cyclic_denominators.zig").evaluate(v, index, ch);
        for (0..4) |slot| {
            var after = R.tuple(v, slot, false);
            after[9] = index.mul(E.q(4)).add(E.q(@intCast(slot + 1)));
            try std.testing.expect(denominators[2 * slot].eql(ch.denominator(R.tuple(v, slot, true))));
            try std.testing.expect(denominators[2 * slot + 1].eql(ch.denominator(after)));
        }
        for (expandedTerms(v, index, ch), C.terms(v, index, ch)) |old, factored| {
            try std.testing.expect(old.denominator.eql(factored.denominator));
            try std.testing.expect(old.numerator.eql(factored.numerator));
        }
    }
}
test "rv64 cyclic state rejects every forged event fraction even with colluding terminal prefix claim" {
    const rows = @import("../rows.zig");
    const M = @import("stwo_core").fields.m31.M31;
    var native: rows.Main = @splat(M.zero());
    rows.putWord(&native, .a, 0xf123456789abcdef);
    rows.putWord(&native, .b, 0x8000000000000001);
    rows.putWord(&native, .previous_rd, 0x12345678ffffffff);
    rows.putWord(&native, .result, 0x9234567800000001);
    rows.putWord(&native, .address, 0xf123456780003fe0);
    rows.putWord(&native, .memory_before, 17);
    rows.putWord(&native, .memory_after, 0xffffffffffffffff);
    native[E.L.readable] = M.one();
    native[E.L.writable] = M.one();
    for (0..4) |slot| native[E.L.previousClock(slot)] = M.fromCanonical(@intCast(slot + 1));
    var fixed: E.Fixed = @splat(Q.zero());
    @memset(fixed[E.L.fixed.slot_start..][0..4], Q.one());
    fixed[E.L.fixed.rs1] = E.q(1);
    fixed[E.L.fixed.rs2] = E.q(2);
    fixed[E.L.fixed.rd] = E.q(3);
    var main: E.Main = undefined;
    for (&main, native) |*value, part| value.* = Q.fromBase(part);
    const v = E.View{ .f = &fixed, .m = &main };
    var channel = P.Channel{};
    const ch = C.draw(&channel);
    const index = E.q(7);
    const honest = store(try C.advance(v, index, ch, Q.zero()));
    var residuals: [3]Q = undefined;
    var sink = E.Sink{ .values = &residuals };
    C.evaluate(v, index, Q.one(), &honest, &honest, ch, C.secure(&honest, 2), &sink);
    for (residuals) |value| try std.testing.expect(value.isZero());
    for (0..8) |forged_event| {
        var sums: [3]Q = undefined;
        var sum = Q.zero();
        for (0..8) |event| {
            const slot = event / 2;
            const before = event % 2 == 0;
            var entry = R.tuple(v, slot, before);
            if (!before) entry[9] = index.mul(E.q(4)).add(E.q(@intCast(slot + 1)));
            var denominator = ch.denominator(entry);
            if (event == forged_event) denominator = denominator.add(Q.one());
            const fraction = try denominator.inv();
            sum = if (before) sum.add(fraction) else sum.sub(fraction);
            if (event == 2) sums[0] = sum;
            if (event == 5) sums[1] = sum;
            if (event == 7) sums[2] = sum;
        }
        const forged = store(sums);
        sink.count = 0;
        C.evaluate(v, index, Q.one(), &forged, &forged, ch, sums[2], &sink);
        try std.testing.expect(anyNonzero(&residuals));
    }
}
