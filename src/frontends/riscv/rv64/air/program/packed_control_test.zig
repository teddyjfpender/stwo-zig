const std = @import("std");
const E = @import("../evaluation.zig");
const Q = E.Q;
const L = E.L;
const P = @import("packed_control.zig");
const C = @import("compact.zig");
const R = @import("setup.zig");
const ops = @import("../operations.zig");
fn randomQ(random: std.Random) Q {
    const modulus = @import("stwo_core").fields.m31.Modulus;
    return Q.fromU32Unchecked(random.int(u32) % modulus, random.int(u32) % modulus, random.int(u32) % modulus, random.int(u32) % modulus);
}
fn project(full: *const R.Tuple) P.Tuple {
    var result: P.Tuple = undefined;
    result[0] = full[R.field.valid];
    @memcpy(result[P.field.pc..][0..3], &P.packBytes(full[R.field.pc..][0..8].*));
    @memcpy(result[P.field.increment..][0..3], &P.packBytes(full[R.field.increment..][0..8].*));
    @memcpy(result[P.field.target..][0..3], &P.packBytes(full[R.field.target..][0..8].*));
    @memcpy(result[P.field.opcode..P.field.increment], full[R.field.opcode..R.field.increment]);
    return result;
}
// Independent pre-refactor expansion and per-opcode enable formula. No use of
// DecodedView or compile-time deduplicated enable_plan in this oracle.
fn legacyInflate(entry: *const C.Tuple, selectors: *const [L.fixed.OPCODES]Q) E.Fixed {
    const full = C.expand(entry);
    var result: E.Fixed = @splat(Q.zero());
    result[L.fixed.active] = full[R.field.valid];
    @memcpy(result[L.fixed.opcode_start..][0..L.fixed.OPCODES], selectors);
    result[L.fixed.rs1] = full[R.field.rs1];
    result[L.fixed.rs2] = full[R.field.rs2];
    result[L.fixed.rd] = full[R.field.rd];
    @memcpy(result[L.fixed.slot_start..][0..4], full[R.field.slots..][0..4]);
    @memcpy(result[L.fixed.immediate..][0..8], full[R.field.immediate..][0..8]);
    @memcpy(result[L.fixed.pc..][0..8], full[R.field.pc..][0..8]);
    @memcpy(result[L.fixed.increment..][0..8], full[R.field.increment..][0..8]);
    @memcpy(result[L.fixed.target..][0..8], full[R.field.target..][0..8]);
    for (0..L.WORDS) |w| {
        const slot: ?usize = switch (@as(L.Word, @enumFromInt(w))) {
            .a => 0,
            .b => 1,
            .previous_rd => 2,
            .memory_before, .memory_after => 3,
            else => null,
        };
        if (slot) |s| {
            result[L.fixed.word_start + w] = full[R.field.slots + s];
            continue;
        }
        for (selectors, 0..) |selector, opcode| if (ops.wordActive(@enumFromInt(w), @enumFromInt(opcode), @splat(false))) {
            result[L.fixed.word_start + w] = result[L.fixed.word_start + w].add(selector);
        };
    }
    for (0..L.CARRIES) |c| for (selectors, 0..) |selector, opcode| if (ops.carryActive(@enumFromInt(c / 8), c % 8, @enumFromInt(opcode))) {
        result[L.fixed.carry_start + c] = result[L.fixed.carry_start + c].add(selector);
    };
    return result;
}
test "packed control distributed155 denominator is exact for arbitrary QM31 source bytes and selectors" {
    var rng = std.Random.DefaultPrng.init(0x5f19a83);
    var channel = @import("../protocol.zig").Channel{};
    const challenges = P.draw(&channel);
    for (0..16) |_| {
        var full: R.Tuple = undefined;
        for (&full) |*value| value.* = randomQ(rng.random());
        const entry = project(&full);
        try std.testing.expectEqualDeep(challenges.denominator(&full), P.denominator(challenges, &entry));
        full[R.field.valid] = Q.one();
        try std.testing.expectEqualDeep(challenges.denominator(&full), P.executionDenominator(challenges, &entry));
    }
}
test "decoded view refactor preserves every legacy fixed field on independent dense QM31 values" {
    var rng = std.Random.DefaultPrng.init(0x185a9d6);
    for (0..16) |_| {
        var entry: C.Tuple = undefined;
        var selectors: [L.fixed.OPCODES]Q = undefined;
        for (&entry) |*value| value.* = randomQ(rng.random());
        for (&selectors) |*value| value.* = randomQ(rng.random());
        try std.testing.expectEqualDeep(legacyInflate(&entry, &selectors), C.inflateFixed(&entry, &selectors));
        const full = C.expand(&entry);
        const packed_entry = project(&full);
        var expected = legacyInflate(&entry, &selectors);
        @memset(expected[L.fixed.pc..][0..8], Q.zero());
        @memset(expected[L.fixed.increment..][0..8], Q.zero());
        @memset(expected[L.fixed.target..][0..8], Q.zero());
        try std.testing.expectEqualDeep(expected, P.inflateFixed(&packed_entry, &selectors));
    }
}
test "packed ROM preserves full64 wrapping addresses and canonical separate high limbs" {
    const a = std.testing.allocator;
    const pcs = [_]u64{ 0, 0x00fffffc, 0x0000fffffffffffc, 0xfffffffffffffffc };
    var setup = try R.Setup.init(a, .{ .base = 0, .words = &.{ 0x00108093, 0x00108093, 0x00108093, 0x00108093 }, .addresses = &pcs });
    defer setup.deinit();
    const columns = try setup.packedFixedColumns(a);
    defer a.free(columns);
    const n = setup.domainSize();
    for (pcs, 0..) |pc, i| {
        const native = P.fromRowBase(&setup.rows[i]);
        const expected_pc = P.packBase(pc);
        const expected_next = P.packBase(pc +% 4);
        try std.testing.expectEqualSlices(@TypeOf(native[0]), &expected_pc, native[P.field.pc..][0..3]);
        try std.testing.expectEqualSlices(@TypeOf(native[0]), &expected_next, native[P.field.increment..][0..3]);
        for (native[P.field.pc..][0..3], 0..) |limb, j| try std.testing.expect(limb.v < @as(u32, 1) << @as(u5, if (j == 2) 16 else 24));
        const at = @import("../witness.zig").physical(i, setup.log_size);
        for (native, 0..) |value, j| try std.testing.expectEqualDeep(value, columns[j * n + at]);
    }
}

test "shared ROM denominator evaluator preserves all four pre-refactor residuals over dense QM31" {
    const provider = @import("provider.zig");
    var rng = std.Random.DefaultPrng.init(0x517abc3);
    for (0..16) |_| {
        const random = rng.random();
        var entry: R.Tuple = undefined;
        var current: [provider.INTERACTION]Q = undefined;
        var previous: [provider.INTERACTION]Q = undefined;
        var challenges: provider.Challenges = undefined;
        challenges.offset = randomQ(random);
        for (&challenges.coefficients) |*value| value.* = randomQ(random);
        for (&entry) |*value| value.* = randomQ(random);
        for (&current, &previous) |*value, *old| {
            value.* = randomQ(random);
            old.* = randomQ(random);
        }
        const first = randomQ(random);
        const last = randomQ(random);
        const multiplicity = randomQ(random);
        const claim = randomQ(random);
        const inverse = provider.secure(&current, 0);
        const sum = provider.secure(&current, 4);
        const prior = provider.secure(&previous, 4);
        const contribution = multiplicity.mul(inverse);
        const denominator = challenges.denominator(&entry);
        const expected = [provider.CONSTRAINTS]Q{ denominator.mul(inverse).sub(Q.one()), sum.sub(Q.one().sub(first).mul(prior)).add(contribution), first.mul(sum.add(contribution)), last.mul(sum.sub(claim)) };
        var full_values: [provider.CONSTRAINTS]Q = undefined;
        var direct_values: [provider.CONSTRAINTS]Q = undefined;
        var full_sink = E.Sink{ .values = &full_values };
        var direct_sink = E.Sink{ .values = &direct_values };
        provider.evaluate(first, last, &entry, multiplicity, &current, &previous, challenges, claim, &full_sink);
        provider.evaluateDenominator(first, last, denominator, multiplicity, &current, &previous, claim, &direct_sink);
        try std.testing.expectEqualDeep(expected, full_values);
        try std.testing.expectEqualDeep(expected, direct_values);
    }
}
