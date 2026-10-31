//! Every lane uses the existing scalar-Q public evaluator as its oracle. Inputs
//! include arbitrary nonboolean selectors and nonbyte words, rather than only
//! valid execution rows where a wrong polynomial could happen to vanish.
const std = @import("std");
const core = @import("stwo_core");
const E = @import("../evaluation.zig");
const Encoding = @import("../encoding.zig");
const Plan = Encoding.Plan;
const Q = E.Q;
const M = core.fields.m31.M31;
const a = std.testing.allocator;
const arithmetic = @import("../arithmetic_constraints.zig");
const memory = @import("../memory_constraints.zig");
const division = @import("../division_constraints.zig");
const barrel = @import("../shift_constraints.zig");
const product = @import("../product_constraints.zig");
const ranges = @import("../range/constraints.zig");
const operations = @import("../range/operations.zig");
const control = @import("../full/packed_control_constraints.zig");
const Case = enum { arithmetic_legacy, arithmetic_bytes, memory, division, barrel, product_legacy, product_compact, words, clocks, bitwise, shifts, packed_control, local };
const cases = std.enums.values(Case);

fn scalar(comptime F: type, value: F, lane: usize) Q {
    return if (F == E.PackedBase) Q.fromBase(value.lane(lane)) else value.lane(lane);
}
fn randomQ(random: std.Random) Q {
    const p = core.fields.m31.Modulus;
    return Q.fromU32Unchecked(random.int(u32) % p, random.int(u32) % p, random.int(u32) % p, random.int(u32) % p);
}
fn randomField(comptime F: type, random: std.Random) F {
    if (F == E.PackedBase) {
        var values: [E.LANES]M = undefined;
        for (&values) |*value| value.* = M.fromCanonical(random.int(u32) % core.fields.m31.Modulus);
        values[0] = M.zero();
        values[1] = M.one();
        values[2] = M.fromCanonical(core.fields.m31.Modulus - 1);
        values[3] = M.fromCanonical(core.fields.m31.Modulus - 2);
        return F.fromLanes(values);
    }
    var values: [E.LANES]Q = undefined;
    for (&values) |*value| value.* = randomQ(random);
    values[0] = Q.zero();
    values[1] = Q.one();
    const last = core.fields.m31.Modulus - 1;
    values[2] = Q.fromU32Unchecked(last, last, last, last);
    values[3] = Q.fromU32Unchecked(0, last, 1, last - 1);
    return F.fromLanes(values);
}
fn allOpcodes() [63]E.O {
    var result: [63]E.O = undefined;
    for (&result, 0..) |*op, i| op.* = @enumFromInt(i);
    return result;
}
fn emitPacked(comptime F: type, which: Case, v: E.ViewFor(F), physical: []const F, plan: *const Plan, out: *E.SinkFor(F)) void {
    switch (which) {
        .arithmetic_legacy => arithmetic.evaluateGeneric(F, v, out),
        .arithmetic_bytes => arithmetic.evaluateProfileWithControlGeneric(F, v, out, true, plan.control_policy),
        .memory => memory.evaluateGeneric(F, v, out),
        .division => division.evaluateGeneric(F, v, out),
        .barrel => barrel.evaluateGeneric(F, v, out),
        .product_legacy => product.evaluateProfileGeneric(F, v, out, false),
        .product_compact => product.evaluateProfileGeneric(F, v, out, true),
        .words => ranges.wordRangesGeneric(F, v, out, plan),
        .clocks => ranges.clockRangesGeneric(F, v, out, plan),
        .bitwise => operations.bitwiseGeneric(F, v, physical, plan, out),
        .shifts => operations.shiftsGeneric(F, v, physical, plan, out),
        .packed_control => control.evaluateGeneric(F, v, physical[0..3].*, physical[3..6].*, physical[6..9].*, out),
        .local => ranges.localGeneric(F, v, out, plan, physical),
    }
}
fn emitScalar(which: Case, v: E.View, physical: []const Q, plan: *const Plan, out: *E.Sink) void {
    switch (which) {
        .arithmetic_legacy => arithmetic.evaluate(v, out),
        .arithmetic_bytes => arithmetic.evaluateProfileWithControl(v, out, true, plan.control_policy),
        .memory => memory.evaluate(v, out),
        .division => division.evaluate(v, out),
        .barrel => barrel.evaluate(v, out),
        .product_legacy => product.evaluateProfile(v, out, false),
        .product_compact => product.evaluateProfile(v, out, true),
        .words => ranges.wordRanges(v, out, plan),
        .clocks => ranges.clockRanges(v, out, plan),
        .bitwise => operations.bitwise(v, physical, plan, out),
        .shifts => operations.shifts(v, physical, plan, out),
        .packed_control => control.evaluate(v, physical[0..3].*, physical[3..6].*, physical[6..9].*, out),
        .local => ranges.local(v, out, plan, physical),
    }
}
fn compare(comptime F: type) !void {
    const fixed = try a.create(E.FixedFor(F));
    defer a.destroy(fixed);
    const main = try a.create(E.MainFor(F));
    defer a.destroy(main);
    const qmain = try a.create(E.Main);
    defer a.destroy(qmain);
    var qfixed: E.Fixed = undefined;
    var plan = Plan.fromOpcodes(&allOpcodes());
    const physical = try a.alloc(F, plan.main_count);
    defer a.free(physical);
    const qphysical = try a.alloc(Q, plan.main_count);
    defer a.free(qphysical);
    const actual_values = try a.alloc(E.PackedSecure, 8192);
    defer a.free(actual_values);
    const expected = try a.alloc(Q, 8192);
    defer a.free(expected);
    var prng = std.Random.DefaultPrng.init(0x4c4f43414c4c414e);
    const random = prng.random();
    for (fixed) |*value| value.* = randomField(F, random);
    for (main) |*value| value.* = randomField(F, random);
    for (physical) |*value| value.* = randomField(F, random);
    for ([_]@import("../control_policy.zig").Policy{ .bytes_v1, .limbs24_v2 }) |policy| {
        plan.control_policy = policy;
        for (cases) |which| {
            var sink = E.SinkFor(F){ .values = actual_values };
            emitPacked(F, which, .{ .f = fixed, .m = main }, physical, &plan, &sink);
            for (0..E.LANES) |lane| {
                for (&qfixed, fixed) |*value, source| value.* = scalar(F, source, lane);
                for (qmain, main) |*value, source| value.* = scalar(F, source, lane);
                for (qphysical, physical) |*value, source| value.* = scalar(F, source, lane);
                var oracle = E.Sink{ .values = expected };
                emitScalar(which, .{ .f = &qfixed, .m = qmain }, qphysical, &plan, &oracle);
                try std.testing.expectEqual(oracle.count, sink.count);
                for (expected[0..oracle.count], actual_values[0..sink.count], 0..) |want, actual, ordinal| {
                    if (!want.eql(actual.lane(lane))) {
                        std.debug.print("local lane mismatch field={s} family={s} control={s} lane={d} residual={d}\n", .{ @typeName(F), @tagName(which), @tagName(policy), lane, ordinal });
                        return error.LocalLaneResidualMismatch;
                    }
                }
            }
        }
    }
}
test "RV64 all local polynomial families preserve every scalar residual in16 packed base rows" {
    try compare(E.PackedBase);
}
test "RV64 all local polynomial families preserve every scalar residual in16 dense secure rows" {
    try compare(E.PackedSecure);
}

fn compareInflation(comptime F: type) !void {
    const fixed = try a.create(E.FixedFor(F));
    defer a.destroy(fixed);
    const logical = try a.create(E.MainFor(F));
    defer a.destroy(logical);
    const qlogical = try a.create(E.Main);
    defer a.destroy(qlogical);
    var qfixed: E.Fixed = undefined;
    const actual_values = try a.alloc(E.PackedSecure, 8192);
    defer a.free(actual_values);
    const expected = try a.alloc(Q, 8192);
    defer a.free(expected);
    var prng = std.Random.DefaultPrng.init(0x494e464c4154454c);
    const random = prng.random();
    for (0..2) |profile| {
        const plan = if (profile == 0) Plan.fromOpcodes(&allOpcodes()) else try Plan.fromOpcodesWithProfiles(&allOpcodes(), .division_multiplication_services_v3, .ethereum_services_v2);
        const inflation = plan.inflation();
        const physical = try a.alloc(F, plan.main_count);
        defer a.free(physical);
        const qphysical = try a.alloc(Q, plan.main_count);
        defer a.free(qphysical);
        for (fixed) |*value| value.* = randomField(F, random);
        @memset(logical, F.zero());
        // Reusing the same zero-omission scratch for several independent rows
        // tests that every live source/reconstruction is actually overwritten.
        for (0..3) |_| {
            for (physical) |*value| value.* = randomField(F, random);
            const prepared = inflation.applyPreparedGeneric(F, physical, logical);
            var sink = E.SinkFor(F){ .values = actual_values };
            ranges.localInflatedGeneric(F, fixed, prepared, &sink, &plan, physical);
            if (plan.support.product) product.evaluateInflatedGeneric(F, fixed, prepared, &sink, true);
            for (0..E.LANES) |lane| {
                for (&qfixed, fixed) |*value, source| value.* = scalar(F, source, lane);
                for (qphysical, physical) |*value, source| value.* = scalar(F, source, lane);
                @memset(qlogical, Q.zero());
                const qprepared = inflation.applyPrepared(qphysical, qlogical);
                for (qlogical, logical) |want, actual| try std.testing.expect(want.eql(scalar(F, actual, lane)));
                var oracle = E.Sink{ .values = expected };
                ranges.localInflated(&qfixed, qprepared, &oracle, &plan, qphysical);
                if (plan.support.product) product.evaluateInflated(&qfixed, qprepared, &oracle, true);
                try std.testing.expectEqual(oracle.count, sink.count);
                for (expected[0..oracle.count], actual_values[0..sink.count]) |want, actual| try std.testing.expect(want.eql(actual.lane(lane)));
            }
        }
    }
}
test "RV64 prepared packed inflation preserves all coordinates and residual order across scratch reuse" {
    try compareInflation(E.PackedBase);
    try compareInflation(E.PackedSecure);
}
