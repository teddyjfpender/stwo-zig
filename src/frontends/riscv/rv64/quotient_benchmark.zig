//! Standalone arithmetic microbenchmark; no proof or security parameters change.
const std = @import("std");
const core = @import("stwo_core");
const E = @import("air/evaluation.zig");
const C = @import("air/full/component.zig");
const Plan = @import("air/encoding.zig").Plan;
const F = @import("air/full/frame.zig");
const T = @import("air/providers/tables.zig");
const Q = E.Q;
const Mode = enum { identity_multiply, unscaled_horner, weighted, weighted_legacy_inflation, weighted_reused_inflation, weighted_original_byte_terms };
pub fn main() !void {
    const a = std.heap.smp_allocator;
    var ops: [63]E.O = undefined;
    for (&ops, 0..) |*op, i| op.* = @enumFromInt(i);
    const plan = Plan.fromOpcodes(&ops);
    const alpha = Q.fromU32Unchecked(3, 5, 7, 11);
    const typed = T.Challenges{ .offset = alpha, .coefficients = @splat(alpha) };
    const challenges = C.Challenges{ .state = .{ .offset = alpha, .coefficients = @splat(alpha) }, .rom = .{ .offset = alpha, .coefficients = @splat(alpha) }, .bytes = alpha, .bitwise = typed, .shifts = typed };
    const claims = C.Claims{ .state = alpha, .rom = alpha, .bytes = alpha, .bitwise = alpha, .shifts = alpha };
    const component = try C.Component.init(12, &plan, .{ .steps = 4000, .initial_pc = 0x1000, .final_pc = 0x2000 }, challenges, claims, .{});
    const width = component.mainCount();
    const inter = component.interactionCount();
    const bank_width = 3 + 2 * width + 2 * inter;
    const banks = try a.alloc(Q, bank_width * 16);
    defer a.free(banks);
    var rng = std.Random.DefaultPrng.init(0x51554f5449454e54);
    for (banks) |*value| value.* = E.q(rng.random().int(u32) % core.fields.m31.Modulus);
    const powers = try a.alloc(Q, component.constraint_count);
    defer a.free(powers);
    var p = alpha.pow(16);
    for (powers) |*power| {
        power.* = p;
        p = p.mul(alpha);
    }
    var expected: ?Q = null;
    for (0..3) |sample| for ([_]Mode{ .identity_multiply, .unscaled_horner, .weighted, .weighted_legacy_inflation, .weighted_reused_inflation, .weighted_original_byte_terms }) |mode| {
        var timer = try std.time.Timer.start();
        var checksum = Q.zero();
        var logical: E.Main = @splat(Q.zero());
        for (0..1024) |i| {
            const bank = banks[(i % 16) * bank_width ..][0..bank_width];
            var horner = core.air.accumulation.PointEvaluationAccumulator.init(alpha);
            var weighted = E.WeightedAccumulator{ .powers = powers };
            var sink = E.Sink{ .values = null };
            switch (mode) {
                .identity_multiply => {
                    sink.accumulator = &horner;
                    sink.scale = Q.one();
                },
                .unscaled_horner => sink.accumulator = &horner,
                .weighted, .weighted_legacy_inflation, .weighted_reused_inflation, .weighted_original_byte_terms => sink.weighted_accumulator = &weighted,
            }
            if (mode == .weighted_original_byte_terms) {
                component.inflation.apply(bank[3..][0..plan.main_count], &logical);
                @import("air/tests/byte_terms_test.zig").emitWithOriginalByteTerms(&component, bank[0..3].*, bank[3..][0..width], bank[3 + width ..][0..width], bank[3 + 2 * width ..][0..inter], bank[3 + 2 * width + inter ..], &logical, &sink);
            } else if (mode == .weighted_reused_inflation) {
                component.inflation.apply(bank[3..][0..plan.main_count], &logical);
                component.emitWithLogical(bank[0..3].*, bank[3..][0..width], bank[3 + width ..][0..width], bank[3 + 2 * width ..][0..inter], bank[3 + 2 * width + inter ..], &logical, &sink);
            } else if (mode == .weighted_legacy_inflation) {
                const original = @import("air/tests/inflation_reuse_test.zig").reference(&plan, bank[3..][0..plan.main_count]);
                component.emitWithLogical(bank[0..3].*, bank[3..][0..width], bank[3 + width ..][0..width], bank[3 + 2 * width ..][0..inter], bank[3 + 2 * width + inter ..], &original, &sink);
            } else {
                component.emit(bank[0..3].*, bank[3..][0..width], bank[3 + width ..][0..width], bank[3 + 2 * width ..][0..inter], bank[3 + 2 * width + inter ..], &sink);
            }
            const value = if (mode == .identity_multiply or mode == .unscaled_horner) horner.finalize().mul(powers[0]) else weighted.accumulation;
            checksum = checksum.add(value);
        }
        const ns = timer.read();
        if (expected) |value| {
            if (!checksum.eql(value)) return error.AccumulationMismatch;
        } else expected = checksum;
        std.debug.print("RV64_QUOTIENT_KERNEL sample={d} mode={s} rows=1024 constraints={d} main={d} interaction={d} ns={d}\n", .{ sample, @tagName(mode), component.constraint_count, width, inter, ns });
    };
}
