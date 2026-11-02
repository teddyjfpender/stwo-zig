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
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    if (args.len == 2 and std.mem.eql(u8, args[1], "prepared-frame")) return benchmarkPreparedFrame(a);
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

// Compare the former dispatch order against the prepared view using the same
// complete service polynomial authority, residual ordering, and random weights.
fn benchmarkPreparedFrame(a: std.mem.Allocator) !void {
    const oracle = @import("air/full/tests/prepared_view_test.zig");
    var ops: [65]E.O = undefined;
    for (&ops, 0..) |*op, i| op.* = @enumFromInt(i);
    const plan = try Plan.fromOpcodesWithProfiles(&ops, .division_multiplication_services_v3, .ethereum_services_v2);
    const component = try oracle.componentForPlan(&plan);
    const width = component.mainCount();
    const inter = component.interactionCount();
    const bank_width = 3 + 2 * width + 2 * inter;
    const banks = try a.alloc(Q, bank_width * 16);
    defer a.free(banks);
    var rng = std.Random.DefaultPrng.init(0x5052455041524544);
    for (banks) |*value| value.* = E.q(rng.random().int(u32) % core.fields.m31.Modulus);
    const powers = try a.alloc(Q, component.constraint_count);
    defer a.free(powers);
    const alpha = Q.fromU32Unchecked(3, 5, 7, 11);
    var power = alpha;
    for (powers) |*p| {
        p.* = power;
        power = power.mul(alpha);
    }
    var expected: ?Q = null;
    for (0..4) |sample| for ([_]enum { repeated, hoisted, derived }{ .repeated, .hoisted, .derived }) |mode| {
        var logical: E.Main = @splat(Q.zero());
        var checksum = Q.zero();
        var timer = try std.time.Timer.start();
        for (0..4096) |i| {
            const bank = banks[(i % 16) * bank_width ..][0..bank_width];
            const physical = bank[3..][0..width];
            const prior_main = bank[3 + width ..][0..width];
            const current = bank[3 + 2 * width ..][0..inter];
            const previous = bank[3 + 2 * width + inter ..];
            const inflated = component.inflation.applyPrepared(physical[0..plan.main_count], &logical);
            var weighted = E.WeightedAccumulator{ .powers = powers };
            var sink = E.Sink{ .values = null, .weighted_accumulator = &weighted };
            switch (mode) {
                .repeated => oracle.emitRepeatedInflation(&component, bank[0..3].*, physical, prior_main, current, previous, &logical, &sink),
                .hoisted => component.emitWithLogical(bank[0..3].*, physical, prior_main, current, previous, &logical, &sink),
                .derived => component.emitInflated(bank[0..3].*, physical, prior_main, current, previous, inflated, &sink),
            }
            checksum = checksum.add(weighted.accumulation);
        }
        const ns = timer.read();
        if (expected) |value| {
            if (!checksum.eql(value)) return error.PreparedFrameMismatch;
        } else expected = checksum;
        std.debug.print("RV64_PREPARED_FRAME sample={d} mode={s} rows=4096 constraints={d} main={d} interaction={d} ns={d} checksum={any}\n", .{ sample, @tagName(mode), component.constraint_count, width, inter, ns, checksum.toM31Array() });
    };
}
