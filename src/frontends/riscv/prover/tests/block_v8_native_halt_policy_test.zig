const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const H = @import("../block_v8_native_halt_policy_v1.zig");
const p = H.Policy{ .halt_address = 0x100000 };
fn zero(checks: [10]M) bool {
    for (checks) |v| if (!v.isZero()) return false;
    return true;
}
fn row(store: bool, address: u32, after: u32, cycle: u32) [50]M {
    var out: [50]M = @splat(M.zero());
    out[0] = M.fromCanonical(cycle);
    out[48] = M.fromCanonical(address / 4);
    out[if (store) 41 else 38] = M.one();
    for (0..4) |i| out[(if (store) @as(usize, 8) else 19) + i] = M.fromCanonical((after >> @as(u5, @intCast(8 * i))) & 255);
    return out;
}
test "v8 native halt per-access policy rejects transient nonzero values and altered auxiliaries" {
    for ([_]bool{ false, true }) |store| {
        for ([_]u32{ 1, 256, 65536, 0xff000000, 0x7fffffff, 0xffffffff }) |after| {
            const current = row(store, p.halt_address, after, 2);
            const aux = try H.witness(true, M.fromCanonical(p.halt_address), p);
            try std.testing.expect(!zero(try H.constraintsNative(M, p, M.one(), &current, aux)));
            for (0..2) |i| {
                var altered = aux;
                altered[i] = altered[i].add(M.one());
                try std.testing.expect(!zero(try H.constraintsNative(M, p, M.one(), &current, altered)));
            }
            // The following zero after-word is valid but cannot cancel this row.
            const later = row(store, p.halt_address, 0, 3);
            try std.testing.expect(zero(try H.constraintsNative(M, p, M.one(), &later, aux)));
            const other = row(store, p.halt_address + 4, after, 2);
            const other_aux = try H.witness(true, M.fromCanonical(p.halt_address + 4), p);
            try std.testing.expect(zero(try H.constraintsNative(M, p, M.one(), &other, other_aux)));
            var hidden = aux;
            hidden[0] = M.zero();
            try std.testing.expect(!zero(try H.constraintsNative(M, p, M.one(), &current, hidden)));
        }
    }
    const inactive: [50]M = @splat(M.zero());
    try std.testing.expect(zero(try H.constraintsNative(M, p, M.zero(), &inactive, .{ M.zero(), M.zero() })));
    for ([_][2]M{ .{ M.one(), M.zero() }, .{ M.zero(), M.one() } }) |bad|
        try std.testing.expect(!zero(try H.constraintsNative(M, p, M.zero(), &inactive, bad)));
}
test "v8 native halt terminal policy permits only its exact instruction cycle" {
    const terminal = H.Policy{ .halt_address = p.halt_address, .permitted_final_instruction_cycle = 9 };
    for ([_]bool{ false, true }) |store| for ([_]u32{ 1, 8, 9, 10 }) |cycle| {
        const current = row(store, p.halt_address, 1, cycle);
        const aux = try H.witness(true, M.fromCanonical(p.halt_address), terminal);
        try std.testing.expectEqual(cycle == 9, zero(try H.constraintsNative(M, terminal, M.one(), &current, aux)));
    };
}
const Degree = struct {
    n: usize,
    pub fn one() @This() {
        return .{ .n = 0 };
    }
    pub fn splat(_: core.fields.qm31.QM31) @This() {
        return .{ .n = 0 };
    }
    pub fn add(a: @This(), b: @This()) @This() {
        return .{ .n = @max(a.n, b.n) };
    }
    pub fn sub(a: @This(), b: @This()) @This() {
        return a.add(b);
    }
    pub fn mul(a: @This(), b: @This()) @This() {
        return .{ .n = a.n + b.n };
    }
};
test "v8 native halt degree is at most four with two auxiliary columns" {
    for ([_]?u32{ null, 9 }) |last| {
        const d = Degree{ .n = 1 };
        const current: [50]Degree = @splat(d);
        const checks = try H.constraintsNative(Degree, .{ .halt_address = p.halt_address, .permitted_final_instruction_cycle = last }, d, &current, @splat(d));
        for (checks) |check| try std.testing.expect(check.n <= H.DEGREE);
    }
}

test "v8 native halt independently bounded policy rejects unaligned and aliased addresses" {
    for ([_]u32{ 1, p.halt_address + 1, 1 << 30, 0x7fffffff, 0xffffffff }) |address| {
        try std.testing.expectError(error.InvalidNativeHaltPolicy, (H.Policy{ .halt_address = address }).validate());
    }
}

test "v8 native halt packed sparse scalar and secure fold parity covers boundary field values" {
    const Q = core.fields.qm31.QM31;
    const lanes = core.fields.m31.PACK_WIDTH;
    var rng = std.Random.DefaultPrng.init(0xb8a17);
    const random = rng.random();
    var weights: [H.CONSTRAINT_COUNT]H.PackedQ = undefined;
    var scalar_weights: [H.CONSTRAINT_COUNT]Q = undefined;
    for (&weights, &scalar_weights) |*packed_value, *scalar| {
        scalar.* = Q.fromU32Unchecked(random.int(u32) % core.fields.m31.Modulus, random.int(u32) % core.fields.m31.Modulus, random.int(u32) % core.fields.m31.Modulus, random.int(u32) % core.fields.m31.Modulus);
        packed_value.* = H.PackedQ.splat(scalar.*);
    }
    for ([_]?u32{ null, 9 }) |last| {
        const policy = H.Policy{ .halt_address = p.halt_address, .permitted_final_instruction_cycle = last };
        for (0..96) |batch| {
            var mains: [lanes][H.NativeColumns.width]M = undefined;
            var actives: [lanes]M = undefined;
            var auxiliaries: [lanes][2]M = undefined;
            for (&mains, &actives, &auxiliaries, 0..) |*main, *active, *aux, lane| {
                for (main) |*value| value.* = M.fromCanonical(random.int(u32) % core.fields.m31.Modulus);
                active.* = M.fromCanonical(switch ((batch + lane) % 4) {
                    0 => 0,
                    1 => 1,
                    2 => core.fields.m31.Modulus - 1,
                    else => random.int(u32) % core.fields.m31.Modulus,
                });
                aux.* = .{ M.fromCanonical(random.int(u32) % core.fields.m31.Modulus), M.fromCanonical(random.int(u32) % core.fields.m31.Modulus) };
                if (batch < 16) {
                    // Valid row shapes pin actual LB/LH/LW/SB/SH/SW after
                    // selection as well as inactive/terminal edge cases.
                    main.* = row(batch % 2 == 0, if (lane % 2 == 0) p.halt_address else p.halt_address + 4, if (batch < 8) 0 else 0x7fffffff, @intCast(8 + batch % 3));
                    active.* = M.fromCanonical(@intFromBool(batch % 4 != 0));
                    aux.* = try H.witness(!active.isZero(), main[H.NativeColumns.quarter].mul(M.fromCanonical(4)), policy);
                }
            }
            var packed_input: [H.INPUT_COUNT]H.PackedBase = undefined;
            for (&packed_input, H.NativeColumns.used) |*packed_value, index| {
                var values: core.fields.m31.PackedM31 = undefined;
                for (0..lanes) |lane| values[lane] = mains[lane][index].v;
                packed_value.* = .{ .value = values };
            }
            var packed_active: H.PackedBase = undefined;
            var packed_aux: [2]H.PackedBase = undefined;
            for (0..lanes) |lane| {
                packed_active.value[lane] = actives[lane].v;
                for (0..2) |i| packed_aux[i].value[lane] = auxiliaries[lane][i].v;
            }
            const packed_checks = H.constraintsSparse(H.PackedBase, policy, packed_active, packed_input, packed_aux);
            const folded = H.foldPacked(packed_checks, weights);
            for (0..lanes) |lane| {
                const scalar_checks = try H.constraintsNative(M, policy, actives[lane], &mains[lane], auxiliaries[lane]);
                var main_q: [H.NativeColumns.width]Q = undefined;
                for (&main_q, mains[lane]) |*value, base| value.* = Q.fromBase(base);
                const secure_checks = try H.constraintsNative(Q, policy, Q.fromBase(actives[lane]), &main_q, .{ Q.fromBase(auxiliaries[lane][0]), Q.fromBase(auxiliaries[lane][1]) });
                var scalar_fold = Q.zero();
                for (scalar_checks, secure_checks, 0..) |scalar, secure, index| {
                    try std.testing.expectEqual(scalar.v, packed_checks[index].value[lane]);
                    try std.testing.expect(secure.eql(Q.fromBase(scalar)));
                    scalar_fold = scalar_fold.add(scalar_weights[index].mulM31(scalar));
                }
                try std.testing.expect(scalar_fold.eql(folded.lane(lane)));
                // Vanishing-segment multipliers remain a lane-local M31
                // scaling after the identical ordered secure fold.
                const inverse = M.fromCanonical(if (lane % 2 == 0) 1 else core.fields.m31.Modulus - 1);
                try std.testing.expect(scalar_fold.mulM31(inverse).eql(folded.lane(lane).mulM31(inverse)));
            }
        }
    }
}

fn domainCacheFixture(a: std.mem.Allocator, cache_bytes: usize) !void {
    const engine = @import("stwo_prover_engine");
    const Guard = @import("../block_v8_native_halt_component_v1.zig").Component;
    const Cache = @import("../block_v7_leased_quotient_cache_v1.zig");
    const Q = core.fields.qm31.QM31;
    const Poly = engine.air.component_prover.Poly;
    const trace_log = 2;
    const eval_log = trace_log + 2;
    var coeff: [H.INPUT_COUNT + 3][1 << trace_log]M = undefined;
    for (&coeff, 0..) |*column, i| for (column, 0..) |*value, j| {
        value.* = M.fromCanonical(@intCast(i * 17 + j + 1));
    };
    var fixed: [1]Poly = undefined;
    var main: [H.NativeColumns.width + 2]Poly = undefined;
    // Unused native columns intentionally carry no values or coefficients.
    // Sparse recovery must never validate, recover or FFT those columns.
    @memset(&main, .{ .log_size = trace_log, .values = &.{} });
    fixed[0] = .{ .log_size = trace_log, .values = &.{}, .coefficients = try engine.poly.circle.poly.CircleCoefficients.initBorrowed(&coeff[0]) };
    for (H.NativeColumns.used, 0..) |index, i| main[index] = .{ .log_size = trace_log, .values = &.{}, .coefficients = try engine.poly.circle.poly.CircleCoefficients.initBorrowed(&coeff[i + 1]) };
    for (0..2) |i| main[H.NativeColumns.width + i] = .{ .log_size = trace_log, .values = &.{}, .coefficients = try engine.poly.circle.poly.CircleCoefficients.initBorrowed(&coeff[H.INPUT_COUNT + 1 + i]) };
    var trees = [_][]const Poly{ &fixed, &main, &.{} };
    const trace = engine.air.component_prover.Trace{ .polys = .{ .items = &trees } };
    var cache = try Cache.Cache.initBounded(a, cache_bytes, H.INPUT_COUNT);
    defer cache.deinit();
    const guard = Guard{ .log_size = trace_log, .active_column = 0, .main_offset = 0, .aux_offset = H.NativeColumns.width, .policy = p, .providers = &.{}, .leased_quotient_cache = &cache };
    try std.testing.expectEqual(@as(u32, 2), guard.compositionLogSplit());
    try std.testing.expectEqual(@as(u32, eval_log), guard.maxConstraintLogDegreeBound());
    const alpha = Q.fromU32Unchecked(3, 5, 7, 11);
    var first = try engine.air.accumulation.DomainEvaluationAccumulator.init(a, alpha, eval_log, H.CONSTRAINT_COUNT);
    defer first.deinit();
    try guard.evaluateConstraintQuotientsOnDomain(&trace, &first);
    var second = try engine.air.accumulation.DomainEvaluationAccumulator.init(a, alpha, eval_log, H.CONSTRAINT_COUNT);
    defer second.deinit();
    try guard.evaluateConstraintQuotientsOnDomain(&trace, &second);
    try std.testing.expectEqual(@as(usize, 0), first.next_power_index);
    try std.testing.expectEqual(@as(usize, 0), second.next_power_index);
    if (cache_bytes != 0) {
        try std.testing.expectEqual(H.INPUT_COUNT, cache.recovered_columns);
        try std.testing.expectEqual(H.INPUT_COUNT, cache.reused_columns);
    } else try std.testing.expectEqual(@as(usize, 0), cache.recovered_columns);
    const domain = core.poly.circle.canonic.CanonicCoset.new(eval_log).circleDomain();
    for (0..domain.size()) |physical| {
        const base = domain.at(core.utils.bitReverseIndex(physical, eval_log));
        const point = core.circle.CirclePointQM31{ .x = Q.fromBase(base.x), .y = Q.fromBase(base.y) };
        var row_q: [H.NativeColumns.width]Q = @splat(Q.zero());
        for (H.NativeColumns.used) |index| row_q[index] = main[index].coefficients.?.evalAtPoint(point);
        const checks = try H.constraintsNative(Q, p, fixed[0].coefficients.?.evalAtPoint(point), &row_q, .{ main[H.NativeColumns.width].coefficients.?.evalAtPoint(point), main[H.NativeColumns.width + 1].coefficients.?.evalAtPoint(point) });
        var expected = Q.zero();
        for (checks, 0..) |check, i| expected = expected.add(first.random_coeff_powers[H.CONSTRAINT_COUNT - 1 - i].mul(check));
        const inverse = try core.constraints.cosetVanishing(Q, core.poly.circle.canonic.CanonicCoset.new(trace_log).coset(), point).inv();
        expected = expected.mul(inverse);
        try std.testing.expect(expected.eql(first.sub_accumulations[eval_log].?.at(physical)));
        try std.testing.expect(expected.eql(second.sub_accumulations[eval_log].?.at(physical)));
    }
}
test "v8 native halt sparse packed domain matches coefficient oracle with cache reuse and zero capacity" {
    try domainCacheFixture(std.testing.allocator, 4096);
    try domainCacheFixture(std.testing.allocator, 0);
}
test "v8 native halt sparse domain releases leases and buffers on every allocation failure" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, domainCacheFixture, .{@as(usize, 4096)});
}
