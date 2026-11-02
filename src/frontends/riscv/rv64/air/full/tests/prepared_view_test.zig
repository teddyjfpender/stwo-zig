//! Regression oracle for the former repeated-inflation dispatch order.
const std = @import("std");
const core = @import("stwo_core");
const C = @import("../component.zig");
const Component = C.Component;
const E = @import("../../evaluation.zig");
const L = E.L;
const Q = E.Q;
const Plan = @import("../../encoding.zig").Plan;
const frame = @import("../frame.zig");
const bytes = @import("../../range/cpu.zig");
const division = @import("../../delegations/division/mod.zig");
const multiplication = @import("../../delegations/multiplication/mod.zig");
const keccak_bus = @import("../../delegations/keccak/cpu_bus.zig");
const secp = @import("../../delegations/secp256k1/mod.zig");
pub fn emitRepeatedInflation(self: *const Component, fixed_geometry: frame.Geometry, physical: []const Q, previous_main: []const Q, current: []const Q, previous: []const Q, main: *const E.Main, out: *E.Sink) void {
    self.emitExecutionConstraints(fixed_geometry, physical, previous_main, current, previous, main, out);
    bytes.evaluatePrepared(self.plan, physical[0..self.plan.main_count], current[self.byteStart()..self.andStart()], previous[self.byteStart()..self.andStart()], fixed_geometry[1], fixed_geometry[2], &self.byte_alpha, self.claims.bytes, out);
    self.emitTableLookupConstraints(fixed_geometry, physical, current, previous, main, out);
    if (self.division_bus) |bus| {
        const advice = physical[self.plan.main_count..][0..frame.WIDTH].*;
        const original = frame.inflate(&advice, fixed_geometry);
        division.cpu_bus.evaluate(.{ .f = &original, .m = main }, current[self.divisionStart()..][0..8], previous[self.divisionStart()..][0..8], fixed_geometry[1], fixed_geometry[2], bus, out);
    }
    if (self.keccak_bus) |bus| {
        const advice = physical[self.plan.main_count..][0..frame.WIDTH].*;
        const original = frame.inflate(&advice, fixed_geometry);
        const counter = self.plan.main_count + frame.WIDTH;
        const enabled = if (self.secp_bus != null) physical[self.plan.main_count + frame.SERVICE_FLAGS] else original[L.fixed.opcode_start + @intFromEnum(E.O.ECALL)];
        keccak_bus.evaluateWithSelector(.{ .f = &original, .m = main }, fixed_geometry, physical[counter], previous_main[counter], current[self.keccakStart()..][0..8], previous[self.keccakStart()..][0..8], bus, enabled, out);
    }
    if (self.multiplication_bus) |bus| {
        const advice = physical[self.plan.main_count..][0..frame.WIDTH].*;
        const original = frame.inflate(&advice, fixed_geometry);
        multiplication.cpu_bus.evaluate(.{ .f = &original, .m = main }, current[self.multiplicationStart()..][0..8], previous[self.multiplicationStart()..][0..8], fixed_geometry[1], fixed_geometry[2], bus, out);
    }
    if (self.secp_bus) |bus| {
        const advice = physical[self.plan.main_count..][0..frame.WIDTH].*;
        const original = frame.inflate(&advice, fixed_geometry);
        const view = E.View{ .f = &original, .m = main };
        const flags = physical[self.plan.main_count + frame.SERVICE_FLAGS ..][0..3].*;
        secp.cpu_bus.evaluateSelectors(view, flags, self.plan.execution_profile, out);
        secp.cpu_bus.evaluate(view, fixed_geometry, flags[1..3].*, physical[self.plan.main_count + frame.SECP_COUNTERS ..][0..2].*, previous_main[self.plan.main_count + frame.SECP_COUNTERS ..][0..2].*, bytes.secure(current, self.secpStart()), bytes.secure(previous, self.secpStart()), bus, out);
    }
}

pub fn componentForPlan(plan: *const Plan) !Component {
    const alpha = Q.fromU32Unchecked(3, 5, 7, 11);
    const typed = @import("../../providers/tables.zig").Challenges{ .offset = alpha, .coefficients = @splat(alpha) };
    const challenges = C.Challenges{ .state = .{ .offset = alpha, .coefficients = @splat(alpha) }, .rom = .{ .offset = alpha, .coefficients = @splat(alpha) }, .bytes = alpha, .bitwise = typed, .shifts = typed };
    const claims = C.Claims{ .state = alpha, .rom = alpha, .bytes = alpha, .bitwise = alpha, .shifts = alpha };
    const div = division.cpu_bus.Bus{ .challenges = .{ .offset = alpha, .coefficients = @splat(alpha) }, .claim = alpha };
    const mul = multiplication.cpu_bus.Bus{ .challenges = .{ .offset = alpha, .coefficients = @splat(alpha) }, .claim = alpha };
    const keccak = keccak_bus.Bus{ .challenges = .{ .offset = alpha, .coefficients = @splat(alpha) }, .claim = alpha, .calls = 1, .first_call_id = 1 };
    const elliptic = secp.cpu_bus.Bus{ .challenges = .{ .offset = alpha, .coefficients = @splat(alpha) }, .claim = alpha, .calls = .{ 1, 1 }, .execution_profile = plan.execution_profile };
    const public = frame.Public{ .steps = 4000, .initial_pc = 0x1000, .final_pc = 0x2000 };
    if (plan.execution_profile == .ethereum_services_v1 or plan.execution_profile == .ethereum_services_v2) return Component.initWithEthereum(12, plan, public, challenges, claims, .{}, div, keccak, if (plan.arithmetic_policy == .division_multiplication_services_v3) mul else null, elliptic);
    if (plan.execution_profile == .keccak_service_v1) {
        if (plan.arithmetic_policy == .division_multiplication_services_v3) return Component.initWithKeccakAndMultiplication(12, plan, public, challenges, claims, .{}, div, keccak, mul);
        return Component.initWithKeccak(12, plan, public, challenges, claims, .{}, div, keccak);
    }
    if (plan.arithmetic_policy == .division_service_v2) return Component.initWithDivision(12, plan, public, challenges, claims, .{}, div);
    return Component.init(12, plan, public, challenges, claims, .{});
}
test "single prepared CPU frame preserves every base and arbitrary-Q residual in all execution profiles" {
    const a = std.testing.allocator;
    const Profile = @import("../../../execution_profile.zig").Profile;
    const Policy = @import("../../delegations/division/policy.zig").Policy;
    const cases = [_]struct { Profile, Policy }{
        .{ .rv64im, .inline_v4 },                                         .{ .rv64im, .division_service_v2 },
        .{ .keccak_service_v1, .division_service_v2 },                    .{ .keccak_service_v1, .division_multiplication_services_v3 },
        .{ .ethereum_services_v1, .division_multiplication_services_v3 }, .{ .ethereum_services_v2, .division_multiplication_services_v3 },
    };
    var opcodes: [65]E.O = undefined;
    for (&opcodes, 0..) |*opcode, i| opcode.* = @enumFromInt(i);
    var rng = std.Random.DefaultPrng.init(0x5052455041524544);
    const random = rng.random();
    for (cases) |case| {
        const plan = try Plan.fromOpcodesWithProfiles(&opcodes, case[1], case[0]);
        const component = try componentForPlan(&plan);
        const width = component.mainCount();
        const inter = component.interactionCount();
        const bank = try a.alloc(Q, 3 + 2 * width + 2 * inter);
        defer a.free(bank);
        const expected = try a.alloc(Q, component.constraint_count);
        defer a.free(expected);
        const actual = try a.alloc(Q, component.constraint_count);
        defer a.free(actual);
        for (0..16) |sample| {
            for (bank) |*v| v.* = if (sample < 8) E.q(random.int(u32) % core.fields.m31.Modulus) else Q.fromU32Unchecked(random.int(u32) % core.fields.m31.Modulus, random.int(u32) % core.fields.m31.Modulus, random.int(u32) % core.fields.m31.Modulus, random.int(u32) % core.fields.m31.Modulus);
            const physical = bank[3..][0..width];
            const prior_main = bank[3 + width ..][0..width];
            const current = bank[3 + 2 * width ..][0..inter];
            const previous = bank[3 + 2 * width + inter ..];
            const logical = plan.inflateMain(physical[0..plan.main_count]);
            var before = E.Sink{ .values = expected };
            var after = E.Sink{ .values = actual };
            emitRepeatedInflation(&component, bank[0..3].*, physical, prior_main, current, previous, &logical, &before);
            component.emitWithLogical(bank[0..3].*, physical, prior_main, current, previous, &logical, &after);
            try std.testing.expectEqual(component.constraint_count, before.count);
            try std.testing.expectEqual(before.count, after.count);
            try std.testing.expectEqualSlices(Q, expected, actual);
            // The public OODS dispatcher must use the identical logical authority.
            after.count = 0;
            component.emit(bank[0..3].*, physical, prior_main, current, previous, &after);
            try std.testing.expectEqualSlices(Q, expected, actual);
        }
    }
}

test "general word and carry View wrappers reject independent derived-coordinate mutations" {
    const ranges = @import("../../range/constraints.zig");
    const products = @import("../../product_constraints.zig");
    const plan = Plan.fromOpcodes(&.{ .MULH, .MULW, .LB, .DIVU });
    var fixed: E.Fixed = @splat(Q.one());
    var logical: E.Main = @splat(Q.zero());
    var storage: [4096]Q = undefined;
    var sink = E.Sink{ .values = &storage };
    const view = E.View{ .f = &fixed, .m = &logical };
    ranges.wordRanges(view, &sink, &plan);
    for (storage[0..sink.count]) |value| try std.testing.expect(value.isZero());
    logical[L.byte(.memory_before, 0)] = Q.one();
    sink.count = 0;
    ranges.wordRanges(view, &sink, &plan);
    var nonzero: usize = 0;
    for (storage[0..sink.count]) |value| if (!value.isZero()) {
        nonzero += 1;
    };
    try std.testing.expectEqual(@as(usize, 1), nonzero);
    // Product carry reconstruction is retained for both compact and full bits.
    logical = @splat(Q.zero());
    logical[L.productCarry(0)] = Q.one();
    sink.count = 0;
    ranges.productCarryRange(view, &sink, 0, Q.one());
    try std.testing.expect(storage[3].eql(Q.one()));
    fixed = @splat(Q.zero());
    for ([_]bool{ false, true }) |compact_carries| {
        sink.count = 0;
        products.evaluateProfile(view, &sink, compact_carries);
        const reconstruction = 16 + @as(usize, if (compact_carries) 3 else 11);
        try std.testing.expect(storage[reconstruction].eql(Q.one()));
    }
}

test "canonical substitution preserves compact and full signed product carry residuals over arbitrary QM31" {
    const products = @import("../../product_constraints.zig");
    const a = std.testing.allocator;
    var rng = std.Random.DefaultPrng.init(0x4341525259494445);
    const random = rng.random();
    for ([_]bool{ false, true }) |compact_carries| {
        var plan = Plan.fromOpcodes(&.{ .MULH, .MULHSU, .MULW, .DIVW, .REMUW });
        plan.compact_product_carries = compact_carries;
        const inflation = plan.inflation();
        const physical = try a.alloc(Q, plan.main_count);
        defer a.free(physical);
        for (0..8) |_| {
            for (physical) |*v| v.* = randomQ(random);
            var fixed: E.Fixed = undefined;
            for (&fixed) |*v| v.* = randomQ(random);
            var logical: E.Main = @splat(Q.zero());
            const inflated = inflation.applyPrepared(physical, &logical);
            var original: [512]Q = undefined;
            var optimized: [512]Q = undefined;
            var before = E.Sink{ .values = &original };
            var after = E.Sink{ .values = &optimized };
            products.evaluateProfile(.{ .f = &fixed, .m = &logical }, &before, compact_carries);
            products.evaluateInflated(&fixed, inflated, &after, compact_carries);
            try std.testing.expectEqual(before.count, after.count);
            try std.testing.expectEqualSlices(Q, original[0..before.count], optimized[0..after.count]);
        }
    }
}
fn randomQ(random: std.Random) Q {
    const p = core.fields.m31.Modulus;
    return Q.fromU32Unchecked(random.int(u32) % p, random.int(u32) % p, random.int(u32) % p, random.int(u32) % p);
}
