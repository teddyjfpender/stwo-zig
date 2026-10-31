const std = @import("std");
const core = @import("stwo_core");
const E = @import("../evaluation.zig");
const R = @import("../relations.zig");
const Cyclic = @import("../state_cyclic.zig");
const Bytes = @import("../range/cpu.zig");
const Tables = @import("../range/table_cpu.zig");
const Provider = @import("../providers/tables.zig");
const Rom = @import("../program/provider.zig");
const Frame = @import("../full/frame.zig");
const Plan = @import("../encoding.zig").Plan;
const Q = E.Q;
const M = core.fields.m31.M31;
const a = std.testing.allocator;
const CAPACITY = 2048;
const Scalar = struct {
    fixed: E.Fixed,
    main: E.Main,
    physical: [E.L.MAIN]Q,
    current: [1024]Q,
    previous: [1024]Q,
    advice: [Frame.WIDTH]Q,
    prior_advice: [Frame.WIDTH]Q,
    geometry: [Frame.FIXED]Q,
};
const Challenges = struct { state: R.Challenges, rom: Rom.Challenges, tables: Provider.Challenges, alpha: Q, claim: Q };
fn randomQ(rng: std.Random) Q {
    return Q.fromU32Unchecked(rng.int(u32) % core.fields.m31.Modulus, rng.int(u32) % core.fields.m31.Modulus, rng.int(u32) % core.fields.m31.Modulus, rng.int(u32) % core.fields.m31.Modulus);
}
fn fill(comptime F: type, rng: std.Random, destination: []F, scalar: []Scalar, comptime field: []const u8) void {
    for (destination, 0..) |*value, column| {
        var secure: [E.LANES]Q = undefined;
        var base: [E.LANES]M = undefined;
        for (0..E.LANES) |lane| {
            secure[lane] = if (F == E.PackedBase) Q.fromBase(M.fromCanonical(rng.int(u32) % core.fields.m31.Modulus)) else randomQ(rng);
            base[lane] = secure[lane].c0.a;
            @field(scalar[lane], field)[column] = secure[lane];
        }
        value.* = if (F == E.PackedBase) E.PackedBase.fromLanes(base) else E.PackedSecure.fromLanes(secure);
    }
}
fn emit(comptime F: type, plan: *const Plan, view: E.ViewFor(F), physical: []const F, current: []const F, previous: []const F, advice: []const F, prior_advice: []const F, geometry: [Frame.FIXED]F, ch: Challenges, out: *E.SinkFor(F)) void {
    const public = Frame.Public{ .steps = 27, .initial_pc = 0x123456789ab0, .final_pc = 0xfedcba987654 };
    inline for ([_]@import("../control_policy.zig").Policy{ .bytes_v1, .limbs24_v2 }) |policy| {
        Frame.evaluateWithControlFor(F, advice[0..Frame.bodyWidth(policy)], prior_advice[0..Frame.bodyWidth(policy)], geometry, public, 5, policy, out);
        const denominator = Frame.executionDenominatorWithControlFor(F, ch.rom, advice[0..Frame.bodyWidth(policy)], policy);
        out.emit(denominator);
        const fixed = Frame.inflateWithControlFor(F, advice[0..Frame.bodyWidth(policy)], geometry, policy);
        for (fixed) |value| out.emit(value);
    }
    R.evaluateFor(F, view, current[0..E.L.INTERACTION], previous[0..E.L.INTERACTION], ch.state, ch.claim, out);
    Cyclic.evaluateFor(F, view, geometry[0], geometry[1], current[0..Cyclic.INTERACTION], previous[0..Cyclic.INTERACTION], ch.state, ch.claim, out);
    const count = Bytes.interactionCount(plan);
    const prepared = Bytes.PreparedAlpha.init(ch.alpha);
    Bytes.evaluatePreparedFor(F, plan, physical, current[0..count], previous[0..count], geometry[1], geometry[2], &prepared, ch.claim, out);
    inline for ([_]Provider.Kind{ .byte_and, .byte_shift }) |kind| {
        const n = Tables.interactionCount(plan, kind);
        Tables.evaluateFor(F, plan, kind, view.m, physical, current[0..n], previous[0..n], geometry[1], geometry[2], ch.tables, ch.claim, out);
    }
}
fn compare(comptime F: type) !void {
    var prng = std.Random.DefaultPrng.init(0x4d495845444c414e);
    const rng = prng.random();
    const plan = Plan.fromOpcodes(&.{ .ADDI, .ADD, .AND, .SRA, .MUL });
    const scalar = try a.alloc(Scalar, E.LANES);
    defer a.free(scalar);
    const fixed = try a.create(E.FixedFor(F));
    defer a.destroy(fixed);
    const main = try a.create(E.MainFor(F));
    defer a.destroy(main);
    const physical = try a.alloc(F, plan.main_count);
    defer a.free(physical);
    const current = try a.alloc(F, 1024);
    defer a.free(current);
    const previous = try a.alloc(F, 1024);
    defer a.free(previous);
    const advice = try a.alloc(F, Frame.WIDTH);
    defer a.free(advice);
    const prior_advice = try a.alloc(F, Frame.WIDTH);
    defer a.free(prior_advice);
    const geometry = try a.create([Frame.FIXED]F);
    defer a.destroy(geometry);
    fill(F, rng, fixed, scalar, "fixed");
    fill(F, rng, main, scalar, "main");
    fill(F, rng, physical, scalar, "physical");
    fill(F, rng, current, scalar, "current");
    fill(F, rng, previous, scalar, "previous");
    fill(F, rng, advice, scalar, "advice");
    fill(F, rng, prior_advice, scalar, "prior_advice");
    fill(F, rng, geometry, scalar, "geometry");
    var ch: Challenges = undefined;
    ch.state.offset = randomQ(rng);
    for (&ch.state.coefficients) |*c| c.* = randomQ(rng);
    ch.rom.offset = randomQ(rng);
    for (&ch.rom.coefficients) |*c| c.* = randomQ(rng);
    ch.tables.offset = randomQ(rng);
    for (&ch.tables.coefficients) |*c| c.* = randomQ(rng);
    ch.alpha = randomQ(rng);
    ch.claim = randomQ(rng);
    const output = try a.alloc(E.PackedSecure, CAPACITY);
    defer a.free(output);
    var packed_sink = E.PackedSink{ .values = output };
    emit(F, &plan, .{ .f = fixed, .m = main }, physical, current, previous, advice, prior_advice, geometry.*, ch, &packed_sink);
    const expected = try a.alloc(Q, CAPACITY);
    defer a.free(expected);
    for (scalar, 0..) |*row, lane| {
        var sink = E.Sink{ .values = expected };
        emit(Q, &plan, .{ .f = &row.fixed, .m = &row.main }, row.physical[0..plan.main_count], &row.current, &row.previous, &row.advice, &row.prior_advice, row.geometry, ch, &sink);
        try std.testing.expectEqual(sink.count, packed_sink.count);
        for (expected[0..sink.count], output[0..sink.count]) |value, actual| try std.testing.expect(value.eql(actual.lane(lane)));
    }
}
test "mixed SIMD state ROM frame and lookup equations equal16arbitrary base-valued scalar rows" {
    try compare(E.PackedBase);
}
test "mixed SIMD authority retains arbitrary extension-valued OODS polynomial identities" {
    try compare(E.PackedSecure);
}
