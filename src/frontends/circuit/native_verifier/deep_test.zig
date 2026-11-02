//! Value-mode parity of `deep.zig` with the native DEEP answers: the
//! capture's `deep_answers` (`quotients.friAnswers` expanded to raw query
//! order) on the prover-built fixture, and `addConstantPoint`.

const std = @import("std");
const core = @import("stwo_core");
const builder = @import("../builder/mod.zig");
const sv_circle = @import("../stark_verifier/circle.zig");
const deep = @import("deep.zig");
const fixture_mod = @import("test_fixture.zig");
const proof_mod = @import("proof.zig");
const shape_mod = @import("shape.zig");

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const Context = builder.Context(QM31);
const Var = builder.Var;
const Simd = builder.simd.Simd;

fn packLanes(ctx: *Context, values: []const M31) !Simd {
    const lanes = try ctx.scratch().alloc(builder.wrappers.M31Wrapper(Var), values.len);
    for (lanes, values) |*lane, value| lane.* = try builder.wrappers.guessM31(QM31, ctx, builder.wrappers.m31Value(QM31, value));
    return builder.simd.pack(QM31, ctx, lanes);
}

test "native deep: friInput reproduces the native DEEP answers at every raw query" {
    const gpa = std.testing.allocator;
    var fixture = try fixture_mod.Fixture.init(gpa, fixture_mod.default_config, fixture_mod.default_statement);
    defer fixture.deinit(gpa);
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const value_proof = try proof_mod.fromNative(arena.allocator(), fixture_mod.Hasher, &fixture.proof, &fixture.capture, &fixture.shape);

    var ctx = try Context.init(gpa, 0);
    defer ctx.deinit();
    const wires = try proof_mod.guess(QM31, &ctx, &value_proof);
    const oods = core.circle.secureFieldPointFromRandomSeed(fixture.capture.oods_seed);
    const oods_wires: sv_circle.Point(Var) = .{ .x = try ctx.guess(oods.x), .y = try ctx.guess(oods.y) };
    const alpha = try ctx.guess(fixture.capture.deep_randomness);

    const lifting_log = fixture.shape.liftingLogSize();
    const domain = core.poly.circle.canonic.CanonicCoset.new(lifting_log).circleDomain();
    const raw = fixture.capture.queries.raw;
    const xs = try arena.allocator().alloc(M31, raw.len);
    const ys = try arena.allocator().alloc(M31, raw.len);
    for (raw, xs, ys) |position, *x, *y| {
        const point = domain.at(core.utils.bitReverseIndex(position, lifting_log));
        x.* = point.x;
        y.* = point.y;
    }
    const points: sv_circle.Point(Simd) = .{ .x = try packLanes(&ctx, xs), .y = try packLanes(&ctx, ys) };

    const plan = try shape_mod.SamplePlan.init(arena.allocator(), &fixture.shape);
    const answers = try deep.friInput(QM31, &ctx, &plan, oods_wires, wires.sampled_values, alpha, points, wires.queried_values);
    try std.testing.expectEqual(fixture.capture.deep_answers.len, answers.len);
    for (answers, fixture.capture.deep_answers) |wire, expected| try std.testing.expect(ctx.get(wire).eql(expected));
    try ctx.finalize(false);
    try std.testing.expect(try ctx.isCircuitValid());
}

test "native deep: addConstantPoint is the circle group law" {
    var ctx = try Context.init(std.testing.allocator, 0);
    defer ctx.deinit();
    const oods = core.circle.SECURE_FIELD_CIRCLE_GEN.mul(99_991);
    const shift = core.circle.CirclePointIndex.subgroupGen(7).neg().toPoint();
    const point = try deep.addConstantPoint(QM31, &ctx, .{ .x = try ctx.guess(oods.x), .y = try ctx.guess(oods.y) }, shift);
    const expected = oods.add(.{ .x = QM31.fromBase(shift.x), .y = QM31.fromBase(shift.y) });
    try std.testing.expect(ctx.get(point.x).eql(expected.x));
    try std.testing.expect(ctx.get(point.y).eql(expected.y));
    const real = try deep.re(QM31, &ctx, point.x);
    try std.testing.expect(ctx.get(real).eql(.{ .c0 = expected.x.c0, .c1 = core.fields.cm31.CM31.zero() }));
}
