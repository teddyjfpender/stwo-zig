//! Differential test against the native physical component, not a second copy
//! of its equations. Every eight-coordinate input is a circuit witness.
const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const E = A.evaluation;
const C = @import("common.zig");
const V = @import("cpu_oods.zig");
const Role = @import("../../word16_global_execution/services/gkr_local/role.zig");
const O = C.O;
const F = C.F;
const M = core.fields.m31.M31;
const a = std.testing.allocator;
fn dense(i: usize) O {
    var c: [8]M = undefined;
    for (&c, 0..) |*v, j| v.* = M.fromCanonical(@intCast(31 + i * 71 + j * 193));
    return O.fromM31Array(c);
}
fn lift(ctx: *C.Context, comptime T: type, value: T) !F {
    return F.guess(ctx, value);
}
test "CPU leaf original ALU OODS and terminal marginals match native component in all OM31 coordinates" {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const scratch = arena.allocator();
    var ctx = try C.Context.init(a, 0);
    defer ctx.deinit();
    C.lane.begin(&ctx);
    var active = true;
    defer if (active) C.lane.finish() catch {};
    const instance = V.Frame.Instance{ .origin = .{ .core = .alu }, .row_log = 5, .terms = 13, .fixed_offset = 0, .main_offset = 0 };
    const common_point = [_]O{ dense(1), dense(2), dense(3), dense(4), dense(5), dense(6), dense(7), dense(8), dense(9), dense(10) };
    const pair = [_]O{ dense(11), dense(12) };
    const marginals = [_][]const O{&pair};
    const variables = [_]usize{9};
    const artifact = struct { ood_point: []const O, claims_to_verify_by_instance: []const []const O, n_variables_by_instance: []const usize }{ .ood_point = &common_point, .claims_to_verify_by_instance = &marginals, .n_variables_by_instance = &variables };
    var challenges: V.Authority.Source.Challenges.For(O) = undefined;
    for (&challenges.offsets, 0..) |*v, i| v.* = dense(i + 201);
    for (&challenges.coefficients, 0..) |*row, i| for (row, 0..) |*v, j| {
        v.* = dense(301 + 40 * i + j);
    };
    const local = try V.localFromArtifact(O, scratch, instance, 0, artifact, challenges, dense(13));
    var weights: [V.Frame.MAX_LOCAL_TERMS]O = undefined;
    @memcpy(weights[0..local.lane_weights.len], local.lane_weights);
    const data = Role.Data{ .instance = instance, .point = local.point, .lane_weights = weights, .lane_count = local.lane_weights.len, .challenges = challenges, .eta = local.eta, .target_per_row = local.target_per_row };
    const component = Role.Component{ .main = .{ .log_size = 5, .public = .{ .alu = {} }, .offsets = .{ 0, 0 } }, .data = data, .inter_offset = 0, .epoch = 1 };
    const NativeMask = core.air.components.ForField(O).MaskValues;
    const trees = try scratch.alloc([][]O, 3);
    const widths = [_]usize{ 0, 47, 16 };
    const wires = try scratch.alloc([]const []const F, 3);
    for (trees, widths, wires, 0..) |*tree, width, *wiretree, t| {
        tree.* = try scratch.alloc([]O, width);
        const wc = try scratch.alloc([]const F, width);
        wiretree.* = wc;
        for (tree.*, wc, 0..) |*column, *wirecolumn, c| {
            const count: usize = if (t == 2 or (t == 1 and component.previousMain(c))) 2 else 1;
            column.* = try scratch.alloc(O, count);
            const w = try scratch.alloc(F, count);
            wirecolumn.* = w;
            for (column.*, w, 0..) |*v, *wire, s| {
                v.* = dense(1000 + t * 500 + c * 2 + s);
                wire.* = try lift(&ctx, O, v.*);
            }
        }
    }
    var mask = NativeMask{ .items = trees };
    const seed = dense(21);
    const point = core.circle.CirclePoint(O){ .x = O.one().sub(seed.square()).mul(try O.one().add(seed.square()).inv()), .y = seed.add(seed).mul(try O.one().add(seed.square()).inv()) };
    var expected = core.air.accumulation.ForField(O).PointEvaluationAccumulator.init(dense(22));
    try component.evaluateConstraintQuotientsAtPoint(point, &mask, &expected, 5);
    var native = core.air.accumulation.ForField(O).PointEvaluationAccumulator.init(dense(22));
    var source_public = [_]O{O.zero()} ** V.Authority.Source.Public.count;
    source_public[V.Authority.Source.Public.epoch] = O.one();
    const unused: V.Authority.PublicFor(O) = .{ .cpu = undefined, .rows = 0, .nonempty = {}, .span = undefined };
    const native_public = V.PublicFor(O){ .main = unused, .source = source_public, .shared = undefined, .claims = .zero(), .local = local };
    const descriptor = V.Authority.Source.Descriptor{ .origin = instance.origin };
    const slot = V.Slot{ .origin = instance.origin, .log = 5, .fixed_offset = 0, .main_offset = 0, .inter_offset = 0, .binding_index = 0, .claim_offset = 0 };
    const native_samples = try scratch.alloc([]const []const O, 3);
    for (native_samples, trees) |*out, tree| out.* = tree;
    _ = try V.evaluateRole(O, scratch, descriptor, slot, native_public, point, 5, native_samples, &native);
    try std.testing.expect(expected.finalize().eql(native.finalize()));
    var wc: V.Authority.Source.Challenges.For(F) = undefined;
    for (&wc.offsets, challenges.offsets) |*w, v| w.* = try F.guess(&ctx, v);
    for (&wc.coefficients, challenges.coefficients) |*row, vals| for (row, vals) |*w, v| {
        w.* = try F.guess(&ctx, v);
    };
    const wp = try scratch.alloc(F, common_point.len);
    for (wp, common_point) |*w, v| w.* = try F.guess(&ctx, v);
    const pair_wires = [_]F{ try F.guess(&ctx, pair[0]), try F.guess(&ctx, pair[1]) };
    const wm = [_][]const F{&pair_wires};
    const wa = .{ .ood_point = wp, .claims_to_verify_by_instance = &wm, .n_variables_by_instance = &variables };
    const wl = try V.localFromArtifact(F, scratch, instance, 0, wa, wc, try F.guess(&ctx, local.eta));
    var public_wires: [V.Authority.Source.Public.count]F = undefined;
    for (&public_wires, source_public) |*w, v| w.* = try F.guess(&ctx, v);
    var accumulator = E.lane.PointAccumulator(F).init(try F.guess(&ctx, dense(22)));
    const public = V.PublicFor(F){ .main = .{ .cpu = undefined, .rows = F.zero(), .nonempty = F.zero(), .span = undefined }, .source = public_wires, .shared = undefined, .claims = .zero(), .local = wl };
    _ = try V.evaluateRole(F, scratch, descriptor, slot, public, .{ .x = try F.guess(&ctx, point.x), .y = try F.guess(&ctx, point.y) }, 5, wires, &accumulator);
    try C.eq(&ctx, accumulator.finalize(), try F.guess(&ctx, expected.finalize()));
    try C.lane.finish();
    active = false;
    try ctx.finalize(false);
    try std.testing.expect(try ctx.isCircuitValid());
}
