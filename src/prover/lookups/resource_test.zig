//! Numerical admission bound compared to actual live allocations, not RSS.
const std = @import("std");
const core = @import("stwo_core");
const O = core.fields.om31.OM31;
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const Resource = @import("resource.zig");
const Budget = @import("../host_budget_allocator.zig").HostBudgetAllocator;
const Observation = struct { peak: usize, plan: usize };
fn run(comptime S: type, comptime Channel: type, a: std.mem.Allocator, shapes: []const Resource.Shape, constrained: bool) !Observation {
    const G = @import("gkr_prover.zig").ForField(S);
    const ML = @import("mle.zig");
    const plan = try Resource.ForField(S).Plan.forShapes(shapes);
    var budget = Budget.init(a, if (constrained) plan.input_bytes + @sizeOf(G.Layer) * shapes.len + 1 else plan.peak_bytes);
    const ba = budget.allocator();
    // Caller layer descriptors count under the same bound as actual adapters.
    const layers = try ba.alloc(G.Layer, shapes.len);
    defer ba.free(layers);
    var done: usize = 0;
    defer for (layers[0..done]) |*layer| layer.deinit(ba);
    for (shapes, layers) |shape, *layer| {
        const n = @as(usize, 1) << @intCast(shape.variables);
        const d = try ba.alloc(S, n);
        errdefer ba.free(d);
        for (d, 0..) |*v, i| v.* = S.fromBase(M.fromCanonical(@intCast(i % 31 + 3)));
        layer.* = switch (shape.kind) {
            .grand_product => .{ .GrandProduct = try ML.MleFor(S, S).initOwned(d) },
            .singles => .{ .LogUpSingles = .{ .denominators = try ML.MleFor(S, S).initOwned(d) } },
            .generic => blk: {
                const num = try ba.alloc(S, n);
                @memset(num, S.one());
                break :blk .{ .LogUpGeneric = .{ .numerators = try ML.MleFor(S, S).initOwned(num), .denominators = try ML.MleFor(S, S).initOwned(d) } };
            },
            .multiplicities => blk: {
                const num = try ba.alloc(M, n);
                @memset(num, M.one());
                break :blk .{ .LogUpMultiplicities = .{ .numerators = try ML.MleFor(S, M).initOwned(num), .denominators = try ML.MleFor(S, S).initOwned(d) } };
            },
        };
        done += 1;
    }
    var channel = Channel.init();
    var result = @import("gkr_prover.zig").ForField(S).proveBatch(ba, &channel, layers) catch |err| {
        if (constrained and budget.didExceedBudget()) {
            try std.testing.expectEqual(error.OutOfMemory, err);
            return .{ .peak = budget.peak_live_bytes, .plan = plan.peak_bytes };
        }
        return err;
    };
    defer result.deinit(ba);
    try std.testing.expect(!constrained);
    try std.testing.expect(!budget.didExceedBudget());
    try std.testing.expect(budget.peak_live_bytes <= plan.peak_bytes);
    return .{ .peak = budget.peak_live_bytes, .plan = plan.peak_bytes };
}
fn allKinds(a: std.mem.Allocator) !void {
    _ = try run(O, core.channel.raw_mod_m31.Om31Channel, a, &.{
        .{ .kind = .multiplicities, .variables = 7 },
        .{ .kind = .generic, .variables = 6 },
        .{ .kind = .grand_product, .variables = 8 },
        .{ .kind = .singles, .variables = 5 },
    }, false);
}
test "GKR bound covers actual mixed-height all-kind allocations and every OOM" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allKinds, .{});
}
test "GKR bound covers Q and OM single/multiple/mixed small and large matrices" {
    for ([_]u32{ 1, 2, 8, 14, 16 }) |v| {
        const shape = [_]Resource.Shape{.{ .kind = .multiplicities, .variables = v }};
        const om = try run(O, core.channel.raw_mod_m31.Om31Channel, std.testing.allocator, &shape, false);
        const qm = try run(Q, core.channel.raw_mod_m31.Qm31Channel, std.testing.allocator, &shape, false);
        std.debug.print("GKR_ADMISSION single vars={d} OM peak={d} plan={d}; Q peak={d} plan={d}\n", .{ v, om.peak, om.plan, qm.peak, qm.plan });
    }
    try allKinds(std.testing.allocator);
    const mixed = [_]Resource.Shape{
        .{ .kind = .multiplicities, .variables = 16 },
        .{ .kind = .generic, .variables = 14 },
        .{ .kind = .grand_product, .variables = 15 },
        .{ .kind = .singles, .variables = 12 },
    };
    const mixed_observation = try run(O, core.channel.raw_mod_m31.Om31Channel, std.testing.allocator, &mixed, false);
    std.debug.print("GKR_ADMISSION mixed vars=16,14,15,12 OM peak={d} plan={d}\n", .{ mixed_observation.peak, mixed_observation.plan });
    const many = [_]Resource.Shape{.{ .kind = .multiplicities, .variables = 8 }} ** 12;
    const repeated = try run(O, core.channel.raw_mod_m31.Om31Channel, std.testing.allocator, &many, false);
    std.debug.print("GKR_ADMISSION twelve vars=8 OM peak={d} plan={d}\n", .{ repeated.peak, repeated.plan });
}
test "GKR plan rejects malformed and overflowing shape counts" {
    const P = Resource.ForField(O).Plan;
    try std.testing.expectError(error.InvalidGkrResourceShape, P.forShapes(&.{}));
    try std.testing.expectError(error.InvalidGkrResourceShape, P.forShapes(&.{.{ .kind = .generic, .variables = 0 }}));
    try std.testing.expectError(error.InvalidGkrResourceShape, P.forShapes(&.{.{ .kind = .generic, .variables = 31 }}));
    var p = P{ .instances = std.math.maxInt(usize), .max_variables = 30 };
    try std.testing.expectError(error.Overflow, p.finish());
}

test "hard numerical cap reports resource OutOfMemory rather than malformed proof" {
    _ = try run(O, core.channel.raw_mod_m31.Om31Channel, std.testing.allocator, &.{.{ .kind = .multiplicities, .variables = 7 }}, true);
}
