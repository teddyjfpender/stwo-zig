//! Pure context, census and ownership checks; no fake parent/leaf acceptance.
const std = @import("std");
const core = @import("stwo_core");
const Base = @import("../recursion/blake3_execution_parent_protocol.zig");
const Ram = @import("../recursion/block_v5_ram_range_forest_fixed_context_v1.zig");
const Join = @import("../recursion/block_v5_source_ram_forest_join_fixed_context_v1.zig");
const Plan = @import("../recursion/block_v5_ram_range_forest_plan_v1.zig");
const Factory = @import("../recursion/block_v5_ram_range_forest_fixed_assembly_v1.zig");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
fn child() Base.Context {
    return .{ .child_key_id = @splat(10), .child_config = Base.CSP_CONFIG, .graph_ids = .{ @splat(11), @splat(12), @splat(13) }, .transcript_plan_id = @splat(14) };
}
fn node() Plan.Node {
    return .{ .kind = .aggregate, .children = @splat(.{ .node = 0 }), .child_count = 2, .lanes = .{ .first = 3, .count = 5 }, .shards = .{ .first = 1, .count = 2 }, .events = 7, .requests = 9 };
}
fn finish(channels: [5]core.channel.blake3.Channel) Base.Context {
    return .{ .child_key_id = channels[0].digestBytes(), .child_config = Base.CSP_CONFIG, .graph_ids = .{ channels[1].digestBytes(), channels[2].digestBytes(), channels[3].digestBytes() }, .transcript_plan_id = channels[4].digestBytes() };
}
test "compact memory fixed assembly: VERSION19 exact original context and child order" {
    const n = node();
    var actual = Ram.Owned.init(2, n, @splat(1), @splat(2));
    var original: [5]core.channel.blake3.Channel = @splat(.{});
    for (&original, 0..) |*c, i| {
        c.mixU32s(&.{ 0x52524652, 19, @intCast(i), 2, n.lanes.first, n.lanes.count, n.shards.first, n.shards.count });
        c.mixRoot(@splat(1));
        c.mixRoot(@splat(2));
    }
    actual.child(@splat(3), child());
    for (&original) |*c| c.mixRoot(@splat(3));
    for (original[1..4], child().graph_ids) |*c, id| c.mixRoot(id);
    original[4].mixRoot(child().transcript_plan_id);
    actual.attachment(@splat(4));
    actual.attachment(@splat(5));
    for (&original) |*c| {
        c.mixRoot(@splat(4));
        c.mixRoot(@splat(5));
    }
    try std.testing.expectEqualDeep(finish(original), actual.finish(Base.CSP_CONFIG));
    var changed = Ram.Owned.init(2, n, @splat(1), @splat(2));
    changed.attachment(@splat(4));
    changed.child(@splat(3), child());
    changed.attachment(@splat(5));
    try std.testing.expect(!std.meta.eql(changed.finish(Base.CSP_CONFIG), actual.finish(Base.CSP_CONFIG)));
}
test "compact memory fixed assembly: VERSION20 exact original expected key namespaces and closures" {
    var actual = Join.Owned.init(2, @splat(1), @splat(2), @splat(3));
    var original: [5]core.channel.blake3.Channel = @splat(.{});
    for (&original, 0..) |*c, i| {
        c.mixU32s(&.{ 0x42354d52, 20, @intCast(i), 2 });
        c.mixRoot(@splat(1));
        c.mixRoot(@splat(2));
        c.mixRoot(@splat(3));
    }
    actual.child(@splat(4), @splat(5), child());
    for (&original) |*c| {
        c.mixRoot(@splat(4));
        c.mixRoot(@splat(5));
    }
    for (original[1..4], child().graph_ids) |*c, id| c.mixRoot(id);
    original[4].mixRoot(child().transcript_plan_id);
    actual.attachment(@splat(6));
    actual.attachment(@splat(7));
    for (&original) |*c| {
        c.mixRoot(@splat(6));
        c.mixRoot(@splat(7));
    }
    try std.testing.expectEqualDeep(finish(original), actual.finish(Base.CSP_CONFIG));
    var changed = Join.Owned.init(1, @splat(1), @splat(2), @splat(3));
    changed.child(@splat(4), @splat(5), child());
    changed.attachment(@splat(6));
    changed.attachment(@splat(7));
    try std.testing.expect(!std.meta.eql(changed.finish(Base.CSP_CONFIG), actual.finish(Base.CSP_CONFIG)));
}
test "compact memory fixed assembly: ordinal census plan and seal mutations change original contexts" {
    const original = Ram.Owned.init(2, node(), @splat(1), @splat(2)).finish(Base.CSP_CONFIG);
    var n = node();
    n.lanes.count += 1;
    try std.testing.expect(!std.meta.eql(original, Ram.Owned.init(2, n, @splat(1), @splat(2)).finish(Base.CSP_CONFIG)));
    try std.testing.expect(!std.meta.eql(original, Ram.Owned.init(3, node(), @splat(1), @splat(2)).finish(Base.CSP_CONFIG)));
    try std.testing.expect(!std.meta.eql(original, Ram.Owned.init(2, node(), @splat(3), @splat(2)).finish(Base.CSP_CONFIG)));
    try std.testing.expect(!std.meta.eql(original, Ram.Owned.init(2, node(), @splat(1), @splat(3)).finish(Base.CSP_CONFIG)));
}
test "compact memory fixed assembly: limits fail before dereferencing original admissions" {
    const F = Factory.ForBackend(@import("stwo_cpu_backend").CpuBackend);
    try std.testing.expectError(error.RamRangeFixedResourceLimit, F.derive(std.testing.allocator, undefined, @splat(0), 0, .csp_q70_pow26, .{}));
    try std.testing.expectError(error.RamRangeFixedResourceLimit, F.derive(std.testing.allocator, undefined, @splat(0), 1, .csp_q70_pow26, .{ .max_live_bytes = 0 }));
    try std.testing.expectError(error.RamRangeFixedResourceLimit, (Factory.Limits{ .max_rows_per_cohort = (1 << 24) + 1 }).validate(1));
}
fn custody(a: std.mem.Allocator) !void {
    const aggregate = try Budget.createRetainingParent(a, 1024);
    var creator: ?*Budget = aggregate;
    defer if (creator) |owner| owner.destroy();
    const metadata = try Budget.createRetainingParent(aggregate.allocator(), 16);
    defer metadata.destroy();
    const live = try Budget.createRetainingParent(aggregate.allocator(), 256);
    defer live.destroy();
    const record = try metadata.allocator().alloc(u8, 8);
    defer metadata.allocator().free(record);
    const scratch = try live.allocator().alloc(u8, 128);
    defer live.allocator().free(scratch);
    // Both lanes retain backing independently; a larger live allocation does
    // not charge the metadata16-byte cap, and creator release leaves both alive.
    aggregate.destroy();
    creator = null;
    @memset(record, 9);
    @memset(scratch, 7);
    try std.testing.expectEqual(@as(u8, 9), record[7]);
    try std.testing.expectEqual(@as(u8, 7), scratch[127]);
}
test "compact memory fixed assembly: independent metadata live caps retained backing and OOM" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, custody, .{});
}
